// v3 复用层（大哥 2026-11-23 18:06 "加入udp吧，加入连接复用"）：
// 一条 TCP（或 TLS）连接上跑一个 yamux 会话，多条逻辑流共用它。
//
// 为什么选 hashicorp/yamux 而不是手写分帧：
//   - 经过验证的库：yamux 是 HashiCorp 给 Consul/Nomad 写的复用库，
//     流控、窗口、keepalive、半关闭都经过长期生产检验；
//     手写分帧要自己重新实现流控和背压，稍有不慎就丢数据或死锁。
//   - 和 smux 比：smux 也是成熟库，但 yamux 用得更广、维护更活跃，
//     且 yamux 的 Close() 是半关闭（本地关只禁写，读端把缓冲排空
//     再收 EOF），正好符合代理中继“先结束的那边发 FIN、对端读完
//     再断”的语义；smux 的流关闭语义没这么干净。
//   - yamux 跑在加密帧连接（frameConn）之上：yamux 自己的帧头
//     全在 AES-GCM 密文里，线上看不到复用结构。
//
// 限速是按会话算的（一只桶，全会话所有流共用）：
//   - 这同时堵住了 v2 的口子：v2 每条连接各拿一个桶，并行连 10 条
//     就能跑到 500 Mbps；v3 一个会话不管开多少流，总量就是服务端
//     的 rate（默认 6250K/s ≈ 50 Mbps）。
package mmx

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// ---------------------------------------------------------------------------
// frameConn：把 *Conn（加密帧连接）包成 net.Conn 给 yamux 用
// ---------------------------------------------------------------------------

// frameConn 是 yamux 的传输层：Write → 一帧 FrameData，
// Read → 按帧读回、拼成字节流。yamux 的读写各只有一个 goroutine，
// 不用再加锁；Conn 自己的写锁（writeOneFrame 的 mu）仍在。
type frameConn struct {
	c       *Conn
	buf     []byte // 上一帧没读完的剩余载荷
	readErr error  // 读到 FrameClose 后记下来，后续 Read 都返回 EOF
}

func NewFrameConn(c *Conn) net.Conn { return &frameConn{c: c} }

func (f *frameConn) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	for len(f.buf) == 0 {
		ftype, payload, err := f.c.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch ftype {
		case FrameData:
			f.buf = payload
		case FrameClose:
			f.readErr = io.EOF
			return 0, io.EOF
		default:
			// 复用会话里不该出现 CONNECT/ACK 帧，跳过（不影响流语义）
			continue
		}
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *frameConn) Write(p []byte) (int, error) {
	if err := f.c.WriteFrame(FrameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *frameConn) Close() error {
	// FrameClose 是礼貌通知：对端收到就知道会话正常结束。
	// 但关连接不能等它写完——对端可能早就不读了，
	// 同步管道（net.Pipe）上写会一直等到对方读，直接等就死锁
	//（空闲超时的测试就撞上过：服务端关会话时客户端没人读）。
	// 起个 goroutine 发，发不出去也无所谓，底层连接照样关；
	// 写操作在连接关掉后会立刻失败返回，不会漏 goroutine。
	go func() { _ = f.c.WriteFrame(FrameClose, nil) }()
	return f.c.Close()
}

func (f *frameConn) LocalAddr() net.Addr                { return f.c.LocalAddr() }
func (f *frameConn) RemoteAddr() net.Addr               { return f.c.RemoteAddr() }
func (f *frameConn) SetDeadline(t time.Time) error      { return f.c.SetDeadline(t) }
func (f *frameConn) SetReadDeadline(t time.Time) error  { return f.c.SetReadDeadline(t) }
func (f *frameConn) SetWriteDeadline(t time.Time) error { return f.c.SetWriteDeadline(t) }

// YamuxConfig 是复用会话的配置：keepalive（死会话及时发现，
// 客户端会话池靠它知道该重拨）；日志丢弃（yamux 默认往 stderr 写，
// 服务端日志里不要混进复用库的噪音）。
// keepalive 间隔每会话随机 25–50 秒（原来固定 30 秒）：
// 固定周期的小记录本身就是一个时序特征，随机化把它抹掉。
// 间隔用 crypto/rand 现抽——它就是线上能观测到的量。
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	jitter, err := rand.Int(rand.Reader, big.NewInt(26))
	if err != nil {
		jitter = big.NewInt(0)
	}
	cfg.KeepAliveInterval = time.Duration(25+jitter.Int64()) * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// ---------------------------------------------------------------------------
// 双向中继（v2 relay 的通用版，yamux 流和普通连接都能用）
// ---------------------------------------------------------------------------

// RelayConns 在两条连接之间双向转发，任一方向结束就关两端。
// yamux 流的 Close 是半关闭：先结束的那边发 FIN，对端把缓冲里的数据
// 读完再收 EOF，所以先结束不会丢另一方向还在路上的数据；
// 普通 TCP 连接的 Close 就是全关，和 v2 的行为一致。
func RelayConns(a, b net.Conn, lim *Limiter) {
	done := make(chan struct{}, 2)
	go func() { pumpConnToConn(a, b, lim); done <- struct{}{} }()
	go func() { pumpConnToConn(b, a, lim); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func pumpConnToConn(src, dst net.Conn, lim *Limiter) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			lim.Wait(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// RelayConnsCounted 是 RelayConns 的服务端版：双向转发的同时记流量。
// a 是客户端一侧（yamux 流），b 是目标一侧：a→b 是入站
// （客户端→服务端→目标），b→a 是出站（目标→服务端→客户端）。
// 只统计真实转发出去的字节（写成功后才记），握手和流头不算。
// 超限后 tc.Wait 会把流量压到 TC 限速值（阻断模式/不限额时直接返回，
// 不影响正常流量）。tc 为 nil 时就是普通中继，不计数不限速。
func RelayConnsCounted(a, b net.Conn, lim *Limiter, tc *TrafficCounter) {
	done := make(chan struct{}, 2)
	go func() { pumpConnToConnCounted(a, b, lim, tc, false); done <- struct{}{} }()
	go func() { pumpConnToConnCounted(b, a, lim, tc, true); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func pumpConnToConnCounted(src, dst net.Conn, lim *Limiter, tc *TrafficCounter, outbound bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			lim.Wait(n)
			tc.Wait(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if outbound {
				tc.AddOut(int64(n))
			} else {
				tc.AddIn(int64(n))
			}
		}
		if err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// UDP 数据报帧（流内）：2 字节长度 + 数据报
// ---------------------------------------------------------------------------

const maxDatagramSize = 65535 // UDP 数据报上限

// WriteDatagram 往流里写一个数据报（长度前缀 + 数据报本身）。
func WriteDatagram(w io.Writer, b []byte) error {
	if len(b) > maxDatagramSize {
		return fmt.Errorf("数据报太大：%d 字节（上限 %d）", len(b), maxDatagramSize)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// ReadDatagram 从流里读一个数据报。
func ReadDatagram(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 0 || n > maxDatagramSize {
		return nil, fmt.Errorf("数据报长度不合法：%d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// 服务端：会话级限速 + 流处理
// ---------------------------------------------------------------------------

// ServerSession 是一条 v3 会话在服务端的状态：限速器由会话里所有流共用，
// 第一条流的 CONNECT（rate/burst）和服务端上限取 min 后定下来，
// 后面的流不再另算——并行开多少流总量都是这一个桶。
// active 是当前开着的流数（空闲超时用：有流在跑时不算空闲，
// 正在传大文件的会话不会因为 10 分钟没开新流就被断开）。
type ServerSession struct {
	mu     sync.Mutex
	lim    *Limiter
	active int
}

// NewServerSession 新建一条 v3 会话的服务端状态。
func NewServerSession() *ServerSession { return &ServerSession{} }

func (s *ServerSession) limiter(rate, burst, serverRate, serverBurst int64) *Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lim == nil {
		s.lim = NewLimiter(MinRate(serverRate, rate), EffectiveBurst(serverBurst, burst))
	}
	return s.lim
}

// addStream / removeStream 记一条流的开/关（ServeMuxStream 进出时调）。
func (s *ServerSession) addStream() {
	s.mu.Lock()
	s.active++
	s.mu.Unlock()
}

func (s *ServerSession) removeStream() {
	s.mu.Lock()
	if s.active > 0 {
		s.active--
	}
	s.mu.Unlock()
}

// ActiveStreams 返回当前开着的流数。
func (s *ServerSession) ActiveStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// SessionIdleTimeout 是 v3 会话的空闲超时：10 分钟没开新流、
// 且没有流在跑，就关掉会话（重放出来的死会话、客户端早已不用的
// 残留会话不会一直占着）。客户端会话池会在下次请求时重拨，
// 正常使用只多一次握手（约 100ms），感觉不到。
const SessionIdleTimeout = 10 * time.Minute

// ServeMuxSession 在一条已握手的加密连接上跑 v3 复用会话：
// 接受流、逐条处理，直到会话断开或空闲超时才返回（调用方记日志即可）。
// idleTimeout <= 0 表示不设空闲超时（测试用）。
// 空闲的定义：idleTimeout 内没开新流、且没有流在跑。
// 接受流的 goroutine 整个会话只有一个（done 关掉时它才退出），
// 不会每轮都起一个——否则有流在跑时每次超时都会漏一个 goroutine。
// tc 是流量计数器（可为 nil）：流里转发的字节都记进去，
// 阻断模式超限后新开的流直接关掉（会话建立之前就超限的连接
// 由调用方在握手后挡掉，这里是第二道防线）。
func ServeMuxSession(mc *Conn, serverRate, serverBurst int64, remote string, policy TargetPolicy, idleTimeout time.Duration, tc *TrafficCounter) error {
	ys, err := yamux.Server(NewFrameConn(mc), YamuxConfig())
	if err != nil {
		return fmt.Errorf("建立复用会话失败：%v", err)
	}
	sess := NewServerSession()
	type acceptResult struct {
		st  net.Conn
		err error
	}
	ch := make(chan acceptResult, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			st, err := ys.AcceptStream()
			select {
			case ch <- acceptResult{st, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	var timer *time.Timer
	var timerCh <-chan time.Time
	resetTimer := func() {
		if idleTimeout <= 0 {
			return
		}
		if timer == nil {
			timer = time.NewTimer(idleTimeout)
		} else {
			timer.Reset(idleTimeout)
		}
		timerCh = timer.C
	}
	resetTimer()
	for {
		select {
		case r := <-ch:
			if r.err != nil {
				return nil // 会话断了（对端关了 / 底层连接断了），正常结束
			}
			sess.addStream()
			go ServeMuxStream(r.st, sess, serverRate, serverBurst, remote, policy, tc)
			resetTimer()
		case <-timerCh:
			if sess.ActiveStreams() > 0 {
				resetTimer() // 有流在跑：不算空闲，再等一轮
				continue
			}
			ys.Close() // 叫醒上面阻塞的 AcceptStream goroutine
			return nil
		}
	}
}

// ServeMuxStream 处理复用会话里新开的一条流：读流头，按种类分流。
// 阻断模式下流量已超限时直接关流（会话是超限前建好的，
// 新流不能再用；已有流由服务端的流量监视 goroutine 断开）。
func ServeMuxStream(stream net.Conn, sess *ServerSession, serverRate, serverBurst int64, remote string, policy TargetPolicy, tc *TrafficCounter) {
	defer sess.removeStream()
	kind, target, rate, burst, err := DecodeStreamHeader(stream)
	if err != nil {
		stream.Close()
		return
	}
	if tc.Blocked() {
		stream.Close()
		return
	}
	lim := sess.limiter(rate, burst, serverRate, serverBurst)
	switch kind {
	case StreamKindTCP:
		serveMuxTCP(stream, target, lim, remote, policy, tc)
	case StreamKindUDP:
		serveMuxUDP(stream, target, lim, remote, policy, tc)
	default:
		stream.Close()
	}
}

func serveMuxTCP(stream net.Conn, target string, lim *Limiter, remote string, policy TargetPolicy, tc *TrafficCounter) {
	targetConn, err := DialTarget("tcp", target, 10*time.Second, policy)
	if err != nil {
		// 目标地址不记进日志（A6）：服务端日志只留错误码，
		// 目标地址是用户的访问记录，不该留在 VPS 的日志里；
		// 完整原因在客户端的 ACK 里（客户端是用户自己的机器）。
		log.Printf("[%s] 流目标拨号失败 [%s]", remote, ClassifyDialError(err))
		_ = WriteStreamAck(stream, err)
		stream.Close()
		return
	}
	if err := WriteStreamAck(stream, nil); err != nil {
		targetConn.Close()
		stream.Close()
		return
	}
	RelayConnsCounted(stream, targetConn, lim, tc)
}

// udpFlowIdleTimeout：一条 UDP 流多久没数据报就关掉（避免流泄漏）。
// DNS/QUIC 平时几秒就有包，120 秒足够宽松；
// 客户端的 UDP 关联断开时也会主动关流。
const udpFlowIdleTimeout = 120 * time.Second

func serveMuxUDP(stream net.Conn, target string, lim *Limiter, remote string, policy TargetPolicy, tc *TrafficCounter) {
	udpConn, err := DialTarget("udp", target, 10*time.Second, policy)
	if err != nil {
		// 目标地址不记进日志（A6，理由同 serveMuxTCP）。
		log.Printf("[%s] UDP 流目标拨号失败 [%s]", remote, ClassifyDialError(err))
		_ = WriteStreamAck(stream, err)
		stream.Close()
		return
	}
	if err := WriteStreamAck(stream, nil); err != nil {
		udpConn.Close()
		stream.Close()
		return
	}
	defer udpConn.Close()
	defer stream.Close()
	done := make(chan struct{}, 2)
	// 流 → UDP：读长度前缀数据报，发给目标（入站）
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_ = stream.SetReadDeadline(time.Now().Add(udpFlowIdleTimeout))
			dg, err := ReadDatagram(stream)
			if err != nil {
				return
			}
			lim.Wait(len(dg))
			tc.Wait(len(dg))
			_ = udpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := udpConn.Write(dg); err != nil {
				return
			}
			tc.AddIn(int64(len(dg)))
		}
	}()
	// UDP → 流：读目标回来的数据报，写长度前缀进流（出站）
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, maxDatagramSize)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(udpFlowIdleTimeout))
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			lim.Wait(n)
			tc.Wait(n)
			_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := WriteDatagram(stream, buf[:n]); err != nil {
				return
			}
			tc.AddOut(int64(n))
		}
	}()
	<-done
	// 任一方向结束（对端关流 / 目标不回包超时）就关两端，另一方向随之退出
	udpConn.Close()
	stream.Close()
	<-done
	_ = remote
}

// ---------------------------------------------------------------------------
// 客户端：v3 会话 + 会话池
// ---------------------------------------------------------------------------

// ClientSession 是一条 v3 复用会话：一条 TCP（或 TLS）连接 + yamux，
// 上面开多条流；会话级限速器由会话里所有流共用。
// createdAt 是会话拨通的时间（会话轮换用：太老的会话在空闲时重拨，
// 避免一条连接一跑就是几小时——真实浏览器的连接没这么长寿）。
type ClientSession struct {
	cfg       *LinkConfig
	raw       net.Conn
	ys        *yamux.Session
	lim       *Limiter
	closed    chan struct{}
	once      sync.Once
	createdAt time.Time
}

// DialAndHandshake 拨号 + mm-x 握手（C5）：域名解析出多个 IP 时逐个试，
// 拨号或握手失败就换下一个 IP；全部失败时优先报第一个握手阶段的错误
// （TCP 接通后 pin/密钥/版本不对 = 服务端明确拒绝），而不是最后一个
// IP 的 connection refused——否则 ::1 这类没服务的 IP 会把真正的
// 拒绝原因盖掉（localhost 测 bad-pin 时就这么丢过一次）。
// 密钥错了会在每个 IP 上都失败，最后一次的错误就是密钥错，不会误导。
func DialAndHandshake(cfg *LinkConfig, badMagic, badVersion, tlsInsecure bool) (net.Conn, *SessionKeys, error) {
	// 有上游代理时跳过本地解析：目标域名原样发进 SOCKS5 CONNECT，
	// 由代理端解析（链式时入口转发器在本机，解析的是它该拨的地址）。
	if cfg.ProxyAddr != "" {
		return dialAndHandshakeViaProxy(cfg, badMagic, badVersion, tlsInsecure)
	}
	ips, err := ResolveHost(cfg.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("连接服务端失败：%v", err)
	}
	var lastErr error
	var firstHandshakeErr error
	// SNI 按会话定一次（v5 + IP host 时每会话轮换，见 SessionSNI），
	// 同一次拨号里的多个 IP 尝试共用同一个 SNI。
	sni := SessionSNI(cfg)
	for _, ip := range ips {
		raw, keys, tcpOK, err := dialAndHandshakeIP(cfg, ip, sni, badMagic, badVersion, tlsInsecure)
		if err == nil {
			return raw, keys, nil
		}
		if tcpOK && firstHandshakeErr == nil {
			firstHandshakeErr = err
		}
		lastErr = err
	}
	if firstHandshakeErr != nil {
		return nil, nil, firstHandshakeErr
	}
	return nil, nil, lastErr
}

// dialAndHandshakeViaProxy 经上游 SOCKS5 代理拨 mm-x 服务端再握手
// （链式代理：出口转发器的 --proxy 指到入口转发器）。
// 和直连路径的区别只有底层 TCP 怎么来：DialProxyTCP CONNECT 到
// cfg.Host:cfg.Port，域名原样发、IP 原样发；之后的 TLS 包装
// （tlsHandshakeOverConn）和 mm-x 握手（ClientHandshakeVersion）
// 与直连完全一致，SNI/pin/版本逻辑都不动。
func dialAndHandshakeViaProxy(cfg *LinkConfig, badMagic, badVersion, tlsInsecure bool) (net.Conn, *SessionKeys, error) {
	tcp, err := DialProxyTCP(cfg.ProxyAddr, cfg.Host, cfg.Port, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("连接服务端失败：%v", err)
	}
	var raw net.Conn
	if cfg.Obfs == "tls" {
		pin := ""
		if len(cfg.PIN) == 32 {
			pin = FormatPIN(cfg.PIN)
		}
		raw, err = tlsHandshakeOverConn(tcp, SessionSNI(cfg), pin, 5*time.Second, tlsInsecure)
		if err != nil {
			tcp.Close()
			return nil, nil, fmt.Errorf("连接服务端失败：%v", err)
		}
	} else {
		raw = tcp
	}
	keys, err := ClientHandshakeVersion(raw, cfg.PSK, cfg.Version, badMagic, badVersion)
	if err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("%s", FormatHandshakeError(err))
	}
	return raw, keys, nil
}

// dialAndHandshakeIP 对一个 IP 做一次拨号 + mm-x 握手。
// sni 是本次会话定好的 SNI（调用方 SessionSNI 算好传进来，
// 多个 IP 尝试共用同一个）。
// 返回 tcpOK 表示 TCP 是否接通：接通后握手失败 = 服务端明确拒绝。
func dialAndHandshakeIP(cfg *LinkConfig, ip, sni string, badMagic, badVersion, tlsInsecure bool) (net.Conn, *SessionKeys, bool, error) {
	var raw net.Conn
	var err error
	if cfg.Obfs == "tls" {
		pin := ""
		if len(cfg.PIN) == 32 {
			pin = FormatPIN(cfg.PIN)
		}
		var tcpOK bool
		raw, tcpOK, err = DialTLSWithPinIP(ip, cfg.Port, sni, pin, 5*time.Second, tlsInsecure)
		if err != nil {
			return nil, nil, tcpOK, fmt.Errorf("连接服务端失败：%v", err)
		}
	} else {
		raw, err = net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(cfg.Port)), 5*time.Second)
		if err != nil {
			return nil, nil, false, fmt.Errorf("连接服务端失败：%v", err)
		}
	}
	keys, err := ClientHandshakeVersion(raw, cfg.PSK, cfg.Version, badMagic, badVersion)
	if err != nil {
		raw.Close()
		return nil, nil, true, fmt.Errorf("%s", FormatHandshakeError(err))
	}
	return raw, keys, true, nil
}

// DialSession 拨一条 v3/v4 会话：TCP/TLS 拨号 → 握手 → yamux。
// badMagic/badVersion/badKey 仅供测试错误情况。
func DialSession(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error) {
	raw, keys, err := DialAndHandshake(cfg, badMagic, badVersion, tlsInsecure)
	if err != nil {
		return nil, err
	}
	mc, err := NewConn(raw, keys, true)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("建立加密连接失败：%v", err)
	}
	if badKey {
		mc.TamperSendKey()
	}
	ys, err := yamux.Client(NewFrameConn(mc), YamuxConfig())
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("建立复用会话失败：%v", err)
	}
	return &ClientSession{
		cfg: cfg, raw: raw, ys: ys,
		lim:       NewLimiter(cfg.Rate, cfg.Burst),
		closed:    make(chan struct{}),
		createdAt: time.Now(),
	}, nil
}

// IsClosed 会话是不是已经死了（底层连接断了或 yamux 关了）。
func (s *ClientSession) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
	}
	return s.ys.IsClosed()
}

// Close 关掉整条会话（所有流一起断）。
func (s *ClientSession) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closed)
		err = s.ys.Close()
		_ = s.raw.Close()
	})
	return err
}

// NumStreams 当前会话上开着的流数（监控/测试用）。
func (s *ClientSession) NumStreams() int { return s.ys.NumStreams() }

// openStream 在会话上开一条流并写流头、等 ACK。
func (s *ClientSession) openStream(kind byte, target string) (net.Conn, error) {
	st, err := s.ys.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("复用会话开流失败：%v", err)
	}
	if _, err := st.Write(EncodeStreamHeader(kind, target, s.cfg.Rate, s.cfg.Burst)); err != nil {
		st.Close()
		return nil, fmt.Errorf("发送流头失败：%v", err)
	}
	if err := ReadStreamAck(st); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// OpenTCPStream 在会话上开一条 TCP 流（已接通目标，可直接转发字节流）。
func (s *ClientSession) OpenTCPStream(target string) (net.Conn, error) {
	return s.openStream(StreamKindTCP, target)
}

// OpenUDPFlow 在会话上开一条 UDP 流（已接通目标，之后按长度前缀收发数据报）。
func (s *ClientSession) OpenUDPFlow(target string) (net.Conn, error) {
	return s.openStream(StreamKindUDP, target)
}

// Relay 在一条 TCP 流和本地连接之间双向转发（会话级限速）。
func (s *ClientSession) Relay(local, stream net.Conn) {
	RelayConns(local, stream, s.lim)
}

// SessionPool 是客户端的会话池：同一条链接留最多 maxSessions 条
// 活会话（默认 3 条），多个 SOCKS5 请求按轮询分到不同会话上
// （多路并行：一 条会话的 yamux 流控/丢包不会拖住所有流，
// 一条会话死了也有别的会话能顶上）。
// 键是整条链接文本（里面有密钥和全部参数，只在内存里用，不记日志）。
// maxAge 是会话轮换的最长存活（0 = 不轮换）：超过这个时间的会话，
// 下次 Get 时如果正好没有流在跑，就关掉重拨一条新的——
// 一条连接一跑几小时本身就是特征，真实浏览器会不断开新连接。
// 只在“没有流在跑”的空闲时刻轮换，正在传的流不会被打断；
// 如果一直有流在跑，轮换就一直等下去（不断流、不丢数据）。
// 限速注意：限速器是按会话算的（DialSession 里每条会话各拿一个桶，
// 服务端同样按会话限速），池里 N 条会话时总限速理论上是 N×rate——
// 默认上限 3 条，超出有限；真正的总量控制是服务端的流量配额
// （TrafficCounter，全局），不是这里的会话级限速。
type poolEntry struct {
	sessions []*ClientSession
	next     int // 轮询下标
}

// DefaultPoolMaxSessions 是每条链接默认最多同时留的活会话数。
// 3 条是上限：再多收益递减（握手成本、限速放大、服务端连接数都涨）。
const DefaultPoolMaxSessions = 3

type SessionPool struct {
	mu          sync.Mutex
	m           map[string]*poolEntry
	maxAge      time.Duration
	maxSessions int
	// dial 是拨一条新会话的函数（默认 DialSession）：
	// 单独抽出来是为了测试能注入 pipe 会话，不用真的联网拨号。
	dial func(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error)
}

// NewSessionPool 新建会话池（默认不轮换；命令行客户端用 SetMaxAge 开）。
func NewSessionPool() *SessionPool {
	return &SessionPool{
		m:           make(map[string]*poolEntry),
		maxSessions: DefaultPoolMaxSessions,
		dial:        DialSession,
	}
}

// SetMaxAge 设置会话轮换的最长存活（<=0 = 不轮换）。
func (p *SessionPool) SetMaxAge(d time.Duration) {
	p.mu.Lock()
	p.maxAge = d
	p.mu.Unlock()
}

// SetMaxSessions 设置每条链接最多同时留的活会话数（<1 时按 1 算，
// 上限建议不超过 4：再多握手成本和限速放大都不划算）。
func (p *SessionPool) SetMaxSessions(n int) {
	if n < 1 {
		n = 1
	}
	p.mu.Lock()
	p.maxSessions = n
	p.mu.Unlock()
}

// SessionCount 返回池里某条链接当前活着的会话数（测试/监控用）。
func (p *SessionPool) SessionCount(cfg *LinkConfig) int {
	key := sessionKey(cfg)
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.m[key]
	if e == nil {
		return 0
	}
	n := 0
	for _, s := range e.sessions {
		if !s.IsClosed() {
			n++
		}
	}
	return n
}

// pruneLocked 清掉一条池项里的死会话和过期空闲会话（调用方须持锁）。
// 死会话：底层断了或 yamux 关了；过期会话：超过 maxAge 且没有流在跑。
func (p *SessionPool) pruneLocked(e *poolEntry) {
	kept := e.sessions[:0]
	for _, s := range e.sessions {
		if s.IsClosed() {
			_ = s.Close()
			continue
		}
		if p.maxAge > 0 && time.Since(s.createdAt) > p.maxAge && s.NumStreams() == 0 {
			// 轮换只多一次握手（约 100ms），感觉不到。
			// 注意这里有个极小的竞态：判断完没流、还没关掉的
			// 瞬间可能有新流进来——那条流会在关会话时收到错误，
			// 浏览器/客户端重发一次即可，单用户可接受。
			_ = s.Close()
			continue
		}
		kept = append(kept, s)
	}
	e.sessions = kept
	if e.next > len(e.sessions) {
		e.next = 0
	}
}

// pickIdleLocked 在活会话里轮询挑一条当前没有流在跑的（调用方须持锁），
// 没有空闲的返回 nil。轮询下标只在空闲会话之间走，
// 这样连续请求会均匀分到各条会话上，而不是总粘在第一条。
func (e *poolEntry) pickIdleLocked() *ClientSession {
	n := len(e.sessions)
	for i := 0; i < n; i++ {
		idx := (e.next + i) % n
		if e.sessions[idx].NumStreams() == 0 {
			e.next = idx + 1
			return e.sessions[idx]
		}
	}
	return nil
}

// Get 拿一条会话：池里有空闲的活会话就轮询返回一条，
// 没有空闲的、且还没到上限就现拨一条新的，
// 全部在忙且已到上限时轮询返回一条（调用方在上面开流，共用会话）。
// 拨号全程持有锁（单飞）：并发首次请求时只有一个 goroutine 真去拨号，
// 其他的等锁、直接用拨好的那条——否则 20 个并发请求会拨出 20 条会话，
// 服务端看到 20 次握手，复用“一条连接多条流”的意义就没了。
// 代价：服务端挂了时并发请求要一起等拨号超时（最多 5 秒），单用户可接受。
// 注意：池是按需长大的——顺序单流使用只留 1 条会话，
// 并发上来、所有活会话都在忙时才拨新的（最多 maxSessions 条），
// 不会为了凑数在首连时就多做 2 次握手。
func (p *SessionPool) Get(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error) {
	key := sessionKey(cfg)
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.m[key]
	if e == nil {
		e = &poolEntry{}
		p.m[key] = e
	}
	p.pruneLocked(e)
	if s := e.pickIdleLocked(); s != nil {
		return s, nil
	}
	if len(e.sessions) < p.maxSessions {
		s, err := p.dial(cfg, badMagic, badVersion, badKey, tlsInsecure)
		if err != nil {
			return nil, err
		}
		e.sessions = append(e.sessions, s)
		return s, nil
	}
	s := e.sessions[e.next%len(e.sessions)]
	e.next++
	return s, nil
}

// Drop 把一条死会话从池里清掉（下次 Get 会重拨）。
func (p *SessionPool) Drop(s *ClientSession) {
	key := sessionKey(s.cfg)
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.m[key]
	if e == nil {
		return
	}
	for i, cur := range e.sessions {
		if cur == s {
			e.sessions = append(e.sessions[:i], e.sessions[i+1:]...)
			break
		}
	}
	if len(e.sessions) == 0 {
		delete(p.m, key)
	}
}

// OpenTCPStream 在池里开一条到目标的 TCP 流（已接通目标，可直接转发字节流）。
// 按轮询在活会话上试：会话死了就清掉、换下一条/重拨再试；
// 会话活着但开流失败（目标被服务端拒绝）时重试没用，直接返回错误。
// 最多尝试 maxSessions+1 次，避免死循环。
func (p *SessionPool) OpenTCPStream(cfg *LinkConfig, target string, badMagic, badVersion, badKey, tlsInsecure bool) (net.Conn, *ClientSession, error) {
	return p.openStream(StreamKindTCP, cfg, target, badMagic, badVersion, badKey, tlsInsecure)
}

// OpenUDPFlow 在池里开一条到目标的 UDP 流（重试规则同 OpenTCPStream）。
func (p *SessionPool) OpenUDPFlow(cfg *LinkConfig, target string, badMagic, badVersion, badKey, tlsInsecure bool) (net.Conn, *ClientSession, error) {
	return p.openStream(StreamKindUDP, cfg, target, badMagic, badVersion, badKey, tlsInsecure)
}

func (p *SessionPool) openStream(kind byte, cfg *LinkConfig, target string, badMagic, badVersion, badKey, tlsInsecure bool) (net.Conn, *ClientSession, error) {
	p.mu.Lock()
	maxAttempts := p.maxSessions + 1
	p.mu.Unlock()
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sess, err := p.Get(cfg, badMagic, badVersion, badKey, tlsInsecure)
		if err != nil {
			return nil, nil, err
		}
		var st net.Conn
		if kind == StreamKindTCP {
			st, err = sess.OpenTCPStream(target)
		} else {
			st, err = sess.OpenUDPFlow(target)
		}
		if err == nil {
			return st, sess, nil
		}
		lastErr = err
		if !sess.IsClosed() {
			// 会话还活着：是目标被拒之类的流级错误，重试没用。
			return nil, nil, err
		}
		// 会话死了：清出池、关掉，下一轮 Get 会换一条/重拨。
		p.Drop(sess)
		_ = sess.Close()
	}
	if lastErr == nil {
		lastErr = errSessionClosed
	}
	return nil, nil, lastErr
}

// sessionKey 会话池的键：短链接 + 影响会话行为的字段。
// BuildLink 是短格式（省掉了 rate/burst 和可由版本推断的 obfs），
// 但会话池必须区分它们（不同限速/混淆 = 不同会话），所以这里单独拼上。
func sessionKey(cfg *LinkConfig) string {
	return fmt.Sprintf("%s|rate=%d|burst=%d|obfs=%s",
		BuildLink(cfg), cfg.Rate, cfg.Burst, effectiveObfs(cfg.Version, cfg.Obfs))
}

var errSessionClosed = errors.New("复用会话已关闭")
