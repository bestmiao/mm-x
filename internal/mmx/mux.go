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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
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

// YamuxConfig 是复用会话的配置：keepalive 30 秒（死会话及时发现，
// 客户端会话池靠它知道该重拨）；日志丢弃（yamux 默认往 stderr 写，
// 服务端日志里不要混进复用库的噪音）。
func YamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
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
func ServeMuxSession(mc *Conn, serverRate, serverBurst int64, remote string, allowPrivate bool, idleTimeout time.Duration) error {
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
			go ServeMuxStream(r.st, sess, serverRate, serverBurst, remote, allowPrivate)
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
func ServeMuxStream(stream net.Conn, sess *ServerSession, serverRate, serverBurst int64, remote string, allowPrivate bool) {
	defer sess.removeStream()
	kind, target, rate, burst, err := DecodeStreamHeader(stream)
	if err != nil {
		stream.Close()
		return
	}
	lim := sess.limiter(rate, burst, serverRate, serverBurst)
	switch kind {
	case StreamKindTCP:
		serveMuxTCP(stream, target, lim, remote, allowPrivate)
	case StreamKindUDP:
		serveMuxUDP(stream, target, lim, remote, allowPrivate)
	default:
		stream.Close()
	}
}

func serveMuxTCP(stream net.Conn, target string, lim *Limiter, remote string, allowPrivate bool) {
	targetConn, err := DialTarget("tcp", target, 10*time.Second, allowPrivate)
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
	RelayConns(stream, targetConn, lim)
}

// udpFlowIdleTimeout：一条 UDP 流多久没数据报就关掉（避免流泄漏）。
// DNS/QUIC 平时几秒就有包，120 秒足够宽松；
// 客户端的 UDP 关联断开时也会主动关流。
const udpFlowIdleTimeout = 120 * time.Second

func serveMuxUDP(stream net.Conn, target string, lim *Limiter, remote string, allowPrivate bool) {
	udpConn, err := DialTarget("udp", target, 10*time.Second, allowPrivate)
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
	// 流 → UDP：读长度前缀数据报，发给目标
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_ = stream.SetReadDeadline(time.Now().Add(udpFlowIdleTimeout))
			dg, err := ReadDatagram(stream)
			if err != nil {
				return
			}
			lim.Wait(len(dg))
			_ = udpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := udpConn.Write(dg); err != nil {
				return
			}
		}
	}()
	// UDP → 流：读目标回来的数据报，写长度前缀进流
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
			_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := WriteDatagram(stream, buf[:n]); err != nil {
				return
			}
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
type ClientSession struct {
	cfg    *LinkConfig
	raw    net.Conn
	ys     *yamux.Session
	lim    *Limiter
	closed chan struct{}
	once   sync.Once
}

// DialAndHandshake 拨号 + mm-x 握手（C5）：域名解析出多个 IP 时逐个试，
// 拨号或握手失败就换下一个 IP；全部失败时优先报第一个握手阶段的错误
// （TCP 接通后 pin/密钥/版本不对 = 服务端明确拒绝），而不是最后一个
// IP 的 connection refused——否则 ::1 这类没服务的 IP 会把真正的
// 拒绝原因盖掉（localhost 测 bad-pin 时就这么丢过一次）。
// 密钥错了会在每个 IP 上都失败，最后一次的错误就是密钥错，不会误导。
func DialAndHandshake(cfg *LinkConfig, badMagic, badVersion, tlsInsecure bool) (net.Conn, *SessionKeys, error) {
	ips, err := ResolveHost(cfg.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("连接服务端失败：%v", err)
	}
	var lastErr error
	var firstHandshakeErr error
	for _, ip := range ips {
		raw, keys, tcpOK, err := dialAndHandshakeIP(cfg, ip, badMagic, badVersion, tlsInsecure)
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

// dialAndHandshakeIP 对一个 IP 做一次拨号 + mm-x 握手。
// 返回 tcpOK 表示 TCP 是否接通：接通后握手失败 = 服务端明确拒绝。
func dialAndHandshakeIP(cfg *LinkConfig, ip string, badMagic, badVersion, tlsInsecure bool) (net.Conn, *SessionKeys, bool, error) {
	var raw net.Conn
	var err error
	if cfg.Obfs == "tls" {
		pin := ""
		if len(cfg.PIN) == 32 {
			pin = FormatPIN(cfg.PIN)
		}
		var tcpOK bool
		raw, tcpOK, err = DialTLSWithPinIP(ip, cfg.Port, ResolveSNI(cfg), pin, 5*time.Second, tlsInsecure)
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
		lim:    NewLimiter(cfg.Rate, cfg.Burst),
		closed: make(chan struct{}),
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

// SessionPool 是客户端的会话池：同一条链接只留一条会话，
// 多个 SOCKS5 请求共用它（复用的意义就在于此）。
// 键是整条链接文本（里面有密钥和全部参数，只在内存里用，不记日志）。
type SessionPool struct {
	mu sync.Mutex
	m  map[string]*ClientSession
}

// NewSessionPool 新建会话池。
func NewSessionPool() *SessionPool {
	return &SessionPool{m: make(map[string]*ClientSession)}
}

// sessionKey 会话池的键：短链接 + 影响会话行为的字段。
// BuildLink 是短格式（省掉了 rate/burst 和可由版本推断的 obfs），
// 但会话池必须区分它们（不同限速/混淆 = 不同会话），所以这里单独拼上。
func sessionKey(cfg *LinkConfig) string {
	return fmt.Sprintf("%s|rate=%d|burst=%d|obfs=%s",
		BuildLink(cfg), cfg.Rate, cfg.Burst, effectiveObfs(cfg.Version, cfg.Obfs))
}

// Get 拿一条会话：池里有活的就直接用，没有就现拨一条。
// 拨号全程持有锁（单飞）：并发首次请求时只有一个 goroutine 真去拨号，
// 其他的等锁、直接用拨好的那条——否则 20 个并发请求会拨出 20 条会话，
// 服务端看到 20 次握手，复用“一条连接多条流”的意义就没了。
// 代价：服务端挂了时并发请求要一起等拨号超时（最多 5 秒），单用户可接受。
func (p *SessionPool) Get(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error) {
	key := sessionKey(cfg)
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.m[key]; ok && !s.IsClosed() {
		return s, nil
	}
	if old, ok := p.m[key]; ok {
		// 池里那条已经死了：清掉再拨。
		delete(p.m, key)
		_ = old.Close()
	}
	s, err := DialSession(cfg, badMagic, badVersion, badKey, tlsInsecure)
	if err != nil {
		return nil, err
	}
	p.m[key] = s
	return s, nil
}

// Drop 把一条死会话从池里清掉（下次 Get 会重拨）。
func (p *SessionPool) Drop(s *ClientSession) {
	key := sessionKey(s.cfg)
	p.mu.Lock()
	if cur, ok := p.m[key]; ok && cur == s {
		delete(p.m, key)
	}
	p.mu.Unlock()
}

var errSessionClosed = errors.New("复用会话已关闭")
