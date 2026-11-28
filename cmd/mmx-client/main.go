// mmx-client：mm-x 协议客户端原型。
// 两种工作模式（只用一种）：
//  1. 固定目标模式（原型测试用）：--target <host:port>，本地监听收到连接后
//     全部转发到这一个目标。
//     mmx-client --link "mmx://..." --target 127.0.0.1:18082 --listen 127.0.0.1:18080
//  2. SOCKS5 模式（MM 客户端集成用）：--socks-listen <127.0.0.1:端口>，
//     本地起一个 SOCKS5 代理（无认证，支持 CONNECT 和 UDP ASSOCIATE）：
//     CONNECT 按 SOCKS5 请求里的目标地址转发；UDP ASSOCIATE（v3 才有）
//     把 UDP 数据报经复用会话里的 UDP 流发出去。sing-box 用 socks
//     出站指到这个端口，就能把任意目标的流量经 mm-x 发出去。
//     mmx-client --link "mmx://..." --socks-listen 127.0.0.1:18080
//
// 版本分流（按链接里的 ver）：
//
//	v2：每个目标一次 mm-x 握手 + CONNECT，独占一条 TCP 连接（老流程）；
//	v3/v4/v5：复用会话（会话池按需维持 1–3 条）上开多条流，TCP 和 UDP 流共用
//	    会话级限速——并行开多少流总量都是一个桶。v4 在此之外加了
//	    握手加长、会话重协商和 TLS 1.2 记录版本号；v5 加流量形态伪装。
//	    注意：服务端自 2026-11-26 起不再接受 ver=4（仅 v2/v3/v5），
//	    v4 链接仍能解析，但握手会被服务端明确拒绝。
//
// 不用链接时，用 --server + --psk 也行。
// 测试用的错误开关：--bad-magic / --bad-version / --bad-key
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"mmxpoc/internal/mmx"
)

// pool 是 v3 会话池：同一条链接按需维持 1–3 条复用会话，
// 进程里所有 SOCKS5 请求 / 固定目标连接共用它。
var pool = mmx.NewSessionPool()

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	linkStr := flag.String("link", "", "mmx:// 节点链接（优先于 --server/--psk），也支持 mmx:// 不透明链接（一串乱码）")
	serverAddr := flag.String("server", "127.0.0.1:18081", "mm-x 服务端地址")
	pskHex := flag.String("psk", "", "预共享密钥：64 位十六进制（32 字节），不用 --link 时必填")
	listenAddr := flag.String("listen", "127.0.0.1:18080", "本地监听地址（固定目标模式用）")
	socksListen := flag.String("socks-listen", "", "SOCKS5 监听地址，例如 127.0.0.1:18080；给了就按 SOCKS5 模式跑，--target 不用给")
	target := flag.String("target", "", "目标地址 host:port（固定目标模式必填，例如 127.0.0.1:18082 或 example.com:80）")
	badMagic := flag.Bool("bad-magic", false, "测试用：发送错误的魔数")
	badVersion := flag.Bool("bad-version", false, "测试用：发送错误的版本号")
	badKey := flag.Bool("bad-key", false, "测试用：握手后篡改会话密钥")
	tlsInsecure := flag.Bool("tls-insecure", false, "测试用：obfs=tls 时跳过服务端证书校验（只用于自签名证书的测试，正式部署绝不能用）")
	proxyAddr := flag.String("proxy", "", "上游 SOCKS5 代理地址，例如 127.0.0.1:入口转发器端口；给了就经该代理拨 mm-x 服务端（链式代理用，目标域名原样发进 CONNECT 由代理端解析），不给则直连")
	coverStr := flag.String("cover-traffic", "low", "掩护流量（v5 会话）：off（关）/ low（默认，空闲时平均约 45 秒一帧小记录）/ high（空闲时平均约 20 秒一帧）")
	sessionMaxAgeStr := flag.String("session-max-age", "30m", "会话轮换的最长存活：超过后在空闲时重拨新会话，例如 30m / 1h，0 = 不轮换")
	flag.Parse()

	// 掩护流量档位 + 会话轮换（校验失败直接退出，指明错在哪一项）。
	coverMode, err := mmx.ParseCoverMode(*coverStr)
	if err != nil {
		log.Fatalf("掩护流量：%v", err)
	}
	mmx.DefaultCoverMode = coverMode
	maxAge, err := time.ParseDuration(*sessionMaxAgeStr)
	if err != nil || maxAge < 0 {
		log.Fatalf("会话轮换时长不合法：%q，应为 30m / 1h 这类时长，0 = 不轮换", *sessionMaxAgeStr)
	}
	pool.SetMaxAge(maxAge)

	socksMode := *socksListen != ""
	if !socksMode && *target == "" {
		log.Fatal("缺少目标地址：固定目标模式请用 --target 指定，例如 --target 127.0.0.1:18082；SOCKS5 模式请用 --socks-listen 指定监听地址")
	}

	var cfg *mmx.LinkConfig
	if *linkStr != "" {
		c, err := mmx.ParseLink(*linkStr)
		if err != nil {
			log.Fatalf("mmx:// 链接不合法：%v", err)
		}
		cfg = c
		fmt.Printf("已解析链接：节点 %q，服务器 %s:%d，加密 %s，混淆 %s，版本 %d\n",
			cfg.Name, cfg.Host, cfg.Port, cfg.Enc, cfg.Obfs, cfg.Version)
	} else {
		if *pskHex == "" {
			log.Fatal("未给 --link 时必须给 --psk（64 位十六进制），或直接用 --link 传 mmx:// 链接")
		}
		psk, err := decodeHexKey(*pskHex)
		if err != nil {
			log.Fatalf("psk 不合法：%v", err)
		}
		host, port, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			log.Fatalf("服务端地址不合法：%v", err)
		}
		var portNum int
		if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil || portNum < 1 || portNum > 65535 {
			log.Fatalf("端口不合法：%q 应为 1-65535 之间的数字", port)
		}
		cfg = &mmx.LinkConfig{PSK: psk, Host: host, Port: portNum,
			Enc: "aes-256-gcm", Obfs: "tls-fake", Version: mmx.Version, Name: "mm-x",
			Burst: mmx.BurstUnset}
	}
	// 上游代理（链式用）：两种配置来源都生效。
	cfg.ProxyAddr = *proxyAddr

	if socksMode {
		runSocks(cfg, *socksListen, *badMagic, *badVersion, *badKey, *tlsInsecure)
		return
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("本地监听失败：%v", err)
	}
	defer ln.Close()
	fmt.Printf("mm-x 客户端启动，本地监听 %s，目标 %s，服务端 %s:%d\n",
		*listenAddr, *target, cfg.Host, cfg.Port)
	for {
		local, err := ln.Accept()
		if err != nil {
			log.Printf("接受本地连接失败：%v", err)
			continue
		}
		go handleLocal(local, cfg, *target, *badMagic, *badVersion, *badKey, *tlsInsecure)
	}
}

func decodeHexKey(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("psk 应为 64 位十六进制字符（32 字节），实际 %d 位", len(s))
	}
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var v int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
			return nil, fmt.Errorf("psk 第 %d 字节不是十六进制：%v", i, err)
		}
		b[i] = byte(v)
	}
	return b, nil
}

// dialMMX 对一个目标做一次 v2 的 mm-x 连接：TCP 拨号、握手、发 CONNECT、等 ACK。
// 成功返回加密连接（调用方负责在转发结束时关掉 raw 和 mc；
// raw 是底层 TCP 连接，mc 包装了它，关任意一个都会关底层连接）。
// 失败返回中文原因（日志用，SOCKS5 模式据此回不同的 REP 码）。
// 注意：v3/v4 不走这里（v3/v4 用会话池 + 流，见 openV3Stream）。
func dialMMX(cfg *mmx.LinkConfig, target string, badMagic, badVersion, badKey, tlsInsecure bool) (*mmx.Conn, net.Conn, error) {
	// 拨号 + 握手走 DialAndHandshake：域名解析出多个 IP 时逐个试，
	// 拨号或握手失败就换下一个 IP（C5）。
	raw, keys, err := mmx.DialAndHandshake(cfg, badMagic, badVersion, tlsInsecure)
	if err != nil {
		return nil, nil, err
	}
	mc, err := mmx.NewConn(raw, keys, true)
	if err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("建立加密连接失败：%v", err)
	}
	if badKey {
		mc.TamperSendKey()
	}

	// CONNECT（序号 0），带上链接里的限速和突发要求（最终由服务端取 min 后执行）
	if err := mc.WriteFrame(mmx.FrameConnect, mmx.EncodeConnectTargetWithRateAndBurst(target, cfg.Rate, cfg.Burst)); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("发送 CONNECT 失败：%v", err)
	}
	ftype, payload, err := mc.ReadFrame()
	if err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("等待服务端 ACK 失败：%v", err)
	}
	if ftype != mmx.FrameAck {
		raw.Close()
		return nil, nil, fmt.Errorf("服务端回的不是 ACK（type=0x%02x）", ftype)
	}
	if len(payload) < 1 || payload[0] != 0x00 {
		code, msg := mmx.ParseAckError(payload)
		if msg == "" {
			msg = "（无错误信息）"
		}
		raw.Close()
		// 新服务端 ACK 文本带 "[错误码] …" 前缀，ParseAckError 已解析；
		// 老服务端无前缀文本时 code 为 UNKNOWN，msg 即原文。
		log.Printf("服务端拒绝转发 [%s]：%s（目标 %s）", code, msg, target)
		return nil, nil, fmt.Errorf("服务端拒绝转发 [%s]：%s", code, msg)
	}
	return mc, raw, nil
}

// relay 在本地明文连接和 mm-x 加密连接之间双向转发（两端都按链接里的
// rate / burst 限流，双向）。任一方向结束就立刻关闭两端，不挂起。
func relay(local net.Conn, mc *mmx.Conn, raw net.Conn, cfg *mmx.LinkConfig) {
	// 客户端也按链接里的 rate / burst 限流（双向）：把自己的出口流量先压平，
	// 服务端再按 min(服务端参数，链接参数) 兜底执行，客户端改大也突破不了。
	lim := mmx.NewLimiter(cfg.Rate, cfg.Burst)
	done := make(chan struct{}, 2)
	go func() { pumpMMXToRaw(mc, local, lim); done <- struct{}{} }()
	go func() { pumpRawToMMX(local, mc, lim); done <- struct{}{} }()
	<-done
	local.Close()
	raw.Close()
	<-done
}

// openV3Stream 在会话池的 v3 会话上开一条到目标的 TCP 流。
// 重试规则在池里（pool.OpenTCPStream）：只有会话真死了才换会话重拨；
// 目标被服务端拒绝（[目标拒绝] 等 ACK 错误）时会话还活着，
// 重试只会白白多做一次握手——直接返回错误。
func openV3Stream(cfg *mmx.LinkConfig, target string, badMagic, badVersion, badKey, tlsInsecure bool) (net.Conn, *mmx.ClientSession, error) {
	return pool.OpenTCPStream(cfg, target, badMagic, badVersion, badKey, tlsInsecure)
}

func handleLocal(local net.Conn, cfg *mmx.LinkConfig, target string, badMagic, badVersion, badKey, tlsInsecure bool) {
	remote := local.RemoteAddr().String()
	defer local.Close()

	if mmx.IsMuxVersion(cfg.Version) {
		st, sess, err := openV3Stream(cfg, target, badMagic, badVersion, badKey, tlsInsecure)
		if err != nil {
			log.Printf("[%s] %v", remote, err)
			return
		}
		defer st.Close()
		log.Printf("[%s] 已接通 %s（v3/v4 流，会话上现有 %d 条流），开始转发", remote, target, sess.NumStreams())
		sess.Relay(local, st)
		log.Printf("[%s] 连接结束（%s）", remote, target)
		return
	}

	mc, raw, err := dialMMX(cfg, target, badMagic, badVersion, badKey, tlsInsecure)
	if err != nil {
		log.Printf("[%s] %v", remote, err)
		return
	}
	defer raw.Close()
	log.Printf("[%s] 已接通 %s，开始转发", remote, target)
	relay(local, mc, raw, cfg)
	log.Printf("[%s] 连接结束（%s）", remote, target)
}

// ---------------------------------------------------------------------------
// SOCKS5 模式
// ---------------------------------------------------------------------------

// SOCKS5 回复码（只用得到的几个）
const (
	socksRepSuccess          = 0x00
	socksRepFailure          = 0x01
	socksRepNotAllowed       = 0x02
	socksRepNetworkUnreach   = 0x03
	socksRepHostUnreach      = 0x04
	socksRepRefused          = 0x05
	socksRepCmdNotSupported  = 0x07
	socksRepAddrNotSupported = 0x08
)

func runSocks(cfg *mmx.LinkConfig, listenAddr string, badMagic, badVersion, badKey, tlsInsecure bool) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("SOCKS5 监听失败：%v", err)
	}
	defer ln.Close()
	fmt.Printf("mm-x 客户端启动（SOCKS5 模式），本地监听 %s，服务端 %s:%d\n",
		listenAddr, cfg.Host, cfg.Port)
	for {
		local, err := ln.Accept()
		if err != nil {
			log.Printf("接受本地连接失败：%v", err)
			continue
		}
		go handleSocks(local, cfg, badMagic, badVersion, badKey, tlsInsecure)
	}
}

func socksReply(conn net.Conn, rep byte) {
	// VER(0x05) REP RSV(0x00) ATYP(0x01 IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
	_, _ = conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func handleSocks(local net.Conn, cfg *mmx.LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) {
	remote := local.RemoteAddr().String()
	defer local.Close()
	// 握手：客户端发 VER NMETHODS METHODS…，只接受无认证（0x00）
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(local, hdr); err != nil {
		log.Printf("[%s] SOCKS5 握手失败：%v", remote, err)
		return
	}
	if hdr[0] != 0x05 || hdr[1] == 0 {
		log.Printf("[%s] SOCKS5 版本不对（VER=0x%02x），已断开", remote, hdr[0])
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(local, methods); err != nil {
		log.Printf("[%s] SOCKS5 读认证方法失败：%v", remote, err)
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
		}
	}
	if !noAuth {
		// 不支持的认证方式：按 RFC 1928 回 0xFF
		_, _ = local.Write([]byte{0x05, 0xFF})
		log.Printf("[%s] SOCKS5 客户端要求认证，已拒绝", remote)
		return
	}
	if _, err := local.Write([]byte{0x05, 0x00}); err != nil {
		log.Printf("[%s] SOCKS5 回握手失败：%v", remote, err)
		return
	}
	// 请求：VER CMD RSV ATYP DST.ADDR DST.PORT，只支持 CONNECT（0x01）
	req := make([]byte, 4)
	if _, err := io.ReadFull(local, req); err != nil {
		log.Printf("[%s] SOCKS5 读请求失败：%v", remote, err)
		return
	}
	if req[0] != 0x05 {
		socksReply(local, socksRepFailure)
		log.Printf("[%s] SOCKS5 请求版本不对（VER=0x%02x）", remote, req[0])
		return
	}
	if req[1] == 0x03 {
		// UDP ASSOCIATE：v3/v4 才有（UDP 数据报走复用会话里的 UDP 流）；
		// v2 链接没有 UDP，直接按不支持回。
		if !mmx.IsMuxVersion(cfg.Version) {
			socksReply(local, socksRepCmdNotSupported)
			log.Printf("[%s] SOCKS5 UDP ASSOCIATE 需要 v3/v4 链接（当前是 v%d）", remote, cfg.Version)
			return
		}
		handleSocksUDP(local, cfg, req, badMagic, badVersion, badKey, tlsInsecure)
		return
	}
	if req[1] != 0x01 {
		socksReply(local, socksRepCmdNotSupported)
		log.Printf("[%s] SOCKS5 只支持 CONNECT 和 UDP ASSOCIATE（CMD=0x%02x）", remote, req[1])
		return
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(local, b); err != nil {
			log.Printf("[%s] SOCKS5 读 IPv4 地址失败：%v", remote, err)
			return
		}
		host = net.IP(b).String()
	case 0x03: // 域名
		lb := make([]byte, 1)
		if _, err := io.ReadFull(local, lb); err != nil {
			log.Printf("[%s] SOCKS5 读域名长度失败：%v", remote, err)
			return
		}
		if lb[0] == 0 {
			socksReply(local, socksRepAddrNotSupported)
			return
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(local, b); err != nil {
			log.Printf("[%s] SOCKS5 读域名失败：%v", remote, err)
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(local, b); err != nil {
			log.Printf("[%s] SOCKS5 读 IPv6 地址失败：%v", remote, err)
			return
		}
		// 注意：这里不要自己加方括号，net.JoinHostPort 会给 IPv6 地址加括号，
		// 自己加了就变成 [[::1]]:端口，服务端 dial 会报 missing port in address。
		host = net.IP(b).String()
	default:
		socksReply(local, socksRepAddrNotSupported)
		log.Printf("[%s] SOCKS5 地址类型不支持（ATYP=0x%02x）", remote, req[3])
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(local, pb); err != nil {
		log.Printf("[%s] SOCKS5 读端口失败：%v", remote, err)
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	target := net.JoinHostPort(host, strconv.Itoa(port))

	if mmx.IsMuxVersion(cfg.Version) {
		st, sess, err := openV3Stream(cfg, target, badMagic, badVersion, badKey, tlsInsecure)
		if err != nil {
			socksReply(local, socksRepForErr(err))
			log.Printf("[%s] %v（目标 %s）", remote, err, target)
			return
		}
		defer st.Close()
		socksReply(local, socksRepSuccess)
		log.Printf("[%s] 已接通 %s（v3/v4 流），开始转发", remote, target)
		sess.Relay(local, st)
		log.Printf("[%s] 连接结束（%s）", remote, target)
		return
	}

	mc, raw, err := dialMMX(cfg, target, badMagic, badVersion, badKey, tlsInsecure)
	if err != nil {
		socksReply(local, socksRepForErr(err))
		log.Printf("[%s] %v（目标 %s）", remote, err, target)
		return
	}
	defer raw.Close()
	socksReply(local, socksRepSuccess)
	log.Printf("[%s] 已接通 %s，开始转发", remote, target)
	relay(local, mc, raw, cfg)
	log.Printf("[%s] 连接结束（%s）", remote, target)
}

// socksRepForErr 按服务端 ACK 错误码映射 SOCKS5 回复码（
// 报错里带 "[错误码]" 前缀）；握手/密钥问题仍按拒绝处理。
// sing-box 看到非 0x00 就认为该出站不通，会按自己的逻辑处理。
func socksRepForErr(err error) byte {
	rep := byte(socksRepRefused)
	switch {
	case strings.Contains(err.Error(), "[目标拒绝]"):
		rep = socksRepRefused
	case strings.Contains(err.Error(), "[DNS解析失败]"),
		strings.Contains(err.Error(), "[目标不可达]"):
		rep = socksRepHostUnreach
	case strings.Contains(err.Error(), "[连接超时]"):
		rep = socksRepNetworkUnreach
	case strings.Contains(err.Error(), "服务端拒绝转发"):
		rep = socksRepHostUnreach
	}
	return rep
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP ASSOCIATE（v3 才有）
// ---------------------------------------------------------------------------

// udpFlowIdleTimeout：一条 UDP 流多久没回包就关掉（避免流泄漏）。
// DNS/QUIC 平时几秒就有回包，60 秒足够宽松。
const udpFlowIdleTimeout = 60 * time.Second

// udpFlow 是一条 UDP 流：一个（客户端地址，目标地址）对，
// 对应复用会话里的一条流；回包从流里读出来，原样发回给客户端。
type udpFlow struct {
	stream net.Conn
	target string
	src    *net.UDPAddr
	done   chan struct{}
	once   sync.Once
}

func (f *udpFlow) close() {
	f.once.Do(func() {
		close(f.done)
		f.stream.Close()
	})
}

// udpRelay 是一次 UDP ASSOCIATE 的中继：一个 UDP 监听端口，
// 收到的每个数据报按目标分流到复用会话里的 UDP 流。
type udpRelay struct {
	cfg                                       *mmx.LinkConfig
	udpConn                                   *net.UDPConn
	mu                                        sync.Mutex
	flows                                     map[string]*udpFlow
	badMagic, badVersion, badKey, tlsInsecure bool
}

// openUDPFlow 在会话池的 v3 会话上开一条到目标的 UDP 流（同 openV3Stream，
// 只有会话真死了才重拨；目标被拒时直接返回错误）。
func (r *udpRelay) openUDPFlow(target string) (net.Conn, *mmx.ClientSession, error) {
	return pool.OpenUDPFlow(r.cfg, target, r.badMagic, r.badVersion, r.badKey, r.tlsInsecure)
}

// getFlow 拿一条 UDP 流：同一个（客户端，目标）复用同一条流，
// 没有就新开一条，并起一个 goroutine 把回包写回给客户端。
func (r *udpRelay) getFlow(src *net.UDPAddr, target string) (*udpFlow, error) {
	key := src.String() + "|" + target
	r.mu.Lock()
	if f, ok := r.flows[key]; ok {
		r.mu.Unlock()
		return f, nil
	}
	r.mu.Unlock()
	st, _, err := r.openUDPFlow(target)
	if err != nil {
		return nil, err
	}
	f := &udpFlow{stream: st, target: target, src: src, done: make(chan struct{})}
	r.mu.Lock()
	// 并发时后建的赢：旧的关掉，避免同一个 key 留两条流。
	if old, ok := r.flows[key]; ok {
		r.mu.Unlock()
		old.close()
		r.mu.Lock()
	}
	r.flows[key] = f
	r.mu.Unlock()
	go r.pumpFlowBack(f, key)
	return f, nil
}

// pumpFlowBack 把一条 UDP 流里的回包写回给 SOCKS5 客户端：
// 流里是长度前缀的数据报，写回时前面拼上 SOCKS5 UDP 请求头
// （RSV 0x0000 + FRAG 0x00 + 目标地址），客户端收到就能认出来。
// 60 秒没回包就关流（流泄漏防护）。
func (r *udpRelay) pumpFlowBack(f *udpFlow, key string) {
	defer r.removeFlow(key, f)
	for {
		_ = f.stream.SetReadDeadline(time.Now().Add(udpFlowIdleTimeout))
		dg, err := mmx.ReadDatagram(f.stream)
		if err != nil {
			return
		}
		resp, err := buildUDPResponse(f.target, dg)
		if err != nil {
			return
		}
		if _, err := r.udpConn.WriteToUDP(resp, f.src); err != nil {
			return
		}
	}
}

func (r *udpRelay) removeFlow(key string, f *udpFlow) {
	f.close()
	r.mu.Lock()
	if cur, ok := r.flows[key]; ok && cur == f {
		delete(r.flows, key)
	}
	r.mu.Unlock()
}

// close 关掉中继：UDP 监听端口和所有流一起关。
func (r *udpRelay) close() {
	r.udpConn.Close()
	r.mu.Lock()
	flows := r.flows
	r.flows = make(map[string]*udpFlow)
	r.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
}

// parseUDPRequest 解析 SOCKS5 UDP 数据报头：
// RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA。
// FRAG != 0 的分片直接丢弃（不支持分片重组）。
// 返回目标地址（host:port）和数据部分。
func parseUDPRequest(b []byte) (target string, data []byte, err error) {
	if len(b) < 4 {
		return "", nil, fmt.Errorf("UDP 数据报太短（%d 字节）", len(b))
	}
	if b[2] != 0x00 {
		return "", nil, fmt.Errorf("UDP 分片不支持（FRAG=0x%02x）", b[2])
	}
	off := 4
	var host string
	switch b[3] {
	case 0x01: // IPv4
		if len(b) < off+4+2 {
			return "", nil, fmt.Errorf("UDP 数据报里 IPv4 地址不完整")
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03: // 域名
		if len(b) < off+1 {
			return "", nil, fmt.Errorf("UDP 数据报里域名长度缺失")
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return "", nil, fmt.Errorf("UDP 数据报里域名不完整")
		}
		host = string(b[off : off+l])
		off += l
	case 0x04: // IPv6
		if len(b) < off+16+2 {
			return "", nil, fmt.Errorf("UDP 数据报里 IPv6 地址不完整")
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return "", nil, fmt.Errorf("UDP 数据报地址类型不支持（ATYP=0x%02x）", b[3])
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	return net.JoinHostPort(host, strconv.Itoa(port)), b[off:], nil
}

// buildUDPResponse 拼 SOCKS5 UDP 回包头：RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT + 数据。
// 目标地址按客户端发来的形式原样回（域名就回域名，IP 就回 IP）。
func buildUDPResponse(target string, data []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("目标端口不合法：%q", portStr)
	}
	out := []byte{0x00, 0x00, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, 0x01)
			out = append(out, ip4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("目标域名太长")
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	out = append(out, byte(port>>8), byte(port))
	out = append(out, data...)
	return out, nil
}

// handleSocksUDP 处理 SOCKS5 UDP ASSOCIATE 请求。
// req 是已读的 4 字节请求头（VER CMD RSV ATYP），后面按 ATYP 读地址。
// 回复里给客户端一个 UDP 中继地址，之后：
//   - 客户端把 UDP 数据报发到这个地址，中继按目标分流进复用会话；
//   - TCP 连接不断，中继就一直活着；TCP 一断，中继立刻全关
//     （RFC 1928：UDP 关联随 TCP 连接结束而结束）。
func handleSocksUDP(local net.Conn, cfg *mmx.LinkConfig, req []byte, badMagic, badVersion, badKey, tlsInsecure bool) {
	remote := local.RemoteAddr().String()
	// 读客户端的 UDP 端点地址（一般是 0.0.0.0:0，表示“用 TCP 连接的源地址”），
	// 读完就不用了——中继按实际收到数据报的源地址回包。
	if _, err := readSocksAddr(local, req[3]); err != nil {
		socksReply(local, socksRepAddrNotSupported)
		log.Printf("[%s] SOCKS5 UDP ASSOCIATE 读地址失败：%v", remote, err)
		return
	}
	// UDP 中继绑在 TCP 连接的本地地址上（sing-box 从本机连过来，127.0.0.1 就够）；
	// 端口随机（:0），回复里告诉客户端。
	localIP := local.LocalAddr().(*net.TCPAddr).IP
	udpAddr := &net.UDPAddr{IP: localIP, Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		socksReply(local, socksRepFailure)
		log.Printf("[%s] UDP 中继监听失败：%v", remote, err)
		return
	}
	relay := &udpRelay{
		cfg: cfg, udpConn: udpConn, flows: make(map[string]*udpFlow),
		badMagic: badMagic, badVersion: badVersion, badKey: badKey, tlsInsecure: tlsInsecure,
	}
	// 回复：BND.ADDR 就是 UDP 中继的地址。
	bindAddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00}
	if ip4 := bindAddr.IP.To4(); ip4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, 0x04)
		reply = append(reply, bindAddr.IP.To16()...)
	}
	reply = append(reply, byte(bindAddr.Port>>8), byte(bindAddr.Port))
	if _, err := local.Write(reply); err != nil {
		log.Printf("[%s] SOCKS5 UDP ASSOCIATE 回复失败：%v", remote, err)
		relay.close()
		return
	}
	log.Printf("[%s] UDP ASSOCIATE 已建立，中继地址 %s", remote, bindAddr.String())
	go relay.serveUDP()
	// TCP 连接不断中继就一直活着：读到 EOF/出错就全关。
	buf := make([]byte, 1)
	for {
		if _, err := local.Read(buf); err != nil {
			break
		}
	}
	relay.close()
	log.Printf("[%s] UDP ASSOCIATE 结束（TCP 连接已断）", remote)
}

// serveUDP 收 UDP 数据报：解析目标，分流进复用会话的 UDP 流。
func (r *udpRelay) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			return // 中继关了
		}
		target, data, err := parseUDPRequest(buf[:n])
		if err != nil {
			continue // 格式不对/分片：直接丢，不回包
		}
		f, err := r.getFlow(src, target)
		if err != nil {
			continue // 流开失败：丢包（客户端超时重发，流会再开）
		}
		if err := mmx.WriteDatagram(f.stream, data); err != nil {
			r.removeFlow(src.String()+"|"+target, f)
			continue
		}
	}
}

// readSocksAddr 按 ATYP 从连接里读一个 SOCKS5 地址（TCP 请求和
// UDP ASSOCIATE 请求共用），返回 "host:port"。
func readSocksAddr(conn net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // 域名
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return "", err
		}
		if lb[0] == 0 {
			return "", fmt.Errorf("域名长度为 0")
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("地址类型不支持（ATYP=0x%02x）", atyp)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return "", err
	}
	port := int(binary.BigEndian.Uint16(pb))
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func pumpMMXToRaw(mc *mmx.Conn, local net.Conn, lim *mmx.Limiter) {
	for {
		ftype, payload, err := mc.ReadFrame()
		if err != nil {
			return
		}
		if ftype == mmx.FrameClose {
			return
		}
		if ftype != mmx.FrameData {
			continue
		}
		lim.Wait(len(payload)) // 下行限速
		if _, err := local.Write(payload); err != nil {
			return
		}
	}
}

func pumpRawToMMX(raw net.Conn, mc *mmx.Conn, lim *mmx.Limiter) {
	buf := make([]byte, 32*1024)
	for {
		n, err := raw.Read(buf)
		if n > 0 {
			lim.Wait(n) // 上行限速
			if werr := mc.WriteFrame(mmx.FrameData, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("读取本地数据失败：%v", err)
			}
			_ = mc.WriteFrame(mmx.FrameClose, nil)
			return
		}
	}
}
