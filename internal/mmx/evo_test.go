// 协议演进 1-3 项（客户端传输）的单元测试：
// 指纹轮换、会话恢复接线、多路会话池。
package mmx

import (
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestPickClientHelloIDFromAllowedSet：每会话抽的指纹必须落在
// 允许集合里（只含常见浏览器指纹），不能抽出冷门/编造的指纹。
// 只验 picker 本身，不走网络。
func TestPickClientHelloIDFromAllowedSet(t *testing.T) {
	if len(clientHelloFingerprints) != 5 {
		t.Fatalf("指纹集合应有 5 个（Chrome×2、Firefox、Safari、iOS），实际 %d", len(clientHelloFingerprints))
	}
	allowed := make(map[utls.ClientHelloID]bool, len(clientHelloFingerprints))
	for _, id := range clientHelloFingerprints {
		allowed[id] = true
	}
	// 集合里必须有这几个最常见的浏览器指纹。
	for _, want := range []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	} {
		if !allowed[want] {
			t.Fatalf("指纹集合里缺常见浏览器指纹 %+v", want)
		}
	}
	for i := 0; i < 200; i++ {
		if got := pickClientHelloID(); !allowed[got] {
			t.Fatalf("pickClientHelloID 第 %d 次抽到了不在允许集合里的指纹：%+v", i, got)
		}
	}
}

// TestNewClientTLSConfigSessionCache：外层 TLS 配置必须挂上
// 进程共享的会话恢复缓存，且 pin 校验不能因此丢掉。
func TestNewClientTLSConfigSessionCache(t *testing.T) {
	cfg, err := newClientTLSConfig("www.microsoft.com", "", false)
	if err != nil {
		t.Fatalf("建 TLS 配置失败：%v", err)
	}
	if cfg.ClientSessionCache == nil {
		t.Fatal("ClientSessionCache 应非空（会话恢复没接线，重复连接省不掉握手）")
	}
	if cfg.ClientSessionCache != tlsSessionCache {
		t.Fatal("应用进程共享的会话缓存实例（tlsSessionCache），而不是每次新建")
	}
	if cfg.SessionTicketsDisabled {
		t.Fatal("SessionTicketsDisabled 应为 false，否则会话恢复不生效")
	}
	if cfg.MinVersion != utls.VersionTLS13 || cfg.MaxVersion != utls.VersionTLS13 {
		t.Fatalf("只谈 TLS 1.3，实际 Min=%#x Max=%#x", cfg.MinVersion, cfg.MaxVersion)
	}

	// pin 模式：VerifyPeerCertificate 必须保留（恢复握手也要验 pin）。
	pin := FormatPIN(bytesRepeat(0xAB, 32))
	cfgPin, err := newClientTLSConfig("www.microsoft.com", pin, false)
	if err != nil {
		t.Fatalf("pin 模式建 TLS 配置失败：%v", err)
	}
	if cfgPin.VerifyPeerCertificate == nil {
		t.Fatal("pin 模式下 VerifyPeerCertificate 不应为空（指纹校验不能丢）")
	}
	if cfgPin.ClientSessionCache == nil {
		t.Fatal("pin 模式下会话恢复缓存也不应丢")
	}

	// insecure（仅测试用）：跳过校验。
	cfgIns, err := newClientTLSConfig("www.microsoft.com", "", true)
	if err != nil {
		t.Fatalf("insecure 建 TLS 配置失败：%v", err)
	}
	if !cfgIns.InsecureSkipVerify {
		t.Fatal("insecure=true 时 InsecureSkipVerify 应为 true")
	}

	// 坏 pin 报错（不能悄悄建一个不校验的配置）。
	if _, err := newClientTLSConfig("www.microsoft.com", "xxx", false); err == nil {
		t.Fatal("坏 pin 应报错")
	}
}

// poolTestCfg 是会话池测试用的链接配置：
// 必须和 pipeSessionPair 内部建的 ClientSession.cfg 一致，
// 否则 Drop 时 sessionKey 对不上、清不掉死会话。
func poolTestCfg() *LinkConfig {
	return &LinkConfig{PSK: testPSK, Host: "127.0.0.1", Port: 1, Enc: "aes-256-gcm", Obfs: "tls-fake", Version: VersionV3, Rate: 0, Burst: BurstUnset}
}

// fakePoolDialer 返回一个按 pipe 会话供货的拨号函数
// （不走真实网络），并返回调用次数的指针和清理函数。
func fakePoolDialer(t *testing.T) (func(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error), *int) {
	t.Helper()
	calls := 0
	var cleanups []func()
	t.Cleanup(func() {
		for _, c := range cleanups {
			c()
		}
	})
	dial := func(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error) {
		calls++
		cli, _, cleanup := pipeSessionPair(t, 0, BurstUnset)
		cleanups = append(cleanups, cleanup)
		return cli, nil
	}
	return dial, &calls
}

// waitIdle 等会话上的流数回到 0（yamux 关流是本地同步的，
// 这里只是防抖，最多等 1 秒）。
func waitIdle(t *testing.T, s *ClientSession) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for s.NumStreams() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.NumStreams() != 0 {
		t.Fatalf("关流后流数应回到 0，实际 %d", s.NumStreams())
	}
}

// TestSessionPoolMultiSession：池里能同时留多条会话，
// 忙时拨新会话（有上限）、空闲时轮询分流、死会话跳过。
func TestSessionPoolMultiSession(t *testing.T) {
	pool := NewSessionPool()
	dial, calls := fakePoolDialer(t)
	pool.dial = dial
	cfg := poolTestCfg()

	// 首次 Get 拨一条。
	s1, err := pool.Get(cfg, false, false, false, false)
	if err != nil {
		t.Fatalf("首次 Get 失败：%v", err)
	}
	if *calls != 1 || pool.SessionCount(cfg) != 1 {
		t.Fatalf("首次 Get 应拨 1 条会话，实际拨号 %d 次、池里 %d 条", *calls, pool.SessionCount(cfg))
	}

	// s1 在忙（开一条流不关）时再 Get：应拨第二条，而不是挤同一条。
	busy, err := s1.ys.OpenStream()
	if err != nil {
		t.Fatalf("在 s1 上开流失败：%v", err)
	}
	defer busy.Close()
	s2, err := pool.Get(cfg, false, false, false, false)
	if err != nil {
		t.Fatalf("s1 在忙时 Get 失败：%v", err)
	}
	if s2 == s1 {
		t.Fatal("s1 在忙时 Get 应拨新会话，不应返回同一条")
	}
	if *calls != 2 || pool.SessionCount(cfg) != 2 {
		t.Fatalf("忙时 Get 应拨第 2 条会话，实际拨号 %d 次、池里 %d 条", *calls, pool.SessionCount(cfg))
	}

	// 上限收紧到 2 条：两条都在忙时 Get 不再拨号，轮询返回一条旧的。
	pool.SetMaxSessions(2)
	busy2, err := s2.ys.OpenStream()
	if err != nil {
		t.Fatalf("在 s2 上开流失败：%v", err)
	}
	defer busy2.Close()
	s3, err := pool.Get(cfg, false, false, false, false)
	if err != nil {
		t.Fatalf("两条都忙时 Get 失败：%v", err)
	}
	if *calls != 2 {
		t.Fatalf("已到上限 2 条时 Get 不应再拨号，实际拨号 %d 次", *calls)
	}
	if s3 != s1 && s3 != s2 {
		t.Fatal("已到上限时 Get 应返回已有会话")
	}
	pool.SetMaxSessions(DefaultPoolMaxSessions)
	busy.Close()
	busy2.Close()
	waitIdle(t, s1)
	waitIdle(t, s2)

	// 两条都空闲：连续 Get 应轮询，不总粘在同一条。
	got := make([]*ClientSession, 4)
	for i := range got {
		s, err := pool.Get(cfg, false, false, false, false)
		if err != nil {
			t.Fatalf("第 %d 次 Get 失败：%v", i, err)
		}
		got[i] = s
	}
	if got[0] == got[1] || got[1] == got[2] || got[2] == got[3] {
		t.Fatalf("空闲时连续 Get 应轮询换会话，实际 %v", got)
	}
	if got[0] != got[2] || got[1] != got[3] {
		t.Fatalf("轮询应 s1,s2,s1,s2 交替，实际 %v", got)
	}
	if *calls != 2 {
		t.Fatalf("轮询期间不应再拨号，实际拨号 %d 次", *calls)
	}

	// 死会话跳过：关掉 s1，下次 Get 应返回 s2，不拨新号。
	s1.Close()
	s, err := pool.Get(cfg, false, false, false, false)
	if err != nil {
		t.Fatalf("s1 死后 Get 失败：%v", err)
	}
	if s != s2 {
		t.Fatal("s1 死后 Get 应返回还活着的 s2")
	}
	if *calls != 2 || pool.SessionCount(cfg) != 1 {
		t.Fatalf("死会话应被清掉且不拨新号，实际拨号 %d 次、池里 %d 条", *calls, pool.SessionCount(cfg))
	}

	// 全死了：下次 Get 重拨一条新的。
	s2.Close()
	s4, err := pool.Get(cfg, false, false, false, false)
	if err != nil {
		t.Fatalf("全死后 Get 失败：%v", err)
	}
	if s4 == s1 || s4 == s2 {
		t.Fatal("全死后 Get 应返回新拨的会话")
	}
	if *calls != 3 || pool.SessionCount(cfg) != 1 {
		t.Fatalf("全死后应重拨 1 条，实际拨号 %d 次、池里 %d 条", *calls, pool.SessionCount(cfg))
	}
}

// TestSessionPoolOpenStreamSkipsDeadSession：池里开流时，
// 第一拨到的会话是死的（拨完立刻断），应自动跳过、
// 在下一条活会话上开流成功（回显通），而不是直接报错。
func TestSessionPoolOpenStreamSkipsDeadSession(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()

	pool := NewSessionPool()
	calls := 0
	var cleanups []func()
	t.Cleanup(func() {
		for _, c := range cleanups {
			c()
		}
	})
	pool.dial = func(cfg *LinkConfig, badMagic, badVersion, badKey, tlsInsecure bool) (*ClientSession, error) {
		calls++
		cli, _, cleanup := pipeSessionPair(t, 0, BurstUnset)
		cleanups = append(cleanups, cleanup)
		if calls == 1 {
			// 第一条会话拨完立刻死：模拟服务端刚关掉它。
			cli.Close()
		}
		return cli, nil
	}
	cfg := poolTestCfg()

	st, sess, err := pool.OpenTCPStream(cfg, echoAddr, false, false, false, false)
	if err != nil {
		t.Fatalf("OpenTCPStream 应跳过死会话、在活会话上成功：%v", err)
	}
	defer st.Close()
	if sess == nil || sess.IsClosed() {
		t.Fatal("OpenTCPStream 返回的会话应是活的")
	}
	if calls != 2 {
		t.Fatalf("应拨 2 次（死 1 条 + 活 1 条），实际 %d 次", calls)
	}
	if pool.SessionCount(cfg) != 1 {
		t.Fatalf("死会话清掉后池里应只剩 1 条活会话，实际 %d 条", pool.SessionCount(cfg))
	}
	// 流真通：写进回显服务能读回来。
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatalf("往流里写失败：%v", err)
	}
	buf := make([]byte, 64)
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("回显失败：n=%d err=%v data=%q", n, err, buf[:n])
	}
}
