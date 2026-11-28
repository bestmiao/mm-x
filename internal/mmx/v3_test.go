// v3 单元测试：复用（yamux 会话）、UDP 流、会话级限速。
// 注意沙箱限制：UDP 包在沙箱里发得出系统调用但到不了对端，
// 所以这里只测 UDP 流的管道（开流、ACK、写数据报、关流），
// 数据真正往返的测试在 VPS 部署验证里做（见 test/udp-test.sh）。
package mmx

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// pipeSessionPair 在 net.Pipe 上建一对 v3 会话（客户端 + 服务端），
// 握手走真实的 v3 握手（ver=3），返回两端的 yamux 会话和清理函数。
func pipeSessionPair(t *testing.T, serverRate, serverBurst int64) (*ClientSession, *yamux.Session, func()) {
	return pipeSessionPairVersion(t, VersionV3, serverRate, serverBurst)
}

// pipeSessionPairVersion 和 pipeSessionPair 一样，只是握手版本可指定
// （v4 测试用它建 v4 复用会话）。
func pipeSessionPairVersion(t *testing.T, version int, serverRate, serverBurst int64) (*ClientSession, *yamux.Session, func()) {
	t.Helper()
	cRaw, sRaw := net.Pipe()
	errCh := make(chan error, 2)
	var cConn *Conn
	var sConn *Conn
	go func() {
		keys, err := ClientHandshakeVersion(cRaw, testPSK, version, false, false)
		if err != nil {
			errCh <- fmt.Errorf("客户端握手：%v", err)
			return
		}
		mc, err := NewConn(cRaw, keys, true)
		if err != nil {
			errCh <- fmt.Errorf("客户端建加密连接：%v", err)
			return
		}
		cConn = mc
		errCh <- nil
	}()
	go func() {
		keys, err := ServerHandshakeWithKeys(sRaw, [][]byte{testPSK})
		if err != nil {
			errCh <- fmt.Errorf("服务端握手：%v", err)
			return
		}
		mc, err := NewConn(sRaw, keys, false)
		if err != nil {
			errCh <- fmt.Errorf("服务端建加密连接：%v", err)
			return
		}
		sConn = mc
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("%v", err)
		}
	}
	if cConn == nil || sConn == nil {
		t.Fatal("握手后加密连接为空")
	}
	cs, err := yamux.Client(NewFrameConn(cConn), YamuxConfig())
	if err != nil {
		t.Fatalf("建客户端复用会话失败：%v", err)
	}
	ss, err := yamux.Server(NewFrameConn(sConn), YamuxConfig())
	if err != nil {
		t.Fatalf("建服务端复用会话失败：%v", err)
	}
	cfg := &LinkConfig{PSK: testPSK, Host: "127.0.0.1", Port: 1, Enc: "aes-256-gcm", Obfs: "tls-fake", Version: version, Rate: 0, Burst: BurstUnset}
	cli := &ClientSession{cfg: cfg, raw: cRaw, ys: cs, lim: NewLimiter(0, BurstUnset), closed: make(chan struct{})}
	// 服务端会话在后台跑：接受流、按种类处理（TCP 回显目标用本地 TCP 服务）。
	go func() {
		sess := NewServerSession()
		for {
			st, err := ss.AcceptStream()
			if err != nil {
				return
			}
			// 测试目标是本机回显服务（127.0.0.1），目标过滤默认会拒绝，
			// 这里显式放开（allowPrivate=true）；生产环境不带这个参数。
			go ServeMuxStream(st, sess, serverRate, serverBurst, "test", TargetPolicy{AllowPrivate: true}, nil)
		}
	}()
	cleanup := func() {
		cli.Close()
		ss.Close()
	}
	return cli, ss, cleanup
}

// startTCPEcho 在 loopback 上起一个 TCP 回显服务，返回它的地址。
func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起回显服务失败：%v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestStreamHeaderCodec(t *testing.T) {
	for _, tc := range []struct {
		kind  byte
		tgt   string
		rate  int64
		burst int64
	}{
		{StreamKindTCP, "example.com:443", 6250000, BurstUnset},
		{StreamKindTCP, "127.0.0.1:18082", 0, 0},
		{StreamKindUDP, "8.8.8.8:53", 100000, 5000000},
		{StreamKindUDP, "[2001:db8::1]:53", 0, BurstUnset},
	} {
		enc := EncodeStreamHeader(tc.kind, tc.tgt, tc.rate, tc.burst)
		kind, tgt, rate, burst, err := DecodeStreamHeader(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("解码流头失败（%v）：%v", tc, err)
		}
		if kind != tc.kind || tgt != tc.tgt || rate != tc.rate || burst != tc.burst {
			t.Fatalf("流头编解码不一致：得到 kind=%d tgt=%q rate=%d burst=%d，想要 %+v", kind, tgt, rate, burst, tc)
		}
	}
	// 坏输入：种类不对、载荷截断都要报错，不能静默通过。
	if _, _, _, _, err := DecodeStreamHeader(bytes.NewReader([]byte{0x09})); err == nil {
		t.Fatal("种类 0x09 的流头应报错")
	}
	if _, _, _, _, err := DecodeStreamHeader(bytes.NewReader([]byte{0x01, 0x00})); err == nil {
		t.Fatal("截断的流头应报错")
	}
}

func TestDatagramFraming(t *testing.T) {
	cases := [][]byte{
		{}, // 空数据报也合法（UDP 允许 0 字节）
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 65535), // 上限
	}
	for _, want := range cases {
		var buf bytes.Buffer
		if err := WriteDatagram(&buf, want); err != nil {
			t.Fatalf("写数据报失败（len=%d）：%v", len(want), err)
		}
		got, err := ReadDatagram(&buf)
		if err != nil {
			t.Fatalf("读数据报失败（len=%d）：%v", len(want), err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("数据报内容不一致（len=%d）", len(want))
		}
	}
	// 超限拒绝、截断报错。
	if err := WriteDatagram(&bytes.Buffer{}, bytes.Repeat([]byte{0}, 65536)); err == nil {
		t.Fatal("65536 字节的数据报应被拒绝")
	}
	if _, err := ReadDatagram(bytes.NewReader([]byte{0x00, 0x05, 0x01, 0x02})); err == nil {
		t.Fatal("截断的数据报应报错")
	}
}

// TestMuxConcurrency：20 条并行流跑在一个会话上，数据完整、
// 且整个过程只用一条底层连接（复用的意义）。
func TestMuxConcurrency(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	cli, _, cleanup := pipeSessionPair(t, 0, BurstUnset)
	defer cleanup()

	const streams = 20
	const payloadSize = 64 * 1024
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			st, err := cli.OpenTCPStream(echoAddr)
			if err != nil {
				errs <- fmt.Errorf("流 %d 开流失败：%v", id, err)
				return
			}
			defer st.Close()
			want := bytes.Repeat([]byte{byte(id + 1)}, payloadSize)
			if _, err := st.Write(want); err != nil {
				errs <- fmt.Errorf("流 %d 写失败：%v", id, err)
				return
			}
			got := make([]byte, payloadSize)
			if _, err := io.ReadFull(st, got); err != nil {
				errs <- fmt.Errorf("流 %d 读回显失败：%v", id, err)
				return
			}
			if !bytes.Equal(got, want) {
				errs <- fmt.Errorf("流 %d 回显内容不一致", id)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// 20 条流都走完后，会话上不应再有残留的流。
	// 注意：yamux 的流要等两边都发 FIN 才从会话表里删掉——客户端
	// Close() 只发本地 FIN，对端回 FIN 还有一小段异步时间，
	// 立刻断言 NumStreams()==0 是竞态（旧版本就时不时失败）。
	// 等最多 2 秒，真有泄漏仍会失败。
	deadline := time.Now().Add(2 * time.Second)
	for {
		if n := cli.NumStreams(); n == 0 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("20 条流结束后会话上还剩 %d 条流（应为 0）", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMuxSessionRateLimitShared：两条流共用一只会话级限速桶——
// 每条流上下行各 50KB，两条流共 200KB 过一个 50KB/s 的桶，
// 耗时必须 ≥3s（若每条流各拿一个桶，同样的数据只要 ~2s）。
// 下限断言只会因“限速没生效”而失败，机器慢只会让耗时更长，不会误报。
// 注意：数据必须走 sess.Relay（限速器在中继里），直接读写流绕过了限速器。
func TestMuxSessionRateLimitShared(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	cli, _, cleanup := pipeSessionPair(t, 0, BurstUnset)
	defer cleanup()
	// 把会话限速器换成 50KB/s 严格桶（burst=0）。
	cli.lim = NewLimiter(50*1024, 0)

	const streams = 2
	const payloadSize = 50 * 1024
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := cli.OpenTCPStream(echoAddr)
			if err != nil {
				t.Errorf("开流失败：%v", err)
				return
			}
			defer st.Close()
			localA, localB := net.Pipe()
			go cli.Relay(localA, st)
			payload := bytes.Repeat([]byte{0x5A}, payloadSize)
			if _, err := localB.Write(payload); err != nil {
				t.Errorf("写失败：%v", err)
				return
			}
			got := make([]byte, payloadSize)
			if _, err := io.ReadFull(localB, got); err != nil {
				t.Errorf("读回显失败：%v", err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("回显内容不一致")
			}
			localB.Close()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	// 200KB / 50KB/s = 4s；留 25% 余量，低于 3s 就是限速没按会话聚合。
	if elapsed < 3*time.Second {
		t.Fatalf("两条流 200KB 只用了 %v（<3s），会话级限速没生效（各流可能各拿了一个桶）", elapsed)
	}
}

// TestServerSessionLimiterShared：服务端会话里第一条流定下限速器，
// 后面的流共用同一只桶（指针相同），且取的是 min（服务端上限，链接要求）。
func TestServerSessionLimiterShared(t *testing.T) {
	sess := NewServerSession()
	a := sess.limiter(100000, 0, 6250000, BurstUnset)
	b := sess.limiter(999999999, 0, 6250000, BurstUnset)
	if a != b {
		t.Fatal("同一会话的两条流拿到的不是同一只限速器")
	}
	// 桶的速率应是 min（服务端 6250000，链接 100000）= 100000，
	// 突发应是 min（服务端未指定→默认，链接 0）= 0。
	if a.Rate() != 100000 {
		t.Fatalf("会话限速器速率是 %d，想要 100000（min 逻辑可能错了）", a.Rate())
	}
	if a.Burst() != 0 {
		t.Fatalf("会话限速器突发是 %d，想要 0", a.Burst())
	}
}

// TestMuxUDPFlowPlumbing：UDP 流的管道——开流拿到 ACK、
// 写数据报不报错、关流后服务端侧干净结束。
// 沙箱里 UDP 包到不了对端，所以不 assert 回包内容，
// 只 assert 流本身的行为；回包内容在 VPS 上真测。
func TestMuxUDPFlowPlumbing(t *testing.T) {
	cli, _, cleanup := pipeSessionPair(t, 0, BurstUnset)
	defer cleanup()

	st, err := cli.OpenUDPFlow("127.0.0.1:18090")
	if err != nil {
		t.Fatalf("开 UDP 流失败（服务端应先回 ACK）：%v", err)
	}
	if err := WriteDatagram(st, []byte("hello-udp")); err != nil {
		t.Fatalf("往 UDP 流写数据报失败：%v", err)
	}
	st.Close()
	// 关流后读应很快返回错误（流已关），而不是一直阻塞。
	_ = st.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadDatagram(st); err == nil {
		t.Fatal("关掉的 UDP 流读数据报应报错")
	}
}

// TestMuxUDPFlowBadTarget：目标域名解析失败时，
// 开 UDP 流应直接报错（错误码应为 DNS 解析失败）。
func TestMuxUDPFlowBadTarget(t *testing.T) {
	cli, _, cleanup := pipeSessionPair(t, 0, BurstUnset)
	defer cleanup()

	_, err := cli.OpenUDPFlow("不存在的域名.invalid:53")
	if err == nil {
		t.Fatal("目标域名不存在时开 UDP 流应报错")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("DNS")) && !bytes.Contains([]byte(err.Error()), []byte("解析")) {
		t.Fatalf("期望 DNS 解析失败类错误，得到：%v", err)
	}
}
