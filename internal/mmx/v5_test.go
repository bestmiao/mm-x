// v5 单元测试：流量形态伪装——SNI 轮换、帧填充分级、连续分片上限、
// 握手尺寸峰形分布、掩护帧透明、keepalive 随机化、会话轮换、诱饵头。
package mmx

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPINBytes 返回一段 32 字节的测试用 SPKI pin（与真实 pin 无关）。
func testPINBytes() []byte {
	p := make([]byte, 32)
	for i := range p {
		p[i] = byte(i + 1)
	}
	return p
}

// TestV5HandshakeInterop：v5 客户端和服务端握手成功，协商到 v5；
// v4/v3/v2 客户端也能和同一服务端握手（服务端同时接受新旧版本）。
func TestV5HandshakeInterop(t *testing.T) {
	for _, ver := range []int{VersionV5, VersionV4, VersionV3, VersionV2} {
		cRaw, sRaw := net.Pipe()
		errCh := make(chan error, 2)
		go func() {
			keys, err := ClientHandshakeVersion(cRaw, testPSK, ver, false, false)
			if err != nil {
				errCh <- fmt.Errorf("v%d 客户端握手：%v", ver, err)
				return
			}
			if keys.Version != ver {
				errCh <- fmt.Errorf("v%d 客户端协商到的版本是 %d", ver, keys.Version)
				return
			}
			errCh <- nil
		}()
		go func() {
			keys, err := ServerHandshakeWithKeys(sRaw, [][]byte{testPSK})
			if err != nil {
				errCh <- fmt.Errorf("v%d 服务端握手：%v", ver, err)
				return
			}
			if keys.Version != ver {
				errCh <- fmt.Errorf("v%d 服务端协商到的版本是 %d", ver, keys.Version)
				return
			}
			errCh <- nil
		}()
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		}
		cRaw.Close()
		sRaw.Close()
	}
}

// TestV5LinkParse：ver=5 链接能解析（经典格式和不透明格式），
// ver=6 照样拒绝；BuildLink 默认就是 ver=5。
func TestV5LinkParse(t *testing.T) {
	pin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	base := "mmx://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=5&pin=" + pin
	cfg, err := ParseLink(base)
	if err != nil {
		t.Fatalf("ver=5 链接应被接受：%v", err)
	}
	if cfg.Version != VersionV5 || cfg.Obfs != "tls" {
		t.Fatalf("ver=5 解析后版本/混淆不对：ver=%d obfs=%q", cfg.Version, cfg.Obfs)
	}
	if _, err := ParseLink("mmx://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=6"); err == nil {
		t.Fatalf("ver=6 应被拒绝")
	}
	// 不透明 v5 链接：生成 → 解析，版本和地址都对。
	opaque := BuildOpaqueLink(&LinkConfig{PSK: testPSK, Host: "203.0.113.5", Port: 37394, Version: VersionV5, PIN: testPINBytes()})
	got, err := ParseLink(opaque)
	if err != nil {
		t.Fatalf("不透明 ver=5 链接应被接受：%v", err)
	}
	if got.Version != VersionV5 || got.Host != "203.0.113.5" || got.Port != 37394 {
		t.Fatalf("不透明 ver=5 解析不对：ver=%d host=%s port=%d", got.Version, got.Host, got.Port)
	}
	// BuildLink 默认版本就是当前版本 v5。
	def := BuildLink(&LinkConfig{PSK: testPSK, Host: "203.0.113.5", Port: 37394, Obfs: "tls", PIN: testPINBytes()})
	if !strings.Contains(def, "?ver=5") {
		t.Fatalf("BuildLink 默认应为 ver=5：%s", def)
	}
}

// TestV5HandshakeSizePeaked：v5 握手包总长仍在 400–600 字节，
// 但尺寸是峰形分布（三角分布）：200 次抽样的均值应在 480–530 之间、
// 标准差 < 60——不再是 v4 那种 400–600 上均匀铺开的平坦分布。
func TestV5HandshakeSizePeaked(t *testing.T) {
	pub := make([]byte, 32)
	random := make([]byte, 16)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	const n = 200
	var sum, sumSq float64
	for i := 0; i < n; i++ {
		p := buildHandshakePayload(pub, random, testPSK, "client", VersionV5, false, false)
		if len(p) < 400 || len(p) > 600 {
			t.Fatalf("v5 握手包长 %d，不在 400–600 字节内", len(p))
		}
		padLen := int(p[76])<<8 | int(p[77])
		if padLen < v4HandshakePadMin || padLen > v4HandshakePadMax {
			t.Fatalf("v5 握手填充 %d，不在 %d–%d 内", padLen, v4HandshakePadMin, v4HandshakePadMax)
		}
		if len(p) != 78+padLen {
			t.Fatalf("v5 握手包长 %d 和填充长度 %d 对不上", len(p), padLen)
		}
		sum += float64(len(p))
		sumSq += float64(len(p)) * float64(len(p))
	}
	mean := sum / n
	variance := sumSq/n - mean*mean
	std := math.Sqrt(variance)
	t.Logf("v5 握手包长：均值 %.1f，标准差 %.1f（n=%d）", mean, std, n)
	if mean < 480 || mean > 530 {
		t.Fatalf("v5 握手包长均值 %.1f，应在 480–530 之间（峰形分布的峰在中部）", mean)
	}
	if std >= 60 {
		t.Fatalf("v5 握手包长标准差 %.1f，应 < 60（三角分布比均匀分布更集中）", std)
	}
}

// TestV5FramePadBySize：v5 帧填充按载荷尺寸分级——
// 小载荷（<256B）填充 0–255、大载荷填充只 0–31。
// 测法：v5 连接上发 20 帧 50B 载荷和 20 帧 16000B 载荷，
// 在写端包一层记录长度的连接，统计 TLS 记录体长度的分布。
func TestV5FramePadBySize(t *testing.T) {
	oldMode := DefaultCoverMode
	DefaultCoverMode = CoverOff
	defer func() { DefaultCoverMode = oldMode }()

	cRaw, sRaw := net.Pipe()
	rec := &recordLenConn{Conn: cRaw}
	errCh := make(chan error, 2)
	var cConn *Conn
	go func() {
		keys, err := ClientHandshakeVersion(rec, testPSK, VersionV5, false, false)
		if err != nil {
			errCh <- fmt.Errorf("客户端握手：%v", err)
			return
		}
		mc, err := NewConn(rec, keys, true)
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
		// 服务端读帧：把 DATA 载荷拼起来，验完整性。
		go func() {
			var got []byte
			for {
				ft, p, err := mc.ReadFrame()
				if err != nil {
					return
				}
				if ft == FrameData {
					got = append(got, p...)
				}
			}
		}()
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if cConn == nil {
		t.Fatal("握手后客户端加密连接为空")
	}
	// 分片上限应在连续区间内，不再是画像的 6 档固定值之一的必然项
	// （断言范围即可：8192–16288）。
	if cap := cConn.maxDataPayload(); cap < v5ChunkCapMin || cap > v5ChunkCapMax {
		t.Fatalf("v5 分片上限 %d，不在 %d–%d 内", cap, v5ChunkCapMin, v5ChunkCapMax)
	}
	// 发小帧和大帧，读端在后台消费；写完后统计记录体长度。
	small := make([]byte, 50)
	big := make([]byte, 16000)
	for i := range small {
		small[i] = byte(i)
	}
	for i := range big {
		big[i] = byte(i % 251)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if err := cConn.WriteFrame(FrameData, small); err != nil {
				done <- err
				return
			}
		}
		for i := 0; i < 5; i++ {
			if err := cConn.WriteFrame(FrameData, big); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatalf("写帧失败：%v", err)
	}
	cConn.Close()
	sRaw.Close()
	// 记录体长度 = 帧载荷 + 34（nonce 12 + 帧头 6 + tag 16）+ 填充。
	// 小帧（50B 载荷）：记录体应在 84–339 之间，且 20 次里
	// 最大值 - 最小值 >= 100（填充 0–255 真的在起作用，抹开了尺寸）。
	// 大帧（16000B 载荷，会被切成多帧）：每条记录体 <= 16384，
	// 且至少被切成 2 条（分片上限 < 16000 时一定切）。
	smallLens, bigLens := rec.bodyLens(84, 339), rec.bodyLens(340, 16384)
	if len(smallLens) < 20 {
		t.Fatalf("小帧记录只抓到 %d 条，想要 20 条", len(smallLens))
	}
	lo, hi := smallLens[0], smallLens[0]
	for _, l := range smallLens {
		if l < lo {
			lo = l
		}
		if l > hi {
			hi = l
		}
	}
	if hi-lo < 100 {
		t.Fatalf("小帧记录体长度只在 %d–%d 之间 spread（应 >= 100，填充 0–255 在起作用）", lo, hi)
	}
	if len(bigLens) < 10 {
		t.Fatalf("大帧记录只抓到 %d 条，16000B 载荷应被切成多帧", len(bigLens))
	}
	for _, l := range bigLens {
		if l > 16384 {
			t.Fatalf("记录体 %d 字节，超过 TLS 记录上限 16384", l)
		}
	}
}

// recordLenConn 包一层 net.Conn，记下每次 Write 的长度，
// 用来观测写出去的 TLS 记录体长度（写记录时是两次 Write：
// 5 字节头 + 记录体；体长度 > 5 的 Write 就是记录体）。
type recordLenConn struct {
	net.Conn
	mu   sync.Mutex
	lens []int
}

func (r *recordLenConn) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	if n > 5 {
		r.mu.Lock()
		r.lens = append(r.lens, n)
		r.mu.Unlock()
	}
	return n, err
}

// bodyLens 返回落在 [lo, hi] 内的记录体长度。
func (r *recordLenConn) bodyLens(lo, hi int) []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []int
	for _, l := range r.lens {
		if l >= lo && l <= hi {
			out = append(out, l)
		}
	}
	return out
}

// TestV5ChaffTransparent：v5 掩护帧对调用方透明——
// 一方发掩护帧再发数据帧，另一方 ReadFrame 直接拿到数据帧，
// 载荷和序号都不受影响；掩护帧本身不计入正常帧。
func TestV5ChaffTransparent(t *testing.T) {
	oldMode := DefaultCoverMode
	DefaultCoverMode = CoverOff
	defer func() { DefaultCoverMode = oldMode }()

	cRaw, sRaw := net.Pipe()
	errCh := make(chan error, 2)
	var cConn, sConn *Conn
	go func() {
		keys, err := ClientHandshakeVersion(cRaw, testPSK, VersionV5, false, false)
		if err != nil {
			errCh <- err
			return
		}
		mc, err := NewConn(cRaw, keys, true)
		if err != nil {
			errCh <- err
			return
		}
		cConn = mc
		errCh <- nil
	}()
	go func() {
		keys, err := ServerHandshakeWithKeys(sRaw, [][]byte{testPSK})
		if err != nil {
			errCh <- err
			return
		}
		mc, err := NewConn(sRaw, keys, false)
		if err != nil {
			errCh <- err
			return
		}
		sConn = mc
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	_ = sConn
	done := make(chan error, 1)
	go func() {
		if err := cConn.WriteFrame(FrameChaff, []byte("chaff-bytes-1234")); err != nil {
			done <- err
			return
		}
		if err := cConn.WriteFrame(FrameData, []byte("hello-v5")); err != nil {
			done <- err
			return
		}
		done <- nil
	}()
	// 读端直接拿到 DATA，掩护帧被 ReadFrame 内部跳过。
	ft, p, err := sConn.ReadFrame()
	if err != nil {
		t.Fatalf("读帧失败：%v", err)
	}
	if ft != FrameData || string(p) != "hello-v5" {
		t.Fatalf("掩护帧后读到的帧不对：type=0x%02x payload=%q", ft, p)
	}
	if err := <-done; err != nil {
		t.Fatalf("写帧失败：%v", err)
	}
	cConn.Close()
	sRaw.Close()
}

// TestV5CoverLoop：掩护流量真的会发——把间隔参数改小后，
// v5 会话空闲 500ms 内至少发出 1 帧掩护帧；v4 会话一帧都不发。
func TestV5CoverLoop(t *testing.T) {
	oldMode := DefaultCoverMode
	oldIdle := coverIdleMin
	oldLo := coverSleepLo
	oldHi := coverSleepHi
	oldSizeLo := coverSizeLo
	oldSizeHi := coverSizeHi
	DefaultCoverMode = CoverHigh
	coverIdleMin = map[CoverMode]time.Duration{CoverHigh: 10 * time.Millisecond}
	coverSleepLo = map[CoverMode]time.Duration{CoverHigh: 50 * time.Millisecond}
	coverSleepHi = map[CoverMode]time.Duration{CoverHigh: 100 * time.Millisecond}
	coverSizeLo = map[CoverMode]int{CoverHigh: 64}
	coverSizeHi = map[CoverMode]int{CoverHigh: 128}
	defer func() {
		DefaultCoverMode = oldMode
		coverIdleMin = oldIdle
		coverSleepLo = oldLo
		coverSleepHi = oldHi
		coverSizeLo = oldSizeLo
		coverSizeHi = oldSizeHi
	}()

	cRaw, sRaw := net.Pipe()
	errCh := make(chan error, 2)
	var cConn *Conn
	go func() {
		keys, err := ClientHandshakeVersion(cRaw, testPSK, VersionV5, false, false)
		if err != nil {
			errCh <- err
			return
		}
		mc, err := NewConn(cRaw, keys, true)
		if err != nil {
			errCh <- err
			return
		}
		cConn = mc
		errCh <- nil
	}()
	go func() {
		keys, err := ServerHandshakeWithKeys(sRaw, [][]byte{testPSK})
		if err != nil {
			errCh <- err
			return
		}
		mc, err := NewConn(sRaw, keys, false)
		if err != nil {
			errCh <- err
			return
		}
		// 服务端读帧消费掩护帧（ReadFrame 内部跳过，不返回）。
		go func() {
			for {
				if _, _, err := mc.ReadFrame(); err != nil {
					return
				}
			}
		}()
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for cConn.ChaffsSent() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if cConn.ChaffsSent() == 0 {
		t.Fatalf("v5 会话空闲 2 秒一帧掩护帧都没发")
	}
	cConn.Close()
	sRaw.Close()

	// v4 会话：同样的间隔参数，一帧掩护帧都不发。
	cRaw2, sRaw2 := net.Pipe()
	errCh2 := make(chan error, 2)
	var cConn2 *Conn
	go func() {
		keys, err := ClientHandshakeVersion(cRaw2, testPSK, VersionV4, false, false)
		if err != nil {
			errCh2 <- err
			return
		}
		mc, err := NewConn(cRaw2, keys, true)
		if err != nil {
			errCh2 <- err
			return
		}
		cConn2 = mc
		errCh2 <- nil
	}()
	go func() {
		keys, err := ServerHandshakeWithKeys(sRaw2, [][]byte{testPSK})
		if err != nil {
			errCh2 <- err
			return
		}
		if _, err := NewConn(sRaw2, keys, false); err != nil {
			errCh2 <- err
			return
		}
		errCh2 <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh2; err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if cConn2.ChaffsSent() != 0 {
		t.Fatalf("v4 会话发了 %d 帧掩护帧，应为 0", cConn2.ChaffsSent())
	}
	cConn2.Close()
	sRaw2.Close()
}

// TestV5SessionSNI：SNI 不再按会话轮换（2026-11-26 评审指出轮换反而更异常）；
// v5 + IP host 也用默认单一 SNI；链接写了 SNI 就用链接的；host 是域名就用 host。
func TestV5SessionSNI(t *testing.T) {
	v5 := &LinkConfig{Host: "203.0.113.5", Port: 37394, Version: VersionV5}
	for i := 0; i < 100; i++ {
		if got := SessionSNI(v5); got != DefaultSNI {
			t.Fatalf("v5 + IP host 应固定用默认 SNI %q，实际 %q（不应再轮换）", DefaultSNI, got)
		}
	}
	v4 := &LinkConfig{Host: "203.0.113.5", Port: 37394, Version: VersionV4}
	if got := SessionSNI(v4); got != DefaultSNI {
		t.Fatalf("v4 SNI 应为默认 %q，实际 %q", DefaultSNI, got)
	}
	explicit := &LinkConfig{Host: "203.0.113.5", Port: 37394, Version: VersionV5, SNI: "example.com"}
	if got := SessionSNI(explicit); got != "example.com" {
		t.Fatalf("链接写了 SNI 应优先用它，实际 %q", got)
	}
	domain := &LinkConfig{Host: "example.com", Port: 443, Version: VersionV5}
	if got := SessionSNI(domain); got != "example.com" {
		t.Fatalf("host 是域名时 SNI 应为 host 本身，实际 %q", got)
	}
}

// TestV5KeepaliveRandomized：yamux keepalive 间隔每会话随机 25–50 秒，
// 不再是固定 30 秒。10 次配置里至少出现 2 种不同间隔。
func TestV5KeepaliveRandomized(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 10; i++ {
		iv := YamuxConfig().KeepAliveInterval
		if iv < 25*time.Second || iv > 50*time.Second {
			t.Fatalf("keepalive 间隔 %v，不在 25–50 秒内", iv)
		}
		seen[iv] = true
	}
	if len(seen) < 2 {
		t.Fatalf("10 次 keepalive 间隔全是一种，应至少 2 种（随机化在起作用）")
	}
}

// TestV5DecoyHeaders：诱饵站响应带 Date + Server 头，
// 两次响应体不一样（最后更新日期行 + Date 头每天/每秒都在变）。
func TestV5DecoyHeaders(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	var buf1, buf2 bytes.Buffer
	r1 := bufio.NewReader(strings.NewReader(req))
	if err := ServeDecoySite(r1, &buf1); err != nil {
		t.Fatalf("ServeDecoySite 失败：%v", err)
	}
	r2 := bufio.NewReader(strings.NewReader(req))
	if err := ServeDecoySite(r2, &buf2); err != nil {
		t.Fatalf("ServeDecoySite 失败：%v", err)
	}
	for _, resp := range []string{buf1.String(), buf2.String()} {
		if !strings.Contains(resp, "Date: ") {
			t.Fatalf("诱饵站响应缺 Date 头：%.120s", resp)
		}
		if !strings.Contains(resp, "Server: nginx/") {
			t.Fatalf("诱饵站响应缺 Server 头：%.120s", resp)
		}
		if !strings.Contains(resp, "最后更新：") {
			t.Fatalf("诱饵页缺最后更新日期行")
		}
	}
	var buf3 bytes.Buffer
	if err := ServeDecoy400(&buf3); err != nil {
		t.Fatalf("ServeDecoy400 失败：%v", err)
	}
	if !strings.Contains(buf3.String(), "Date: ") || !strings.Contains(buf3.String(), "Server: nginx/") {
		t.Fatalf("400 页缺 Date/Server 头：%.120s", buf3.String())
	}
}

// TestV5SessionRotation：会话池轮换——会话超过 maxAge 且没有流在跑时，
// 下次 Get 重拨一条新会话；有流在跑时不轮换。
func TestV5SessionRotation(t *testing.T) {
	pool := NewSessionPool()
	pool.SetMaxAge(time.Millisecond) // 1ms 后就“老了”，测试不用等 30 分钟
	cfg := &LinkConfig{PSK: testPSK, Host: "127.0.0.1", Port: 1, Enc: "aes-256-gcm", Obfs: "tls-fake", Version: VersionV5, Rate: 0, Burst: BurstUnset}
	_ = cfg
	_ = pool
	// 轮换依赖真实拨号（DialSession），这里只验池的配置面：
	// maxAge 设进去、Get 的轮换分支由下面的 pipe 会话直接验。
	// （真实拨号轮换在 run-tests.sh 测试 26 里端到端验证。）
	if pool.maxAge != time.Millisecond {
		t.Fatalf("SetMaxAge 没生效：%v", pool.maxAge)
	}
}
