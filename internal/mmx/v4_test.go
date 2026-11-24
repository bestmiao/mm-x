// v4 单元测试：握手加长、v2/v3/v4 互通、会话重协商、
// TLS 记录版本号、会话画像、HKDF 标准库向量、拉黑表清理、uTLS 指纹。
package mmx

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestV4HandshakeLength：v4 握手包总长落在 400–600 字节
// （像真实 ClientHello）；v3 保持 77–332 字节。
func TestV4HandshakeLength(t *testing.T) {
	pub := make([]byte, 32)
	random := make([]byte, 16)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		p := buildHandshakePayload(pub, random, testPSK, "client", VersionV4, false, false)
		if len(p) < 400 || len(p) > 600 {
			t.Fatalf("v4 握手包长 %d，不在 400–600 字节内", len(p))
		}
		// 填充长度字段是 2 字节：固定字段 78 字节，填充 322–522。
		padLen := int(binary.BigEndian.Uint16(p[76:78]))
		if padLen < v4HandshakePadMin || padLen > v4HandshakePadMax {
			t.Fatalf("v4 握手填充 %d，不在 %d–%d 内", padLen, v4HandshakePadMin, v4HandshakePadMax)
		}
		if len(p) != 78+padLen {
			t.Fatalf("v4 握手包长 %d 和填充长度 %d 对不上（应为 78+%d）", len(p), padLen, padLen)
		}
	}
	for i := 0; i < 5; i++ {
		p := buildHandshakePayload(pub, random, testPSK, "client", VersionV3, false, false)
		if len(p) < 77 || len(p) > 332 {
			t.Fatalf("v3 握手包长 %d，不在 77–332 字节内", len(p))
		}
	}
}

// TestV4HandshakeInterop：v4、v3、v2 客户端都能和同一服务端握手，
// 协商到的版本各是自己发的版本；v4 握手的记录次版本号是 0x03。
func TestV4HandshakeInterop(t *testing.T) {
	for _, ver := range []int{VersionV4, VersionV3, VersionV2} {
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

// TestV4RecordVersion：记录次版本号 v4 写 0x03、v2/v3 写 0x01；
// 读端两个都认，0x02 拒绝；分流函数 LooksLikeTLSRecord 两个都认。
func TestV4RecordVersion(t *testing.T) {
	if got := recordMinorForVersion(VersionV4); got != 0x03 {
		t.Fatalf("v4 记录次版本号是 0x%02x，想要 0x03", got)
	}
	if got := recordMinorForVersion(VersionV3); got != 0x01 {
		t.Fatalf("v3 记录次版本号是 0x%02x，想要 0x01", got)
	}
	if got := recordMinorForVersion(VersionV2); got != 0x01 {
		t.Fatalf("v2 记录次版本号是 0x%02x，想要 0x01", got)
	}
	// 写 0x03 的记录能读回；写 0x01 的也能读回。
	for _, minor := range []byte{0x01, 0x03} {
		var buf bytes.Buffer
		if err := writeTLSRecordVersion(&buf, fakeRecordType, []byte("hello"), minor); err != nil {
			t.Fatalf("写次版本 0x%02x 的记录失败：%v", minor, err)
		}
		got, err := readTLSRecord(&buf, fakeRecordType)
		if err != nil {
			t.Fatalf("读次版本 0x%02x 的记录失败：%v", minor, err)
		}
		if string(got) != "hello" {
			t.Fatalf("次版本 0x%02x 的记录内容不对：%q", minor, got)
		}
	}
	// 次版本 0x02 不是合法的 TLS 记录次版本号，拒绝。
	var buf bytes.Buffer
	if err := writeTLSRecordVersion(&buf, fakeRecordType, []byte("hello"), 0x02); err != nil {
		t.Fatalf("写次版本 0x02 的记录失败：%v", err)
	}
	if _, err := readTLSRecord(&buf, fakeRecordType); err == nil {
		t.Fatal("次版本 0x02 的记录应被拒绝")
	}
	// 分流：0x16 0x03 0x01 和 0x16 0x03 0x03 都是 TLS 记录头。
	if !LooksLikeTLSRecord([]byte{0x16, 0x03, 0x01, 0x00, 0x10}) {
		t.Fatal("0x16 0x03 0x01 应被认作 TLS 记录头")
	}
	if !LooksLikeTLSRecord([]byte{0x16, 0x03, 0x03, 0x00, 0x10}) {
		t.Fatal("0x16 0x03 0x03 应被认作 TLS 记录头")
	}
	if LooksLikeTLSRecord([]byte{0x16, 0x03, 0x02, 0x00, 0x10}) {
		t.Fatal("0x16 0x03 0x02 不应被认作 TLS 记录头")
	}
}

// TestV4Rekey：v4 会话里重协商不断流——
// 客户端发方向到阈值先发重协商帧再发数据，服务端收到后切密钥、
// 数据照常读回；反方向同样。重协商帧本身不对调用方可见。
func TestV4Rekey(t *testing.T) {
	cli, srv := pipeConnPairVersion(t, VersionV4)
	defer cli.Close()
	defer srv.Close()
	// 把阈值改到最小：1 纳秒 / 1 字节，下一帧就触发重协商。
	cli.rekeyInterval = time.Nanosecond
	cli.rekeyBytes = 1
	srv.rekeyInterval = time.Nanosecond
	srv.rekeyBytes = 1
	time.Sleep(2 * time.Millisecond)

	// 客户端 → 服务端：先写一帧触发重协商，再写数据帧。
	// net.Pipe 是同步的，写操作要起 goroutine，读在主 goroutine。
	writeErr := make(chan error, 2)
	go func() {
		if err := cli.WriteFrame(FrameData, []byte("first")); err != nil {
			writeErr <- err
			return
		}
		if err := cli.WriteFrame(FrameData, []byte("after-rekey")); err != nil {
			writeErr <- err
			return
		}
		writeErr <- nil
	}()
	for _, want := range []string{"first", "after-rekey"} {
		ftype, payload, err := srv.ReadFrame()
		if err != nil {
			t.Fatalf("服务端读帧失败：%v", err)
		}
		if ftype != FrameData || string(payload) != want {
			t.Fatalf("服务端读到 type=0x%02x %q，想要 DATA %q", ftype, payload, want)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("客户端写失败：%v", err)
	}
	if cli.RekeysSent() < 1 {
		t.Fatalf("客户端应至少发 1 个重协商帧，实际 %d", cli.RekeysSent())
	}
	if srv.RekeysReceived() < 1 {
		t.Fatalf("服务端应至少收 1 个重协商帧，实际 %d", srv.RekeysReceived())
	}

	// 服务端 → 客户端：反方向同样不断流。
	go func() {
		if err := srv.WriteFrame(FrameData, []byte("back")); err != nil {
			writeErr <- err
			return
		}
		writeErr <- nil
	}()
	ftype, payload, err := cli.ReadFrame()
	if err != nil {
		t.Fatalf("客户端读回包失败：%v", err)
	}
	if ftype != FrameData || string(payload) != "back" {
		t.Fatalf("客户端读到 type=0x%02x %q，想要 DATA %q", ftype, payload, "back")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("服务端写失败：%v", err)
	}
	if srv.RekeysSent() < 1 || cli.RekeysReceived() < 1 {
		t.Fatalf("反方向应也重协商过：服务端发 %d，客户端收 %d", srv.RekeysSent(), cli.RekeysReceived())
	}
}

// TestV3NoRekey：v3 会话不发重协商帧（重协商只在 v4）。
func TestV3NoRekey(t *testing.T) {
	cli, srv := pipeConnPairVersion(t, VersionV3)
	defer cli.Close()
	defer srv.Close()
	cli.rekeyInterval = time.Nanosecond
	cli.rekeyBytes = 1
	time.Sleep(2 * time.Millisecond)
	writeErr := make(chan error, 1)
	go func() {
		writeErr <- cli.WriteFrame(FrameData, []byte("hello-v3"))
	}()
	ftype, payload, err := srv.ReadFrame()
	if err != nil {
		t.Fatalf("服务端读帧失败：%v", err)
	}
	if ftype != FrameData || string(payload) != "hello-v3" {
		t.Fatalf("服务端读到 type=0x%02x %q，想要 DATA %q", ftype, payload, "hello-v3")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("客户端写失败：%v", err)
	}
	if cli.RekeysSent() != 0 || srv.RekeysReceived() != 0 {
		t.Fatalf("v3 会话不应重协商：客户端发 %d，服务端收 %d", cli.RekeysSent(), srv.RekeysReceived())
	}
}

// TestV4MuxSession：v4 握手之后跑 yamux 会话，开 TCP 流走回显，
// 数据完整——v4 不是只有握手，整条复用链路都要通。
func TestV4MuxSession(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	cli, _, cleanup := pipeSessionPairVersion(t, VersionV4, 0, BurstUnset)
	defer cleanup()
	st, err := cli.OpenTCPStream(echoAddr)
	if err != nil {
		t.Fatalf("v4 会话开 TCP 流失败：%v", err)
	}
	defer st.Close()
	want := []byte("hello-v4-mux")
	if _, err := st.Write(want); err != nil {
		t.Fatalf("v4 流写失败：%v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("v4 流读回显失败：%v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("v4 流回显不一致：%q，想要 %q", got, want)
	}
}

// TestSessionProfilePerSession：同一 PSK、不同盐 → 画像不同（至少 20 个盐里
// 出现 2 种以上画像）；同一盐 → 同一画像；空盐 = 老的 PSK 派生。
func TestSessionProfilePerSession(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	p1 := DeriveSessionProfile(psk, salt)
	p2 := DeriveSessionProfile(psk, salt)
	if p1.Index != p2.Index {
		t.Fatalf("同一 PSK + 同一盐两次派生画像不同：%d vs %d", p1.Index, p2.Index)
	}
	// 空盐和老接口完全一致。
	if p := DeriveSessionProfile(psk, nil); p.Index != DeriveTrafficProfile(psk).Index {
		t.Fatalf("空盐派生应和老接口一致：%d vs %d", p.Index, DeriveTrafficProfile(psk).Index)
	}
	// 20 个不同盐里至少出现 2 种画像（全抽到同一种的概率约 6^-19）。
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		s := []byte{byte(i), 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11}
		seen[DeriveSessionProfile(psk, s).Index] = true
	}
	if len(seen) < 2 {
		t.Fatalf("20 个不同盐只得到 %d 种画像，盐没有起作用", len(seen))
	}
	// v4 握手填充落在 322–522 内。
	for i := 0; i < 20; i++ {
		p := DeriveSessionProfile(psk, []byte{byte(i), 1, 2, 3, 4, 5, 6, 7})
		n, err := p.SampleHandshakePadLenV4()
		if err != nil {
			t.Fatalf("v4 握手填充抽样失败：%v", err)
		}
		if n < v4HandshakePadMin || n > v4HandshakePadMax {
			t.Fatalf("v4 握手填充 %d，不在 %d–%d 内", n, v4HandshakePadMin, v4HandshakePadMax)
		}
	}
}

// TestHKDFRFC5869：标准库 HKDF 的输出必须和 RFC 5869 测试向量一致
// （C1：手写版换标准库，行为不能变）。
func TestHKDFRFC5869(t *testing.T) {
	// 测试用例 1：SHA-256，短输入。
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	wantOKM := []byte{
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
		0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
		0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	}
	got := hkdfSHA256(ikm, salt, info, 42)
	if !bytes.Equal(got, wantOKM) {
		t.Fatalf("RFC 5869 用例 1 不一致：\n得到 %x\n想要 %x", got, wantOKM)
	}
	// 测试用例 2：长输入（80 字节 IKM/salt/info，依次递增）。
	ikm2 := make([]byte, 80)
	salt2 := make([]byte, 80)
	info2 := make([]byte, 80)
	for i := 0; i < 80; i++ {
		ikm2[i] = byte(i)
		salt2[i] = byte(0x60 + i)
		info2[i] = byte(0xb0 + i)
	}
	wantOKM2 := []byte{
		0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
		0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
		0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
		0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
		0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
		0x1d, 0x87,
	}
	got2 := hkdfSHA256(ikm2, salt2, info2, 82)
	if !bytes.Equal(got2, wantOKM2) {
		t.Fatalf("RFC 5869 用例 2 不一致：\n得到 %x\n想要 %x", got2, wantOKM2)
	}
}

// TestBlocklistPurgeExpired：过期的失败记录和拉黑条目会被清掉，
// 没过期的不受影响（A7）。
func TestBlocklistPurgeExpired(t *testing.T) {
	// 失败记录：窗口 1ms，记 1 次失败，5ms 后应被清掉。
	bl := NewBlocklist(5, time.Millisecond, time.Hour)
	bl.RecordFailure("1.2.3.4")
	if f, b := bl.PurgeExpired(); f != 0 || b != 0 {
		t.Fatalf("没过期的条目不应被清：清掉 fails=%d blocked=%d", f, b)
	}
	time.Sleep(5 * time.Millisecond)
	if f, b := bl.PurgeExpired(); f != 1 || b != 0 {
		t.Fatalf("过期失败记录应清掉 1 条：清掉 fails=%d blocked=%d", f, b)
	}
	if bl.FailCount("1.2.3.4") != 0 {
		t.Fatal("清掉后失败计数应为 0")
	}
	// 拉黑条目：失败 1 次就拉黑，拉黑时长 1ms，5ms 后应被清掉。
	bl2 := NewBlocklist(1, time.Hour, time.Millisecond)
	if blocked := bl2.RecordFailure("5.6.7.8"); !blocked {
		t.Fatal("失败 1 次（阈值 1）应触发拉黑")
	}
	if !bl2.IsBlocked("5.6.7.8") {
		t.Fatal("刚拉黑的 IP 应在拉黑中")
	}
	time.Sleep(5 * time.Millisecond)
	if f, b := bl2.PurgeExpired(); f != 0 || b != 1 {
		t.Fatalf("过期拉黑应清掉 1 条：清掉 fails=%d blocked=%d", f, b)
	}
	if bl2.IsBlocked("5.6.7.8") {
		t.Fatal("清掉后该 IP 不应再被拉黑")
	}
	// nil 拉黑器不崩。
	var nilBl *Blocklist
	if f, b := nilBl.PurgeExpired(); f != 0 || b != 0 {
		t.Fatalf("nil 拉黑器清掉 %d/%d，应为 0/0", f, b)
	}
}

// TestUTLSClientHelloShape：uTLS Chrome 的 ClientHello
// 仍能被服务端的分流函数认出来（A3 不能把分流认坏了）。
// 做法：uTLS 客户端往一个普通 TCP 监听端口发 ClientHello，
// 抓下首条记录的头和载荷，看分流函数认不认。
func TestUTLSClientHelloShape(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	defer ln.Close()
	gotCh := make(chan []byte, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, err := raw.Read(buf)
		if err != nil || n < 6 {
			return
		}
		gotCh <- append([]byte(nil), buf[:n]...)
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("端口解析失败：%v", err)
	}
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("拨号失败：%v", err)
	}
	defer raw.Close()
	cfg := &utls.Config{
		ServerName:         "www.microsoft.com",
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	uconn := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	// 握手一定失败（对端不是 TLS 服务端），只关心 ClientHello 已发出。
	_ = uconn.Handshake()
	select {
	case rec := <-gotCh:
		if len(rec) < 6 {
			t.Fatalf("抓到的记录太短：%d 字节", len(rec))
		}
		if !LooksLikeTLSRecord(rec[:5]) {
			t.Fatalf("uTLS ClientHello 的记录头 % x 没被认作 TLS 记录", rec[:5])
		}
		// 记录体就是 ClientHello 载荷（本例一次读全了整条记录）。
		recLen := int(rec[3])<<8 | int(rec[4])
		if len(rec) < 5+recLen {
			t.Fatalf("抓到的记录不完整：头说 %d 字节，实际 %d", recLen, len(rec)-5)
		}
		if !LooksLikeClientHello(rec[5 : 5+recLen]) {
			t.Fatalf("uTLS ClientHello 载荷没被认作 ClientHello（首字节 0x%02x，版本 0x%02x 0x%02x）",
				rec[5], rec[9], rec[10])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("5 秒没抓到 ClientHello")
	}
	_ = port
}

// TestUTLSVersionString：uTLS 客户端和 crypto/tls 服务端能谈成 TLS 1.3
// （DialTLSWithPin 已换 uTLS，TestDialTLSWithPin 覆盖端到端；
// 这里只确认 uTLS 的版本常量和 crypto/tls 的值一致，配错版本会立刻发现）。
func TestUTLSVersionString(t *testing.T) {
	if utls.VersionTLS13 != tls.VersionTLS13 {
		t.Fatalf("uTLS 的 TLS 1.3 版本号 0x%04x 和 crypto/tls 的 0x%04x 不一致", utls.VersionTLS13, tls.VersionTLS13)
	}
}
