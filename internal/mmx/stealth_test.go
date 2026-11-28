// v2 隐蔽性加强的单元测试：动态魔数、包长分片、诱饵站。
package mmx

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
)

var testPSK = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

func TestHandshakeMagicIsRandomPerConnection(t *testing.T) {
	pub := make([]byte, 32)
	random := make([]byte, 16)
	p1 := buildHandshakePayload(pub, random, testPSK, "client", Version, false, false)
	p2 := buildHandshakePayload(pub, random, testPSK, "client", Version, false, false)
	// 同一个密钥、同一对公钥/随机数，两次握手载荷的前 11 字节（盐 8 + 魔数 3）
	// 必须不一样：盐每次随机，魔数由盐派生。
	if bytes.Equal(p1[:saltLen+magicLen], p2[:saltLen+magicLen]) {
		t.Fatalf("两次握手的盐+魔数完全相同：线上仍有固定特征")
	}
	// 线上不再出现任何固定魔数字节：v1 的 "MMX" 不能出现，版本字节也不再是固定的 0x01。
	if bytes.Contains(p1, []byte("MMX")) || bytes.Contains(p2, []byte("MMX")) {
		t.Fatalf("握手载荷里仍有固定魔数 MMX")
	}
	// 两次握手的版本字节（盐+魔数之后 1 字节）也不同（被魔数首字节异或过）。
	if p1[saltLen+magicLen] == p2[saltLen+magicLen] {
		t.Fatalf("两次握手的版本字节相同：版本仍是固定特征")
	}
	// 两个载荷都能正常解析（盐+魔数自洽）。
	peerRandom := make([]byte, 16)
	if _, _, _, err := parseHandshakePayload(p1, testPSK, "client", peerRandom); err != nil {
		t.Fatalf("握手载荷 1 解析失败：%v", err)
	}
	if _, _, _, err := parseHandshakePayload(p2, testPSK, "client", peerRandom); err != nil {
		t.Fatalf("握手载荷 2 解析失败：%v", err)
	}
	// 密钥不对 / 魔数被改都应拒绝。
	wrongPSK := append([]byte{}, testPSK...)
	wrongPSK[0] ^= 0xFF
	if _, _, _, err := parseHandshakePayload(p1, wrongPSK, "client", peerRandom); err == nil {
		t.Fatalf("密钥不对的握手载荷竟然通过了")
	}
	tampered := append([]byte{}, p1...)
	tampered[saltLen] ^= 0xFF
	if _, _, _, err := parseHandshakePayload(tampered, testPSK, "client", peerRandom); err == nil {
		t.Fatalf("魔数被改的握手载荷竟然通过了")
	}
}

// handshakePair 在 net.Pipe 两端完成一次 v2 握手，返回两端的 Conn。
func handshakePair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	cSide, sSide := net.Pipe()
	errCh := make(chan error, 1)
	var sKeys *SessionKeys
	go func() {
		var err error
		sKeys, err = ServerHandshake(sSide, testPSK)
		errCh <- err
	}()
	cKeys, err := ClientHandshake(cSide, testPSK, false, false)
	if err != nil {
		t.Fatalf("客户端握手失败：%v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("服务端握手失败：%v", err)
	}
	cc, err := NewConn(cSide, cKeys, true)
	if err != nil {
		t.Fatalf("客户端 NewConn 失败：%v", err)
	}
	sc, err := NewConn(sSide, sKeys, false)
	if err != nil {
		t.Fatalf("服务端 NewConn 失败：%v", err)
	}
	return cc, sc
}

func TestDataFrameChunking(t *testing.T) {
	cc, sc := handshakePair(t)
	defer cc.Close()
	defer sc.Close()

	// 40000 字节一次写出：按本连接实际的分片上限切帧
	// （旧版固定 16000 时是 16000/16000/8000 三帧；画像改后分片
	// 上限因 PSK 而异，v5 又改成每会话连续随机值——
	// 这里按连接实际生效的上限算期望帧数，不再硬编码 3 帧）。
	// 接收方按顺序读回，拼起来和原文完全一致（流语义不变）。
	expectedFrames := (40000 + cc.maxDataPayload() - 1) / cc.maxDataPayload()
	data := make([]byte, 40000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	done := make(chan error, 1)
	go func() {
		done <- cc.WriteFrame(FrameData, data)
	}()
	var got []byte
	for i := 0; i < expectedFrames; i++ {
		ft, payload, err := sc.ReadFrame()
		if err != nil {
			t.Fatalf("读第 %d 帧失败：%v", i+1, err)
		}
		if ft != FrameData {
			t.Fatalf("第 %d 帧类型不对：%d", i+1, ft)
		}
		got = append(got, payload...)
	}
	if err := <-done; err != nil {
		t.Fatalf("写帧失败：%v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("分片后重组的数据不一致（收到 %d 字节，应为 %d）", len(got), len(data))
	}
}

func TestRecordNeverExceedsTLSMax(t *testing.T) {
	cc, sc := handshakePair(t)
	defer cc.Close()
	defer sc.Close()

	data := make([]byte, 40000)
	done := make(chan error, 1)
	go func() {
		done <- cc.WriteFrame(FrameData, data)
	}()
	// 直接在原始连接上按 TLS 记录读：每条记录都不超过 16384 字节
	// （真实 TLS 1.2 的记录上限），记录数 = ceil(40000 / 实际分片上限）
	// （旧版固定 16000 时正好是 3 条；画像改后按实际画像算；
	// v5 是每会话连续随机值，按连接实际生效的上限算）。
	expectedRecords := (40000 + cc.maxDataPayload() - 1) / cc.maxDataPayload()
	records := 0
	total := 0
	for total < 40000+expectedRecords*(12+6+63+16) { // 粗略上限：每条记录的密文开销
		rec, err := readTLSRecord(sc, 0x17)
		if err != nil {
			t.Fatalf("读第 %d 条记录失败：%v", records+1, err)
		}
		if len(rec) > maxRecordLen {
			t.Fatalf("第 %d 条记录 %d 字节，超过 TLS 记录上限 %d", records+1, len(rec), maxRecordLen)
		}
		records++
		total += len(rec)
		if records > expectedRecords {
			t.Fatalf("40000 字节写出后收到 %d 条记录，预期 %d 条", records, expectedRecords)
		}
		// 每条记录的明文至少包含一个数据块；
		// 全部记录的总载荷去掉每帧开销后应正好是 40000 字节的数据
		// （开销：每帧 nonce 12 + 帧头 6 + 填充 0–63 + tag 16）。
		if records == expectedRecords {
			break
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("写帧失败：%v", err)
	}
	if records != expectedRecords {
		t.Fatalf("40000 字节应切成 %d 条记录，实际 %d 条", expectedRecords, records)
	}
}

func TestDecoySite(t *testing.T) {
	// HTTP 请求 → 200 + 诱饵页
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	var buf bytes.Buffer
	r := bufio.NewReader(strings.NewReader(req))
	if err := ServeDecoySite(r, &buf); err != nil {
		t.Fatalf("ServeDecoySite 失败：%v", err)
	}
	resp := buf.String()
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("诱饵站应回 200 OK，实际：%.80s", resp)
	}
	if !strings.Contains(resp, "家庭影音") {
		t.Fatalf("诱饵页内容不对：%.120s", resp)
	}
	if strings.Contains(resp, "mm-x") || strings.Contains(resp, "mmx://") {
		t.Fatalf("诱饵页泄露了 mm-x 信息")
	}

	// 乱字节/TLS 握手 → 400 页
	buf.Reset()
	if err := ServeDecoy400(&buf); err != nil {
		t.Fatalf("ServeDecoy400 失败：%v", err)
	}
	if !strings.Contains(buf.String(), "400 Bad Request") {
		t.Fatalf("应回 400 Bad Request，实际：%.80s", buf.String())
	}

	// 首字节分类
	if !LooksLikeHTTP([]byte("GET / HTTP/1.1")) {
		t.Fatalf("GET 请求没识别成 HTTP")
	}
	if !LooksLikeHTTP([]byte("POST /x HTTP/1.1")) {
		t.Fatalf("POST 请求没识别成 HTTP")
	}
	if LooksLikeHTTP([]byte{0x16, 0x03, 0x01, 0x00, 0x01}) {
		t.Fatalf("TLS 记录头被误认成 HTTP")
	}
	if !LooksLikeTLSRecord([]byte{0x16, 0x03, 0x01, 0x00, 0x01}) {
		t.Fatalf("TLS 记录头没识别出来")
	}
	if LooksLikeTLSRecord([]byte("GET /")) {
		t.Fatalf("HTTP 请求被误认成 TLS 记录")
	}
}

func TestDecoyHomeMedia(t *testing.T) {
	// 家庭影音：单页登录站。首页回 200，含密码输入框、登录按钮、
	// 永远报错的假登录（JS 拦截提交，永不成功）、自适应 viewport +
	// media query；/about.html、旧博客页、不存在的路径都回 404；
	// POST / 也只回登录页（没有任何接口能“登录成功”）。
	// 内容不含代理信息、无外部资源、无正确密码。
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	var buf bytes.Buffer
	r := bufio.NewReader(strings.NewReader(req))
	if err := ServeDecoySite(r, &buf); err != nil {
		t.Fatalf("首页 ServeDecoySite 失败：%v", err)
	}
	home := buf.String()
	if !strings.Contains(home, "200 OK") {
		t.Fatalf("首页应回 200 OK，实际：%.80s", home)
	}
	for _, want := range []string{
		"家庭影音", "访问密码", "登录", "密码错误，请重试",
		`type="password"`, "preventDefault",
		"width=device-width", "@media (max-width: 600px)",
		"最后更新：",
	} {
		if !strings.Contains(home, want) {
			t.Fatalf("首页缺 %q：%.200s", want, home)
		}
	}
	for _, bad := range []string{
		"mm-x", "mmx://", "代理", "VPN",
		"http://", "https://", // 无外部资源
		"src=",       // 无外部脚本/图片
		"登录成功", "欢迎", // 没有任何“成功进站”的内容
		"留言板", "关于我", "localStorage", // 旧站内容已撤下
	} {
		if strings.Contains(home, bad) {
			t.Fatalf("首页含不应有的内容 %q", bad)
		}
	}
	if !strings.Contains(home, "Date: ") || !strings.Contains(home, "Server: nginx/") {
		t.Fatalf("首页缺 Date/Server 头：%.120s", home)
	}

	// POST / 也只回登录页：没有任何登录接口，密码永远进不去。
	req = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\nConnection: close\r\n\r\npwd=whatever"
	buf.Reset()
	r = bufio.NewReader(strings.NewReader(req))
	if err := ServeDecoySite(r, &buf); err != nil {
		t.Fatalf("POST 首页 ServeDecoySite 失败：%v", err)
	}
	post := buf.String()
	if !strings.Contains(post, "200 OK") || !strings.Contains(post, "家庭影音") {
		t.Fatalf("POST / 应回登录页，实际：%.120s", post)
	}
	if strings.Contains(post, "登录成功") || strings.Contains(post, "欢迎") {
		t.Fatalf("POST / 不应有任何登录成功内容")
	}

	// 单页站：/about.html、旧博客页、不存在的路径都回 404。
	for _, p := range []string{"/about.html", "/blog/ssd.html", "/blog/kyoto.html", "/blog/photo.html", "/blog/cooking.html", "/不存在的页"} {
		req = "GET " + p + " HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
		buf.Reset()
		r = bufio.NewReader(strings.NewReader(req))
		if err := ServeDecoySite(r, &buf); err != nil {
			t.Fatalf("%s：ServeDecoySite 失败：%v", p, err)
		}
		if !strings.Contains(buf.String(), "404 Not Found") {
			t.Fatalf("%s 已撤下，应回 404，实际：%.80s", p, buf.String())
		}
	}
}
