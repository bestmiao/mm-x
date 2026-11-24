package mm1

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
)

// 固定测试密钥/指纹（各 32 字节），和真实部署的密钥无关。
var linkTestPSK = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}
var linkTestPIN = []byte{
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
}

func linkTestKeyB64() string {
	return base64.RawURLEncoding.EncodeToString(linkTestPSK)
}
func linkTestPinB64() string {
	return base64.RawURLEncoding.EncodeToString(linkTestPIN)
}

// v3 TLS 短链接往返：生成是短格式（只有 ver + pin），解析回来字段一致，
// 再生成一次结果不变（幂等）。
func TestShortLinkV3RoundTrip(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Enc: "aes-256-gcm", Obfs: "tls", Version: VersionV3,
		SNI: DefaultSNI, PIN: linkTestPIN, Rate: 6250 * 1024, Burst: 0, Name: "MM-1",
	}
	link := BuildLink(cfg)
	for _, banned := range []string{"enc=", "obfs=", "rate=", "burst=", "sni=", "#"} {
		if strings.Contains(link, banned) {
			t.Fatalf("短链接不应含 %q：%s", banned, link)
		}
	}
	if !strings.Contains(link, "?ver=3&pin=") {
		t.Fatalf("短链接应为 ?ver=3&pin=...：%s", link)
	}
	// 长度：mm://(5) + 密钥(43) + @(1) + host(11) + :(1) + 端口(5)
	// + ?ver=3(6) + &pin=(5) + 指纹(43) = 120（本例 host 是 203.0.113.5）
	wantLen := 5 + 43 + 1 + len("203.0.113.5") + 1 + 5 + 6 + 5 + 43
	if len(link) != wantLen {
		t.Fatalf("短链接长度 %d，想要 %d：%s", len(link), wantLen, link)
	}
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("短链接解析失败：%v", err)
	}
	if !bytes.Equal(got.PSK, cfg.PSK) {
		t.Fatalf("解析后密钥变了")
	}
	if got.Host != cfg.Host || got.Port != cfg.Port {
		t.Fatalf("解析后地址变了：%s:%d", got.Host, got.Port)
	}
	if got.Version != VersionV3 || got.Obfs != "tls" {
		t.Fatalf("解析后版本/混淆不对：ver=%d obfs=%q", got.Version, got.Obfs)
	}
	if !bytes.Equal(got.PIN, cfg.PIN) {
		t.Fatalf("解析后 pin 变了")
	}
	if got.SNI != "" {
		t.Fatalf("短链接没写 sni，解析后 SNI 应为空（拨号时再默认）：%q", got.SNI)
	}
	if got.Name != "MM-1" {
		t.Fatalf("短链接没写名字，解析后名字应默认 MM-1：%q", got.Name)
	}
	if got.Rate != 0 || got.Burst != BurstUnset {
		t.Fatalf("短链接没写限速，解析后应为不限速/默认突发：rate=%d burst=%d", got.Rate, got.Burst)
	}
	if ResolveSNI(got) != DefaultSNI {
		t.Fatalf("短链接没写 sni，拨号 SNI 应默认 %q，实际 %q", DefaultSNI, ResolveSNI(got))
	}
	if BuildLink(got) != link {
		t.Fatalf("往返后链接变了：\n生成：%s\n再生成：%s", link, BuildLink(got))
	}
}

// 非默认 SNI 要写进链接，解析回来一致。
func TestShortLinkCustomSNI(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "example.com", Port: 443,
		Obfs: "tls", Version: VersionV3, SNI: "example.com", PIN: linkTestPIN,
	}
	link := BuildLink(cfg)
	if !strings.Contains(link, "sni=example.com") {
		t.Fatalf("非默认 SNI 应写进链接：%s", link)
	}
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if got.SNI != "example.com" {
		t.Fatalf("解析后 SNI 不对：%q", got.SNI)
	}
}

// 明文 v3：obfs 和版本默认不一致，必须显式写 obfs=tls-fake，
// 否则解析时会按 ver=3 默认成 tls（再因缺 pin 被拒）。
func TestShortLinkPlainV3(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV3,
	}
	link := BuildLink(cfg)
	if !strings.Contains(link, "obfs=tls-fake") {
		t.Fatalf("明文 v3 链接必须显式写 obfs=tls-fake：%s", link)
	}
	if strings.Contains(link, "pin=") {
		t.Fatalf("明文链接不应带 pin：%s", link)
	}
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if got.Version != VersionV3 || got.Obfs != "tls-fake" {
		t.Fatalf("解析后版本/混淆不对：ver=%d obfs=%q", got.Version, got.Obfs)
	}
}

// v2 短链接：只有 ver=2，解析后 obfs 默认 tls-fake。
func TestShortLinkV2(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV2,
	}
	link := BuildLink(cfg)
	want := "mm://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=2"
	if link != want {
		t.Fatalf("v2 短链接不对：\n生成：%s\n想要：%s", link, want)
	}
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if got.Version != VersionV2 || got.Obfs != "tls-fake" {
		t.Fatalf("解析后版本/混淆不对：ver=%d obfs=%q", got.Version, got.Obfs)
	}
}

// 完整格式（老链接）照常解析，所有字段都在。
func TestFullLinkStillParses(t *testing.T) {
	full := "mm://" + linkTestKeyB64() + "@203.0.113.5:37394" +
		"?enc=aes-256-gcm&obfs=tls&ver=3&rate=6250K&burst=0" +
		"&sni=www.microsoft.com&pin=" + linkTestPinB64() + "#MM-1"
	got, err := ParseLink(full)
	if err != nil {
		t.Fatalf("完整格式解析失败：%v", err)
	}
	if got.Version != VersionV3 || got.Obfs != "tls" || got.Enc != "aes-256-gcm" {
		t.Fatalf("解析后版本/混淆/加密不对：ver=%d obfs=%q enc=%q", got.Version, got.Obfs, got.Enc)
	}
	if got.Rate != 6250*1024 {
		t.Fatalf("解析后限速不对：%d", got.Rate)
	}
	if got.Burst != 0 {
		t.Fatalf("解析后突发不对：%d", got.Burst)
	}
	if got.SNI != "www.microsoft.com" || !bytes.Equal(got.PIN, linkTestPIN) {
		t.Fatalf("解析后 sni/pin 不对：sni=%q pin=%x", got.SNI, got.PIN)
	}
	if got.Name != "MM-1" {
		t.Fatalf("解析后名字不对：%q", got.Name)
	}
	// 老 v2 完整链接（含 UUID 密钥）也照常解析
	uuidLink := "mm://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:18081?enc=aes-256-gcm&obfs=tls-fake&ver=2#UUID节点"
	got2, err := ParseLink(uuidLink)
	if err != nil {
		t.Fatalf("老 v2 链接解析失败：%v", err)
	}
	if got2.Version != VersionV2 || got2.Obfs != "tls-fake" || got2.Name != "UUID节点" {
		t.Fatalf("老 v2 链接解析后不对：ver=%d obfs=%q name=%q", got2.Version, got2.Obfs, got2.Name)
	}
	if len(got2.PSK) != 32 {
		t.Fatalf("UUID 密钥派生后应为 32 字节，实际 %d", len(got2.PSK))
	}
}

// ver=3 + TLS 缺 pin 必须拒绝（指纹锁定不可跳过）；
// 明文 v3 缺 pin 是合法的。
func TestShortLinkMissingPinRejected(t *testing.T) {
	for _, link := range []string{
		"mm://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=3",
		"mm://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=3&obfs=tls",
	} {
		if _, err := ParseLink(link); err == nil {
			t.Fatalf("ver=3 TLS 缺 pin 应被拒绝：%s", link)
		} else if !strings.Contains(err.Error(), "pin") {
			t.Fatalf("缺 pin 的报错应提到 pin：%v", err)
		}
	}
	// 明文 v3 不带 pin 是合法的
	if _, err := ParseLink("mm://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=3&obfs=tls-fake"); err != nil {
		t.Fatalf("明文 v3 不带 pin 应合法：%v", err)
	}
}

// pin 格式不对拒绝；格式对但值不对的 pin 解析时放行，
// 握手时才会被 TLS 指纹校验拒绝（已有测试 21 的 bad-pin 覆盖）。
func TestShortLinkBadPinRejected(t *testing.T) {
	for _, pin := range []string{"AAAA", "!!!", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		link := "mm://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=3&pin=" + pin
		if _, err := ParseLink(link); err == nil {
			t.Fatalf("格式不对的 pin 应被拒绝：%s", pin)
		}
	}
}

// 版本号只认 2 和 3；不写 ver 默认 v2。
func TestShortLinkVersion(t *testing.T) {
	for _, ver := range []string{"1", "4", "9"} {
		link := "mm://" + linkTestKeyB64() + "@203.0.113.5:37394?ver=" + ver
		if _, err := ParseLink(link); err == nil {
			t.Fatalf("ver=%s 应被拒绝", ver)
		}
	}
	got, err := ParseLink("mm://" + linkTestKeyB64() + "@203.0.113.5:37394")
	if err != nil {
		t.Fatalf("不写 ver 应合法：%v", err)
	}
	if got.Version != VersionV2 || got.Obfs != "tls-fake" {
		t.Fatalf("不写 ver 应默认 v2 明文：ver=%d obfs=%q", got.Version, got.Obfs)
	}
}

// ---- 不透明链接（乱码式）----

// 不透明链接的变异工具：解码 → 改字节 → 重算 CRC → 重新编码。
// 重算 CRC 是为了让变异后的链接能走到目标校验（而不是先死在 CRC 上）。
func opaqueMutate(t *testing.T, link string, mutate func(blob []byte)) string {
	t.Helper()
	rest := strings.TrimPrefix(link, "mm://")
	blob, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		t.Fatalf("测试链接解码失败：%v", err)
	}
	mutate(blob)
	binary.BigEndian.PutUint32(blob[len(blob)-4:], crc32.ChecksumIEEE(blob[:len(blob)-4]))
	return "mm://" + base64.RawURLEncoding.EncodeToString(blob)
}

// 标准的 v3 不透明链接（IPv4 + TLS + 默认 SNI + PIN）：
// blob 84 字节（magic 4 + 版本 1 + PSK 32 + host 类型 1 + IPv4 4 +
// port 2 + ver 1 + obfs 1 + SNI 标志 1 + PIN 标志 1 + PIN 32 + CRC 4），
// base64url 112 字符，总长 117。
// 各字段偏移：magic 0、blob 版本 4、PSK 5、host 类型 37、IPv4 38、
// port 42、协议 ver 44、obfs 标志 45、SNI 标志 46、PIN 标志 47、PIN 48、CRC 80。
func opaqueV3Link() string {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Enc: "aes-256-gcm", Obfs: "tls", Version: VersionV3,
		SNI: DefaultSNI, PIN: linkTestPIN, Rate: 6250 * 1024, Burst: 0, Name: "MM-1",
	}
	return BuildOpaqueLink(cfg)
}

// 1. 往返：v3 + TLS + 默认 SNI + PIN → 生成 → 解析 → 配置一致；
// 生成两次结果完全相同（确定性）；总长 117；除前缀外没有任何可读字符。
func TestOpaqueLinkV3RoundTrip(t *testing.T) {
	link := opaqueV3Link()
	if len(link) != 117 {
		t.Fatalf("v3 不透明链接总长应为 117，实际 %d：%s", len(link), link)
	}
	rest := strings.TrimPrefix(link, "mm://")
	for _, banned := range []string{"@", ":", "?", "#", "/", "=", "+", " "} {
		if strings.Contains(rest, banned) {
			t.Fatalf("不透明链接不应含 %q：%s", banned, link)
		}
	}
	if BuildOpaqueLink(&LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, SNI: DefaultSNI, PIN: linkTestPIN,
	}) != link {
		t.Fatalf("同一份配置两次生成应完全相同")
	}
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("不透明链接解析失败：%v", err)
	}
	if !bytes.Equal(got.PSK, linkTestPSK) {
		t.Fatalf("解析后密钥变了")
	}
	if got.Host != "203.0.113.5" || got.Port != 37394 {
		t.Fatalf("解析后地址变了：%s:%d", got.Host, got.Port)
	}
	if got.Version != VersionV3 || got.Obfs != "tls" {
		t.Fatalf("解析后版本/混淆不对：ver=%d obfs=%q", got.Version, got.Obfs)
	}
	if !bytes.Equal(got.PIN, linkTestPIN) {
		t.Fatalf("解析后 pin 变了")
	}
	if got.SNI != "" {
		t.Fatalf("不透明链接没写自定义 SNI，解析后 SNI 应为空（拨号时再默认）：%q", got.SNI)
	}
	if ResolveSNI(got) != DefaultSNI {
		t.Fatalf("解析后拨号 SNI 应默认 %q，实际 %q", DefaultSNI, ResolveSNI(got))
	}
	if got.Name != "MM-1" || got.Rate != 0 || got.Burst != BurstUnset {
		t.Fatalf("解析后名字/限速不对：name=%q rate=%d burst=%d", got.Name, got.Rate, got.Burst)
	}
	if BuildOpaqueLink(got) != link {
		t.Fatalf("往返后链接变了：\n生成：%s\n再生成：%s", link, BuildOpaqueLink(got))
	}
}

// 2. 往返：明文 v3（obfs 标志 1）→ 解析出 tls-fake，无 PIN/SNI。
func TestOpaqueLinkPlainV3(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV3,
	}
	link := BuildOpaqueLink(cfg)
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("明文 v3 不透明链接解析失败：%v", err)
	}
	if got.Version != VersionV3 || got.Obfs != "tls-fake" {
		t.Fatalf("解析后版本/混淆不对：ver=%d obfs=%q", got.Version, got.Obfs)
	}
	if len(got.PIN) != 0 || got.SNI != "" {
		t.Fatalf("明文链接不应带 PIN/SNI")
	}
}

// 3. 往返：v2（无 PIN）→ 解析出 ver=2、tls-fake；总长 75。
func TestOpaqueLinkV2(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV2,
	}
	link := BuildOpaqueLink(cfg)
	if len(link) != 75 {
		t.Fatalf("v2 不透明链接总长应为 75，实际 %d：%s", len(link), link)
	}
	got, err := ParseLink(link)
	if err != nil {
		t.Fatalf("v2 不透明链接解析失败：%v", err)
	}
	if got.Version != VersionV2 || got.Obfs != "tls-fake" {
		t.Fatalf("解析后版本/混淆不对：ver=%d obfs=%q", got.Version, got.Obfs)
	}
}

// 4. 往返：IPv6 host、域名 host、自定义 SNI 各一例。
func TestOpaqueLinkHosts(t *testing.T) {
	cases := []LinkConfig{
		{PSK: linkTestPSK, Host: "::1", Port: 37394, Obfs: "tls-fake", Version: VersionV2},
		{PSK: linkTestPSK, Host: "example.com", Port: 443, Obfs: "tls-fake", Version: VersionV2},
		{PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394, Obfs: "tls", Version: VersionV3, SNI: "example.com", PIN: linkTestPIN},
	}
	for i, cfg := range cases {
		link := BuildOpaqueLink(&cfg)
		got, err := ParseLink(link)
		if err != nil {
			t.Fatalf("第 %d 例解析失败：%v", i, err)
		}
		if got.Host != cfg.Host || got.Port != cfg.Port {
			t.Fatalf("第 %d 例解析后地址变了：%s:%d，想要 %s:%d", i, got.Host, got.Port, cfg.Host, cfg.Port)
		}
		if got.SNI != cfg.SNI {
			t.Fatalf("第 %d 例解析后 SNI 不对：%q，想要 %q", i, got.SNI, cfg.SNI)
		}
		if BuildOpaqueLink(got) != link {
			t.Fatalf("第 %d 例往返后链接变了", i)
		}
	}
}

// 5. 老格式回归：同一份配置，经典短格式和不透明格式解析出的配置完全一致。
func TestOpaqueLinkSameConfigAsClassic(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, SNI: DefaultSNI, PIN: linkTestPIN,
	}
	classic, err := ParseLink(BuildLink(cfg))
	if err != nil {
		t.Fatalf("经典短格式解析失败：%v", err)
	}
	opaque, err := ParseLink(BuildOpaqueLink(cfg))
	if err != nil {
		t.Fatalf("不透明格式解析失败：%v", err)
	}
	if !bytes.Equal(classic.PSK, opaque.PSK) || classic.Host != opaque.Host ||
		classic.Port != opaque.Port || classic.Version != opaque.Version ||
		classic.Obfs != opaque.Obfs || classic.SNI != opaque.SNI ||
		!bytes.Equal(classic.PIN, opaque.PIN) || classic.Name != opaque.Name {
		t.Fatalf("两种格式解析出的配置不一致：\n经典：%+v\n不透明：%+v", classic, opaque)
	}
	// 会话池的键也必须一致：同一份配置只建一条会话。
	if sessionKey(classic) != sessionKey(opaque) {
		t.Fatalf("两种格式的会话键应相同，否则会多建会话")
	}
}

// 6. 坏 magic：改一个字节 → 拒绝（CRC 已重算，所以报错应指魔数）。
func TestOpaqueLinkBadMagic(t *testing.T) {
	bad := opaqueMutate(t, opaqueV3Link(), func(blob []byte) { blob[0] = 'X' })
	if _, err := ParseLink(bad); err == nil {
		t.Fatalf("魔数不对的链接应被拒绝")
	} else if !strings.Contains(err.Error(), "魔数") {
		t.Fatalf("魔数不对的报错应提到魔数：%v", err)
	}
}

// 7. 截断：去掉末尾几个字符 → 拒绝。
func TestOpaqueLinkTruncated(t *testing.T) {
	link := opaqueV3Link()
	for _, cut := range []int{1, 4, 10} {
		if _, err := ParseLink(link[:len(link)-cut]); err == nil {
			t.Fatalf("截断 %d 个字符的链接应被拒绝", cut)
		}
	}
	// 太短的串直接拒绝
	if _, err := ParseLink("mm://AAAA"); err == nil {
		t.Fatalf("过短的链接应被拒绝")
	}
}

// 8. 改一个中间字符 → CRC 不一致 → 拒绝。
func TestOpaqueLinkFlippedChar(t *testing.T) {
	link := opaqueV3Link()
	rest := strings.TrimPrefix(link, "mm://")
	mid := len(rest) / 2
	repl := byte('A')
	if rest[mid] == 'A' {
		repl = 'B'
	}
	bad := "mm://" + rest[:mid] + string(repl) + rest[mid+1:]
	if _, err := ParseLink(bad); err == nil {
		t.Fatalf("改了一个字符的链接应被拒绝（CRC）")
	} else if !strings.Contains(err.Error(), "损坏") {
		t.Fatalf("改字符的报错应提到损坏：%v", err)
	}
}

// 9. blob 版本改成 0x02 → 拒绝。
func TestOpaqueLinkBlobVersion(t *testing.T) {
	bad := opaqueMutate(t, opaqueV3Link(), func(blob []byte) { blob[4] = 0x02 })
	if _, err := ParseLink(bad); err == nil {
		t.Fatalf("blob 版本 0x02 应被拒绝")
	} else if !strings.Contains(err.Error(), "版本") {
		t.Fatalf("blob 版本不对的报错应提到版本：%v", err)
	}
}

// 10. 协议 ver 改成 4 → 接受（v4 是当前版本）；改成 5 → 拒绝
// （偏移 44 是本例的协议 ver 字节）。
func TestOpaqueLinkProtocolVersion(t *testing.T) {
	v4 := opaqueMutate(t, opaqueV3Link(), func(blob []byte) { blob[44] = 4 })
	got, err := ParseLink(v4)
	if err != nil {
		t.Fatalf("协议 ver=4 应被接受：%v", err)
	}
	if got.Version != VersionV4 {
		t.Fatalf("协议 ver=4 解析后版本是 %d，想要 %d", got.Version, VersionV4)
	}
	bad := opaqueMutate(t, opaqueV3Link(), func(blob []byte) { blob[44] = 5 })
	if _, err := ParseLink(bad); err == nil {
		t.Fatalf("协议 ver=5 应被拒绝")
	} else if !strings.Contains(err.Error(), "版本") {
		t.Fatalf("协议版本不对的报错应提到版本：%v", err)
	}
}

// 11. ver=3 + TLS 但 PIN 标志为 0 → 拒绝。
func TestOpaqueLinkV3TLSMissingPin(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, SNI: DefaultSNI,
	}
	link := BuildOpaqueLink(cfg)
	if _, err := ParseLink(link); err == nil {
		t.Fatalf("ver=3 TLS 缺 pin 应被拒绝")
	} else if !strings.Contains(err.Error(), "pin") {
		t.Fatalf("缺 pin 的报错应提到 pin：%v", err)
	}
}

// 12. tls-fake 但带 PIN → 拒绝。
func TestOpaqueLinkPlainWithPin(t *testing.T) {
	cfg := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV3, PIN: linkTestPIN,
	}
	link := BuildOpaqueLink(cfg)
	if _, err := ParseLink(link); err == nil {
		t.Fatalf("明文链接带 pin 应被拒绝")
	} else if !strings.Contains(err.Error(), "sni/pin") {
		t.Fatalf("明文带 pin 的报错应提到 sni/pin：%v", err)
	}
}

// 杂项：不是 base64url 字符、host 类型不对、obfs 标志不对 → 都拒绝。
func TestOpaqueLinkMalformed(t *testing.T) {
	if _, err := ParseLink("mm://abc!def"); err == nil {
		t.Fatalf("含非法字符的链接应被拒绝")
	}
	badHost := opaqueMutate(t, opaqueV3Link(), func(blob []byte) { blob[37] = 0x09 })
	if _, err := ParseLink(badHost); err == nil {
		t.Fatalf("host 类型不对的链接应被拒绝")
	} else if !strings.Contains(err.Error(), "服务器地址") {
		t.Fatalf("host 类型不对的报错应提到服务器地址：%v", err)
	}
	badObfs := opaqueMutate(t, opaqueV3Link(), func(blob []byte) { blob[45] = 0x09 })
	if _, err := ParseLink(badObfs); err == nil {
		t.Fatalf("obfs 标志不对的链接应被拒绝")
	} else if !strings.Contains(err.Error(), "混淆") {
		t.Fatalf("obfs 标志不对的报错应提到混淆：%v", err)
	}
}

// 会话池的键必须区分短链接里省掉的字段：
// 限速不同、混淆不同 = 不同会话；完全相同 = 同一个键。
func TestSessionKeyDiffers(t *testing.T) {
	base := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, PIN: linkTestPIN, Rate: 1000, Burst: 0,
	}
	same := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, PIN: linkTestPIN, Rate: 1000, Burst: 0,
	}
	diffRate := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, PIN: linkTestPIN, Rate: 2000, Burst: 0,
	}
	v2tls := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV2, PIN: linkTestPIN,
	}
	v2plain := &LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV2,
	}
	if sessionKey(base) != sessionKey(same) {
		t.Fatalf("相同配置的会话键应相同")
	}
	if sessionKey(base) == sessionKey(diffRate) {
		t.Fatalf("限速不同，会话键应不同（否则会串用限速）")
	}
	if sessionKey(v2tls) == sessionKey(v2plain) {
		t.Fatalf("v2 TLS 和 v2 明文的会话键应不同（否则会串用连接方式）")
	}
}
