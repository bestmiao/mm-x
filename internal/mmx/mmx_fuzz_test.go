package mmx

// mm-x 协议的 fuzz 测试（Go 原生 testing.F）。
//
// 覆盖三类解析入口，都是对端/用户能直接喂任意字节的地方：
//   - 链接解析：ParseLink、parseOpaqueLink（不透明 blob）
//   - 不透明链接往返：BuildOpaqueLink 生成的链接必须能解析回来，且再生成一次不变
//   - 帧解析：CONNECT 载荷、复用流头、ACK 载荷、握手载荷、TLS 记录头
//
// 断言一律是“解析器只应返回 error，绝不能 panic、死循环或越界”；
// 往返类再加字段级一致性。种子全部取自现有 go test 用例里的真实样本。
// 注意：这里只加测试，不改任何协议源码和链接格式。
//
// 跑法（每个目标单独跑）：
//   go test -fuzz=FuzzParseLink -fuzztime=20s ./internal/mmx/

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 链接解析
// ---------------------------------------------------------------------------

// 现有测试里的真实链接样本（经典短格式 / 不透明格式 / 明文格式）。
func fuzzLinkSeeds() (classicV3, classicPlain, classicFull, opaqueV3, opaqueV2, opaqueV6 string) {
	classicV3 = BuildLink(&LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, SNI: DefaultSNI, PIN: linkTestPIN,
		Rate: 6250 * 1024, Burst: 0, Name: "mm-x",
	})
	classicPlain = BuildLink(&LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV3,
	})
	classicFull = BuildLink(&LinkConfig{
		PSK: linkTestPSK, Host: "example.com", Port: 443,
		Obfs: "tls", Version: VersionV3, SNI: "example.com", PIN: linkTestPIN,
	})
	opaqueV3 = BuildOpaqueLink(&LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, SNI: DefaultSNI, PIN: linkTestPIN,
	})
	opaqueV2 = BuildOpaqueLink(&LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls-fake", Version: VersionV2,
	})
	opaqueV6 = BuildOpaqueLink(&LinkConfig{
		PSK: linkTestPSK, Host: "::1", Port: 37394,
		Obfs: "tls-fake", Version: VersionV2,
	})
	return
}

func FuzzParseLink(f *testing.F) {
	classicV3, classicPlain, classicFull, opaqueV3, opaqueV2, opaqueV6 := fuzzLinkSeeds()
	for _, seed := range []string{
		classicV3, classicPlain, classicFull,
		opaqueV3, opaqueV2, opaqueV6,
		// 畸形输入：空、前缀不对、字符集不对、截断、翻转
		"", "not a link", "mmx://", "mmx://!!!", "mm://",
		"mmx://" + opaqueV3[len("mmx://"):len(opaqueV3)-5],
		"mmx://" + opaqueV3[len("mmx://"):len(opaqueV3)-1] + "A",
		strings.Replace(classicV3, "mmx://", "mm://", 1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		cfg, err := ParseLink(s)
		if err != nil {
			// 非法输入只应返回 error，不应崩。
			return
		}
		if cfg == nil {
			t.Fatalf("ParseLink 成功却返回 nil 配置：%q", s)
		}
		if cfg.Host == "" || cfg.Port < 1 || cfg.Port > 65535 {
			t.Fatalf("ParseLink 成功却返回非法地址：%+v（输入 %q）", cfg, s)
		}
		if cfg.Version != VersionV2 && cfg.Version != VersionV3 &&
			cfg.Version != VersionV4 && cfg.Version != VersionV5 {
			t.Fatalf("ParseLink 成功却返回非法版本 %d：%+v", cfg.Version, cfg)
		}
	})
}

func FuzzParseOpaqueLink(f *testing.F) {
	_, _, _, opaqueV3, opaqueV2, opaqueV6 := fuzzLinkSeeds()
	opaqueCustomSNI := BuildOpaqueLink(&LinkConfig{
		PSK: linkTestPSK, Host: "203.0.113.5", Port: 37394,
		Obfs: "tls", Version: VersionV3, SNI: "example.com", PIN: linkTestPIN,
	})
	opaqueDomain := BuildOpaqueLink(&LinkConfig{
		PSK: linkTestPSK, Host: "example.com", Port: 443,
		Obfs: "tls-fake", Version: VersionV2,
	})
	rest := opaqueV3[len("mmx://"):]
	for _, seed := range []string{
		opaqueV3, opaqueV2, opaqueV6, opaqueCustomSNI, opaqueDomain,
		// 畸形输入：截断、翻转一个字符、改魔数、改 blob 版本、改 CRC
		"mmx://" + rest[:len(rest)-5],
		"mmx://" + rest[:10] + "A" + rest[11:],
		"mmx://" + rest[:len(rest)-4] + "AAAA",
		"mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"mmx://",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		cfg, err := parseOpaqueLink(s)
		if err != nil {
			return
		}
		if cfg == nil {
			t.Fatalf("parseOpaqueLink 成功却返回 nil 配置：%q", s)
		}
		if len(cfg.PSK) != 32 {
			t.Fatalf("parseOpaqueLink 成功却返回非法 PSK 长度 %d", len(cfg.PSK))
		}
		if cfg.Host == "" || cfg.Port < 1 || cfg.Port > 65535 {
			t.Fatalf("parseOpaqueLink 成功却返回非法地址：%+v", cfg)
		}
	})
}

// ---------------------------------------------------------------------------
// 不透明链接往返：任意输入字节 → 确定性合法配置 → 生成链接 → 解析回来必须一致
// ---------------------------------------------------------------------------

// fuzzOpaqueLayout（输入字节的确定性布局，缺字节时用默认值补）：
//   [0:32]  PSK（不足 32 字节用 linkTestPSK 补齐）
//   [32]    host 选择：0 IPv4 / 1 IPv6 ::1 / 2 IPv6 2001:db8::1 / 3 域名 / 4 随机域名
//   [33:35] 端口（大端，映射到 1..65535）
//   [35]    版本选择：0 v2 / 1 v3 / 2 v4 / 3 v5
//   [36]    混淆选择：0 默认 / 1 tls-fake / 2 tls
//   [37]    SNI 选择：0 空 / 1 默认 / 2 example.com / 3 随机域名（仅 tls 时有效）
//   [38:58] 随机域名/SNI 的字符来源（只取 [a-z0-9]）
func fuzzSafeDomain(b []byte) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	n := len(b)
	if n > 16 {
		n = 16
	}
	for i := 0; i < n; i++ {
		sb.WriteByte(letters[int(b[i])%len(letters)])
	}
	if sb.Len() == 0 {
		return "fuzz.example"
	}
	sb.WriteString(".example")
	return sb.String()
}

func fuzzOpaqueConfig(data []byte) *LinkConfig {
	byteAt := func(i int, def byte) byte {
		if i < len(data) {
			return data[i]
		}
		return def
	}
	psk := make([]byte, 32)
	copy(psk, linkTestPSK)
	copy(psk, data)
	// 随机域名/SNI 的字符来源：输入短于 38 字节时为空（fuzzSafeDomain 会用默认值）。
	charSource := func() []byte {
		if len(data) > 38 {
			return data[38:]
		}
		return nil
	}
	var host string
	switch byteAt(32, 0) % 5 {
	case 0:
		host = "203.0.113.5"
	case 1:
		host = "::1"
	case 2:
		host = "2001:db8::1"
	case 3:
		host = "example.com"
	case 4:
		host = fuzzSafeDomain(charSource())
	}
	port := 1 + int(binary.BigEndian.Uint16([]byte{byteAt(33, 0x92), byteAt(34, 0x12)}))%65535
	vers := []int{VersionV2, VersionV3, VersionV4, VersionV5}
	ver := vers[int(byteAt(35, 1))%4]
	obfss := []string{"", "tls-fake", "tls"}
	obfs := obfss[int(byteAt(36, 2))%3]
	eff := effectiveObfs(ver, obfs)
	// sni/pin 只在 tls 时有效；tls-fake 时强制留空，否则解析会拒收。
	var sni string
	var pin []byte
	if eff == "tls" {
		switch byteAt(37, 0) % 4 {
		case 0:
			sni = ""
		case 1:
			sni = DefaultSNI
		case 2:
			sni = "example.com"
		case 3:
			sni = fuzzSafeDomain(charSource())
		}
		if ver >= VersionV3 {
			pin = linkTestPIN
		}
	}
	return &LinkConfig{PSK: psk, Host: host, Port: port, Obfs: obfs, Version: ver, SNI: sni, PIN: pin}
}

// roundTripSeed 按 fuzzOpaqueConfig 的布局拼一份种子输入。
func roundTripSeed(hostChoice int, portHi, portLo byte, verSel, obfsSel, sniSel int) []byte {
	b := make([]byte, 58)
	copy(b, linkTestPSK)
	b[32] = byte(hostChoice)
	b[33] = portHi
	b[34] = portLo
	b[35] = byte(verSel)
	b[36] = byte(obfsSel)
	b[37] = byte(sniSel)
	copy(b[38:], []byte("abcdefghijklmnopqrst"))
	return b
}

func FuzzOpaqueLinkRoundTrip(f *testing.F) {
	f.Add([]byte{}) // 全默认：v3 + IPv4 + tls + pin
	f.Add(roundTripSeed(0, 0x92, 0x12, 1, 2, 0)) // v3 IPv4 tls
	f.Add(roundTripSeed(3, 0x01, 0xbb, 0, 1, 0)) // v2 域名 tls-fake
	f.Add(roundTripSeed(1, 0x92, 0x12, 2, 2, 2)) // v4 IPv6 ::1 tls + 自定义 SNI
	f.Add(roundTripSeed(2, 0x92, 0x12, 3, 2, 3)) // v5 IPv6 2001:db8::1 tls + 随机 SNI
	f.Add(roundTripSeed(4, 0x1f, 0x90, 1, 1, 0)) // v3 随机域名 tls-fake
	f.Add(roundTripSeed(0, 0x92, 0x12, 0, 2, 0)) // v2 IPv4 tls（v2 不强制 pin）
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := fuzzOpaqueConfig(data)
		link := BuildOpaqueLink(cfg)
		got, err := ParseLink(link)
		if err != nil {
			t.Fatalf("往返失败：生成的链接解析不回来：%v\ncfg=%+v\nlink=%s", err, cfg, link)
		}
		if BuildOpaqueLink(got) != link {
			t.Fatalf("往返后链接变了：\n生成：%s\n再生成：%s\ncfg=%+v", link, BuildOpaqueLink(got), cfg)
		}
		if !bytes.Equal(got.PSK, cfg.PSK) {
			t.Fatalf("往返后 PSK 变了")
		}
		if got.Host != cfg.Host || got.Port != cfg.Port {
			t.Fatalf("往返后地址变了：%s:%d，想要 %s:%d", got.Host, got.Port, cfg.Host, cfg.Port)
		}
		if got.Version != cfg.Version {
			t.Fatalf("往返后版本变了：%d，想要 %d", got.Version, cfg.Version)
		}
		if got.Obfs != effectiveObfs(cfg.Version, cfg.Obfs) {
			t.Fatalf("往返后混淆变了：%q，想要 %q", got.Obfs, effectiveObfs(cfg.Version, cfg.Obfs))
		}
		// SNI：链接里“默认或空”都省略（flag 0），解析回来是空串；
		// 所以只比“写进链接的 SNI”（空/DefaultSNI 都算省略），不比 ResolveSNI。
		// 注意（fuzz 发现的边界情况，见回报）：如果 SNI 被显式设成 DefaultSNI
		// 且 host 是域名，链接会省略它，解析后 ResolveSNI 会回落到 host 域名
		// 而不是 DefaultSNI——有效 SNI 在往返后会变。这是链接格式“省略默认值”
		// 与 ResolveSNI“空 SNI 时用 host 域名”两条规则叠加的结果，host 为 IP
		// 时不受影响（IP 不会成为 SNI，会回落到 DefaultSNI）。
		linkSNI := cfg.SNI
		if linkSNI == DefaultSNI {
			linkSNI = ""
		}
		if got.SNI != linkSNI {
			t.Fatalf("往返后 SNI 变了：%q，想要 %q", got.SNI, linkSNI)
		}
		if !bytes.Equal(got.PIN, cfg.PIN) {
			t.Fatalf("往返后 PIN 变了：%d 字节，想要 %d 字节", len(got.PIN), len(cfg.PIN))
		}
	})
}

// ---------------------------------------------------------------------------
// 帧解析
// ---------------------------------------------------------------------------

func FuzzDecodeConnectRequest(f *testing.F) {
	f.Add(EncodeConnectTargetWithRateAndBurst("example.com:443", 0, BurstUnset))
	f.Add(EncodeConnectTargetWithRateAndBurst("203.0.113.5:37394", 6250*1024, 5*1024*1024))
	f.Add(EncodeConnectTarget("10.0.0.1:80"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x05, 'a'})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		target, rate, burst, err := DecodeConnectRequest(data)
		if err != nil {
			return
		}
		// 成功解码的三元组再编码、再解码必须幂等（老格式缺字段时补默认值）。
		target2, rate2, burst2, err2 := DecodeConnectRequest(EncodeConnectTargetWithRateAndBurst(target, rate, burst))
		if err2 != nil {
			t.Fatalf("解码成功却无法再编码：%v（target=%q rate=%d burst=%d）", err2, target, rate, burst)
		}
		if target2 != target || rate2 != rate || burst2 != burst {
			t.Fatalf("CONNECT 载荷编解码不幂等：(%q,%d,%d) -> (%q,%d,%d)",
				target, rate, burst, target2, rate2, burst2)
		}
		// DecodeConnectTarget 只是 DecodeConnectRequest 的薄封装，结果必须一致。
		if target3, err3 := DecodeConnectTarget(data); err3 != nil || target3 != target {
			t.Fatalf("DecodeConnectTarget 与 DecodeConnectRequest 不一致：%q vs %q（err=%v）", target3, target, err3)
		}
	})
}

func FuzzDecodeStreamHeader(f *testing.F) {
	f.Add(EncodeStreamHeader(StreamKindTCP, "example.com:443", 0, BurstUnset))
	f.Add(EncodeStreamHeader(StreamKindUDP, "203.0.113.5:37394", 1000, 0))
	f.Add(EncodeStreamHeader(StreamKindTCP, "10.0.0.1:80", 6250*1024, 5*1024*1024))
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x09, 0x00, 0x05}) // 非法种类
	f.Add([]byte{0x01, 0xff, 0xff}) // 目标长度 65535，超上限
	f.Fuzz(func(t *testing.T, data []byte) {
		kind, target, _, _, err := DecodeStreamHeader(bytes.NewReader(data))
		if err != nil {
			return
		}
		if kind != StreamKindTCP && kind != StreamKindUDP {
			t.Fatalf("流头解码成功却返回非法种类 0x%02x", kind)
		}
		if target == "" {
			t.Fatalf("流头解码成功却返回空目标")
		}
	})
}

func FuzzParseAckError(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, '[', 'T', 'I', 'M', 'E', 'O', 'U', 'T', ']', ' ', 'x'})
	f.Add([]byte{0x01, 'p', 'l', 'a', 'i', 'n'})
	f.Add([]byte{0x02, 'x'})
	f.Add([]byte{0x01, '[', ']'})
	f.Fuzz(func(t *testing.T, data []byte) {
		code, msg := ParseAckError(data)
		// 成功（空或 0x00 开头）必须返回空码空消息；其余情况只要求不崩。
		if len(data) == 0 || data[0] == 0x00 {
			if code != "" || msg != "" {
				t.Fatalf("成功 ACK 应返回空码空消息，实际 (%q, %q)", code, msg)
			}
		}
		_ = code
		_ = msg
	})
}

func FuzzParseHandshakePayload(f *testing.F) {
	pub := bytes.Repeat([]byte{0x11}, 32)
	random := bytes.Repeat([]byte{0x22}, 16)
	f.Add(buildHandshakePayload(pub, random, linkTestPSK, "client", VersionV3, false, false))
	f.Add(buildHandshakePayload(pub, random, linkTestPSK, "client", VersionV4, false, false))
	f.Add(buildHandshakePayload(pub, random, linkTestPSK, "client", VersionV5, false, false))
	f.Add(buildHandshakePayload(pub, random, linkTestPSK, "client", VersionV3, true, false))  // 坏魔数
	f.Add(buildHandshakePayload(pub, random, linkTestPSK, "client", VersionV3, false, true))  // 坏版本
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, data []byte) {
		peerRandom := make([]byte, 16)
		gotPub, gotRandom, ver, err := parseHandshakePayload(data, linkTestPSK, "client", peerRandom)
		if err != nil {
			return
		}
		if len(gotPub) != 32 {
			t.Fatalf("握手解析成功却返回非法公钥长度 %d", len(gotPub))
		}
		if len(gotRandom) != 16 {
			t.Fatalf("握手解析成功却返回非法随机数长度 %d", len(gotRandom))
		}
		if ver != VersionV2 && ver != VersionV3 && ver != VersionV4 && ver != VersionV5 {
			t.Fatalf("握手解析成功却返回非法版本 %d", ver)
		}
		if !bytes.Equal(peerRandom, gotRandom) {
			t.Fatalf("peerRandomOut 应等于返回的 random")
		}
	})
}

func FuzzReadTLSRecord(f *testing.F) {
	var buf bytes.Buffer
	if err := writeTLSRecord(&buf, fakeRecordType, []byte("hello mm-x")); err != nil {
		f.Fatalf("种子构造失败：%v", err)
	}
	f.Add(buf.Bytes())
	var buf2 bytes.Buffer
	if err := writeTLSRecordVersion(&buf2, fakeRecordType, []byte("v4 record"), fakeTLSMinorV4); err != nil {
		f.Fatalf("种子构造失败：%v", err)
	}
	f.Add(buf2.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0x17, 0x03, 0x01})
	f.Add([]byte{0x17, 0x03, 0x01, 0x00, 0x05, 'h', 'i'})
	f.Add([]byte{0x17, 0x03, 0x01, 0xff, 0xff}) // 长度 65535，超上限
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00}) // 类型不对
	f.Fuzz(func(t *testing.T, data []byte) {
		body, err := readTLSRecord(bytes.NewReader(data), fakeRecordType)
		if err != nil {
			return
		}
		if len(body) > maxRecordLen {
			t.Fatalf("读出的记录体超过上限：%d > %d", len(body), maxRecordLen)
		}
	})
}
