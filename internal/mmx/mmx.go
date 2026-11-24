// Package mmx 实现 mm-x 协议原型：自定义握手 + X25519 密钥协商 +
// AES-256-GCM 帧加密 + TLS 形伪装 + mmx:// 链接格式。
// 仅供试验，不可直接用于生产。
package mmx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
)

const (
	// v2/v3/v4 握手：线上没有任何固定不变的字节。
	// 每条连接的握手载荷以 8 字节随机盐开头，魔数是随盐变化的
	// magic = HMAC-SHA256(psk, "MM-1 magic vN" || 盐）的前 3 字节
	// （N 是协议版本，v2、v3、v4 各用自己的标签，所以魔数本身就区分版本）；
	// 版本字节也用魔数的首字节异或过，线上看不到明文版本号。
	// 不知道密钥的人既认不出也伪造不了；同一密钥下每次握手的
	// 前几个字节也全都不一样，防火墙无法用一条固定特征批量识别。
	// v1（固定魔数 HMAC(psk,"MM-1 magic v1")[:3]、明文版本字节、
	// 填充 0–63）已经作废。
	// v3（上一版本）：握手之后是 yamux 复用会话（见 mux.go），
	// 一条 TCP 连接上开多条逻辑流 + UDP-over-TCP；服务端同时接受
	// v2 和 v3 握手（版本由魔数标签区分），老 v2 节点不用换链接。
	// v4（当前版本）：v3 的复用 + 三点加固——握手包加长到 400–600 字节
	//（填充长度字段从 1 字节改 2 字节）、会话重协商（定期换会话密钥，
	// 不断流）、TLS 记录版本号改 0x03 0x03（TLS 1.2，真流量就这样）。
	// 服务端同时接受 v2、v3 和 v4 握手，老 v2/v3 链接不用换。
	Version   = 4
	VersionV2 = 2
	VersionV3 = 3
	VersionV4 = 4
	saltLen   = 8
	magicLen  = 3

	// 帧类型
	FrameConnect = 0x01 // payload: 2 字节长度 + "host:port"
	FrameData    = 0x02
	FrameClose   = 0x03
	FrameAck     = 0x04 // payload: 0x00 成功 / 0x01 失败 + 错误文本
	FrameRekey   = 0x05 // payload: 32 字节重协商种子（v4：定期换会话密钥）
)

// IsMuxVersion 是不是复用版本（v3/v4）：握手之后跑 yamux 会话。
// v2 是单连接转发，不走复用。
func IsMuxVersion(v int) bool { return v >= VersionV3 }

const (
	// 伪装：数据帧看起来像 TLS 1.2 Application Data 记录
	fakeRecordType = 0x17
	fakeTLSMajor   = 0x03
	// fakeTLSMinor 是 v2/v3 的 TLS 记录次版本号（0x01 = TLS 1.0）；
	// v4 起用 fakeTLSMinorV4（0x03 = TLS 1.2，真流量现在多是这个）。
	// 接收方两个都认（readTLSRecord），老客户端照常连。
	fakeTLSMinor      = 0x01
	fakeTLSMinorV4    = 0x03
	fakeHandshakeType = 0x16 // 握手包看起来像 TLS Handshake 记录

	// 单条 TLS 记录最大长度（真实 TLS 1.2 记录上限 16384 字节）：
	// 帧分片后每条记录都不超过这个值，包长分布才像正常 HTTPS。
	// 记录体 = nonce(12) + 明文(6 + 填充 + 载荷） + 认证标签(16)，
	// 所以 DATA 帧载荷上限取 16000，留足余量。
	maxRecordLen    = 16384
	maxFramePayload = 16000
)

// ---------------------------------------------------------------------------
// HKDF-SHA256（标准库 x/crypto/hkdf；以前是手写版，输出和 RFC 5869
// 向量一致，换标准库只是去掉“没人审计的手写密码学”，行为不变）
// ---------------------------------------------------------------------------

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), out); err != nil {
		panic(err)
	}
	return out
}

func authTag(psk, label, a, b []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(label)
	mac.Write(a)
	mac.Write(b)
	return mac.Sum(nil)[:16]
}

// ---------------------------------------------------------------------------
// mmx:// 链接
// ---------------------------------------------------------------------------

// LinkConfig 是 mmx:// 链接解析出的配置。
type LinkConfig struct {
	PSK     []byte // 32 字节预共享密钥（握手鉴权用）
	Host    string
	Port    int
	Enc     string // 加密方式，原型只支持 aes-256-gcm
	Obfs    string // 混淆方式：tls-fake（明文，浅层 TLS 外壳）或 tls（真 TLS 包装）
	Version int
	Name    string
	Rate    int64  // 限速：每秒字节数，0 = 不限速（链接里的要求，最终以服务端为准）
	Burst   int64  // 突发额度：字节数，-1 = 未指定（默认 5MB），0 = 不许突发（严格按平均限速）
	SNI     string // TLS 模式的 SNI（obfs=tls 时用；不填时客户端用默认常见域名）
	PIN     []byte // TLS 证书 SPKI 指纹（SHA-256，32 字节；obfs=tls + 自签证书时锁定验证用）
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// effectiveObfs 链接缺 obfs 参数时的默认值：ver=3/4 默认真 TLS，
// ver=2 / 没写版本默认明文（tls-fake）。obfs 非空时按写的来。
// ParseLink、BuildLink、会话池键都用这一个规则，别各写一份。
func effectiveObfs(version int, obfs string) string {
	if obfs != "" {
		return obfs
	}
	if version >= VersionV3 {
		return "tls"
	}
	return "tls-fake"
}

// 不透明链接（乱码式）的 blob 常量（见 PROTOCOL.md“mmx:// 不透明链接格式”一节）。
const (
	opaqueMagic       = "MMX1" // blob 魔数（4 字节）
	opaqueBlobVersion = 0x01   // blob 格式版本（和协议 ver 2/3 是两回事）
	opaqueMinLen      = 52     // 最短 blob：v2 + IPv4 + 无 PIN
)

const (
	opaqueHostIPv4   = 0x01
	opaqueHostIPv6   = 0x02
	opaqueHostDomain = 0x03
)

const (
	opaqueObfsDefault = 0x00 // 按版本默认
	opaqueObfsFake    = 0x01 // tls-fake
	opaqueObfsTLS     = 0x02 // tls
)

// ParseLink 解析 mmx:// 链接，非法链接返回中文报错。
// 旧的 mm:// 链接也照常解析（向后兼容）；新链接一律用 mmx://。
// 完整格式：mmx://<base64url密钥或UUID>@<服务器>:<端口>?enc=aes-256-gcm&obfs=tls&ver=3&rate=6250K&burst=0&sni=www.microsoft.com&pin=<SPKI指纹>#<节点名>
// 短格式（BuildLink 默认生成）：mmx://<密钥>@<服务器>:<端口>?ver=3&pin=<SPKI指纹>
// 不透明格式（BuildOpaqueLink 生成）：mmx://<一串 base64url 字符>，
// 里面是二进制 blob（magic MMX1 + 版本 + PSK + 地址 + 端口 + 版本 +
// 标志位 + 可选 SNI/PIN + CRC32），外人看不出服务器地址和密钥。
// 分流靠结构：前缀后含 @ 的走老格式，不含 @ 且全是 base64url 字符的
// 走不透明格式。
// 可省略的参数与默认值：enc 不写 = aes-256-gcm；obfs 不写时按版本默认，
// ver=3 默认 tls，ver=2 / 没写默认 tls-fake；rate 不写 = 不限速
// （最终以服务端为准）；burst 不写 = 默认 5MB；sni 不写 =
// www.microsoft.com（拨号时 ResolveSNI 决定）；#名字不写 = mm-x。
// 完整格式照常解析（向后兼容）。ver=3/4 + obfs=tls 的链接必须带 pin
// （证书指纹锁定不可跳过），缺 pin 直接报错。
// stripLinkScheme 去掉链接前缀，返回前缀后的部分；
// 新前缀 mmx:// 和旧前缀 mm:// 都接受（旧链接向后兼容）。
func stripLinkScheme(s string) (string, bool) {
	if strings.HasPrefix(s, "mmx://") {
		return strings.TrimPrefix(s, "mmx://"), true
	}
	if strings.HasPrefix(s, "mm://") {
		return strings.TrimPrefix(s, "mm://"), true
	}
	return "", false
}

func ParseLink(s string) (*LinkConfig, error) {
	// 新旧两种前缀都接受：新链接是 mmx://，老的 mm:// 链接继续能用。
	rest, ok := stripLinkScheme(s)
	if !ok {
		return nil, errors.New("链接前缀不是 mmx://，应以 mmx:// 开头")
	}
	// 结构分流：含 @ 的是老格式（密钥@地址），不含 @ 的是
	// 不透明格式（一串 base64url 字符）。
	if !strings.Contains(rest, "@") {
		return parseOpaqueLink(s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败：%v", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("链接缺少密钥：mmx:// 后应为 <密钥>@<服务器>:<端口>")
	}
	if _, hasPass := u.User.Password(); hasPass {
		return nil, errors.New("链接格式错误：密钥后面不应带密码")
	}
	keyPart := u.User.Username()

	// 不写 ver 的老链接按 v2 处理（v2 客户端从来不用链接里的版本号，
	// 行为就是 v2；新链接服务端都会写 ver=3）。
	// Obfs 先不填：默认值由版本决定（ver=3 默认 tls，ver=2 默认 tls-fake），
	// 在下面解析完 ver 之后再补。
	cfg := &LinkConfig{Enc: "aes-256-gcm", Version: VersionV2, Burst: BurstUnset}
	// 密钥：UUID 或 base64url 编码的 32 字节密钥
	if uuidRe.MatchString(keyPart) {
		sum := sha256.Sum256([]byte(strings.ToLower(keyPart)))
		cfg.PSK = sum[:]
	} else {
		key, err := base64.RawURLEncoding.DecodeString(keyPart)
		if err != nil {
			return nil, fmt.Errorf("链接密钥不是合法的 base64url 编码：%v", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("链接密钥长度不对：应为 32 字节，实际 %d 字节", len(key))
		}
		cfg.PSK = key
	}

	cfg.Host = u.Hostname()
	if cfg.Host == "" {
		return nil, errors.New("链接缺少服务器地址：@ 后应为 <服务器>:<端口>")
	}
	portStr := u.Port()
	if portStr == "" {
		return nil, errors.New("链接缺少端口：服务器地址后应带 :端口")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("端口不合法：%q 应为 1-65535 之间的数字", portStr)
	}
	cfg.Port = port

	q := u.Query()
	// ver 先解析：obfs 的默认值由版本决定。
	if v := q.Get("ver"); v != "" {
		ver, err := strconv.Atoi(v)
		if err != nil || (ver != VersionV2 && ver != VersionV3 && ver != VersionV4) {
			return nil, fmt.Errorf("版本号不受支持：%q，原型只支持 ver=%d、ver=%d 或 ver=%d", v, VersionV2, VersionV3, VersionV4)
		}
		cfg.Version = ver
	}
	if v := q.Get("enc"); v != "" {
		if v != "aes-256-gcm" {
			return nil, fmt.Errorf("不支持的加密方式：%q，原型只支持 aes-256-gcm", v)
		}
		cfg.Enc = v
	}
	if v := q.Get("obfs"); v != "" {
		if v != "tls-fake" && v != "tls" {
			return nil, fmt.Errorf("不支持的混淆方式：%q，原型只支持 tls-fake（浅层 TLS 外壳）或 tls（真 TLS 包装，需域名 + 真证书）", v)
		}
		cfg.Obfs = v
	} else {
		cfg.Obfs = effectiveObfs(cfg.Version, "")
	}
	if v := q.Get("sni"); v != "" {
		if strings.ContainsAny(v, " /:") || len(v) > 253 {
			return nil, fmt.Errorf("SNI 不合法：%q，应为域名（不带端口和斜杠）", v)
		}
		cfg.SNI = v
	}
	if v := q.Get("pin"); v != "" {
		pin, err := ParsePIN(v)
		if err != nil {
			return nil, fmt.Errorf("证书指纹 pin 不合法：%v", err)
		}
		cfg.PIN = pin
	}
	// sni/pin 只在 TLS 模式下有意义：明文模式带它们是写错了链接，直接报错
	// （不要静默忽略——静默忽略会让用户以为锁定生效了，实际没锁）。
	if cfg.Obfs != "tls" && (cfg.SNI != "" || len(cfg.PIN) > 0) {
		return nil, errors.New("sni/pin 只在 obfs=tls 时有效，明文模式（tls-fake）请去掉这两个参数")
	}
	// ver=3/4 + TLS 必须带 pin：自签证书没有系统根证书可验，pin 是唯一的
	// 锁定手段，缺了等于不校验——直接拒绝，不留“先连上再说”的口子。
	if cfg.Version >= VersionV3 && cfg.Obfs == "tls" && len(cfg.PIN) != 32 {
		return nil, errors.New("ver=3/4 的 TLS 链接必须带 pin 参数（证书指纹锁定不可跳过）")
	}
	if v := q.Get("rate"); v != "" {
		rate, err := ParseRate(v)
		if err != nil {
			return nil, fmt.Errorf("限速参数不合法：%v", err)
		}
		cfg.Rate = rate
	}
	if v := q.Get("burst"); v != "" {
		burst, err := ParseRate(v)
		if err != nil {
			return nil, fmt.Errorf("突发参数不合法：%v", err)
		}
		cfg.Burst = burst
	}
	cfg.Name = u.Fragment // url.Parse 已做解码
	if cfg.Name == "" {
		cfg.Name = "mm-x"
	}
	return cfg, nil
}

// BuildLink 生成 mmx:// 链接（短格式，只写非默认参数）。
// 短格式：mmx://<密钥>@<服务器>:<端口>?ver=4&pin=<SPKI指纹>
// 省掉的都是默认值：enc=aes-256-gcm 不写；obfs 按版本默认（ver=3/4 是 tls，
// ver=2 是 tls-fake），只有和版本默认不一致时才写出来（例如明文 v4
// 要写 obfs=tls-fake）；sni 只有非默认域名时才写（默认 www.microsoft.com
// 不写）；rate/burst 不写进链接（限速由服务端强制，客户端不需要）；
// #名字不写（只是显示名，解析时缺了默认 mm-x）。
// 完整格式的链接照常能解析（ParseLink 向后兼容），所以老链接不用换。
// 注意：BuildLink 同时被会话池当键用——短链接省掉的 rate/burst/obfs
// 由 mux.go 的 sessionKey 另外拼上，会话池不会因此串会话。
func BuildLink(cfg *LinkConfig) string {
	key := base64.RawURLEncoding.EncodeToString(cfg.PSK)
	ver := cfg.Version
	if ver == 0 {
		ver = Version
	}
	obfs := effectiveObfs(ver, cfg.Obfs)
	link := fmt.Sprintf("mmx://%s@%s:%d?ver=%d", key, cfg.Host, cfg.Port, ver)
	// obfs 只有和版本默认不一致时才写出来
	if obfs != effectiveObfs(ver, "") {
		link += "&obfs=" + obfs
	}
	if obfs == "tls" {
		if cfg.SNI != "" && cfg.SNI != DefaultSNI {
			link += "&sni=" + url.QueryEscape(cfg.SNI)
		}
		if len(cfg.PIN) == 32 {
			link += "&pin=" + base64.RawURLEncoding.EncodeToString(cfg.PIN)
		}
	}
	return link
}

// parseOpaqueLink 解析 mmx:// 不透明链接（乱码式）。
// 布局（见 PROTOCOL.md“mmx:// 不透明链接格式”一节）：
// magic MMX1(4) + blob 版本 0x01(1) + PSK(32) + host 类型(1) +
// host（IPv4 4 / IPv6 16 / 域名 1 字节长度 + UTF-8）+ port 大端(2) +
// 协议 ver(1) + obfs 标志(1) + SNI 标志(1) + 可选 SNI +
// PIN 标志(1) + 可选 PIN(32) + CRC32(4)。
// 每一步都做边界检查，绝不 panic、不越界；报错全是中文。
func parseOpaqueLink(s string) (*LinkConfig, error) {
	rest, ok := stripLinkScheme(s)
	if !ok {
		return nil, errors.New("链接前缀不是 mmx://，应以 mmx:// 开头")
	}
	for _, c := range rest {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("不是合法的不透明链接：只应含 base64url 字符")
		}
	}
	blob, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("不是合法的不透明链接：%v", err)
	}
	if len(blob) < opaqueMinLen {
		return nil, errors.New("链接太短，已损坏或不完整")
	}
	if string(blob[:4]) != opaqueMagic {
		return nil, errors.New("魔数不对，不是 mm-x 不透明链接")
	}
	if blob[4] != opaqueBlobVersion {
		return nil, fmt.Errorf("链接格式版本不受支持：0x%02x，当前只支持 0x01", blob[4])
	}
	// CRC32 在最后 4 字节（大端），先验再解析字段。
	body := blob[:len(blob)-4]
	if crc32.ChecksumIEEE(body) != binary.BigEndian.Uint32(blob[len(blob)-4:]) {
		return nil, errors.New("链接已损坏或不完整")
	}

	// 逐字段解析：读 n 字节，越界就报错。
	off := 5
	read := func(n int) ([]byte, error) {
		if n < 0 || off+n > len(body) {
			return nil, errors.New("链接已损坏或不完整")
		}
		b := body[off : off+n]
		off += n
		return b, nil
	}
	psk, err := read(32)
	if err != nil {
		return nil, err
	}
	hostType, err := read(1)
	if err != nil {
		return nil, err
	}
	var host string
	switch hostType[0] {
	case opaqueHostIPv4:
		b, err := read(4)
		if err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case opaqueHostIPv6:
		b, err := read(16)
		if err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case opaqueHostDomain:
		lb, err := read(1)
		if err != nil {
			return nil, err
		}
		if lb[0] == 0 || lb[0] > 253 {
			return nil, errors.New("服务器地址不合法")
		}
		b, err := read(int(lb[0]))
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, errors.New("服务器地址不合法")
		}
		host = string(b)
	default:
		return nil, errors.New("服务器地址不合法")
	}
	portB, err := read(2)
	if err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portB))
	if port < 1 || port > 65535 {
		return nil, errors.New("端口不合法：应为 1-65535 之间的数字")
	}
	verB, err := read(1)
	if err != nil {
		return nil, err
	}
	ver := int(verB[0])
	if ver != VersionV2 && ver != VersionV3 && ver != VersionV4 {
		return nil, fmt.Errorf("版本号不受支持：%d，原型只支持 ver=%d、ver=%d 或 ver=%d", ver, VersionV2, VersionV3, VersionV4)
	}
	obfsB, err := read(1)
	if err != nil {
		return nil, err
	}
	var obfs string
	switch obfsB[0] {
	case opaqueObfsDefault:
		obfs = effectiveObfs(ver, "")
	case opaqueObfsFake:
		obfs = "tls-fake"
	case opaqueObfsTLS:
		obfs = "tls"
	default:
		return nil, errors.New("混淆方式不受支持")
	}
	sniB, err := read(1)
	if err != nil {
		return nil, err
	}
	var sni string
	switch sniB[0] {
	case 0:
		// 默认 SNI（拨号时 ResolveSNI 决定），这里留空。
	case 1:
		lb, err := read(1)
		if err != nil {
			return nil, err
		}
		if lb[0] == 0 || lb[0] > 253 {
			return nil, errors.New("SNI 不合法")
		}
		b, err := read(int(lb[0]))
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) || strings.ContainsAny(string(b), " /:") {
			return nil, errors.New("SNI 不合法：应为域名（不带端口和斜杠）")
		}
		sni = string(b)
	default:
		return nil, errors.New("SNI 不合法")
	}
	pinB, err := read(1)
	if err != nil {
		return nil, err
	}
	var pin []byte
	switch pinB[0] {
	case 0:
	case 1:
		b, err := read(32)
		if err != nil {
			return nil, err
		}
		pin = append([]byte(nil), b...)
	default:
		return nil, errors.New("证书指纹不合法")
	}
	// 字段读完必须正好到 CRC 前面，多一个字节都是损坏。
	if off != len(body) {
		return nil, errors.New("链接已损坏或不完整")
	}

	// 和老格式一致的校验：sni/pin 只在 TLS 模式下有效；
	// ver=3/4 + TLS 必须带 pin（指纹锁定不可跳过）。
	if obfs != "tls" && (sni != "" || len(pin) > 0) {
		return nil, errors.New("sni/pin 只在 obfs=tls 时有效，明文模式（tls-fake）请去掉这两个参数")
	}
	if ver >= VersionV3 && obfs == "tls" && len(pin) != 32 {
		return nil, errors.New("ver=3/4 的 TLS 链接必须带 pin 参数（证书指纹锁定不可跳过）")
	}
	return &LinkConfig{
		PSK: psk, Host: host, Port: port,
		Enc: "aes-256-gcm", Obfs: obfs, Version: ver,
		SNI: sni, PIN: pin, Name: "mm-x", Burst: BurstUnset,
	}, nil
}

// BuildOpaqueLink 生成 mmx:// 不透明链接（乱码式）：
// 同一份配置拼成二进制 blob（magic MMX1 + 版本 + PSK + 地址 + 端口 +
// 版本 + 标志位 + 可选 SNI/PIN + CRC32），再 base64url（不带填充）编码，
// 前面拼 mmx://。除前缀外没有任何可读信息；真实部署约 118 字符，
// 比短格式还短。默认值一律省略，和短格式的规则一致：
// obfs 和版本默认一致写标志 0；SNI 默认或空写标志 0；无 PIN 写标志 0；
// enc、rate/burst、节点名不进 blob。
// 注意：会话池的键用的是 BuildLink（经典短格式），不透明链接解析出的
// LinkConfig 拼出的键和经典链接完全一致，不会因此多建会话。
func BuildOpaqueLink(cfg *LinkConfig) string {
	ver := cfg.Version
	if ver == 0 {
		ver = Version
	}
	obfs := effectiveObfs(ver, cfg.Obfs)
	var blob []byte
	blob = append(blob, []byte(opaqueMagic)...)
	blob = append(blob, opaqueBlobVersion)
	blob = append(blob, cfg.PSK...)
	// host：IP 按字节写，域名按 1 字节长度 + UTF-8 写。
	if ip := net.ParseIP(cfg.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			blob = append(blob, opaqueHostIPv4)
			blob = append(blob, v4...)
		} else {
			blob = append(blob, opaqueHostIPv6)
			blob = append(blob, ip.To16()...)
		}
	} else {
		blob = append(blob, opaqueHostDomain)
		blob = append(blob, byte(len(cfg.Host)))
		blob = append(blob, []byte(cfg.Host)...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(cfg.Port))
	blob = append(blob, portBuf[:]...)
	blob = append(blob, byte(ver))
	// obfs 标志：和版本默认一致写 0，否则写 1/2。
	switch {
	case obfs == effectiveObfs(ver, ""):
		blob = append(blob, opaqueObfsDefault)
	case obfs == "tls-fake":
		blob = append(blob, opaqueObfsFake)
	default: // tls
		blob = append(blob, opaqueObfsTLS)
	}
	// SNI 标志：默认域名或空写 0，否则写 1 + 长度 + 字节。
	if cfg.SNI == "" || cfg.SNI == DefaultSNI {
		blob = append(blob, 0)
	} else {
		blob = append(blob, 1, byte(len(cfg.SNI)))
		blob = append(blob, []byte(cfg.SNI)...)
	}
	// PIN 标志：无写 0，有写 1 + 32 字节。
	if len(cfg.PIN) == 32 {
		blob = append(blob, 1)
		blob = append(blob, cfg.PIN...)
	} else {
		blob = append(blob, 0)
	}
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(blob))
	blob = append(blob, crcBuf[:]...)
	return "mmx://" + base64.RawURLEncoding.EncodeToString(blob)
}

// RandomPSK 生成一个随机的 32 字节预共享密钥。
func RandomPSK() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

// magicLabel 是各版本的魔数标签：标签本身带版本号，所以魔数
// 就能区分 v2 和 v3 握手（服务端先验魔数就知道对方是哪个版本）。
func magicLabel(version int) string {
	return fmt.Sprintf("MM-1 magic v%d", version)
}

// magicBytes 计算与密钥、盐和版本绑定的动态魔数（3 字节）：
// magic = HMAC-SHA256(psk, "MM-1 magic vN" || salt) 的前 3 字节。
// 盐每次连接随机，同一密钥下每次握手的魔数也全都不一样。
func magicBytes(psk, salt []byte, version int) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(magicLabel(version)))
	mac.Write(salt)
	return mac.Sum(nil)[:magicLen]
}

// LooksLikeMMXHandshake 判断一段 TLS 记录载荷是不是 mm-x 握手
// （v2、v3 或 v4，任一密钥）：只验魔数，不碰版本字节和鉴权标签。
// 服务端双模式分流用：先验魔数（明文 mm-x），验不过再看是不是
// 真实 TLS ClientHello。返回协商到的版本号，0 = 不是 mm-x 握手。
// 魔数比较用恒定时间（A5）：时序不能泄露魔数前几个字节对不对。
func LooksLikeMMXHandshake(payload []byte, keys [][]byte) int {
	if len(payload) < saltLen+4 {
		return 0
	}
	salt := payload[:saltLen]
	want := payload[saltLen : saltLen+3]
	for _, psk := range keys {
		for _, ver := range []int{VersionV4, VersionV3, VersionV2} {
			if subtle.ConstantTimeCompare(magicBytes(psk, salt, ver), want) == 1 {
				return ver
			}
		}
	}
	return 0
}

// LooksLikeClientHello 判断一段 TLS 记录载荷是不是真实 TLS ClientHello：
// 握手类型 0x01（ClientHello）+ 客户端版本 TLS 1.0/1.1/1.2（0x03 0x01–0x03）。
// mm-x 伪装握手的载荷首字节是随机盐，同时满足这两条的概率约 1/1600 万，
// 万一撞上那次连接会走 TLS 分支然后握手失败、客户端重连即可（见 PROTOCOL.md）。
func LooksLikeClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == 0x01 &&
		payload[4] == 0x03 && payload[5] >= 0x01 && payload[5] <= 0x03
}

// handshakePayload 组装/解析握手载荷（v2/v3/v4 共用，区别只在魔数标签和版本字节）：
// 盐(8) | 动态魔数(3) | 版本异或魔数首字节(1) | 公钥(32) | 随机数(16) |
// 鉴权标签(16) | 填充长度 | 随机填充
// 填充长度字段：v2/v3 是 1 字节（填充 0–255，总包长 77–332）；
// v4 是 2 字节（填充 322–522，总包长 400–600，像真实 ClientHello）。
// 填充长度按本次会话的画像抽样（PSK + 盐，见 A2）：同一部署每次会话
// 的画像都可能不同；抽样失败时退回均匀随机，握手绝不因此失败。
func buildHandshakePayload(pub, random, psk []byte, label string, version int, badMagic, badVersion bool) []byte {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	magic := magicBytes(psk, salt, version)
	if badMagic {
		magic[0] ^= 0xFF
	}
	ver := byte(version) ^ magic[0]
	if badVersion {
		ver = 0x09 ^ magic[0] // 发一个不受支持的版本号 9（当前只支持 2、3 和 4）
	}
	// 握手填充按会话画像抽样（分布因部署、因会话而异）。
	profile := DeriveSessionProfile(psk, salt)
	var padLen int
	var padLenField []byte
	if version >= VersionV4 {
		if n, err := profile.SampleHandshakePadLenV4(); err == nil {
			padLen = n
		} else {
			tmp := make([]byte, 2)
			if _, err := rand.Read(tmp); err != nil {
				panic(err)
			}
			padLen = v4HandshakePadMin + int(binary.BigEndian.Uint16(tmp))%(v4HandshakePadMax-v4HandshakePadMin+1)
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(padLen))
		padLenField = b[:]
	} else {
		if n, err := profile.SampleHandshakePadLen(); err == nil {
			padLen = n
		} else {
			tmp := make([]byte, 1)
			if _, err := rand.Read(tmp); err != nil {
				panic(err)
			}
			padLen = int(tmp[0])
		}
		padLenField = []byte{byte(padLen)}
	}
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		panic(err)
	}
	tag := authTag(psk, []byte(label), pub, random)
	out := make([]byte, 0, saltLen+3+1+32+16+16+len(padLenField)+padLen)
	out = append(out, salt...)
	out = append(out, magic...)
	out = append(out, ver)
	out = append(out, pub...)
	out = append(out, random...)
	out = append(out, tag...)
	out = append(out, padLenField...)
	out = append(out, padding...)
	return out
}

// parseHandshakePayloadVersion 解析握手载荷：先按 v4 再按 v3、v2 验魔数，
// 魔数对上哪个版本就按哪个版本继续验（版本字节、鉴权标签）。
// v4 的填充长度字段是 2 字节（v2/v3 是 1 字节），v4 还要验总长度
// 和填充长度一致（截断/多余字节都拒绝）；v2/v3 保持原来的宽松解析，
// 老客户端不受影响。魔数比较用恒定时间（A5）。
// 返回对端公钥、随机数和协商到的版本号。
func parseHandshakePayload(p []byte, psk []byte, label string, peerRandomOut []byte) (pub []byte, random []byte, version int, err error) {
	if len(p) < saltLen+3+1+32+16+16+1 {
		return nil, nil, 0, errors.New("握手包太短")
	}
	salt := p[:saltLen]
	gotMagic := p[saltLen : saltLen+3]
	var magic []byte
	version = 0
	for _, ver := range []int{VersionV4, VersionV3, VersionV2} {
		if subtle.ConstantTimeCompare(magicBytes(psk, salt, ver), gotMagic) == 1 {
			magic = magicBytes(psk, salt, ver)
			version = ver
			break
		}
	}
	if version == 0 {
		return nil, nil, 0, errors.New("魔数不对：不是 mm-x 协议")
	}
	if p[saltLen+3]^magic[0] != byte(version) {
		return nil, nil, version, fmt.Errorf("版本号不受支持：对方版本 %d，本端只支持 %d、%d 和 %d", p[saltLen+3]^magic[0], VersionV2, VersionV3, VersionV4)
	}
	if version >= VersionV4 {
		// v4：填充长度字段 2 字节，总长必须正好等于 78 + 填充长度。
		if len(p) < saltLen+3+1+32+16+16+2 {
			return nil, nil, 0, errors.New("握手包太短")
		}
		padLen := int(binary.BigEndian.Uint16(p[saltLen+3+1+32+16+16:]))
		if len(p) != saltLen+3+1+32+16+16+2+padLen {
			return nil, nil, 0, errors.New("握手包长度不对")
		}
	}
	pub = p[saltLen+4 : saltLen+36]
	random = p[saltLen+36 : saltLen+52]
	tag := p[saltLen+52 : saltLen+68]
	want := authTag(psk, []byte(label), pub, random)
	if !hmac.Equal(tag, want) {
		return nil, nil, version, errors.New("密钥不对：握手鉴权失败（请检查 mmx:// 链接里的密钥）")
	}
	copy(peerRandomOut, random)
	return pub, random, version, nil
}

// recordMinorForVersion：v4 的 TLS 记录次版本号用 0x03（TLS 1.2，
// 真流量现在多是这个）；v2/v3 保持 0x01，老客户端、老服务端照常。
func recordMinorForVersion(version int) byte {
	if version >= VersionV4 {
		return fakeTLSMinorV4
	}
	return fakeTLSMinor
}

func writeTLSRecord(w io.Writer, recType byte, payload []byte) error {
	return writeTLSRecordVersion(w, recType, payload, fakeTLSMinor)
}

// writeTLSRecordVersion 写一条 TLS 形记录，次版本号由调用方指定
// （v4 用 0x03，v2/v3 用 0x01）。
func writeTLSRecordVersion(w io.Writer, recType byte, payload []byte, minor byte) error {
	hdr := []byte{recType, fakeTLSMajor, minor,
		byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readTLSRecord(r io.Reader, wantType byte) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("读取记录头失败：%w", err)
	}
	// 次版本号认 0x01（v2/v3）和 0x03（v4）两种：老客户端发 0x01、
	// 新客户端发 0x03，服务端两个都接；类型和主版本号仍严格校验。
	if hdr[0] != wantType || hdr[1] != fakeTLSMajor || (hdr[2] != fakeTLSMinor && hdr[2] != fakeTLSMinorV4) {
		return nil, fmt.Errorf("记录头不是预期的 TLS 形伪装（type=0x%02x）", hdr[0])
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n <= 0 || n > maxRecordLen {
		return nil, fmt.Errorf("记录长度不合法：%d（超过 TLS 记录上限 %d）", n, maxRecordLen)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("读取记录体失败：%w", err)
	}
	return payload, nil
}

func deriveKeys(shared, clientRand, serverRand []byte) (c2s, s2c []byte) {
	salt := append(append([]byte{}, clientRand...), serverRand...)
	c2s = hkdfSHA256(shared, salt, []byte("MM-1 v1 c2s"), 32)
	s2c = hkdfSHA256(shared, salt, []byte("MM-1 v1 s2c"), 32)
	return c2s, s2c
}

// SessionKeys 是握手协商出的会话密钥。
type SessionKeys struct {
	C2S []byte // 客户端→服务端
	S2C []byte // 服务端→客户端
	// Version 是协商到的协议版本（2 或 3），决定握手之后走
	// 单连接转发（v2）还是复用会话（v3）。
	Version int
	// Profile 是本次连接由 PSK 派生的流量画像（见 profile.go），
	// 决定本连接发送方的填充分布和分片大小；接收方不依赖它。
	Profile TrafficProfile
	// PSK 是本次握手匹配到的预共享密钥（服务端用它登记 v3 会话：
	// 密钥轮换的宽限期一到，只断开用旧密钥建的会话，用新密钥建的不受影响）。
	PSK []byte
}

// ClientHandshake 在 conn 上完成客户端握手（当前版本 v3）。
// badMagic/badVersion 仅供测试错误情况。
func ClientHandshake(conn net.Conn, psk []byte, badMagic, badVersion bool) (*SessionKeys, error) {
	return ClientHandshakeVersion(conn, psk, Version, badMagic, badVersion)
}

// ClientHandshakeVersion 用指定版本完成客户端握手。
// version 必须是 2 或 3；badVersion 时发一个不受支持的版本号 9。
func ClientHandshakeVersion(conn net.Conn, psk []byte, version int, badMagic, badVersion bool) (*SessionKeys, error) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	clientRand := make([]byte, 16)
	if _, err := rand.Read(clientRand); err != nil {
		return nil, err
	}
	// 握手时间戳写进随机数前 8 字节（后 8 字节仍随机）：
	// 服务端凭它拒绝过期重放；时间戳在鉴权标签覆盖范围内，改不了。
	// 注意：下面 buildHandshakePayload 和 deriveKeys 用的必须是同一份
	// clientRand（带时间戳的），否则两边派生的会话密钥对不上。
	clientRand = withHandshakeTimestamp(clientRand)
	payload := buildHandshakePayload(priv.PublicKey().Bytes(), clientRand, psk, "MM-1 auth c", version, badMagic, badVersion)
	// 握手记录的次版本号按版本来：v4 用 0x03（TLS 1.2），v2/v3 用 0x01。
	if err := writeTLSRecordVersion(conn, fakeHandshakeType, payload, recordMinorForVersion(version)); err != nil {
		return nil, fmt.Errorf("发送握手失败：%w", err)
	}
	resp, err := readTLSRecord(conn, fakeHandshakeType)
	if err != nil {
		return nil, fmt.Errorf("等待服务端握手回应失败：%w", err)
	}
	serverRand := make([]byte, 16)
	serverPub, _, serverVersion, err := parseHandshakePayload(resp, psk, "MM-1 auth s", serverRand)
	if err != nil {
		return nil, fmt.Errorf("服务端握手校验失败：%w", err)
	}
	if serverVersion != version {
		return nil, fmt.Errorf("服务端握手版本不对：服务端回的是 v%d，本次握手是 v%d", serverVersion, version)
	}
	// 服务端鉴权标签 = HMAC(psk, "MM-1 auth s" || 服务端公钥 || 服务端随机数），
	// 与服务端 buildHandshakePayload 的算法一致，这里直接验算。
	peer, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, fmt.Errorf("服务端公钥不合法：%w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("密钥协商失败：%w", err)
	}
	c2s, s2c := deriveKeys(shared, clientRand, serverRand)
	// 会话画像由 PSK + 本次握手的盐派生（A2）：同一 PSK 每次会话
	// 的画像都可能不同；盐在握手载荷前 8 字节，服务端用同一个盐
	// 派生出同一份画像（见服务端握手）。
	return &SessionKeys{C2S: c2s, S2C: s2c, Version: version, Profile: DeriveSessionProfile(psk, payload[:saltLen]), PSK: append([]byte(nil), psk...)}, nil
}

// ServerHandshake 在 conn 上完成服务端握手，返回会话密钥与客户端随机数。
func ServerHandshake(conn net.Conn, psk []byte) (*SessionKeys, error) {
	return ServerHandshakeWithKeys(conn, [][]byte{psk})
}

// ServerHandshakeWithKeys 用多个密钥依次尝试握手（密钥轮换时新旧密钥都能用）。
// 握手记录只读一次，依次用每个密钥验魔数和鉴权标签；
// 都验不过时返回最有信息量的那个错误（版本不对优先于魔数不对，
// 因为版本是和密钥无关的；密钥不对时只会看到魔数不对）。
// 不带重放防护（cache=nil）——测试和不设防的场景用；
// 服务端正式跑请用 ServerHandshakeWithKeysAndReplay。
func ServerHandshakeWithKeys(conn net.Conn, keys [][]byte) (*SessionKeys, error) {
	return ServerHandshakeWithKeysAndReplay(conn, keys, nil)
}

// ServerHandshakeWithKeysAndReplay 和 ServerHandshakeWithKeys 一样，
// 外加握手重放防护（cache 传 nil 时等于不设防）：
// 握手验过之后、回包之前，先校验客户端随机数里的时间戳
// （太旧或太超前都拒绝），再查盐缓存（同一个盐第二次出现就是重放）。
// 两项检查都在回包之前——重放的握手拿不到回应、开不了会话，
// 调用方（serveMMX）也不会把它记成“成功”、把攻击者 IP 标成信任。
// 老客户端（random 里没有时间戳）照常接受，只受盐缓存保护。
func ServerHandshakeWithKeysAndReplay(conn net.Conn, keys [][]byte, cache *ReplayCache) (*SessionKeys, error) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	req, err := readTLSRecord(conn, fakeHandshakeType)
	if err != nil {
		return nil, fmt.Errorf("读取客户端握手失败：%w", err)
	}
	// 盐在载荷前 8 字节；太短的记录后面解析会直接报错，
	// 这里先防住切片越界（salt 只在解析成功后才进缓存）。
	var salt []byte
	if len(req) >= saltLen {
		salt = req[:saltLen]
	}
	var firstErr error
	var nonMagicErr error
	for _, psk := range keys {
		clientRand := make([]byte, 16)
		clientPub, _, version, err := parseHandshakePayload(req, psk, "MM-1 auth c", clientRand)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if !strings.Contains(err.Error(), "魔数不对") && nonMagicErr == nil {
				nonMagicErr = err
			}
			continue
		}
		// 握手验过了：先防重放，再回包。
		if err := checkHandshakeTimestamp(clientRand); err != nil {
			return nil, err
		}
		if cache != nil && cache.CheckAndAdd(salt) {
			return nil, errors.New("握手被重放：同一个握手盐第二次出现")
		}
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		serverRand := make([]byte, 16)
		if _, err := rand.Read(serverRand); err != nil {
			return nil, err
		}
		// 服务端回应也带时间戳（和客户端同一规则），
		// 下面 buildHandshakePayload 和 deriveKeys 用同一份 serverRand。
		serverRand = withHandshakeTimestamp(serverRand)
		// 服务端回应必须用客户端握手协商到的同一版本（魔数标签一致），
		// 否则客户端验魔数失败——版本协商就靠这个。
		// 回应记录的次版本号也按协商到的版本来（v4 用 0x03，v2/v3 用 0x01）。
		resp := buildHandshakePayload(priv.PublicKey().Bytes(), serverRand, psk, "MM-1 auth s", version, false, false)
		if err := writeTLSRecordVersion(conn, fakeHandshakeType, resp, recordMinorForVersion(version)); err != nil {
			return nil, fmt.Errorf("发送握手回应失败：%w", err)
		}
		peer, err := ecdh.X25519().NewPublicKey(clientPub)
		if err != nil {
			return nil, fmt.Errorf("客户端公钥不合法：%w", err)
		}
		shared, err := priv.ECDH(peer)
		if err != nil {
			return nil, fmt.Errorf("密钥协商失败：%w", err)
		}
		c2s, s2c := deriveKeys(shared, clientRand, serverRand)
		// 会话画像由 PSK + 客户端握手的盐派生（A2），和客户端同一份。
		return &SessionKeys{C2S: c2s, S2C: s2c, Version: version, Profile: DeriveSessionProfile(psk, salt), PSK: append([]byte(nil), psk...)}, nil
	}
	if nonMagicErr != nil {
		return nil, nonMagicErr
	}
	return nil, firstErr
}

// ---------------------------------------------------------------------------
// 加密帧连接
// ---------------------------------------------------------------------------

// Conn 是握手完成后的加密帧连接。
type Conn struct {
	net.Conn
	send cipher.AEAD
	recv cipher.AEAD
	mu   sync.Mutex
	// 递增序号，防重放
	sendSeq uint32
	recvSeq uint32
	// profile 是本连接的流量画像（由 PSK + 会话盐派生），只决定发送方的
	// 填充分布和分片大小；接收方（ReadFrame）完全不读它。
	profile TrafficProfile
	// version 是协商到的协议版本（2/3/4）：决定记录次版本号和是否重协商。
	version int
	// recordMinor 是本连接写 TLS 记录用的次版本号（v4=0x03，否则 0x01）。
	recordMinor byte
	// sendKey/recvKey 是会话密钥（NewConn 传入的切片本身）：
	// 重协商时轮换，Close 时清零（C2：已结束会话的密钥不留在内存里）。
	sendKey []byte
	recvKey []byte
	// 重协商（v4 才有，B2）：上次换密钥的时间和之后发出的字节数，
	// 到阈值就先发一个重协商帧再写数据帧，不断流。
	// 两个方向各自独立：发方向按自己的发送量触发。
	lastRekey      time.Time
	sentSinceRekey int64
	rekeyInterval  time.Duration
	rekeyBytes     int64
	rekeysSent     int // 已发出的重协商帧数（测试/监控用）
	rekeysReceived int // 已收到的重协商帧数（测试/监控用）
}

// 重协商的默认阈值：5 分钟或 64MB，先到先换。
// 64MB 远低于 AES-GCM 随机 nonce 的安全边界（2^32 帧量级），
// 5 分钟则保证长会话的密钥不会用到死；两个都是约数，不是硬安全线。
const (
	rekeyDefaultInterval = 5 * time.Minute
	rekeyDefaultBytes    = 64 << 20 // 64MB
	rekeySeedLen         = 32
)

// Profile 返回本连接的流量画像。
func (c *Conn) Profile() TrafficProfile { return c.profile }

// maxDataPayload 返回本连接 DATA 帧单帧载荷上限（画像决定，
// 未设置画像时退回旧的固定值 16000）。
func (c *Conn) maxDataPayload() int {
	if c.profile.MaxDataPayload > 0 {
		return c.profile.MaxDataPayload
	}
	return maxFramePayload
}

// NewConn 用会话密钥包装一个已握手连接。isClient 决定收发密钥方向。
func NewConn(c net.Conn, keys *SessionKeys, isClient bool) (*Conn, error) {
	var sendKey, recvKey []byte
	if isClient {
		sendKey, recvKey = keys.C2S, keys.S2C
	} else {
		sendKey, recvKey = keys.S2C, keys.C2S
	}
	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, err
	}
	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, err
	}
	sendAEAD, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, err
	}
	profile := keys.Profile
	if profile.MaxDataPayload == 0 {
		profile = trafficProfiles[0]
	}
	return &Conn{Conn: c, send: sendAEAD, recv: recvAEAD, profile: profile,
		version: keys.Version, recordMinor: recordMinorForVersion(keys.Version),
		sendKey: sendKey, recvKey: recvKey,
		lastRekey: time.Now(), rekeyInterval: rekeyDefaultInterval, rekeyBytes: rekeyDefaultBytes}, nil
}

// RekeysSent 已发出的重协商帧数（v4 测试用）。
func (c *Conn) RekeysSent() int { return c.rekeysSent }

// RekeysReceived 已收到的重协商帧数（v4 测试用）。
func (c *Conn) RekeysReceived() int { return c.rekeysReceived }

// Close 关掉连接并清零会话密钥（C2）：已结束会话的密钥不留在内存里。
// 注意：AEAD 内部已经复制过密钥，清零这里的切片不影响已建好的 AEAD，
// 只是把原始密钥材料从内存里抹掉；PSK 不在这里（它在 KeyManager 里长期有效）。
func (c *Conn) Close() error {
	for i := range c.sendKey {
		c.sendKey[i] = 0
	}
	for i := range c.recvKey {
		c.recvKey[i] = 0
	}
	return c.Conn.Close()
}

// TamperSendKey 仅供测试：破坏发送密钥，让对端解密失败。
func (c *Conn) TamperSendKey() {
	// 换一把随机密钥重新构造发送 AEAD
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	c.send = aead
}

// WriteFrame 发送一帧：明文 = 类型(1) | 序号(4) | 填充长度(1) | 随机填充(0–63) | 载荷，整体 AES-GCM 加密。
// 每帧的随机填充让密文长度每次都不同，避免形成固定包长模式。
// DATA 帧载荷超过本连接画像的分片上限时自动切成多帧发出：每条 TLS 记录
// 都不超过 16384 字节（真实 TLS 1.2 的记录上限），包长分布才像正常 HTTPS；
// 接收方按序号依次读回，流语义不变。
func (c *Conn) WriteFrame(frameType byte, payload []byte) error {
	maxPayload := c.maxDataPayload()
	if frameType == FrameData && len(payload) > maxPayload {
		for len(payload) > 0 {
			n := len(payload)
			if n > maxPayload {
				n = maxPayload
			}
			if err := c.writeOneFrame(frameType, payload[:n]); err != nil {
				return err
			}
			payload = payload[n:]
		}
		return nil
	}
	return c.writeOneFrame(frameType, payload)
}

func (c *Conn) writeOneFrame(frameType byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// v4 重协商：到阈值先换密钥再写数据帧（B2）；换密钥本身
	// 也是一帧（FrameRekey），和数据帧共用序号和写锁，不断流。
	if c.rekeyDueLocked() {
		if err := c.doRekeyLocked(); err != nil {
			return err
		}
	}
	return c.writeFrameLocked(frameType, payload)
}

// rekeyDueLocked：v4 且（距上次重协商超过 interval，或之后发了超过
// rekeyBytes 字节）就该换密钥了。调用方必须已持 c.mu。
func (c *Conn) rekeyDueLocked() bool {
	if c.version < VersionV4 {
		return false
	}
	if c.rekeyInterval > 0 && time.Since(c.lastRekey) >= c.rekeyInterval {
		return true
	}
	if c.rekeyBytes > 0 && c.sentSinceRekey >= c.rekeyBytes {
		return true
	}
	return false
}

// doRekeyLocked：发一个重协商帧（32 字节随机种子，用旧密钥加密），
// 再把发送密钥换成 HKDF(旧发送密钥，种子，"MM-1 rekey v4")。
// 接收方收到重协商帧后用同样的办法算出新接收密钥——
// 帧顺序保证接收方先切好密钥，才会收到新密钥加密的帧；
// 序号不重置，继续递增。调用方必须已持 c.mu。
func (c *Conn) doRekeyLocked() error {
	seed := make([]byte, rekeySeedLen)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	newKey := hkdfSHA256(c.sendKey, seed, []byte("MM-1 rekey v4"), 32)
	if err := c.writeFrameLocked(FrameRekey, seed); err != nil {
		return err
	}
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	for i := range c.sendKey {
		c.sendKey[i] = 0
	}
	c.sendKey = newKey
	c.send = aead
	c.lastRekey = time.Now()
	c.sentSinceRekey = 0
	c.rekeysSent++
	return nil
}

// applyRekey：收到重协商帧后算出新接收密钥并切换。
// 种子在加密帧里（已验过 AEAD），不知道会话密钥的人伪造不了。
// 只在 ReadFrame 的读 goroutine 里调，接收密钥只有它碰，不用锁。
func (c *Conn) applyRekey(seed []byte) error {
	newKey := hkdfSHA256(c.recvKey, seed, []byte("MM-1 rekey v4"), 32)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	for i := range c.recvKey {
		c.recvKey[i] = 0
	}
	c.recvKey = newKey
	c.recv = aead
	c.rekeysReceived++
	return nil
}

// writeFrameLocked：组一帧并写出去（调用方必须已持 c.mu）。
// 序号分配 + 自增和写操作在同一把锁里（A1）：两个流同时写帧
// 再也不会拿到同一个序号。
func (c *Conn) writeFrameLocked(frameType byte, payload []byte) error {
	// 帧填充长度按本连接画像抽样（分布因部署而异，仍在 0–63 内）；
	// 抽样失败时退回原来的均匀 0–63，发送绝不因此失败。
	padLenByte := byte(0)
	if n, err := c.profile.SampleFramePadLen(); err == nil {
		padLenByte = byte(n)
	} else {
		tmp := make([]byte, 1)
		if _, err := rand.Read(tmp); err != nil {
			return err
		}
		padLenByte = tmp[0] % 64
	}
	padding := make([]byte, padLenByte)
	if _, err := rand.Read(padding); err != nil {
		return err
	}
	plain := make([]byte, 0, 6+len(padding)+len(payload))
	plain = append(plain, frameType)
	var seqBuf [4]byte
	binary.BigEndian.PutUint32(seqBuf[:], c.sendSeq)
	plain = append(plain, seqBuf[:]...)
	plain = append(plain, padLenByte)
	plain = append(plain, padding...)
	plain = append(plain, payload...)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := c.send.Seal(nil, nonce, plain, nil)
	body := append(append([]byte{}, nonce...), ct...)

	// 记录次版本号按协商到的版本来（v4 用 0x03，v2/v3 用 0x01）。
	if err := writeTLSRecordVersion(c.Conn, fakeRecordType, body, c.recordMinor); err != nil {
		return err
	}
	c.sendSeq++
	c.sentSinceRekey += int64(len(payload))
	return nil
}

// ReadFrame 读取并解密一帧，校验递增序号。
// 重协商帧（v4，FrameRekey）是内部帧：在这里直接处理
// （算出新接收密钥并切换），不返回给调用方，继续读下一帧——
// 调用方只会看到 CONNECT/DATA/CLOSE/ACK，和以前一样。
func (c *Conn) ReadFrame() (byte, []byte, error) {
	for {
		body, err := readTLSRecord(c.Conn, fakeRecordType)
		if err != nil {
			return 0, nil, err
		}
		if len(body) < 12+16+6 {
			return 0, nil, errors.New("帧太短")
		}
		nonce, ct := body[:12], body[12:]
		plain, err := c.recv.Open(nil, nonce, ct, nil)
		if err != nil {
			return 0, nil, errors.New("解密失败：密钥不对或数据被篡改")
		}
		if len(plain) < 6 {
			return 0, nil, errors.New("帧明文太短")
		}
		frameType := plain[0]
		seq := binary.BigEndian.Uint32(plain[1:5])
		if seq != c.recvSeq {
			return 0, nil, fmt.Errorf("序号不对：期望 %d，实际 %d（可能重放攻击）", c.recvSeq, seq)
		}
		c.recvSeq++
		padLen := int(plain[5])
		if len(plain) < 6+padLen {
			return 0, nil, errors.New("帧填充长度不对")
		}
		payload := plain[6+padLen:]
		if frameType == FrameRekey {
			// v4 才有重协商帧：老版本会话收到它就是协议错误，
			// 直接断开（不静默跳过——不知道会话密钥的人发不出
			// 能解密的重协商帧，能解密却不该发的就是对端出 bug 了）。
			if c.version < VersionV4 {
				return 0, nil, errors.New("收到重协商帧，但本会话不是 v4")
			}
			if len(payload) != rekeySeedLen {
				return 0, nil, errors.New("重协商帧长度不对")
			}
			if err := c.applyRekey(payload); err != nil {
				return 0, nil, fmt.Errorf("重协商失败：%v", err)
			}
			continue
		}
		return frameType, payload, nil
	}
}

// ---------------------------------------------------------------------------
// CONNECT / ACK 载荷
// ---------------------------------------------------------------------------

// EncodeConnectTarget 把目标地址编码进 CONNECT 帧载荷（不限速，rate=0）。
func EncodeConnectTarget(target string) []byte {
	return EncodeConnectTargetWithRate(target, 0)
}

// EncodeConnectTargetWithRate 把目标地址 + 客户端要求的限速编码进 CONNECT 帧载荷：
// 2 字节长度 + "host:port" + 8 字节限速（每秒字节数大端，0 = 不限速）。
// 限速由服务端取 min(服务端 --rate，链接 rate) 后执行，客户端改大也突破不了上限。
// 突发额度未指定（-1），由服务端按默认值处理。
func EncodeConnectTargetWithRate(target string, rate int64) []byte {
	return EncodeConnectTargetWithRateAndBurst(target, rate, BurstUnset)
}

// EncodeConnectTargetWithRateAndBurst 把目标地址 + 客户端要求的限速和
// 突发额度编码进 CONNECT 帧载荷：
// 2 字节长度 + "host:port" + 8 字节限速 + 8 字节突发额度
// （有符号大端，-1 = 未指定，用默认值；0 = 不许突发）。
// 限速和突发都由服务端取 min(服务端参数，链接参数) 后执行。
func EncodeConnectTargetWithRateAndBurst(target string, rate, burst int64) []byte {
	b := []byte(target)
	out := make([]byte, 2+len(b)+16)
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	binary.BigEndian.PutUint64(out[2+len(b):], uint64(rate))
	binary.BigEndian.PutUint64(out[2+len(b)+8:], uint64(burst))
	return out
}

// DecodeConnectTarget 解码 CONNECT 帧载荷（只取目标地址，兼容老格式）。
func DecodeConnectTarget(p []byte) (string, error) {
	target, _, _, err := DecodeConnectRequest(p)
	return target, err
}

// DecodeConnectRequest 解码 CONNECT 帧载荷，返回目标地址、客户端要求的限速
// 和突发额度（每秒字节数，0 = 不限速；突发 -1 = 未指定，用默认值，0 = 不许突发）。
// 兼容老格式：没有限速字段时 rate 返回 0，没有突发字段时 burst 返回 -1。
func DecodeConnectRequest(p []byte) (string, int64, int64, error) {
	if len(p) < 2 {
		return "", 0, BurstUnset, errors.New("CONNECT 载荷太短")
	}
	n := int(binary.BigEndian.Uint16(p[:2]))
	if len(p) < 2+n {
		return "", 0, BurstUnset, errors.New("CONNECT 载荷长度不对")
	}
	var rate int64
	if len(p) >= 2+n+8 {
		rate = int64(binary.BigEndian.Uint64(p[2+n : 2+n+8]))
	}
	burst := BurstUnset
	if len(p) >= 2+n+16 {
		burst = int64(binary.BigEndian.Uint64(p[2+n+8 : 2+n+16]))
	}
	return string(p[2 : 2+n]), rate, burst, nil
}

// ---------------------------------------------------------------------------
// v3 复用流：流头与流内 ACK
// ---------------------------------------------------------------------------

// 复用流种类（yamux 流打开后第一个字节）。
const (
	StreamKindTCP = 0x01 // TCP 转发：流头后是 CONNECT 载荷，之后是字节流
	StreamKindUDP = 0x02 // UDP 转发：流头后是 CONNECT 载荷，之后是长度前缀的数据报
)

// EncodeStreamHeader 编码复用流头：种类(1) + CONNECT 载荷
// （2 字节长度 + "host:port" + 8 字节限速 + 8 字节突发，和 v2 的
// CONNECT 帧载荷同一格式，服务端同一套解码逻辑）。
func EncodeStreamHeader(kind byte, target string, rate, burst int64) []byte {
	payload := EncodeConnectTargetWithRateAndBurst(target, rate, burst)
	out := make([]byte, 1+len(payload))
	out[0] = kind
	copy(out[1:], payload)
	return out
}

// DecodeStreamHeader 从流里读一个流头，返回种类、目标、限速、突发。
func DecodeStreamHeader(r io.Reader) (byte, string, int64, int64, error) {
	var kindBuf [1]byte
	if _, err := io.ReadFull(r, kindBuf[:]); err != nil {
		return 0, "", 0, BurstUnset, fmt.Errorf("读流种类失败：%w", err)
	}
	kind := kindBuf[0]
	if kind != StreamKindTCP && kind != StreamKindUDP {
		return 0, "", 0, BurstUnset, fmt.Errorf("流种类不对：0x%02x", kind)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, "", 0, BurstUnset, fmt.Errorf("读目标长度失败：%w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n <= 0 || n > 4096 {
		return 0, "", 0, BurstUnset, fmt.Errorf("目标长度不合法：%d", n)
	}
	rest := make([]byte, n+16)
	if _, err := io.ReadFull(r, rest); err != nil {
		return 0, "", 0, BurstUnset, fmt.Errorf("读流头剩余部分失败：%w", err)
	}
	payload := append(append([]byte{}, lenBuf[:]...), rest...)
	target, rate, burst, err := DecodeConnectRequest(payload)
	if err != nil {
		return 0, "", 0, BurstUnset, fmt.Errorf("流头载荷不合法：%w", err)
	}
	return kind, target, rate, burst, nil
}

// WriteStreamAck 往流里写一个接通确认：成功只写 0x00；
// 失败写 0x01 + 2 字节长度 + 错误文本（文本复用 ACK 的 "[错误码] …" 格式，
// 客户端用 ParseAckError 解析，错误码和 v2 完全一致）。
func WriteStreamAck(w io.Writer, dialErr error) error {
	if dialErr == nil {
		_, err := w.Write([]byte{0x00})
		return err
	}
	code := ClassifyDialError(dialErr)
	text := FormatConnectError(code, dialErr)
	out := make([]byte, 1+2+len(text))
	out[0] = 0x01
	binary.BigEndian.PutUint16(out[1:3], uint16(len(text)))
	copy(out[3:], text)
	_, err := w.Write(out)
	return err
}

// ReadStreamAck 从流里读接通确认：成功返回 nil；
// 失败返回服务端拒绝转发的错误（带 [错误码] 前缀，客户端可映射 SOCKS5 回复码）。
func ReadStreamAck(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return fmt.Errorf("读流 ACK 失败：%w", err)
	}
	if status[0] == 0x00 {
		return nil
	}
	if status[0] != 0x01 {
		return fmt.Errorf("流 ACK 状态不对：0x%02x", status[0])
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return fmt.Errorf("读流 ACK 错误文本长度失败：%w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 0 || n > 4096 {
		return fmt.Errorf("流 ACK 错误文本长度不合法：%d", n)
	}
	text := make([]byte, n)
	if _, err := io.ReadFull(r, text); err != nil {
		return fmt.Errorf("读流 ACK 错误文本失败：%w", err)
	}
	code, msg := ParseAckError(append([]byte{0x01}, text...))
	if msg == "" {
		msg = "（无错误信息）"
	}
	return fmt.Errorf("服务端拒绝转发 [%s]：%s", code, msg)
}
