// TLS 传输（v3 追加，大哥 2026-11-23 18:09 "tls也加入"）：
// 真实 TLS 1.3 会话里面跑 mm-x 握手 + 复用；ALPN h2,http/1.1，
// 看起来就是正常 HTTPS。证书用自签证书 + SPKI 指纹锁定（pin 放进
// mmx:// 链接），不需要域名；大哥以后有了域名再换真证书。
//
// 安全要点（不要为了省事关掉验证）：
//   - pin 模式下不校验主机名、不走系统根证书，只认 pin——
//     pin 就是证书公钥的 SHA-256，中间人换一张证书就对不上 pin，
//     握手直接失败。--tls-insecure 跳过校验只留给自签证书的测试，
//     正式部署绝不能用。
//   - 不开 0-RTT（重放风险）。
//   - SNI 默认用常见域名（www.microsoft.com）：没有域名时先这样用，
//     局限是 SNI 不是自己的域名——但信任锚是 pin 不是 SNI，
//     SNI 只影响握手在旁观者眼里像访问哪个网站。
package mmx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DefaultSNI 是没有域名时 TLS 握手用的 SNI：一个常见域名，
// 让握手在旁观者眼里像在访问一个普通大网站。
// 局限：这个域名不是我们的——信任锚是证书 pin，不是 SNI。
const DefaultSNI = "www.microsoft.com"

// tlsSessionCache 是进程内共享的 TLS 会话票据缓存（只放内存，不落盘）：
// 重复连同一台服务端时可以会话恢复（abbreviated handshake，
// 省一次完整握手 + 一次往返）。uTLS 的 ClientSessionCache 和
// Go 的语义一样：只在 SessionTicketsDisabled=false（默认）时生效，
// 0-RTT 不开——Go/uTLS 客户端本来也不发 0-RTT 数据。
// 缓存按服务端（SNI）分 key，不同服务端不会串票据。
var tlsSessionCache = utls.NewLRUClientSessionCache(64)

// clientHelloFingerprints 是外层 TLS 每会话轮换用的 ClientHello 指纹：
// 只挑真实世界里常见的浏览器指纹（utls v1.6.6 里现成的），不编冷门的。
// Chrome 占两席是故意的：真实流量里 Chrome 本来就是多数。
//   - HelloChrome_Auto（= Chrome 120，桌面 Chrome）；
//   - HelloChrome_120_PQ（Chrome 120 + X25519MLKEM768，
//     Chrome 127+ 默认开 PQ 密钥协商后很常见）；
//   - HelloFirefox_Auto（= Firefox 120）；
//   - HelloSafari_Auto（= Safari 16.0）；
//   - HelloIOS_Auto（= iOS 14）。
var clientHelloFingerprints = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloChrome_120_PQ,
	utls.HelloFirefox_Auto,
	utls.HelloSafari_Auto,
	utls.HelloIOS_Auto,
}

// pickClientHelloID 每会话随机挑一个外层 TLS 指纹（crypto/rand）。
// 指纹按会话定一次：同一会话里的多条流共用同一个 ClientHello，
// 不会一条流换一个指纹。
func pickClientHelloID() utls.ClientHelloID {
	return clientHelloFingerprints[randIntn(len(clientHelloFingerprints))]
}

// ParsePIN 解析链接里的 pin 参数：base64url、标准 base64 或十六进制都接受，
// 解出来必须是 32 字节（SHA-256）。
func ParsePIN(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("pin 为空")
	}
	for _, dec := range []func(string) ([]byte, error){
		func(v string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(v) },
		func(v string) ([]byte, error) { return base64.StdEncoding.DecodeString(v) },
		func(v string) ([]byte, error) { return hex.DecodeString(v) },
	} {
		if b, err := dec(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("pin %q 解出来不是 32 字节（应为 SHA-256 指纹的 base64url 或十六进制）", s)
}

// FormatPIN 把 32 字节指纹写回链接用的 base64url 形式。
func FormatPIN(pin []byte) string {
	return base64.RawURLEncoding.EncodeToString(pin)
}

// SPKIPinOfCert 算一张证书的 SPKI 指纹：
// SHA-256(叶子证书 RawSubjectPublicKeyInfo)，和 pin 参数同一格式。
func SPKIPinOfCert(cert tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("证书里没有证书数据")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("解析叶子证书失败：%v", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return sum[:], nil
}

// SPKIPinOfCertFile 读一个 PEM 证书文件，算它的 SPKI 指纹。
// mm 菜单“查看 TLS 指纹”就调这个（经服务端 --print-pin）。
func SPKIPinOfCertFile(certFile string) ([]byte, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("读证书文件失败：%v", err)
	}
	var block *pem.Block
	for {
		block, b = pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("证书文件 %s 里没有 PEM 证书", certFile)
		}
		if block.Type == "CERTIFICATE" {
			break
		}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败：%v", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return sum[:], nil
}

// GenerateSelfSignedCert 生成一张自签证书（ECDSA P-256，10 年有效期），
// CN 和 SAN 只写 SNI 主机名，私钥 0600、证书 0644 存到指定路径。
// 自签证书没有第三方背书——信任全靠客户端的 pin 锁定，换证书就要换链接里的 pin。
// 注意证书上不写任何能认出协议的东西：Subject 只有 CN（以前写过
// Organization "mm-x"，任何 TLS 探测一抓证书就知道这是 mm-x，
// 伪装白做了），SAN 也不带 localhost / 127.0.0.1 / ::1——
// 一张 www.microsoft.com 的证书带本机回环 SAN 本身就很可疑。
func GenerateSelfSignedCert(certFile, keyFile, sniHost string) (tls.Certificate, error) {
	if sniHost == "" {
		sniHost = DefaultSNI
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成证书私钥失败：%v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("编码私钥失败：%v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("写私钥文件失败：%v", err)
	}
	return issueSelfSignedCert(certFile, sniHost, priv)
}

// ReissueSelfSignedCert 用已有的私钥重新签发一张自签证书（只换证书，不换密钥）。
// 用途：旧证书的 Subject/SAN 里写了协议名之类的识别信息，需要换一张干净的，
// 但又不想换链接里的 pin——pin 是 SPKI 指纹（只和公钥有关），
// 用同一把私钥重签，pin 不变，老链接照常用。
// keyFile 必须是 GenerateSelfSignedCert 写下的 EC 私钥文件。
func ReissueSelfSignedCert(certFile, keyFile, sniHost string) (tls.Certificate, error) {
	if sniHost == "" {
		sniHost = DefaultSNI
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("读私钥文件失败：%v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("私钥文件 %s 里没有 PEM 数据", keyFile)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// 也接受 PKCS#8 形式的私钥（有些工具导出的是这种）。
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return tls.Certificate{}, fmt.Errorf("解析私钥失败：%v", err)
		}
		var ok bool
		priv, ok = k.(*ecdsa.PrivateKey)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("私钥不是 ECDSA 密钥，无法重签证书")
		}
	}
	return issueSelfSignedCert(certFile, sniHost, priv)
}

// issueSelfSignedCert 用给定的私钥签发一张自签证书并存到 certFile。
// 模板只写 CN 和一个 DNS SAN（都是 SNI 主机名），不写 Organization、
// 不写 localhost、不写回环 IP SAN——证书本身不能泄露协议身份。
// KeyUsage 只写 DigitalSignature：ECDSA 密钥做不了 KeyEncipherment，
// 写上它反而是特征（2026-11-26 评审指出）。有效期 1 年：10 年有效期
// 也是特征，公开 CA 的证书最长也就 398 天；注意换证书要换链接里的 pin。
func issueSelfSignedCert(certFile, sniHost string, priv *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成证书序列号失败：%v", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sniHost},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sniHost},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("签发自签证书失败：%v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return tls.Certificate{}, fmt.Errorf("写证书文件失败：%v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("解析刚生成的证书失败：%v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

// LoadOrGenerateCert 拿 TLS 证书：两个文件都在就直接加载；
// 缺了就按 auto 决定：auto=true 时自动生成自签证书并存下来，
// auto=false 时报错（真证书模式缺文件就是配错了，不要悄悄生成）。
// 只有证书缺了、私钥还在时，用现有私钥重签（ReissueSelfSignedCert），
// 不生成新私钥——pin 是公钥指纹，私钥不变 pin 就不变，老链接照常用。
// 这也是已部署服务换干净证书的操作：删掉旧证书文件、重启，
// 服务端自动用原私钥重签一张（Subject 里不再有协议名）。
func LoadOrGenerateCert(certFile, keyFile, sniHost string, auto bool) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("TLS 证书和私钥路径要一起给（--tls-cert 和 --tls-key）")
	}
	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)
	if certExists && keyExists {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("加载证书失败：%v", err)
		}
		return cert, nil
	}
	if certExists && !keyExists {
		return tls.Certificate{}, fmt.Errorf("证书和私钥要成对：%s 存在，%s 不存在", certFile, keyFile)
	}
	if !auto {
		return tls.Certificate{}, fmt.Errorf("证书文件不存在：%s（真证书模式不会自动生成；自签模式请加 --tls-auto）", certFile)
	}
	if keyExists {
		// 证书丢了、私钥还在：用原私钥重签，pin 不变。
		return ReissueSelfSignedCert(certFile, keyFile, sniHost)
	}
	return GenerateSelfSignedCert(certFile, keyFile, sniHost)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ServerTLSConfig 生成服务端 TLS 配置：只谈 TLS 1.3，
// ALPN 报 http/1.1 和 h2（看起来像正常 HTTPS 服务器）。
// 注意顺序：http/1.1 在前、h2 在后——服务端优先选 http/1.1，
// 这样浏览器/curl 过来谈成的就是 HTTP/1.1，诱饵站（只会 HTTP/1.1）
// 能回正常页面；h2 仍在列表里，只谈 h2 的客户端才会协商到 h2——
// 那种客户端诱饵站回不了页面，会拿到 400，这是已知局限。
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1", "h2"},
	}
}

// DialTLSWithPin 拨号到 mm-x 服务端并包一层真 TLS 1.3：
// SNI 用 sni（空时用默认常见域名）；pin 非空时只认 pin（跳过主机名和
// 系统根证书校验，改验叶子证书的 SPKI 指纹——指纹不对就拒绝，
// 中间人换证书没用）；pin 为空时走系统根证书正常校验。
// insecure=true 时跳过一切校验，只用于自签证书的测试，正式部署绝不能用。
// ClientHello 用 uTLS 模拟浏览器（A3）：Go crypto/tls 默认的 ClientHello
// 指纹（JA3）一眼就能认出是 Go 程序，uTLS 的浏览器指纹看起来就是浏览器。
// 指纹每会话现抽一个（见 clientHelloFingerprints），不再固定用 Chrome。
// 域名解析出多个 IP 时逐个试：TCP 拨通但 TLS 握手失败就换下一个 IP（C5）。
func DialTLSWithPin(host string, port int, sni, pin string, timeout time.Duration, insecure bool) (net.Conn, error) {
	ips, err := ResolveHost(host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	var firstHandshakeErr error
	for _, ip := range ips {
		c, tcpOK, err := DialTLSWithPinIP(ip, port, sni, pin, timeout, insecure)
		if err == nil {
			return c, nil
		}
		if tcpOK && firstHandshakeErr == nil {
			firstHandshakeErr = err
		}
		lastErr = err
	}
	// TCP 接通后握手失败（pin、证书不对）比“某个 IP 连不上”更能说明
	// 问题：服务端明确拒绝了，优先报这个错——否则 ::1 这类没服务的
	// IP 的 connection refused 会把真正的 pin 错误盖掉。
	if firstHandshakeErr != nil {
		return nil, fmt.Errorf("连接服务端 %s:%d 失败：%v", host, port, firstHandshakeErr)
	}
	return nil, fmt.Errorf("连接服务端 %s:%d 失败：%v", host, port, lastErr)
}

// newClientTLSConfig 建一次外层 TLS 握手用的 utls 配置：
// SNI 用 sni（空时用默认常见域名）；pin 非空时只认 pin（跳过主机名和
// 系统根证书校验，改验叶子证书的 SPKI 指纹）；pin 为空时走系统根证书
// 正常校验；insecure=true 时跳过一切校验，只用于自签证书的测试，
// 正式部署绝不能用。
// 会话恢复：配置挂进程共享的 tlsSessionCache，重复连接可 abbreviated
// 握手；SessionTicketsDisabled 保持默认 false（不开它恢复才生效），
// 0-RTT 不开（重放风险，见文件头注释）。
// 单独抽出来是为了测试能直接验“恢复缓存已接线”，不用真的拨号。
func newClientTLSConfig(sni, pin string, insecure bool) (*utls.Config, error) {
	if sni == "" {
		sni = DefaultSNI
	}
	cfg := &utls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
		ClientSessionCache: tlsSessionCache,
	}
	if insecure {
		cfg.InsecureSkipVerify = true
	} else if pin != "" {
		want, err := ParsePIN(pin)
		if err != nil {
			return nil, fmt.Errorf("证书指纹 pin 不合法：%v", err)
		}
		cfg.InsecureSkipVerify = true // 主机名/根证书不校验，改由下面的 pin 校验接管
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("服务端没有出示证书")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("服务端证书解析失败：%v", err)
			}
			// C3：pin 模式也要看证书有效期——指纹对上但证书已过期
			// （或还没生效）就拒绝；自签证书 1 年有效期，正常用不会触发。
			now := time.Now()
			if now.After(leaf.NotAfter) {
				return fmt.Errorf("服务端证书已过期（有效期到 %s）", leaf.NotAfter.Format("2006-01-02"))
			}
			if now.Before(leaf.NotBefore) {
				return fmt.Errorf("服务端证书还没生效（有效期从 %s 开始）", leaf.NotBefore.Format("2006-01-02"))
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if !bytesEqual(sum[:], want) {
				return errors.New("服务端证书指纹对不上链接里的 pin（证书可能被换过或链接里的 pin 不对）")
			}
			return nil
		}
	}
	return cfg, nil
}

// DialTLSWithPinIP 拨到指定的一个 IP 并包一层真 TLS 1.3
// （SNI 仍用域名，证书校验和 DialTLSWithPin 同一套规则）。
// 域名解析出多个 IP 时调用方逐个试这个函数，握手失败就换下一个 IP。
// 返回 tcpOK 表示 TCP 是否接通：接通后 TLS 握手失败 = 服务端明确拒绝。
// ClientHello 指纹每会话现抽一个（见 clientHelloFingerprints），
// 不是每次都用同一个 Chrome 指纹。
func DialTLSWithPinIP(ip string, port int, sni, pin string, timeout time.Duration, insecure bool) (net.Conn, bool, error) {
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, false, err
	}
	tlsConn, err := tlsHandshakeOverConn(raw, sni, pin, timeout, insecure)
	if err != nil {
		raw.Close()
		return nil, true, err
	}
	return tlsConn, true, nil
}

// tlsHandshakeOverConn 在一条已建立的 TCP 连接上做 uTLS 1.3 握手
// （SNI、pin 校验、ClientHello 指纹选择和 DialTLSWithPinIP 完全一致）。
// 用途：经上游 SOCKS5 代理拨通后的 TCP 连接也要包 TLS，
// 握手本身不关心这条 TCP 是直连还是经代理来的。
// 握手失败时调用方负责关掉 raw。
func tlsHandshakeOverConn(raw net.Conn, sni, pin string, timeout time.Duration, insecure bool) (net.Conn, error) {
	cfg, err := newClientTLSConfig(sni, pin, insecure)
	if err != nil {
		return nil, err
	}
	tlsConn := utls.UClient(raw, cfg, pickClientHelloID())
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS 握手失败：%v", err)
	}
	return tlsConn, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ResolveSNI 决定 TLS 握手用的 SNI：链接里写了 sni 就用它；
// 没写时，host 是域名就用 host（真证书模式），host 是 IP 就用默认常见域名。
func ResolveSNI(cfg *LinkConfig) string {
	if cfg.SNI != "" {
		return cfg.SNI
	}
	if net.ParseIP(cfg.Host) == nil && cfg.Host != "" {
		return cfg.Host
	}
	return DefaultSNI
}

// RotatedSNIs 是 v5 会话轮换用的 SNI 候选，已废弃（2026-11-26 评审指出：
// 同一个 VPS IP 上一会儿 apple 一会儿 microsoft，反而更像异常；
// 真正的 CDN IP 挂多域名才正常，这台 VPS 的 IP 不是 CDN 的 IP）。
// 保留这个变量只是为了兼容旧代码引用，SessionSNI 已不再用它轮换。
var RotatedSNIs = []string{
	"www.microsoft.com",
	"www.apple.com",
	"www.amazon.com",
	"www.cloudflare.com",
	"www.google.com",
	"www.bing.com",
}

// RandomRotatedSNI 从轮换候选里随机挑一个 SNI（每会话现抽）。
// 已废弃：SessionSNI 不再轮换，保留仅作兼容。
func RandomRotatedSNI() string {
	if len(RotatedSNIs) == 0 {
		return DefaultSNI
	}
	return RotatedSNIs[randIntn(len(RotatedSNIs))]
}

// SessionSNI 决定一次会话握手用的 SNI：
//   - 链接写了 sni：用它（用户指定的最优先）；
//   - host 是域名：用 host（真证书模式，SNI 必须和证书域名一致）；
//   - 其余情况：默认常见域名 www.microsoft.com（和证书 CN 一致）。
// 不再按会话轮换（2026-11-26 评审指出轮换反而更异常，改回单一 SNI）。
func SessionSNI(cfg *LinkConfig) string {
	return ResolveSNI(cfg)
}
