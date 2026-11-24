// v3 TLS 传输的单元测试：自签证书生成/加载、SPKI pin 锁定、
// 指纹不对拒绝、SNI 解析。
package mm1

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePINRoundTrip(t *testing.T) {
	pin := make([]byte, 32)
	for i := range pin {
		pin[i] = byte(i * 7)
	}
	encoded := FormatPIN(pin)
	got, err := ParsePIN(encoded)
	if err != nil {
		t.Fatalf("解析自己生成的 pin 失败：%v", err)
	}
	if len(got) != 32 {
		t.Fatalf("解析出的 pin 是 %d 字节，想要 32", len(got))
	}
	for i := range pin {
		if got[i] != pin[i] {
			t.Fatalf("pin 第 %d 字节不一致", i)
		}
	}
	// 十六进制形式也接受。
	if _, err := ParsePIN(hex.EncodeToString(pin)); err != nil {
		t.Fatalf("十六进制 pin 应被接受：%v", err)
	}
	// 坏输入拒绝。
	for _, bad := range []string{"", "abc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"} {
		if _, err := ParsePIN(bad); err == nil {
			t.Fatalf("pin %q 应被拒绝", bad)
		}
	}
}

func TestSelfSignedCertPin(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls-cert.pem")
	keyFile := filepath.Join(dir, "tls-key.pem")

	// 首次生成。
	cert, err := LoadOrGenerateCert(certFile, keyFile, "www.microsoft.com", true)
	if err != nil {
		t.Fatalf("生成自签证书失败：%v", err)
	}
	// 第二次加载同一张证书（pin 不变）。
	cert2, err := LoadOrGenerateCert(certFile, keyFile, "www.microsoft.com", true)
	if err != nil {
		t.Fatalf("加载已生成的证书失败：%v", err)
	}
	pin1, err := SPKIPinOfCert(cert)
	if err != nil {
		t.Fatalf("算证书指纹失败：%v", err)
	}
	pin2, err := SPKIPinOfCert(cert2)
	if err != nil {
		t.Fatalf("算证书指纹失败：%v", err)
	}
	if string(pin1) != string(pin2) {
		t.Fatal("两次加载的证书指纹不一致（应是同一张证书）")
	}
	// 从文件算指纹应一致（mm 菜单查指纹走这条路）。
	pinFile, err := SPKIPinOfCertFile(certFile)
	if err != nil {
		t.Fatalf("从文件算指纹失败：%v", err)
	}
	if string(pinFile) != string(pin1) {
		t.Fatal("文件算出的指纹和内存算出的不一致")
	}
	// auto=false + 文件不存在 → 报错（真证书模式缺文件就是配错了）。
	if _, err := LoadOrGenerateCert(filepath.Join(dir, "nope.pem"), filepath.Join(dir, "nope-key.pem"), "x", false); err == nil {
		t.Fatal("真证书模式缺证书文件时应报错，不应悄悄生成")
	}
	// 私钥权限应为 0600。
	if fi, err := os.Stat(keyFile); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("私钥文件权限应为 0600，实际 %v（err=%v）", fi.Mode().Perm(), err)
	}
	_ = cert
}

// TestSelfSignedCertCleanSubjectAndReissue：证书不能泄露协议身份，
// 重签必须保住 pin（P0-1）。
func TestSelfSignedCertCleanSubjectAndReissue(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls-cert.pem")
	keyFile := filepath.Join(dir, "tls-key.pem")

	cert, err := GenerateSelfSignedCert(certFile, keyFile, "www.microsoft.com")
	if err != nil {
		t.Fatalf("生成自签证书失败：%v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("解析证书失败：%v", err)
	}
	// Subject 里只能有 CN，不能有 Organization（以前写过 "MM-1"，
	// TLS 探测一抓证书就认出协议）。
	if len(leaf.Subject.Organization) != 0 {
		t.Fatalf("证书 Subject 不应带 Organization，实际 %v", leaf.Subject.Organization)
	}
	if leaf.Subject.CommonName != "www.microsoft.com" {
		t.Fatalf("证书 CN 应为 www.microsoft.com，实际 %q", leaf.Subject.CommonName)
	}
	// SAN 里只能有 SNI 域名，不能带 localhost / 回环 IP。
	for _, dns := range leaf.DNSNames {
		if dns != "www.microsoft.com" {
			t.Fatalf("证书 SAN 不应带 %q", dns)
		}
	}
	if len(leaf.IPAddresses) != 0 {
		t.Fatalf("证书不应带 IP SAN，实际 %v", leaf.IPAddresses)
	}
	pin1, err := SPKIPinOfCert(cert)
	if err != nil {
		t.Fatalf("算证书指纹失败：%v", err)
	}
	keyBefore, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("读私钥失败：%v", err)
	}
	// 重签：只换证书，不换私钥，pin 必须不变。
	cert2, err := ReissueSelfSignedCert(certFile, keyFile, "www.microsoft.com")
	if err != nil {
		t.Fatalf("重签证书失败：%v", err)
	}
	pin2, err := SPKIPinOfCert(cert2)
	if err != nil {
		t.Fatalf("算重签证书指纹失败：%v", err)
	}
	if string(pin1) != string(pin2) {
		t.Fatal("重签后 pin 变了：应用同一把私钥重签，pin 必须不变（否则老链接失效）")
	}
	if string(cert.Certificate[0]) == string(cert2.Certificate[0]) {
		t.Fatal("重签后证书居然没变（序列号应不同）")
	}
	keyAfter, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("读私钥失败：%v", err)
	}
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("重签不应动私钥文件")
	}
	// LoadOrGenerateCert：证书丢了、私钥还在 → 自动用原私钥重签，pin 不变。
	if err := os.Remove(certFile); err != nil {
		t.Fatalf("删证书文件失败：%v", err)
	}
	cert3, err := LoadOrGenerateCert(certFile, keyFile, "www.microsoft.com", true)
	if err != nil {
		t.Fatalf("证书丢失后应自动重签：%v", err)
	}
	pin3, err := SPKIPinOfCert(cert3)
	if err != nil {
		t.Fatalf("算重签证书指纹失败：%v", err)
	}
	if string(pin1) != string(pin3) {
		t.Fatal("证书丢失后重签，pin 变了")
	}
	// 证书和私钥都不在 → 生成全新的（pin 会变，这是首次部署的情况）。
	cert4, err := LoadOrGenerateCert(filepath.Join(dir, "c2.pem"), filepath.Join(dir, "k2.pem"), "www.microsoft.com", true)
	if err != nil {
		t.Fatalf("全新生成证书失败：%v", err)
	}
	pin4, err := SPKIPinOfCert(cert4)
	if err != nil {
		t.Fatalf("算新证书指纹失败：%v", err)
	}
	if string(pin1) == string(pin4) {
		t.Fatal("全新生成的证书 pin 居然和旧的一样（私钥应是新生成的）")
	}
}

func TestDialTLSWithPin(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls-cert.pem")
	keyFile := filepath.Join(dir, "tls-key.pem")
	cert, err := GenerateSelfSignedCert(certFile, keyFile, "www.microsoft.com")
	if err != nil {
		t.Fatalf("生成自签证书失败：%v", err)
	}
	pin, err := SPKIPinOfCert(cert)
	if err != nil {
		t.Fatalf("算指纹失败：%v", err)
	}
	pinStr := FormatPIN(pin)

	// 起一个 TLS 服务端（回显一行）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	defer ln.Close()
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, ServerTLSConfig(cert))
				if err := tc.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 64)
				n, err := tc.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = tc.Write(buf[:n])
			}(raw)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("端口解析失败：%v", err)
	}

	// 正确 pin → 握手成功，能收发。
	conn, err := DialTLSWithPin("127.0.0.1", port, "www.microsoft.com", pinStr, 5*time.Second, false)
	if err != nil {
		t.Fatalf("正确 pin 的 TLS 握手失败：%v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("TLS 写失败：%v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("TLS 回显失败：n=%d err=%v data=%q", n, err, buf[:n])
	}
	conn.Close()

	// 错误 pin → 拒绝（中间人换证书就对不上 pin）。
	wrongPin := FormatPIN(bytesRepeat(0xFF, 32))
	if _, err := DialTLSWithPin("127.0.0.1", port, "www.microsoft.com", wrongPin, 5*time.Second, false); err == nil {
		t.Fatal("错误 pin 的 TLS 握手应被拒绝")
	} else if !strings.Contains(err.Error(), "指纹") {
		t.Fatalf("错误 pin 的报错应提到指纹，实际：%v", err)
	}

	// 没 pin + 不跳过校验 → 自签证书不在系统根里，应失败。
	if _, err := DialTLSWithPin("127.0.0.1", port, "www.microsoft.com", "", 5*time.Second, false); err == nil {
		t.Fatal("没 pin 时自签证书应校验失败（不能悄悄放过）")
	}

	// --tls-insecure（仅测试用）→ 跳过校验，能通。
	conn2, err := DialTLSWithPin("127.0.0.1", port, "www.microsoft.com", "", 5*time.Second, true)
	if err != nil {
		t.Fatalf("--tls-insecure 应跳过校验：%v", err)
	}
	conn2.Close()
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// startTLSEchoServer 起一个带自签证书的 TLS 回显服务（只听 127.0.0.1），
// 返回端口和证书的 pin 字符串。TestDialTLSWithPin 和下面的
// localhost 多 IP 测试共用。
func startTLSEchoServer(t *testing.T) (int, string) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls-cert.pem")
	keyFile := filepath.Join(dir, "tls-key.pem")
	cert, err := GenerateSelfSignedCert(certFile, keyFile, "www.microsoft.com")
	if err != nil {
		t.Fatalf("生成自签证书失败：%v", err)
	}
	pin, err := SPKIPinOfCert(cert)
	if err != nil {
		t.Fatalf("算指纹失败：%v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, ServerTLSConfig(cert))
				if err := tc.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 64)
				n, err := tc.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = tc.Write(buf[:n])
			}(raw)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("端口解析失败：%v", err)
	}
	return port, FormatPIN(pin)
}

// TestDialTLSWithPinLocalhost：localhost 解析出 ::1 和 127.0.0.1 两个 IP，
// 服务只在 127.0.0.1 上。
// 正确 pin → 仍能连通（::1 的 connection refused 不能挡路）；
// 错误 pin → 报错必须提到指纹，不能被 ::1 的 connection refused 盖掉
// （C5 多 IP 循环曾只返回最后一个错误，bad-pin 的 run-tests 测试 21
// 就是这么失败的：客户端日志里只有 dial ::1 refused，没有“指纹”）。
func TestDialTLSWithPinLocalhost(t *testing.T) {
	port, pinStr := startTLSEchoServer(t)
	conn, err := DialTLSWithPin("localhost", port, "www.microsoft.com", pinStr, 5*time.Second, false)
	if err != nil {
		t.Fatalf("localhost + 正确 pin 应连通：%v", err)
	}
	conn.Close()
	wrongPin := FormatPIN(bytesRepeat(0xFF, 32))
	if _, err := DialTLSWithPin("localhost", port, "www.microsoft.com", wrongPin, 5*time.Second, false); err == nil {
		t.Fatal("localhost + 错误 pin 应被拒绝")
	} else if !strings.Contains(err.Error(), "指纹") {
		t.Fatalf("localhost + 错误 pin 的报错应提到指纹，实际：%v", err)
	}
}

// TestDialAndHandshakeWrongPinLocalhost：和上面同一场景，走
// DialAndHandshake（MM-1 拨号 + 握手，生产路径）：
// 错误 pin 时 TLS 握手先失败，返回的错必须提到指纹。
func TestDialAndHandshakeWrongPinLocalhost(t *testing.T) {
	port, _ := startTLSEchoServer(t)
	wrongPin, err := ParsePIN(FormatPIN(bytesRepeat(0xFF, 32)))
	if err != nil {
		t.Fatalf("构造错误 pin 失败：%v", err)
	}
	cfg := &LinkConfig{
		PSK: testPSK, Host: "localhost", Port: port,
		Obfs: "tls", Version: VersionV4, PIN: wrongPin, SNI: "www.microsoft.com",
	}
	if _, _, err := DialAndHandshake(cfg, false, false, false); err == nil {
		t.Fatal("localhost + 错误 pin 的 DialAndHandshake 应被拒绝")
	} else if !strings.Contains(err.Error(), "指纹") {
		t.Fatalf("localhost + 错误 pin 的报错应提到指纹，实际：%v", err)
	}
}

func TestResolveSNI(t *testing.T) {
	cases := []struct {
		cfg  *LinkConfig
		want string
	}{
		{&LinkConfig{SNI: "example.com", Host: "1.2.3.4"}, "example.com"}, // 链接里写了就用它
		{&LinkConfig{Host: "example.com"}, "example.com"},                 // host 是域名就用 host
		{&LinkConfig{Host: "47.238.255.159"}, DefaultSNI},                 // host 是 IP 就用默认常见域名
		{&LinkConfig{Host: "localhost"}, "localhost"},                     // localhost 是域名
		{&LinkConfig{}, DefaultSNI},                                       // 什么都没有就用默认
	}
	for _, tc := range cases {
		if got := ResolveSNI(tc.cfg); got != tc.want {
			t.Fatalf("ResolveSNI(%+v) = %q，想要 %q", tc.cfg, got, tc.want)
		}
	}
}
