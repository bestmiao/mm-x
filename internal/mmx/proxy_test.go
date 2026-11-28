// 上游 SOCKS5 代理拨号的单元测试：
// 假代理只实现握手 + CONNECT，记录收到的目标地址和 ATYP，
// 需要时把 CONNECT 后的连接桥接到真正的假 mm-x 服务端，
// 这样能端到端验证 DialAndHandshake 经代理拨号（含 TLS 路径）。
package mmx

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// proxyConnect 是假代理收到的一次 CONNECT 请求。
type proxyConnect struct {
	atyp byte
	host string
	port int
}

// fakeProxy 是只实现 SOCKS5 握手 + CONNECT 的假上游代理。
// bridgeTo 非空时，CONNECT 成功后把连接桥接到该地址
// （假 mm-x 服务端监听的地址），否则 CONNECT 成功后直接挂起连接
// （只验 CONNECT 目标，不跑后续流量）。
type fakeProxy struct {
	t        *testing.T
	ln       net.Listener
	bridgeTo string

	mu    sync.Mutex
	conns []proxyConnect
}

func startFakeProxy(t *testing.T, bridgeTo string) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("假代理监听失败：%v", err)
	}
	fp := &fakeProxy{t: t, ln: ln, bridgeTo: bridgeTo}
	go fp.serve()
	t.Cleanup(func() { ln.Close() })
	return fp
}

func (fp *fakeProxy) addr() string { return fp.ln.Addr().String() }

// lastConnect 返回最近一次 CONNECT 的记录（没有时 fail）。
func (fp *fakeProxy) lastConnect(t *testing.T) proxyConnect {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fp.mu.Lock()
		n := len(fp.conns)
		fp.mu.Unlock()
		if n > 0 {
			fp.mu.Lock()
			defer fp.mu.Unlock()
			return fp.conns[n-1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("假代理没收到 CONNECT")
	return proxyConnect{}
}

func (fp *fakeProxy) serve() {
	for {
		c, err := fp.ln.Accept()
		if err != nil {
			return
		}
		go fp.handle(c)
	}
}

func (fp *fakeProxy) handle(c net.Conn) {
	defer c.Close()
	// 握手：VER NMETHODS METHODS…，只接受无认证。
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 || hdr[1] == 0 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// CONNECT 请求：VER CMD RSV ATYP DST.ADDR DST.PORT。
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	fp.mu.Lock()
	fp.conns = append(fp.conns, proxyConnect{atyp: req[3], host: host, port: port})
	fp.mu.Unlock()
	// 成功回复（BND 0.0.0.0:0）。
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if fp.bridgeTo == "" {
		// 只验 CONNECT：挂起连接，等测试结束关掉。
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		return
	}
	target, err := net.DialTimeout("tcp", fp.bridgeTo, 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, target); done <- struct{}{} }()
	<-done
}

// startFakeMMXServer 起一个只做 mm-x 握手的假服务端（明文，v3），
// 返回监听地址。握手成功后关连接——DialAndHandshake 只验到握手为止。
func startFakeMMXServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("假服务端监听失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = ServerHandshakeWithKeys(c, [][]byte{testPSK})
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startFakeMMXTLSServer 起一个 TLS 包装的假服务端：先 TLS 握手
// （自签证书），再做 mm-x 握手。返回监听地址和证书 SPKI pin。
func startFakeMMXTLSServer(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls-cert.pem")
	keyFile := filepath.Join(dir, "tls-key.pem")
	cert, err := LoadOrGenerateCert(certFile, keyFile, "www.microsoft.com", true)
	if err != nil {
		t.Fatalf("生成自签证书失败：%v", err)
	}
	pin, err := SPKIPinOfCert(cert)
	if err != nil {
		t.Fatalf("算证书指纹失败：%v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("假 TLS 服务端监听失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = ServerHandshakeWithKeys(c, [][]byte{testPSK})
			}(c)
		}
	}()
	return ln.Addr().String(), pin
}

func TestDialProxyTCP_Domain(t *testing.T) {
	fp := startFakeProxy(t, "")
	conn, err := DialProxyTCP(fp.addr(), "example.com", 8443, 5*time.Second)
	if err != nil {
		t.Fatalf("经代理拨域名失败：%v", err)
	}
	defer conn.Close()
	got := fp.lastConnect(t)
	if got.atyp != 0x03 || got.host != "example.com" || got.port != 8443 {
		t.Fatalf("CONNECT 目标不对：ATYP=0x%02x host=%q port=%d，想要 ATYP=0x03 host=%q port=8443",
			got.atyp, got.host, got.port, "example.com")
	}
}

func TestDialProxyTCP_IP(t *testing.T) {
	fp := startFakeProxy(t, "")
	// IPv4。
	conn, err := DialProxyTCP(fp.addr(), "1.2.3.4", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("经代理拨 IPv4 失败：%v", err)
	}
	conn.Close()
	got := fp.lastConnect(t)
	if got.atyp != 0x01 || got.host != "1.2.3.4" || got.port != 443 {
		t.Fatalf("CONNECT 目标不对：ATYP=0x%02x host=%q port=%d，想要 ATYP=0x01 host=1.2.3.4 port=443",
			got.atyp, got.host, got.port)
	}
	// IPv6。
	conn, err = DialProxyTCP(fp.addr(), "::1", 8443, 5*time.Second)
	if err != nil {
		t.Fatalf("经代理拨 IPv6 失败：%v", err)
	}
	conn.Close()
	got = fp.lastConnect(t)
	if got.atyp != 0x04 || got.host != "::1" || got.port != 8443 {
		t.Fatalf("CONNECT 目标不对：ATYP=0x%02x host=%q port=%d，想要 ATYP=0x04 host=::1 port=8443",
			got.atyp, got.host, got.port)
	}
}

func TestDialProxyTCP_ProxyUnreachable(t *testing.T) {
	// 代理地址上没人监听：应直接报错，不 hang。
	if _, err := DialProxyTCP("127.0.0.1:1", "example.com", 443, 2*time.Second); err == nil {
		t.Fatal("代理连不上时应报错")
	}
}

// TestDialAndHandshakeViaProxy_Plaintext：明文路径经代理握手成功，
// 且 CONNECT 里域名原样发出。
// host 用本地解析不出来的域名：能握手成功就证明走了代理
// （DialAndHandshake 没在本地 ResolveHost），
// 而不是本地解析后直连。
func TestDialAndHandshakeViaProxy_Plaintext(t *testing.T) {
	serverAddr := startFakeMMXServer(t)
	_, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatalf("假服务端地址不合法：%v", err)
	}
	port, _ := strconv.Atoi(portStr)
	fp := startFakeProxy(t, serverAddr)
	cfg := &LinkConfig{
		PSK: testPSK, Host: "mmx-test.invalid", Port: port,
		Enc: "aes-256-gcm", Obfs: "tls-fake", Version: VersionV3,
		Name: "test", Burst: BurstUnset, ProxyAddr: fp.addr(),
	}
	raw, _, err := DialAndHandshake(cfg, false, false, false)
	if err != nil {
		t.Fatalf("经代理握手失败：%v", err)
	}
	raw.Close()
	got := fp.lastConnect(t)
	if got.atyp != 0x03 || got.host != "mmx-test.invalid" || got.port != port {
		t.Fatalf("CONNECT 目标不对：ATYP=0x%02x host=%q port=%d，想要 ATYP=0x03 host=mmx-test.invalid port=%d",
			got.atyp, got.host, got.port, port)
	}
}

// TestDialAndHandshakeViaProxy_TLS：TLS 路径也走代理后的 TCP 连接
// （uTLS 握手跑在代理 CONNECT 出来的连接上，pin 校验不变）。
func TestDialAndHandshakeViaProxy_TLS(t *testing.T) {
	serverAddr, pin := startFakeMMXTLSServer(t)
	_, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatalf("假服务端地址不合法：%v", err)
	}
	port, _ := strconv.Atoi(portStr)
	fp := startFakeProxy(t, serverAddr)
	cfg := &LinkConfig{
		PSK: testPSK, Host: "mmx-test.invalid", Port: port,
		Enc: "aes-256-gcm", Obfs: "tls", Version: VersionV3,
		Name: "test", Burst: BurstUnset, ProxyAddr: fp.addr(),
		SNI: "www.microsoft.com", PIN: pin,
	}
	raw, _, err := DialAndHandshake(cfg, false, false, false)
	if err != nil {
		t.Fatalf("经代理 TLS 握手失败：%v", err)
	}
	raw.Close()
	got := fp.lastConnect(t)
	if got.atyp != 0x03 || got.host != "mmx-test.invalid" || got.port != port {
		t.Fatalf("CONNECT 目标不对：ATYP=0x%02x host=%q port=%d，想要 ATYP=0x03 host=mmx-test.invalid port=%d",
			got.atyp, got.host, got.port, port)
	}
}

// TestDialAndHandshakeNoProxyUnchanged：无代理时行为不变
// （直连假服务端握手成功；这是回归测试，改动不应影响直连路径）。
func TestDialAndHandshakeNoProxyUnchanged(t *testing.T) {
	serverAddr := startFakeMMXServer(t)
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatalf("假服务端地址不合法：%v", err)
	}
	port, _ := strconv.Atoi(portStr)
	cfg := &LinkConfig{
		PSK: testPSK, Host: host, Port: port,
		Enc: "aes-256-gcm", Obfs: "tls-fake", Version: VersionV3,
		Name: "test", Burst: BurstUnset,
	}
	raw, _, err := DialAndHandshake(cfg, false, false, false)
	if err != nil {
		t.Fatalf("无代理直连握手失败：%v", err)
	}
	raw.Close()
}
