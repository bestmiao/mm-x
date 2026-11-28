package mmx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// IP 地址直接返回，不解析。
func TestResolveHostIP(t *testing.T) {
	ips, err := ResolveHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("IP 应原样返回，实际 %v", ips)
	}
	ips, err = ResolveHost("::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "::1" {
		t.Fatalf("IPv6 应原样返回，实际 %v", ips)
	}
}

// localhost 走系统 DNS 就能解析出来（不依赖 DoH）。
func TestResolveHostLocalhost(t *testing.T) {
	ips, err := ResolveHost("localhost")
	if err != nil {
		t.Fatalf("localhost 应能解析：%v", err)
	}
	found := false
	for _, ip := range ips {
		if ip == "127.0.0.1" || ip == "::1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("localhost 应解析出 127.0.0.1 或 ::1，实际 %v", ips)
	}
}

// DoH JSON 接口解析：用本地 httptest 服务器冒充 DoH，
// 返回一条 A 记录；验证 A 记录能取出来、没有 A 时会接着查 AAAA。
func TestResolveViaDoH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "A" {
			fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"203.0.113.9"}]}`)
			return
		}
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"example.com.","type":28,"TTL":300,"data":"2001:db8::1"}]}`)
	}))
	defer srv.Close()
	ep := dohEndpoint{url: srv.URL + "/resolve", dialIP: "127.0.0.1"}
	ips, err := resolveViaDoH("example.com", ep)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("DoH 应返回 A 记录 203.0.113.9，实际 %v", ips)
	}
	// A 记录为空时查 AAAA
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "A" {
			fmt.Fprint(w, `{"Status":0,"Answer":[]}`)
			return
		}
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"example.com.","type":28,"TTL":300,"data":"2001:db8::1"}]}`)
	}))
	defer srv2.Close()
	ep2 := dohEndpoint{url: srv2.URL + "/resolve", dialIP: "127.0.0.1"}
	ips, err = resolveViaDoH("example.com", ep2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("A 为空时应返回 AAAA 记录 2001:db8::1，实际 %v", ips)
	}
}

// 系统 DNS 失败时走 DoH 兜底：把系统解析换成直接失败（模拟解析不出来），
// 再把 dohEndpoints 换成本地假 DoH。注意：沙箱的 DNS 会把不存在的域名也
// “解析”成 198.18.x.x，所以不用真域名测，必须用 systemLookup 注入失败。
func TestResolveHostDoHFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"test.invalid.","type":1,"TTL":300,"data":"203.0.113.9"}]}`)
	}))
	defer srv.Close()
	oldLookup := systemLookup
	systemLookup = func(ctx context.Context, host string) ([]string, error) {
		return nil, fmt.Errorf("模拟系统 DNS 失败")
	}
	defer func() { systemLookup = oldLookup }()
	old := dohEndpoints
	dohEndpoints = []dohEndpoint{{url: srv.URL + "/resolve", dialIP: "127.0.0.1"}}
	defer func() { dohEndpoints = old }()
	ips, err := ResolveHost("test.invalid")
	if err != nil {
		t.Fatalf("系统 DNS 失败后应走 DoH 兜底：%v", err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("DoH 兜底应返回 203.0.113.9，实际 %v", ips)
	}
}

// 系统 DNS 只给假 IP（198.18.0.0/15）时按解析失败处理，走 DoH 兜底拿真 IP。
// （沙箱的 DNS 会把不存在的域名也“解析”成 198.18.x.x，所以用注入桩。）
func TestResolveHostFiltersFakeIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"test.invalid.","type":1,"TTL":300,"data":"203.0.113.9"}]}`)
	}))
	defer srv.Close()
	oldLookup := systemLookup
	systemLookup = func(ctx context.Context, host string) ([]string, error) {
		return []string{"198.18.0.24"}, nil
	}
	defer func() { systemLookup = oldLookup }()
	old := dohEndpoints
	dohEndpoints = []dohEndpoint{{url: srv.URL + "/resolve", dialIP: "127.0.0.1"}}
	defer func() { dohEndpoints = old }()
	ips, err := ResolveHost("test.invalid")
	if err != nil {
		t.Fatalf("系统 DNS 只给假 IP 时应走 DoH 兜底：%v", err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("DoH 兜底应返回 203.0.113.9，实际 %v", ips)
	}
}

// 系统 DNS 混着真假 IP 时只滤掉假的、真 IP 直接用，不走 DoH。
func TestResolveHostSystemMixedFakeAndReal(t *testing.T) {
	oldLookup := systemLookup
	systemLookup = func(ctx context.Context, host string) ([]string, error) {
		return []string{"198.18.0.24", "203.0.113.5"}, nil
	}
	defer func() { systemLookup = oldLookup }()
	old := dohEndpoints
	// DoH 换成必定失败的接口：要是还走 DoH，这里就会报错
	dohEndpoints = []dohEndpoint{{url: "http://127.0.0.1:1/resolve", dialIP: "127.0.0.1"}}
	defer func() { dohEndpoints = old }()
	ips, err := ResolveHost("test.invalid")
	if err != nil {
		t.Fatalf("系统 DNS 里有真 IP 时不应走 DoH：%v", err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.5" {
		t.Fatalf("应只返回真 IP 203.0.113.5，实际 %v", ips)
	}
}

// 系统 DNS 失败、DoH 也只给假 IP 时应报错，不拿假 IP 去拨号。
func TestResolveHostFakeIPOnlyFromDoH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"test.invalid.","type":1,"TTL":300,"data":"198.18.0.24"}]}`)
	}))
	defer srv.Close()
	oldLookup := systemLookup
	systemLookup = func(ctx context.Context, host string) ([]string, error) {
		return nil, fmt.Errorf("模拟系统 DNS 失败")
	}
	defer func() { systemLookup = oldLookup }()
	old := dohEndpoints
	dohEndpoints = []dohEndpoint{{url: srv.URL + "/resolve", dialIP: "127.0.0.1"}}
	defer func() { dohEndpoints = old }()
	if _, err := ResolveHost("test.invalid"); err == nil {
		t.Fatal("DoH 只给假 IP 时应报错")
	}
}

// DoH 的 A 记录只给假 IP 时换 AAAA 再试，不拿假 IP 返回。
func TestResolveViaDoHFiltersFakeIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "A" {
			fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"198.18.0.24"}]}`)
			return
		}
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"example.com.","type":28,"TTL":300,"data":"2001:db8::1"}]}`)
	}))
	defer srv.Close()
	ep := dohEndpoint{url: srv.URL + "/resolve", dialIP: "127.0.0.1"}
	ips, err := resolveViaDoH("example.com", ep)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("A 记录只有假 IP 时应返回 AAAA 记录 2001:db8::1，实际 %v", ips)
	}
}

// DialServer：IP 和域名（localhost）都能拨通本地监听端口；拨不通的端口报中文错。
func TestDialServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c, err := DialServer("127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("DialServer 拨 127.0.0.1 应成功：%v", err)
	}
	c.Close()
	c, err = DialServer("localhost", port, 2*time.Second)
	if err != nil {
		t.Fatalf("DialServer 拨 localhost 应成功：%v", err)
	}
	c.Close()
	_, err = DialServer("127.0.0.1", 1, time.Second)
	if err == nil {
		t.Fatal("拨不通的端口应报错")
	}
	t.Logf("拨不通时的报错（应是中文）：%v", err)
}
