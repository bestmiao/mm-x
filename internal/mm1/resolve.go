// 服务器地址解析：域名怎么解析才可靠。
//
// 策略（写进 PROTOCOL.md 的“IP 还是域名”一节）：
//  1. IP 地址：直接用，不解析；
//  2. 域名：先走系统 DNS（快，也支持内网/自定义域名）；
//  3. 系统 DNS 失败：自动走内置 DoH 兜底（Google → Cloudflare，
//     对 DoH 服务器本身用硬编码 IP 直连 + SNI，不依赖本地 DNS 解析它）；
//  4. 两次都失败才报错，提示换 IP 直连。
//
// 为什么不“走代理去解析”：MM-1 前面没有上游代理可以借——
// 客户端自己就是要去连 MM-1 服务端的，没有别的通道能替它解析。
// 为什么 DoH 只在系统 DNS 失败时触发：个人域名被污染的概率极低，
// 污染返回的是错误 IP 不是解析失败，DoH 也防不住那种情况（除非做
// DNSSEC 校验，原型不做）；真怀疑被污染时，直接用 IP 写链接最稳妥。
package mm1

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dohEndpoint 是一家 DoH JSON 接口：url 是接口地址，dialIP 是直连它的 IP
// （不走本地 DNS 解析这个域名本身，否则 DoH 自己也要先解析）。
type dohEndpoint struct {
	url    string
	dialIP string
}

// dohEndpoints 是 DoH 兜底的顺序：Google 先，Cloudflare 后。
// 测试可以替换这个变量，用本地 httptest 服务器冒充 DoH 接口。
var dohEndpoints = []dohEndpoint{
	{url: "https://dns.google/resolve", dialIP: "8.8.8.8"},
	{url: "https://cloudflare-dns.com/dns-query", dialIP: "1.1.1.1"},
}

// systemLookup 是系统 DNS 解析（可替换，测试用：直接返回失败，
// 模拟系统 DNS 解析不出来的情况，验证 DoH 兜底分支）。
var systemLookup = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// ResolveHost 解析服务器地址：IP 直接返回；域名先系统 DNS，失败再内置 DoH。
func ResolveHost(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ips, err := systemLookup(ctx, host); err == nil && len(ips) > 0 {
		return ips, nil
	}
	var lastErr error
	for _, ep := range dohEndpoints {
		ips, err := resolveViaDoH(host, ep)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("解析域名 %s 失败：系统 DNS 和内置 DoH 都没解析出来（%v），换 IP 直连试试", host, lastErr)
}

// dohJSONResponse 是 DoH JSON 接口（dns.google/resolve、
// cloudflare-dns.com/dns-query + Accept: application/dns-json）的返回格式。
type dohJSONResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// resolveViaDoH 用一家 DoH JSON 接口解析域名：先查 A 记录，没有再查 AAAA。
// 对 https 接口用硬编码 IP 直连 + SNI（不经过本地 DNS）；http 接口只用于测试。
func resolveViaDoH(name string, ep dohEndpoint) ([]string, error) {
	u, err := parseDoHEndpoint(ep.url)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(ep.dialIP, u.port))
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				raw, err := d.DialContext(ctx, network, net.JoinHostPort(ep.dialIP, u.port))
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, &tls.Config{ServerName: u.host, MinVersion: tls.VersionTLS12})
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
	for _, qtype := range []string{"A", "AAAA"} {
		reqURL := fmt.Sprintf("%s?name=%s&type=%s", strings.TrimSuffix(ep.url, "/"), name, qtype)
		req, err := http.NewRequestWithContext(context.Background(), "GET", reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("DoH 请求失败：%v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("DoH 响应读取失败：%v", err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("DoH 返回 HTTP %d", resp.StatusCode)
		}
		var r dohJSONResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("DoH 响应解析失败：%v", err)
		}
		if r.Status != 0 {
			continue // 这家没解析出来（域名不存在等），换记录类型再试一次
		}
		var ips []string
		for _, a := range r.Answer {
			if ip := net.ParseIP(strings.Trim(a.Data, `"`)); ip != nil {
				ips = append(ips, ip.String())
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("DoH 没有返回 %s 的地址记录", name)
}

type dohURL struct {
	host string
	port string
}

// parseDoHEndpoint 从 DoH 接口地址里取 host 和端口（没写端口时 https=443、http=80）。
func parseDoHEndpoint(rawurl string) (dohURL, error) {
	u := dohURL{}
	rest := strings.TrimPrefix(rawurl, "https://")
	scheme := "https"
	if rest == rawurl {
		rest = strings.TrimPrefix(rawurl, "http://")
		scheme = "http"
		if rest == rawurl {
			return u, fmt.Errorf("DoH 接口地址不合法：%q，应以 https:// 或 http:// 开头", rawurl)
		}
	}
	hostport := strings.SplitN(rest, "/", 2)[0]
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
		p = ""
	}
	if p == "" {
		p = "443"
		if scheme == "http" {
			p = "80"
		}
	}
	u.host = h
	u.port = p
	return u, nil
}

// DialServer 拨号到 MM-1 服务端：先解析地址（IP 直连 / 域名系统 DNS + DoH 兜底），
// 再按解析出的 IP 逐个拨，第一个通的就用。失败返回中文原因。
func DialServer(host string, port int, timeout time.Duration) (net.Conn, error) {
	ips, err := ResolveHost(host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("连接服务端 %s:%d 失败：%v", host, port, lastErr)
}
