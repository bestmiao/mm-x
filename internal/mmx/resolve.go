// 服务器地址解析：域名怎么解析才可靠。
//
// 策略：
//  1. IP 地址：直接用，不解析；
//  2. 域名：先走系统 DNS（快，也支持内网/自定义域名）；系统 DNS 给了
//     198.18.0.0/15 假地址段按没解析到处理（0.1.47：被污染的解析器对
//     部分域名返回这个段的假 IP，拨过去是中间件回包，握手发不到真服务器；
//     只过滤这个从不分配给真实公网服务器的保留段，其他 IP 不动——没有
//     DNSSEC 校验就认不出别的假 IP，原型不做那一步）；
//  3. 系统 DNS 失败或只给了假 IP：自动走内置 DoH 兜底（中国大陆可达的先，
//     再走 Google / Cloudflare——后两者在中国大陆常被 GFW 阻断，
//     只靠它们时新域名（如刚解析的 eu.org 域名）解析失败，
//     转发器连一次握手都发不出去；对 DoH 服务器本身用硬编码 IP
//     直连 + SNI，不依赖本地 DNS 解析它）；DoH 返回里同样过滤假 IP；
//  4. 两次都失败才报错，提示换 IP 直连。
//
// 为什么不“走代理去解析”：mm-x 前面没有上游代理可以借——
// 客户端自己就是要去连 mm-x 服务端的，没有别的通道能替它解析。
// 为什么 DoH 只在系统 DNS 失败（或只给假 IP）时触发：个人域名被污染的
// 概率极低；真怀疑被污染时，直接用 IP 写链接最稳妥。
package mmx

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

// dohEndpoints 是 DoH 兜底的顺序：先走中国大陆可达的（阿里 DNS、
// 腾讯 DNSPod，2026-11-27 实测两者 JSON 接口都能解析 example.com，
// 硬编码 IP 直连 + SNI 也通），再走 Google、Cloudflare。
// 顺序不能反：中国大陆的运营商 DNS 解析不出新域名时，Google /
// Cloudflare 的 DoH 常被 GFW 阻断，排在前面只会白白超时。
// 注意：doh.pub 的直连 IP 只能用 120.53.53.53（DNSPod DoH 任播地址，
// 实测 443 通、SNI 校验过）；119.29.29.29 是 DNSPod 的 UDP/53 解析
// 地址，443 根本不通，写它这家兜底永远失败。
// 测试可以替换这个变量，用本地 httptest 服务器冒充 DoH 接口。
var dohEndpoints = []dohEndpoint{
	{url: "https://dns.alidns.com/resolve", dialIP: "223.5.5.5"},
	{url: "https://doh.pub/dns-query", dialIP: "120.53.53.53"},
	{url: "https://dns.google/resolve", dialIP: "8.8.8.8"},
	{url: "https://cloudflare-dns.com/dns-query", dialIP: "1.1.1.1"},
}

// systemLookup 是系统 DNS 解析（可替换，测试用：直接返回失败，
// 模拟系统 DNS 解析不出来的情况，验证 DoH 兜底分支）。
var systemLookup = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// isReservedFakeIP 是不是 198.18.0.0/15 保留假地址段：RFC 2544 基准测试
// 保留段，从不分配给真实公网服务器；劫持型 DNS（NXDOMAIN 也返回一个地址）
// 和 Fake DNS 漏出来的地址常落在这里，解析到这个段等于没解析到
// （和 Windows isReservedFakeIp / 手机 RegionResolver.isReservedFakeIp 一致）。
func isReservedFakeIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

// filterFakeIPs 滤掉解析结果里的 198.18.0.0/15 假地址，剩下的原样返回。
func filterFakeIPs(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !isReservedFakeIP(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// ResolveHost 解析服务器地址：IP 直接返回；域名先系统 DNS（假 IP 过滤），
// 失败或只给假 IP 再内置 DoH（同样过滤假 IP）。
func ResolveHost(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ips, err := systemLookup(ctx, host); err == nil && len(ips) > 0 {
		if filtered := filterFakeIPs(ips); len(filtered) > 0 {
			return filtered, nil
		}
		// 系统 DNS 只给了假 IP：按解析失败处理，往下走 DoH 兜底
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
		// 0.1.47：DoH 返回里同样过滤 198.18.0.0/15 假地址；只剩假地址时
		// 按没解析到处理，换记录类型/换一家再试。
		if filtered := filterFakeIPs(ips); len(filtered) > 0 {
			return filtered, nil
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

// DialServer 拨号到 mm-x 服务端：先解析地址（IP 直连 / 域名系统 DNS + DoH 兜底），
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
