// 目标地址过滤（SSRF 防护）：服务端只替客户端拨公网目标。
// 没有这层时，拿到密钥的人能让服务端去拨内网地址、回环地址、
// 链路本地地址——包括云元数据地址 169.254.169.254，
// 在阿里云上能拿到实例凭证。密钥一旦泄露，危害就从“别人蹭带宽”
// 变成“别人进了这台 VPS 的内网”。
//
// 默认只允许公网单播地址；--allow-private 显式放开（极少数
// 需要经代理访问内网服务的场景，默认绝不开）。
// 域名目标要把解析出的每个 IP 都验一遍：只要有一个是内网/保留地址
// 就拒绝——否则解析结果里混一个内网 IP，拨号时就可能正好拨中它。
package mmx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ErrTargetNotAllowed 是目标地址被过滤器拒绝时的错误。
// 拨号侧（serveV2 / serveMuxTCP / serveMuxUDP）把它原样写进 ACK，
// 客户端看到 "[目标不允许] …"，和普通拨号失败区分开。
var ErrTargetNotAllowed = errors.New("目标地址不允许")

// isPublicIP 判断一个 IP 是不是公网单播地址。
// 拒绝的范围：未指定、回环、组播、链路本地（含云元数据 169.254.169.254）、
// 内网（RFC1918、100.64/10、ULA fc00::/7）、0.0.0.0/8（本网络）、
// 240.0.0.0/4（保留）、文档地址段（TEST-NET，不可路由）。
// IPv4 映射的 IPv6 地址（::ffff:192.168.1.1）先 To4() 归一化再判，
// 不会因为套一层 IPv6 就绕过去。
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	if len(ip) == net.IPv4len {
		// 0.0.0.0/8（本网络，如 0.0.0.1）、240.0.0.0/4（保留段）、
		// 100.64.0.0/10（CGNAT 共享地址段——注意 Go 的 IsPrivate 不含它，
		// 得单列）、192.0.0.0/24（IETF 协议分配）、198.18.0.0/15
		//（基准测试段，不可路由——沙箱出口代理 198.19.0.1 就在这个段里）、
		// 文档地址段 192.0.2.0/24、198.51.100.0/24、203.0.113.0/24。
		if ip[0] == 0 || ip[0] >= 240 {
			return false
		}
		if ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127 {
			return false
		}
		if (ip[0] == 192 && ip[1] == 0 && ip[2] == 0) ||
			(ip[0] == 198 && ip[1] >= 18 && ip[1] <= 19) ||
			(ip[0] == 192 && ip[1] == 0 && ip[2] == 2) ||
			(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) ||
			(ip[0] == 203 && ip[1] == 0 && ip[2] == 113) {
			return false
		}
		return true
	}
	if len(ip) == net.IPv6len {
		// IPv6 文档地址 2001:db8::/32。
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
			return false
		}
		return ip.IsGlobalUnicast()
	}
	return false
}

// resolveTargetIPs 把目标主机解析成 IP 列表。
// IP 字面量直接用（不走 DNS）；域名用系统 DNS 解析，超时 5 秒。
func resolveTargetIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("域名 %s 解析出 0 个地址", host)
	}
	return ips, nil
}

// CheckTargetAllowed 校验一个 "host:port" 目标：
// allowPrivate=true 时只校验格式（端口合法），什么地址都放行；
// 默认时解析出的每个 IP 都必须是公网地址，否则拒绝。
// 注意：解析和拨号之间有时间差（TOCTOU）——只校验不解决重绑问题，
// 真正拨号请用 DialTarget（它拨的就是校验过的那个 IP）。
func CheckTargetAllowed(target string, allowPrivate bool) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("%w：目标地址 %q 格式不对（应为 host:port）：%v", ErrTargetNotAllowed, target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w：目标端口 %q 不合法", ErrTargetNotAllowed, portStr)
	}
	if allowPrivate {
		return nil
	}
	ips, err := resolveTargetIPs(host)
	if err != nil {
		return fmt.Errorf("%w：目标 %q 解析失败：%v", ErrTargetNotAllowed, host, err)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("%w：目标 %q 解析到非公网地址 %s（内网/保留地址不允许经代理访问）", ErrTargetNotAllowed, host, ip.String())
		}
	}
	return nil
}

// DialTarget 校验并拨号：先解析目标、验每个 IP 都是公网地址，
// 再拨第一个校验过的 IP（不用主机名重拨，避免解析和拨号之间
// 目标被换掉）。allowPrivate=true 时跳过校验（--allow-private）。
func DialTarget(network, target string, timeout time.Duration, allowPrivate bool) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("%w：目标地址 %q 格式不对（应为 host:port）：%v", ErrTargetNotAllowed, target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w：目标端口 %q 不合法", ErrTargetNotAllowed, portStr)
	}
	ips, err := resolveTargetIPs(host)
	if err != nil {
		return nil, fmt.Errorf("目标 %q 解析失败：%v", host, err)
	}
	if !allowPrivate {
		for _, ip := range ips {
			if !isPublicIP(ip) {
				return nil, fmt.Errorf("%w：目标 %q 解析到非公网地址 %s（内网/保留地址不允许经代理访问）", ErrTargetNotAllowed, host, ip.String())
			}
		}
	}
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		c, err := net.DialTimeout(network, addr, timeout)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("连接目标 %s 失败：%v", target, lastErr)
}
