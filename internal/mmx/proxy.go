// 上游 SOCKS5 代理拨号（mm-x 链式代理用）。
//
// 背景：手机客户端用 sing-box detour 做链式时，出口 outbound 的
// detour=入口 tag；每个 mm-x 节点是 SOCKS 出站 → 本机回环转发器，
// 转发器直连自己服务器。detour 让入口服务器去拨手机本机的
// 127.0.0.1，根本连不到，所以 mm-x 链式是坏的。
// 修复：出口转发器拨出口服务器时经入口转发器（SOCKS5 代理）出去，
// 即本文件 DialProxyTCP；DialAndHandshake 在 cfg.ProxyAddr 非空时
// 用它代替直连（见 mux.go 的 dialAndHandshakeViaProxy）。
package mmx

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DialProxyTCP 经 SOCKS5 上游代理拨到目标：握手（无认证）+ CONNECT。
// host 是域名时原样发进 CONNECT（ATYP 0x03），由代理端解析；
// 是 IP 时发 IP（IPv4 ATYP 0x01，IPv6 ATYP 0x04）。
// 返回已接通目标的 TCP 连接：之后的上层步骤（TLS 包装、mm-x 握手）
// 都跑在这条连接上，和直连时完全一致。
func DialProxyTCP(proxyAddr, host string, port int, timeout time.Duration) (net.Conn, error) {
	if proxyAddr == "" {
		return nil, fmt.Errorf("上游代理地址为空")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("目标端口不合法：%d", port)
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("连接上游代理 %s 失败：%v", proxyAddr, err)
	}
	// 握手和 CONNECT 都限在 timeout 内；成功返回的连接上不留 deadline。
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	// 握手：只报无认证（0x00）。
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("上游代理握手失败：%v", err)
	}
	ver := make([]byte, 2)
	if _, err := io.ReadFull(conn, ver); err != nil {
		conn.Close()
		return nil, fmt.Errorf("读上游代理握手回复失败：%v", err)
	}
	if ver[0] != 0x05 || ver[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("上游代理不支持无认证（VER=0x%02x METHOD=0x%02x）", ver[0], ver[1])
	}

	// CONNECT 请求：VER CMD RSV + 目标地址 + 端口。
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("目标域名长度不合法：%q", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("向上游代理发 CONNECT 失败：%v", err)
	}

	// 回复：VER REP RSV ATYP BND.ADDR BND.PORT。
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("读上游代理 CONNECT 回复失败：%v", err)
	}
	if hdr[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("上游代理 CONNECT 回复版本不对（VER=0x%02x）", hdr[0])
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("上游代理拒绝连接目标（REP=0x%02x）", hdr[1])
	}
	// 按 ATYP 读掉 BND.ADDR + BND.PORT（不用，只用来对齐流）。
	var bndLen int64
	switch hdr[3] {
	case 0x01:
		bndLen = 4 + 2
	case 0x04:
		bndLen = 16 + 2
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			conn.Close()
			return nil, fmt.Errorf("读上游代理 CONNECT 回复地址失败：%v", err)
		}
		bndLen = int64(lb[0]) + 2
	default:
		conn.Close()
		return nil, fmt.Errorf("上游代理 CONNECT 回复地址类型不支持（ATYP=0x%02x）", hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, bndLen); err != nil {
		conn.Close()
		return nil, fmt.Errorf("读上游代理 CONNECT 回复地址失败：%v", err)
	}
	return conn, nil
}

// socksAddrString 把 SOCKS5 地址拼成 "host:port"（测试和日志用）。
func socksAddrString(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
