// 目标地址过滤（SSRF 防护）的单元测试。
package mm1

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCheckTargetAllowed(t *testing.T) {
	// 公网地址：放行。
	for _, target := range []string{
		"8.8.8.8:443",
		"1.1.1.1:80",
		"203.208.49.65:443",
		"[2606:4700:4700::1111]:443",
		"[240d:c040:1:40::157]:443",
	} {
		if err := CheckTargetAllowed(target, false); err != nil {
			t.Errorf("公网目标 %s 应被放行，实际被拒绝：%v", target, err)
		}
	}
	// 内网 / 保留地址：拒绝（必须包着 ErrTargetNotAllowed）。
	for _, target := range []string{
		"127.0.0.1:18082",         // 回环
		"[::1]:80",                // 回环 IPv6
		"10.0.0.1:80",             // RFC1918
		"172.16.0.1:80",           // RFC1918
		"172.31.255.255:80",       // RFC1918
		"192.168.1.1:80",          // RFC1918
		"100.64.0.1:80",           // CGNAT 共享地址段
		"169.254.169.254:80",      // 链路本地 = 云元数据地址（阿里云上能拿实例凭证）
		"169.254.10.20:80",        // 链路本地
		"224.0.0.1:80",            // 组播
		"[ff02::1]:80",            // 组播 IPv6
		"[fc00::1]:80",            // ULA 内网
		"[fd00::1]:80",            // ULA 内网
		"[fe80::1]:80",            // 链路本地 IPv6
		"0.0.0.0:80",              // 未指定
		"0.0.0.1:80",              // 0.0.0.0/8（本网络）
		"255.255.255.255:80",      // 广播
		"localhost:80",            // 域名解析到回环地址
		"[::ffff:192.168.1.1]:80", // IPv4 映射的 IPv6：套一层 IPv6 也绕不过去
		"192.0.2.1:80",            // 文档地址段
		"198.51.100.1:80",         // 文档地址段
		"203.0.113.1:80",          // 文档地址段
	} {
		err := CheckTargetAllowed(target, false)
		if err == nil {
			t.Errorf("目标 %s 应被拒绝，实际被放行", target)
			continue
		}
		if !errors.Is(err, ErrTargetNotAllowed) {
			t.Errorf("目标 %s 的拒绝错误应包着 ErrTargetNotAllowed，实际：%v", target, err)
		}
	}
	// 格式错误也拒绝。
	for _, target := range []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:abc"} {
		if err := CheckTargetAllowed(target, false); err == nil {
			t.Errorf("目标 %q 格式不对，应被拒绝", target)
		}
	}
	// --allow-private 时内网目标放行（只校验格式）。
	for _, target := range []string{"127.0.0.1:18082", "10.0.0.1:80", "169.254.169.254:80"} {
		if err := CheckTargetAllowed(target, true); err != nil {
			t.Errorf("allowPrivate 时目标 %s 应被放行，实际被拒绝：%v", target, err)
		}
	}
}

func TestDialTarget(t *testing.T) {
	// 本机起一个监听：allowPrivate=true 能拨通，默认拒绝（且不拨号）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败：%v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	target := ln.Addr().String()

	c, err := DialTarget("tcp", target, 5*time.Second, true)
	if err != nil {
		t.Fatalf("allowPrivate 时拨本机目标应成功：%v", err)
	}
	c.Close()

	_, err = DialTarget("tcp", target, 5*time.Second, false)
	if err == nil {
		t.Fatal("默认时拨本机目标应被拒绝")
	}
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("拒绝错误应包着 ErrTargetNotAllowed，实际：%v", err)
	}
	// 拒绝发生在拨号之前：错误文本里不应出现拨号失败的字样。
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("过滤拒绝不应走到拨号：%v", err)
	}
}
