// 连接白名单：只允许白名单里的 IP 连接服务端。
//
// 和拉黑白名单（blocklist.go）的区别，别混在一起：
//   - 拉黑白名单：IP 在里面 = 永远不拉黑（失败也不计数），但谁都能连；
//   - 连接白名单：IP 在里面 = 才允许连，不在里面 = 连接在握手之前就直接
//     丢弃、不回任何字节。默认关闭（一个都没填 = 谁都能连）。
//
// 白名单不是代替密钥：白名单里的 IP 仍要过正常的 MM-1 握手和密钥校验，
// 密钥不对照样拒绝；白名单只是多一层——随机扫描、撞端口的连握手都到不了。
// 所以它防的是“随机扫描、探测连不上”，不防“白名单 IP 被盗用、密钥泄露”
// （密钥泄露还是要靠密钥轮换，见 keymanager.go）。
//
// 注意：入口是机场节点时，机场的出口 IP 可能会变、还可能是多人共用的，
// 填单个 IP 容易把自己挡在外面；这种情况建议填机场出口 IP 段（CIDR，
// 例如 1.2.3.0/24），或者入口改用自己的 VPS（固定 IP）。
package mm1

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Allowlist 是连接白名单：空的 = 关闭（谁都能连）；非空 = 只允许里面的 IP。
type Allowlist struct {
	mu   sync.RWMutex
	ips  map[string]bool // 单个 IP（归一化后的字符串）
	nets []*net.IPNet    // CIDR 段
}

// NewAllowlist 新建空的连接白名单（默认关闭）。
func NewAllowlist() *Allowlist {
	return &Allowlist{ips: make(map[string]bool)}
}

// Add 加一条白名单：单个 IP 或 CIDR 段（例如 1.2.3.0/24）；写错了返回中文错。
func (a *Allowlist) Add(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return fmt.Errorf("白名单条目是空的")
	}
	if ip := net.ParseIP(entry); ip != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.ips == nil {
			a.ips = make(map[string]bool)
		}
		a.ips[ip.String()] = true
		return nil
	}
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.nets = append(a.nets, ipnet)
		return nil
	}
	return fmt.Errorf("白名单条目不合法：%q，应为单个 IP 或 CIDR 段（例如 1.2.3.0/24）", entry)
}

// Enabled 白名单是否开启（至少填了一条）。
func (a *Allowlist) Enabled() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.ips) > 0 || len(a.nets) > 0
}

// Contains 查某 IP 是否允许连接：白名单关闭时任何 IP 都允许；
// 开启时只有里面的单个 IP 或落在 CIDR 段里的 IP 才允许。
func (a *Allowlist) Contains(ipStr string) bool {
	if a == nil {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.ips) == 0 && len(a.nets) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if a.ips[ip.String()] {
		return true
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Count 返回白名单条目数（单个 IP 数 + CIDR 段数），供日志使用。
func (a *Allowlist) Count() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.ips) + len(a.nets)
}

// LoadAllowlistFile 从文件读连接白名单：每行一个 IP 或 CIDR，
// 空行和 # 开头的注释行跳过；哪一行写得不对就报错并指明行号，
// 服务端启动时会直接退出，避免“我以为中转机在白名单里、其实没生效”的静默错误。
func LoadAllowlistFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("连接白名单文件读失败：%v", err)
	}
	var entries []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) == nil {
			if _, _, err := net.ParseCIDR(line); err != nil {
				return nil, fmt.Errorf("连接白名单文件第 %d 行不合法：%q，应为单个 IP 或 CIDR 段（例如 1.2.3.0/24）", i+1, line)
			}
		}
		entries = append(entries, line)
	}
	return entries, nil
}
