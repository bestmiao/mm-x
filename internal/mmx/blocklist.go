// 失败握手拉黑：短时间内握手失败太多次的来源 IP，暂时拉黑。
//
// 规则（默认）：1 分钟内握手失败达到 5 次，就拉黑 10 分钟；
// 拉黑期间该 IP 的连接在 accept 后直接丢弃，不回应任何字节；
// 拉黑时间到了自动解除。
//
// 白名单：白名单里的 IP 永远不拉黑，失败也不计数——
//
//	用来放自己家的中转机（例如 realm 中转）：中转机的出口 IP 固定，
//	万一它某次握手失败被拉黑，后面所有流量都断了；放进白名单就不会发生。
//	白名单通过服务端 --whitelist / --whitelist-file 设置。
//
// 成功即信任：一个 IP 只要有过一次成功握手，就进入信任状态，之后失败
//
//	不再计入拉黑；成功握手还会把之前攒的失败计数清零，不让零星失败
//	攒着攒着就触发拉黑。只有从未成功过的 IP 才按默认规则拉黑。
//	（实现上选的是“成功后失败永不计数”，不是“阈值放宽到 50 次”——
//	私人单用户协议里，成功握手一次就足以证明这个 IP 是自己人；
//	中转机、自己的客户端一旦成功过，就不该再因为偶发失败被封。）
//
// 为什么这个阈值不误伤正常用户：
//   - 正常客户端握手失败很少连续出现——配对的密钥、版本都对，握手一次就过；
//     连续 5 次失败基本只可能是扫端口的、撞密钥的、配错了的客户端。
//   - 误伤时最多 10 分钟，且是按 IP 拉黑，不影响其他 IP；
//     拉黑事件会写进日志，机主能看到。
//   - 注意：如果用户在 NAT/CGNAT 后面和别人共用一个出口 IP，
//     别人的失败也可能连累这个 IP 被拉黑；私人单用户服务器上这点可以接受，
//     真遇到时重启服务端即可立即解除。
//   - 成功过的 IP 不会被拉黑，所以自己的客户端和中转机不用担心误伤。
package mmx

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Blocklist 记录每个来源 IP 的握手失败，触发阈值后拉黑一段时间。
type Blocklist struct {
	mu        sync.Mutex
	maxFails  int
	window    time.Duration
	duration  time.Duration
	fails     map[string][]time.Time // IP -> 窗口内的失败时间点
	blocked   map[string]time.Time   // IP -> 拉黑到期的时间
	whitelist map[string]bool        // 白名单 IP：永远不拉黑，失败也不计数
	trusted   map[string]bool        // 成功握手过的 IP：之后失败不再计数
}

// NewBlocklist 新建拉黑器：window 内失败 maxFails 次即拉黑 duration。
func NewBlocklist(maxFails int, window, duration time.Duration) *Blocklist {
	return &Blocklist{
		maxFails:  maxFails,
		window:    window,
		duration:  duration,
		fails:     make(map[string][]time.Time),
		blocked:   make(map[string]time.Time),
		whitelist: make(map[string]bool),
		trusted:   make(map[string]bool),
	}
}

// AddWhitelist 把一个 IP 加入白名单（已在拉黑中的也立即解除）。
func (b *Blocklist) AddWhitelist(ip string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.whitelist == nil {
		b.whitelist = make(map[string]bool)
	}
	b.whitelist[ip] = true
	delete(b.blocked, ip)
	delete(b.fails, ip)
}

// IsWhitelisted 查某 IP 是否在白名单里。
func (b *Blocklist) IsWhitelisted(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.whitelist[ip]
}

// IsTrusted 查某 IP 是否成功握手过（信任状态）。
func (b *Blocklist) IsTrusted(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.trusted[ip]
}

// FailCount 返回某 IP 窗口内的失败次数（测试和排障用）。
func (b *Blocklist) FailCount(ip string) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := time.Now().Add(-b.window)
	n := 0
	for _, t := range b.fails[ip] {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

// LoadWhitelistFile 从文件读白名单：每行一个 IP，空行和 # 开头的注释行跳过；
// 哪一行写得不对（不是合法 IP）就报错并指明行号，服务端启动时会直接退出，
// 避免“我以为中转机在白名单里、其实没生效”的静默错误。
func LoadWhitelistFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("白名单文件读失败：%v", err)
	}
	var ips []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip == nil {
			return nil, fmt.Errorf("白名单文件第 %d 行不是合法 IP：%q", i+1, line)
		} else {
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}

// IsBlocked 查某 IP 是否正在被拉黑；到期了自动解除。
// 白名单里的 IP 永远返回 false。
func (b *Blocklist) IsBlocked(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.whitelist[ip] {
		return false
	}
	until, ok := b.blocked[ip]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(b.blocked, ip)
	return false
}

// BlockedUntil 返回某 IP 的拉黑到期时间（没被拉黑返回零值）。
func (b *Blocklist) BlockedUntil(ip string) time.Time {
	if b == nil {
		return time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked[ip]
}

// Params 返回拉黑规则（阈值、窗口、拉黑时长），供日志使用。
func (b *Blocklist) Params() (maxFails int, window, duration time.Duration) {
	if b == nil {
		return 0, 0, 0
	}
	return b.maxFails, b.window, b.duration
}

// RecordFailure 记一次握手失败。返回 true 表示这次失败触发了拉黑。
// 白名单 IP 和已信任（成功握手过）的 IP：不计数，永远返回 false。
func (b *Blocklist) RecordFailure(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.whitelist[ip] || b.trusted[ip] {
		return false
	}
	now := time.Now()
	cutoff := now.Add(-b.window)
	kept := b.fails[ip][:0]
	for _, t := range b.fails[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	b.fails[ip] = kept
	if len(kept) >= b.maxFails {
		b.blocked[ip] = now.Add(b.duration)
		delete(b.fails, ip)
		return true
	}
	return false
}

// RecordSuccess 记一次成功握手：该 IP 进入信任状态，之后失败不再计数；
// 之前攒的失败计数清零，不让零星失败攒着攒着触发拉黑。
func (b *Blocklist) RecordSuccess(ip string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.trusted == nil {
		b.trusted = make(map[string]bool)
	}
	b.trusted[ip] = true
	delete(b.fails, ip)
}

// PurgeExpired 清掉已过期的条目（A7）：fails 里窗口外的失败时间点、
// blocked 里已到期的拉黑 IP 都删 key，map 不再只增不减。
// 服务端定期调（默认 5 分钟一次）；返回这次清掉的条目数。
// trusted（成功握手过的 IP）不清理——那是长期信任状态，不是过期数据。
func (b *Blocklist) PurgeExpired() (failsRemoved, blockedRemoved int) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-b.window)
	for ip, ts := range b.fails {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(b.fails, ip)
			failsRemoved++
		} else {
			b.fails[ip] = kept
		}
	}
	for ip, until := range b.blocked {
		if !now.Before(until) {
			delete(b.blocked, ip)
			blockedRemoved++
		}
	}
	return failsRemoved, blockedRemoved
}
