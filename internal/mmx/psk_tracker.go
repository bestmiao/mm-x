// PSK 泄露检测：同一密钥同时从两个 IP 使用时告警（单用户服务端，
// 正常情况下一个 PSK 同一时间只会从 Asam 自己的一个 IP 连进来）。
//
// 设计：按 (密钥指纹, 来源 IP) 计 live 会话数。
//   - 握手成功时 Record(+1)，会话结束时 End(-1)，计数归零就删条目。
//   - 某密钥指纹下出现第 2 个有 live 会话的不同 IP，就告警。
//
// 为什么不用“10 分钟 lastSeen 时间窗口”：
//   - 时间窗口分不清“同时在线”和“先后上线”——手机换网（WiFi→5G、
//     移动网络重连）换 IP 后 60 秒内重连一次就会误报；
//   - live 计数只在两个 IP 的会话真正重叠时才告警，干净重连
//     （旧会话已断）不会触发，误报最少。
//   - End 的接线不侵入：serveMMX 里握手成功后一个 defer 就覆盖
//     v2 和 v3/v4/v5 两条路（两条路都从 serveMMX 返回），
//     漏调 End 的唯一可能是会话 goroutine 泄漏，而会话都有
//     空闲超时/底层连接关闭兜底，serveMMX 总会返回。
// 残留误报：换网时旧会话还没超时断开（半开 TCP）就从新 IP 连上，
// 会误报一次——告警文本写“可能泄露”且每密钥每分钟最多一条，
// 日志里同时印出两个 IP，Asam 自己能一眼认出是不是他自己的换网。
//
// 并发与性能：握手路径上只做 map 操作（一次短互斥锁），无 I/O、
// 无阻塞调用；告警日志在放锁之后打，不占握手路径。
package mmx

import (
	"crypto/sha256"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// leakAlertInterval 是同一密钥指纹两次告警之间的最小间隔，
// 防泄露者持续连接把日志刷爆。
const leakAlertInterval = time.Minute

// KeyFingerprint 返回 PSK 的指纹：SHA-256 的前 8 位十六进制。
// 日志里只出现指纹，永远不出现 PSK 本身。
func KeyFingerprint(psk []byte) string {
	sum := sha256.Sum256(psk)
	return fmt.Sprintf("%x", sum[:4])
}

// PSKLeakTracker 按密钥指纹跟踪各来源 IP 的 live 会话数。
// 零值不可用，请用 NewPSKLeakTracker。
type PSKLeakTracker struct {
	mu sync.Mutex
	// keyID（密钥指纹）-> 来源 IP -> 该 IP 的 live 会话数。
	sessions map[string]map[string]int
	// keyID -> 上次告警时间（限流用）。
	lastAlert map[string]time.Time
	// onAlert 是告警回调；nil 时默认打一条警告日志。
	// 测试可注入回调来捕获告警。
	onAlert func(keyID string, ips []string)
}

// NewPSKLeakTracker 新建一个 PSK 泄露检测器（默认告警打日志）。
func NewPSKLeakTracker() *PSKLeakTracker {
	t := &PSKLeakTracker{
		sessions:  make(map[string]map[string]int),
		lastAlert: make(map[string]time.Time),
	}
	t.onAlert = t.logAlert
	return t
}

// logAlert 是默认告警：一条醒目的警告日志，带密钥指纹和两个 IP。
// 格式：警告：同一密钥同时从多个 IP 使用（可能泄露），密钥指纹=xxxxxxxx，IP=[a b]
func (t *PSKLeakTracker) logAlert(keyID string, ips []string) {
	log.Printf("警告：同一密钥同时从多个 IP 使用（可能泄露），密钥指纹=%s，IP=%v", keyID, ips)
}

// Record 登记一条用 psk 握手成功、来自 ip 的新会话。
// 登记后该密钥同时有 ≥2 个不同 IP 的 live 会话，且距上次告警
// 已过 leakAlertInterval，就触发一次告警（锁外回调，不占握手路径）。
func (t *PSKLeakTracker) Record(psk []byte, ip string) {
	if t == nil || len(psk) == 0 || ip == "" {
		return
	}
	keyID := KeyFingerprint(psk)
	now := time.Now()

	t.mu.Lock()
	byIP := t.sessions[keyID]
	if byIP == nil {
		byIP = make(map[string]int)
		t.sessions[keyID] = byIP
	}
	byIP[ip]++
	// 只有“新出现第 2 个 IP”才可能是泄露：同一 IP 多会话不告警。
	if len(byIP) < 2 {
		t.mu.Unlock()
		return
	}
	if !now.After(t.lastAlert[keyID].Add(leakAlertInterval)) {
		t.mu.Unlock()
		return
	}
	t.lastAlert[keyID] = now
	ips := make([]string, 0, len(byIP))
	for otherIP := range byIP {
		ips = append(ips, otherIP)
	}
	sort.Strings(ips)
	cb := t.onAlert
	t.mu.Unlock()
	if cb != nil {
		cb(keyID, ips)
	}
}

// End 登记一条会话结束：对应 (psk, ip) 的 live 计数 -1，
// 归零删 IP 条目，某密钥下再无 IP 时删密钥条目（不留垃圾）。
// 多调一次也不会把计数减成负数。
func (t *PSKLeakTracker) End(psk []byte, ip string) {
	if t == nil || len(psk) == 0 || ip == "" {
		return
	}
	keyID := KeyFingerprint(psk)

	t.mu.Lock()
	defer t.mu.Unlock()
	byIP := t.sessions[keyID]
	if byIP == nil {
		return
	}
	if byIP[ip] <= 1 {
		delete(byIP, ip)
	} else {
		byIP[ip]--
	}
	if len(byIP) == 0 {
		delete(t.sessions, keyID)
	}
}
