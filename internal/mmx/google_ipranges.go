// 谷歌 IP 段白名单：让 mmx-server 认出“这个 IP 是谷歌的”。
//
// 背景：白名单（DOMAIN_WHITELIST=google）原来只认域名。TUN 模式下
// 客户端（sing-box）先把域名解析成 IP 再交给代理，服务端看到的
// 只是个裸 IP，分不清是不是谷歌的，只能一律拒绝——TUN + 谷歌白名单
// 就全断网。系统代理模式不受影响，因为域名是原样传过来的。
//
// 解决办法：服务端拿谷歌公布的 IP 段列表（goog.json，132 个 IPv4
// 段 + 16 个 IPv6 段），IP 字面量目标落在谷歌段内就放行。
// 这样 TUN 下 youtube、google 解析出来的真实谷歌 IP 能通过，
// 非谷歌的 IP 照样拦，免费额度不会被别的流量吃掉。
//
// 加载策略：启动时先装内置快照（立刻可用，启动不被网络拖住），
// 再后台拉取在线列表并每 24h 刷新一次；拉取失败就保留旧的，
// 绝不因为更新失败把白名单弄坏。
package mmx

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// googleIPRangesURL 是谷歌公布的 IP 段列表。
const googleIPRangesURL = "https://www.gstatic.com/ipranges/goog.json"

// googleIPRanges 保存当前生效的谷歌 IP 段。
type googleIPRangesStore struct {
	mu       sync.RWMutex
	prefixes []netip.Prefix
	source   string // "embedded"（内置快照）或 "online"（在线拉取）
}

var googleIPRanges = &googleIPRangesStore{}

func (s *googleIPRangesStore) set(pres []netip.Prefix, src string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefixes = pres
	s.source = src
}

// parseGoogleIPRanges 解析 goog.json，返回前缀列表。
// 非法条目直接跳过（不让一个坏条目毁掉整张表）；一个可用前缀
// 都没有才报错。
func parseGoogleIPRanges(data []byte) ([]netip.Prefix, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, p := range doc.Prefixes {
		s := p.IPv4Prefix
		if s == "" {
			s = p.IPv6Prefix
		}
		if s == "" {
			continue
		}
		pre, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		out = append(out, pre)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("goog.json 里没有可用前缀")
	}
	return out, nil
}

// fetchGoogleIPRanges 从谷歌拉取最新的 IP 段（10 秒超时，正文最多 1MB）。
func fetchGoogleIPRanges() ([]netip.Prefix, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(googleIPRangesURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取 goog.json 失败：HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseGoogleIPRanges(data)
}

// InitGoogleIPRanges 在服务端启动时调用（白名单开着才调）：
// 先装内置快照（立刻可用），再后台拉取在线列表并每 24h 刷新一次。
func InitGoogleIPRanges() {
	if pres, err := parseGoogleIPRanges([]byte(embeddedGoogleIPRangesJSON)); err == nil {
		googleIPRanges.set(pres, "embedded")
	} else {
		log.Printf("谷歌 IP 段：内置快照解析失败（%v），IP 白名单不可用", err)
	}
	go googleIPRangesRefreshLoop()
}

// googleIPRangesRefreshLoop 后台循环：启动后立刻拉一次在线列表，
// 之后每 24h 刷新；拉取失败就保留旧的，只记日志。
func googleIPRangesRefreshLoop() {
	if pres, err := fetchGoogleIPRanges(); err == nil {
		googleIPRanges.set(pres, "online")
		log.Printf("谷歌 IP 段：在线拉取 %d 条", len(pres))
	} else {
		log.Printf("谷歌 IP 段：在线拉取失败（%v），继续用内置快照", err)
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for range t.C {
		if pres, err := fetchGoogleIPRanges(); err == nil {
			googleIPRanges.set(pres, "online")
			log.Printf("谷歌 IP 段：后台刷新 %d 条", len(pres))
		}
	}
}

// IsGoogleIP 判断一个 IP 是不是谷歌的 IP（在谷歌公布的 IP 段内）。
// 还没加载出任何前缀时一律返回 false（宁可拦错，不可放错）。
func IsGoogleIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	// IPv4 映射的 IPv6 形式（::ffff:8.8.8.8）先还原成 4 字节再比对，
	// goog.json 里的 IPv4 前缀才能命中。
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	googleIPRanges.mu.RLock()
	defer googleIPRanges.mu.RUnlock()
	for _, p := range googleIPRanges.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// GoogleIPRangesInfo 返回当前 IP 段的数量和来源（日志/状态用）。
func GoogleIPRangesInfo() (n int, src string) {
	googleIPRanges.mu.RLock()
	defer googleIPRanges.mu.RUnlock()
	return len(googleIPRanges.prefixes), googleIPRanges.source
}
