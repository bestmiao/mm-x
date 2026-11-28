// 谷歌 IP 段白名单（TUN + 谷歌白名单用）的单元测试。
package mmx

import (
	"net"
	"strings"
	"testing"
)

// loadEmbeddedGoogleIPRangesForTest 把内置快照装进全局表（单测不用联网）。
func loadEmbeddedGoogleIPRangesForTest(t *testing.T) {
	t.Helper()
	pres, err := parseGoogleIPRanges([]byte(embeddedGoogleIPRangesJSON))
	if err != nil {
		t.Fatalf("内置谷歌 IP 段快照解析失败：%v", err)
	}
	googleIPRanges.set(pres, "embedded-test")
}

func TestParseGoogleIPRanges(t *testing.T) {
	pres, err := parseGoogleIPRanges([]byte(embeddedGoogleIPRangesJSON))
	if err != nil {
		t.Fatalf("内置快照应能解析：%v", err)
	}
	if len(pres) < 100 {
		t.Errorf("内置快照前缀太少：%d 条，应为 100+ 条", len(pres))
	}
	// 几个已知谷歌段必须在里面。
	for _, want := range []string{"8.8.8.0/24", "8.8.4.0/24", "142.250.0.0/15", "2001:4860::/32"} {
		found := false
		for _, p := range pres {
			if p.String() == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("内置快照里应有 %s", want)
		}
	}
	// 非法 JSON、空前缀、非法前缀都应报错或被跳过。
	if _, err := parseGoogleIPRanges([]byte(`{不是 json`)); err == nil {
		t.Error("非法 JSON 应报错")
	}
	if _, err := parseGoogleIPRanges([]byte(`{"prefixes":[]}`)); err == nil {
		t.Error("空前缀列表应报错")
	}
	mixed, err := parseGoogleIPRanges([]byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv4Prefix":"999.999.0.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}`))
	if err != nil {
		t.Fatalf("混合非法条目不应整体报错：%v", err)
	}
	if len(mixed) != 2 {
		t.Errorf("非法条目应被跳过，只剩 2 条，实际 %d 条", len(mixed))
	}
}

func TestIsGoogleIP(t *testing.T) {
	loadEmbeddedGoogleIPRangesForTest(t)
	// 谷歌 IP：放行。
	for _, ip := range []string{
		"8.8.8.8", "8.8.4.4", "8.8.8.9",
		"142.250.80.14", "172.217.0.1", "216.58.200.14",
		"2001:4860:4860::8888", "2001:4860:4860::8844",
	} {
		if !IsGoogleIP(net.ParseIP(ip)) {
			t.Errorf("谷歌 IP %s 应被认出", ip)
		}
	}
	// IPv4 映射的 IPv6 形式也要认出来（::ffff:8.8.8.8 就是 8.8.8.8）。
	if !IsGoogleIP(net.ParseIP("::ffff:8.8.8.8")) {
		t.Error("::ffff:8.8.8.8 应被认出是谷歌 IP")
	}
	// 非谷歌 IP：拒绝。
	for _, ip := range []string{"1.1.1.1", "9.9.9.9", "127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"} {
		if IsGoogleIP(net.ParseIP(ip)) {
			t.Errorf("非谷歌 IP %s 不应被认出", ip)
		}
	}
	if IsGoogleIP(nil) {
		t.Error("nil IP 不应被认出")
	}
	if n, src := GoogleIPRangesInfo(); n < 100 || src == "" {
		t.Errorf("GoogleIPRangesInfo 应返回 100+ 条和来源，实际 %d 条 %q", n, src)
	}
}

// 没加载出任何前缀时一律返回 false（宁可拦错，不可放错）。
// 直接换空表再恢复，不依赖测试执行顺序。
func TestIsGoogleIPEmpty(t *testing.T) {
	googleIPRanges.mu.RLock()
	oldPres, oldSrc := googleIPRanges.prefixes, googleIPRanges.source
	googleIPRanges.mu.RUnlock()
	defer googleIPRanges.set(oldPres, oldSrc)
	googleIPRanges.set(nil, "empty-test")
	if IsGoogleIP(net.ParseIP("8.8.8.8")) {
		t.Error("前缀表为空时 8.8.8.8 也不应被认出")
	}
	if !strings.Contains(embeddedGoogleIPRangesJSON, "8.8.8.0/24") {
		t.Error("内置快照里应有 8.8.8.0/24")
	}
}
