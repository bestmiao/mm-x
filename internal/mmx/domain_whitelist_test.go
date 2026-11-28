// 目标域名白名单（GCP 预设用）的单元测试。
package mmx

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDomainWhitelist(t *testing.T) {
	for _, in := range []string{"", "off", "OFF", "none", "  google  ", "GOOGLE"} {
		want := DomainWhitelistOff
		if strings.Contains(strings.ToLower(in), "google") {
			want = DomainWhitelistGoogle
		}
		got, err := ParseDomainWhitelist(in)
		if err != nil {
			t.Errorf("ParseDomainWhitelist(%q) 不应报错：%v", in, err)
		}
		if got != want {
			t.Errorf("ParseDomainWhitelist(%q) = %q，应为 %q", in, got, want)
		}
	}
	if _, err := ParseDomainWhitelist("github"); err == nil {
		t.Error("ParseDomainWhitelist(github) 应报错")
	}
	if _, err := ParseDomainWhitelist("all"); err == nil {
		t.Error("ParseDomainWhitelist(all) 应报错")
	}
}

func TestIsGoogleDomain(t *testing.T) {
	// IP 段白名单的单测要先装内置快照（不用联网）。
	loadEmbeddedGoogleIPRangesForTest(t)
	// 谷歌系：放行。
	for _, host := range []string{
		"google.com",
		"www.google.com",
		"mail.google.com",
		"WWW.GOOGLE.COM",     // 大小写不敏感
		"google.com.",        // 末尾的点容忍
		"googlevideo.com",
		"r1---sn-xxx.googlevideo.com",
		"youtube.com",
		"www.youtube.com",
		"youtu.be",
		"gstatic.com",
		"fonts.gstatic.com",
		"googleapis.com",
		"storage.googleapis.com",
		"ggpht.com",
		"lh3.googleusercontent.com",
		"googleadservices.com",
		"googlesyndication.com",
		"googletagmanager.com",
		"google-analytics.com",
		"googlesource.com",
		"gmail.com",
		"mail.gmail.com",
		"android.com",
		"blogspot.com",
		"myblog.blogspot.com",
		"chrome.com",
		"chromium.org",
		"doubleclick.net",
		"googleplay.com",
		"firebaseio.com",
		"myapp.firebaseio.com",
		"appspot.com",
		"myapp.appspot.com",
		"1e100.net",
		"gvt1.com",
		"ytimg.com",
		"i.ytimg.com",
		"youtube-nocookie.com",
		// 地区搜索域名及其子域名。
		"google.de",
		"www.google.co.uk",
		"google.com.hk",
		"www.google.com.sg",
		"google.co.jp",
		"google.com.au",
		"google.com.tw",
		"google.co.kr",
	} {
		if !IsGoogleDomain(host) {
			t.Errorf("谷歌域名 %s 应被放行", host)
		}
	}
	// 非谷歌：拒绝。
	for _, host := range []string{
		"github.com",
		"www.github.com",
		"bing.com",
		"microsoft.com",
		"apple.com",
		"cloudflare.com",
		"openai.com",
		"api.openai.com",
		"notgoogle.com",       // 名字里带 google 但不是谷歌的
		"evilgoogle.com",
		"fakegoogle.de",
		"google.com.evil.com", // 后缀不是谷歌
		"google.evil.com",
		"mygoogle.com",
		"google", // 裸主机名，不是域名
		"",
		"google.xxx", // 不存在的谷歌地区域名
	} {
		if IsGoogleDomain(host) {
			t.Errorf("非谷歌域名 %s 应被拒绝", host)
		}
	}
	// IP 字面量：Google 公共 DNS 放行；在谷歌 IP 段内的 IP 也放行
	// （TUN 模式用：域名先解析成 IP 再进代理，服务端靠 IP 段认谷歌）。
	for _, host := range []string{
		"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
		"8.8.8.9",        // 在 8.8.8.0/24 内，是谷歌 IP
		"142.250.80.14", // 在 142.250.0.0/15 内，是谷歌 IP
		"172.217.0.1",   // 在 172.217.0.0/16 内，是谷歌 IP
		"216.58.200.14", // 在 216.58.192.0/19 内，是谷歌 IP
	} {
		if !IsGoogleDomain(host) {
			t.Errorf("谷歌 IP %s 应被放行", host)
		}
	}
	for _, host := range []string{"1.1.1.1", "127.0.0.1", "192.168.1.1"} {
		if IsGoogleDomain(host) {
			t.Errorf("IP 字面量 %s 应被拒绝（不是谷歌资产）", host)
		}
	}
}

func TestDomainWhitelistAllows(t *testing.T) {
	off := DomainWhitelistOff
	if !off.Allows("github.com") || !off.Allows("8.8.8.8") {
		t.Error("白名单关时所有目标都应通过")
	}
	g := DomainWhitelistGoogle
	if !g.Allows("www.google.com") || !g.Allows("youtube.com") {
		t.Error("google 白名单应放行谷歌域名")
	}
	if g.Allows("github.com") || g.Allows("1.1.1.1") {
		t.Error("google 白名单应拒绝非谷歌域名和 IP 字面量")
	}
	if g.Label() != "谷歌系" || off.Label() != "关闭" {
		t.Errorf("Label 不对：google=%q off=%q", g.Label(), off.Label())
	}
}

// 白名单拒绝发生在拨号之前：不用联网（拒绝在解析之前），
// 错误包着 ErrTargetNotAllowed（客户端收到“[目标不允许]”）。
func TestCheckTargetAllowedDomainWhitelist(t *testing.T) {
	// IP 段白名单的单测要先装内置快照（不用联网）。
	loadEmbeddedGoogleIPRangesForTest(t)
	google := TargetPolicy{DomainWhitelist: DomainWhitelistGoogle}
	for _, target := range []string{"github.com:443", "api.openai.com:443", "1.1.1.1:443"} {
		err := CheckTargetAllowed(target, google)
		if err == nil {
			t.Errorf("google 白名单下 %s 应被拒绝", target)
			continue
		}
		if !errors.Is(err, ErrTargetNotAllowed) {
			t.Errorf("%s 的拒绝错误应包着 ErrTargetNotAllowed，实际：%v", target, err)
		}
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "i/o timeout") {
			t.Errorf("%s 的拒绝不应走到拨号：%v", target, err)
		}
	}
	// 谷歌 IP 字面量目标：白名单放行（TUN 模式就靠这个），
	// 之后 SSRF 检查也过（谷歌 IP 是公网地址），所以整体放行。
	if err := CheckTargetAllowed("142.250.80.14:443", google); err != nil {
		t.Errorf("google 白名单下 142.250.80.14:443 应被放行：%v", err)
	}
	// 白名单 + allowPrivate 一起开：白名单照样生效。
	googlePrivate := TargetPolicy{AllowPrivate: true, DomainWhitelist: DomainWhitelistGoogle}
	if err := CheckTargetAllowed("github.com:443", googlePrivate); err == nil {
		t.Error("allowPrivate 开了，白名单也应照样拒绝非谷歌域名")
	}
	// 白名单关：原有行为不变（公网目标放行——这里用 IP 字面量，不用 DNS）。
	if err := CheckTargetAllowed("8.8.8.8:443", TargetPolicy{}); err != nil {
		t.Errorf("白名单关时 8.8.8.8:443 应被放行：%v", err)
	}
}
