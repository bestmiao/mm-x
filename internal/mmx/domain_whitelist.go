// 目标域名白名单：只放行指定厂商的域名，其他目标直接拒绝。
//
// 用途：GCP 免费套餐（每账号每月 200 GiB 免费流量，Standard Tier）
// 只覆盖谷歌系流量——开了白名单，GitHub、AI、视频站这些
// 非谷歌流量就走不通这台服务器，免费额度不会被别的流量吃掉。
// （对应 vx 脚本 GCP 预设的“白名单仅谷歌系”，那是 VLESS 的
// geosite:google 路由；mm-x 服务端没有按域名分流，
// 所以在服务端拨目标之前直接按域名过滤，效果一样。）
//
// 默认关（空字符串）：所有目标都按 SSRF 规则放行，
// 现有服务器不受影响。GCP 预设把它设成 google。
//
// 匹配规则：host 等于某个谷歌域名后缀，或以 "."+后缀结尾
// （子域名也算）；谷歌地区搜索域名（google.de、google.co.uk、
// google.com.hk 等）也放行，连同它们的子域名一起算。
// IP 字面量目标：Google 公共 DNS 的 IP，或落在谷歌公布的 IP 段内
// （goog.json，见 google_ipranges.go）的 IP，都放行——后者是给
// TUN 模式用的：TUN 下域名先解析成 IP 再进代理，服务端靠 IP 段
// 认出谷歌流量。不在谷歌段内的 IP 一律拒绝；要走 IP 字面量目标
// 就把白名单关掉。
package mmx

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// DomainWhitelist 是目标域名白名单的模式。
type DomainWhitelist string

const (
	// DomainWhitelistOff 关：不限域名（默认）。
	DomainWhitelistOff DomainWhitelist = ""
	// DomainWhitelistGoogle 只放行谷歌系域名。
	DomainWhitelistGoogle DomainWhitelist = "google"
)

// ParseDomainWhitelist 解析 --domain-whitelist 的值：
// "" / off / none = 关，google = 只放行谷歌系域名。
func ParseDomainWhitelist(s string) (DomainWhitelist, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return DomainWhitelistOff, nil
	case "google":
		return DomainWhitelistGoogle, nil
	default:
		return DomainWhitelistOff, fmt.Errorf("域名白名单不合法：%q，应为 off（关，默认）或 google（只放行谷歌系域名）", s)
	}
}

// Enabled 白名单是否开启。
func (d DomainWhitelist) Enabled() bool { return d != DomainWhitelistOff }

// Label 白名单的中文名（日志和菜单显示用）。
func (d DomainWhitelist) Label() string {
	switch d {
	case DomainWhitelistGoogle:
		return "谷歌系"
	default:
		return "关闭"
	}
}

// googleDomainSuffixes：谷歌系域名后缀（geosite:google 里最常用的部分）。
// 匹配规则：host 等于它，或以 "."+它结尾（子域名也算）。
var googleDomainSuffixes = []string{
	"google.com",
	"googlevideo.com",
	"gstatic.com",
	"youtube.com",
	"youtu.be",
	"googleapis.com",
	"ggpht.com",
	"googleusercontent.com",
	"googleadservices.com",
	"googlesyndication.com",
	"googletagmanager.com",
	"google-analytics.com",
	"googlesource.com",
	"googlecode.com",
	"gmail.com",
	"googlemail.com",
	"android.com",
	"blogspot.com",
	"blogger.com",
	"chrome.com",
	"chromium.org",
	"doubleclick.net",
	"googledrive.com",
	"googleplay.com",
	"googleearth.com",
	"withgoogle.com",
	"googleblog.com",
	"firebaseio.com",
	"firebaseapp.com",
	"appspot.com",
	"1e100.net",
	"gvt1.com",
	"gvt2.com",
	"gvt3.com",
	"ytimg.com",
	"youtube-nocookie.com",
	"googlehosted.com",
}

// googleRegionalRe：谷歌地区搜索域名：google.com / google.de /
// google.co.uk / google.com.hk / google.com.au 等。
// 匹配时连同它的子域名一起算（www.google.co.uk 也放行）：
// 调用方对 host 的每个后缀都试一次。
var googleRegionalRe = regexp.MustCompile(`^google\.(com|[a-z]{2})(\.[a-z]{2})?$`)

// googleDNSIPs：Google 公共 DNS 的 IP——IP 字面量目标里唯一放行的。
// （客户端的 DNS 查询常以 UDP 走 8.8.8.8 经过代理；放行它，
// DNS 才不会被白名单断掉。）
var googleDNSIPs = map[string]bool{
	"8.8.8.8":                true,
	"8.8.4.4":                true,
	"2001:4860:4860::8888":   true,
	"2001:4860:4860::8844":   true,
}

// IsGoogleDomain 判断一个主机名是不是谷歌系域名。
// IP 字面量：Google 公共 DNS 的 IP，或落在谷歌公布的 IP 段内的 IP，
// 都算（后者是给 TUN 模式用的：TUN 下域名先解析成 IP 再进代理，
// 服务端只能靠 IP 段认出谷歌流量）。
func IsGoogleDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	// IP 字面量：Google 公共 DNS 的 IP，或在谷歌 IP 段内的 IP，都放行。
	if ip := net.ParseIP(host); ip != nil {
		if googleDNSIPs[ip.String()] {
			return true
		}
		return IsGoogleIP(ip)
	}
	for _, s := range googleDomainSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	// 地区搜索域名：对 host 的每个后缀都试一次，
// 这样 www.google.co.uk（后缀 google.co.uk）也能放行。
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels); i++ {
		if googleRegionalRe.MatchString(strings.Join(labels[i:], ".")) {
			return true
		}
	}
	return false
}

// Allows 查一个目标主机是否通过白名单：没开白名单一律通过。
func (d DomainWhitelist) Allows(host string) bool {
	if !d.Enabled() {
		return true
	}
	switch d {
	case DomainWhitelistGoogle:
		return IsGoogleDomain(host)
	default:
		return true
	}
}
