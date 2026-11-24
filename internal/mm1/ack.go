// CONNECT 报错分类：只学 Snell“报错要分得清”的思路，不引入 Snell
// 的协议或代码。线上的 ACK 格式不变（0x01 + 错误文本），只是错误
// 文本前面加一个可读的前缀 "[错误码] …"，老客户端按原来的
// string(payload[1:]) 读，看到的仍是可读中文，没有二进制垃圾；
// 新客户端解析 "[...]" 前缀，拿到错误码。
//
// 握手失败不走这条路：握手没通过鉴权时服务端仍静默丢弃/回诱饵页，
// 不回任何错误帧（防主动探测）；客户端只在本地按错误文本分类，
// 不改线路。
package mm1

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// CONNECT 拨号失败的错误码（ACK 文本前缀里的 [...] 内容）。
const (
	DialErrDNS         = "DNS解析失败" // 目标域名解析失败
	DialErrTimeout     = "连接超时"    // 10 秒拨号超时
	DialErrRefused     = "目标拒绝"    // 目标端口拒绝连接
	DialErrUnreachable = "目标不可达"   // 其他拨号失败（无路由 / 网络不可达等）
	DialErrForbidden   = "目标不允许"   // 目标被服务端策略拒绝（内网/保留地址，见 target.go）
	DialErrUnknown     = "UNKNOWN" // 老服务端 / 无前缀文本的回退码，不上线路
)

// dialErrDetail 是每个错误码对应的人话说明（放在 ACK 文本前缀之后）。
var dialErrDetail = map[string]string{
	DialErrDNS:         "目标域名解析失败",
	DialErrTimeout:     "连接目标超时",
	DialErrRefused:     "目标拒绝连接",
	DialErrUnreachable: "目标不可达",
	DialErrForbidden:   "目标地址不允许（内网/保留地址）",
}

func isKnownDialCode(code string) bool {
	_, ok := dialErrDetail[code]
	return ok
}

// ClassifyDialError 把 net.DialTimeout 的失败分类。
// 顺序很重要：策略拒绝（目标不允许）先于其他——它不是拨号失败，
// 是服务端根本没拨；超时其次（超时错误里也可能包着别的信息），
// DNS 其次，拒绝再次之，其余拨号失败一律归为目标不可达。
func ClassifyDialError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrTargetNotAllowed) {
		return DialErrForbidden
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return DialErrTimeout
	}
	msg := err.Error()
	if strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded") {
		return DialErrTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return DialErrDNS
	}
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "name resolution") ||
		strings.Contains(msg, "temporary failure in name resolution") {
		return DialErrDNS
	}
	if strings.Contains(msg, "connection refused") {
		return DialErrRefused
	}
	if strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "host is unreachable") || strings.Contains(msg, "network unreachable") {
		return DialErrUnreachable
	}
	// 其余拨号失败（例如未知网络错误）按“目标不可达”归类，
	// 不引入第五个码，保持码表只有四项。
	return DialErrUnreachable
}

// FormatConnectError 生成 ACK 失败文本：
// "[DNS解析失败] 目标域名解析失败：<原始错误>"。
// 老客户端直接显示这段文本即可读；新客户端用 ParseAckError 解析。
func FormatConnectError(code string, err error) string {
	if !isKnownDialCode(code) {
		code = DialErrUnreachable
	}
	return fmt.Sprintf("[%s] %s：%v", code, dialErrDetail[code], err)
}

// ParseAckError 解析 ACK 载荷。
// 成功（payload[0]==0x00）返回 ("", "")；
// 失败（0x01 + 文本）且文本带 "[已知码] " 前缀时返回 (码, 前缀后的消息)；
// 无前缀的老服务端文本返回 (UNKNOWN, 原文)。
func ParseAckError(payload []byte) (code, message string) {
	if len(payload) == 0 || payload[0] == 0x00 {
		return "", ""
	}
	text := ""
	if len(payload) > 1 {
		text = string(payload[1:])
	}
	if strings.HasPrefix(text, "[") {
		if idx := strings.Index(text, "]"); idx > 1 {
			candidate := text[1:idx]
			if isKnownDialCode(candidate) {
				return candidate, strings.TrimSpace(text[idx+1:])
			}
		}
	}
	return DialErrUnknown, text
}

// 握手失败的本地分类码（只用于客户端日志/报错，不上线路）。
const (
	HandshakeErrMagic   = "魔数不对"
	HandshakeErrKey     = "密钥不对"
	HandshakeErrVersion = "版本号不受支持"
	HandshakeErrTimeout = "超时"
	HandshakeErrUnknown = "未知握手错误"
)

// ClassifyHandshakeError 按现有错误文本把握手失败分类。
// 服务端对未鉴权的握手仍静默丢弃，这里只是客户端本地归类。
func ClassifyHandshakeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "魔数不对") {
		return HandshakeErrMagic
	}
	if strings.Contains(msg, "版本号不受支持") {
		return HandshakeErrVersion
	}
	if strings.Contains(msg, "密钥不对") {
		return HandshakeErrKey
	}
	if strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "超时") || strings.Contains(msg, "timeout") {
		return HandshakeErrTimeout
	}
	return HandshakeErrUnknown
}

// FormatHandshakeError 生成客户端握手失败的报错：
// "握手失败 [魔数不对]：<原始错误>"。
func FormatHandshakeError(err error) string {
	return fmt.Sprintf("握手失败 [%s]：%v", ClassifyHandshakeError(err), err)
}
