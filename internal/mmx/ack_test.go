// CONNECT 报错分类与 ACK 兼容性的单元测试。
package mmx

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// timeoutError 是实现 net.Error 且 Timeout() 为真的测试用错误。
type timeoutError struct{ msg string }

func (e timeoutError) Error() string   { return e.msg }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

func TestClassifyDialError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"DNS 错误", &net.DNSError{IsNotFound: true, Name: "no-such-host.example"}, DialErrDNS},
		{"DNS 文本", errors.New("dial tcp: lookup no-such-host.example: no such host"), DialErrDNS},
		{"超时 net.Error", timeoutError{"dial tcp 1.2.3.4:443: i/o timeout"}, DialErrTimeout},
		{"超时文本", errors.New("dial tcp 1.2.3.4:443: i/o timeout"), DialErrTimeout},
		{"超时 deadline", fmt.Errorf("dial: %w", errors.New("context deadline exceeded")), DialErrTimeout},
		{"拒绝", errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), DialErrRefused},
		{"网络不可达", errors.New("dial tcp 1.2.3.4:443: connect: network is unreachable"), DialErrUnreachable},
		{"无路由", errors.New("dial tcp 1.2.3.4:443: connect: no route to host"), DialErrUnreachable},
		{"主机不可达", errors.New("dial tcp 1.2.3.4:443: connect: host is unreachable"), DialErrUnreachable},
		{"未知错误归为不可达", errors.New("dial tcp 1.2.3.4:443: connect: something strange"), DialErrUnreachable},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		if got := ClassifyDialError(tc.err); got != tc.want {
			t.Errorf("%s：ClassifyDialError = %q，应为 %q（err=%v）", tc.name, got, tc.want, tc.err)
		}
	}
}

func TestFormatAndParseAckError(t *testing.T) {
	codes := []string{DialErrDNS, DialErrTimeout, DialErrRefused, DialErrUnreachable}
	for _, code := range codes {
		raw := errors.New("dial tcp 1.2.3.4:443: connect: connection refused")
		text := FormatConnectError(code, raw)
		if !strings.HasPrefix(text, "["+code+"] ") {
			t.Fatalf("错误码 %s 的 ACK 文本前缀不对：%q", code, text)
		}
		if !strings.Contains(text, raw.Error()) {
			t.Fatalf("ACK 文本丢了原始错误：%q", text)
		}
		payload := append([]byte{0x01}, []byte(text)...)
		gotCode, msg := ParseAckError(payload)
		if gotCode != code {
			t.Fatalf("错误码 %s 解析后变成 %q", code, gotCode)
		}
		if !strings.Contains(msg, raw.Error()) {
			t.Fatalf("错误码 %s 解析后的消息丢了原始错误：%q", code, msg)
		}
		// 老客户端视角：string(payload[1:]) 必须是可读中文，无二进制垃圾。
		oldView := string(payload[1:])
		if oldView != text {
			t.Fatalf("老客户端读到的文本与新文本不一致：%q vs %q", oldView, text)
		}
		for _, r := range oldView {
			if r < 0x20 && r != '\n' && r != '\t' {
				t.Fatalf("老客户端读到的文本含控制字符 %q：%q", r, oldView)
			}
		}
	}
	// 非法码不进线路：Format 时退回“目标不可达”。
	if text := FormatConnectError("不存在的码", errors.New("x")); !strings.HasPrefix(text, "["+DialErrUnreachable+"] ") {
		t.Fatalf("非法码应退回目标不可达，实际：%q", text)
	}
}

func TestParseAckErrorBackwardCompat(t *testing.T) {
	// 老服务端无前缀文本：回退 UNKNOWN，消息即原文。
	code, msg := ParseAckError(append([]byte{0x01}, []byte("connection refused")...))
	if code != DialErrUnknown || msg != "connection refused" {
		t.Fatalf("老文本应解析为 (UNKNOWN, 原文)，实际 (%q, %q)", code, msg)
	}
	// 老服务端中文文本也一样。
	code, msg = ParseAckError(append([]byte{0x01}, []byte("连接目标失败")...))
	if code != DialErrUnknown || msg != "连接目标失败" {
		t.Fatalf("老中文文本应解析为 (UNKNOWN, 原文)，实际 (%q, %q)", code, msg)
	}
	// 未知 "[...]" 前缀不认作码，整段当原文。
	code, msg = ParseAckError(append([]byte{0x01}, []byte("[不存在的码] 出错了")...))
	if code != DialErrUnknown || msg != "[不存在的码] 出错了" {
		t.Fatalf("未知前缀应回退 (UNKNOWN, 原文)，实际 (%q, %q)", code, msg)
	}
	// 成功 ACK：无错误。
	if code, msg := ParseAckError([]byte{0x00}); code != "" || msg != "" {
		t.Fatalf("成功 ACK 应解析为 (\"\", \"\")，实际 (%q, %q)", code, msg)
	}
	if code, msg := ParseAckError(nil); code != "" || msg != "" {
		t.Fatalf("空 ACK 应解析为 (\"\", \"\")，实际 (%q, %q)", code, msg)
	}
	// 失败但无文本：消息为空，不崩。
	if code, msg := ParseAckError([]byte{0x01}); code != DialErrUnknown || msg != "" {
		t.Fatalf("无文本失败 ACK 应为 (UNKNOWN, \"\")，实际 (%q, %q)", code, msg)
	}
}

func TestClassifyHandshakeError(t *testing.T) {
	cases := []struct {
		err  string
		want string
	}{
		{"魔数不对：不是 mm-x 协议", HandshakeErrMagic},
		{"服务端握手校验失败：魔数不对：不是 mm-x 协议", HandshakeErrMagic},
		{"版本号不受支持：对方版本 3，本端只支持 2", HandshakeErrVersion},
		{"密钥不对：握手鉴权失败（请检查 mmx:// 链接里的密钥）", HandshakeErrKey},
		{"等待服务端握手回应失败：read tcp: i/o timeout", HandshakeErrTimeout},
		{"读取客户端握手失败：context deadline exceeded", HandshakeErrTimeout},
		{"读取记录头失败：EOF", HandshakeErrUnknown},
	}
	for _, tc := range cases {
		if got := ClassifyHandshakeError(errors.New(tc.err)); got != tc.want {
			t.Errorf("ClassifyHandshakeError(%q) = %q，应为 %q", tc.err, got, tc.want)
		}
	}
	// FormatHandshakeError 带 "[码]" 前缀且保留原文。
	formatted := FormatHandshakeError(errors.New("魔数不对：不是 mm-x 协议"))
	if !strings.HasPrefix(formatted, "握手失败 [魔数不对]：") || !strings.Contains(formatted, "魔数不对") {
		t.Fatalf("FormatHandshakeError 格式不对：%q", formatted)
	}
	if got := ClassifyHandshakeError(nil); got != "" {
		t.Fatalf("nil 应分类为空，实际 %q", got)
	}
}
