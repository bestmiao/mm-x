// SOCKS5 UDP 数据报头编解码的单元测试：
// buildUDPResponse 拼的头，parseUDPRequest 必须原样解析回来。
package main

import (
	"bytes"
	"testing"
)

func TestUDPHeaderRoundTrip(t *testing.T) {
	for _, target := range []string{
		"127.0.0.1:53",
		"8.8.8.8:53",
		"example.com:443",
		"[2001:db8::1]:53",
	} {
		data := []byte("dns-query-bytes")
		pkt, err := buildUDPResponse(target, data)
		if err != nil {
			t.Fatalf("拼 UDP 回包头失败（%s）：%v", target, err)
		}
		gotTarget, gotData, err := parseUDPRequest(pkt)
		if err != nil {
			t.Fatalf("解析自己拼的 UDP 包失败（%s）：%v", target, err)
		}
		if gotTarget != target {
			t.Fatalf("目标解析不一致：得到 %q，想要 %q", gotTarget, target)
		}
		if !bytes.Equal(gotData, data) {
			t.Fatalf("数据解析不一致（%s）", target)
		}
	}
}

func TestUDPHeaderRejects(t *testing.T) {
	// FRAG != 0 的分片直接拒绝（不支持分片重组）。
	frag := []byte{0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 53, 'x'}
	if _, _, err := parseUDPRequest(frag); err == nil {
		t.Fatal("FRAG=1 的数据报应被拒绝")
	}
	// 截断的包拒绝。
	for _, short := range [][]byte{
		{},
		{0x00, 0x00},
		{0x00, 0x00, 0x00, 0x01, 127, 0},
		{0x00, 0x00, 0x00, 0x03, 0x05, 'a', 'b'},
		{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00},
	} {
		if _, _, err := parseUDPRequest(short); err == nil {
			t.Fatalf("截断/非法包 %x 应被拒绝", short)
		}
	}
}

func TestSocksRepForErr(t *testing.T) {
	cases := []struct {
		err error
		rep byte
	}{
		{errString("服务端拒绝转发 [目标拒绝]：目标拒绝连接"), socksRepRefused},
		{errString("服务端拒绝转发 [DNS解析失败]：解析失败"), socksRepHostUnreach},
		{errString("服务端拒绝转发 [目标不可达]：不可达"), socksRepHostUnreach},
		{errString("服务端拒绝转发 [连接超时]：超时"), socksRepNetworkUnreach},
		{errString("握手失败：魔数不对"), socksRepRefused},
	}
	for _, tc := range cases {
		if got := socksRepForErr(tc.err); got != tc.rep {
			t.Fatalf("socksRepForErr(%q) = 0x%02x，想要 0x%02x", tc.err, got, tc.rep)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
