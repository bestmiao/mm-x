// 连接数上限的测试。
package mmx

import "testing"

func TestConnLimiter(t *testing.T) {
	// 全局 2 条、单 IP 1 条。
	l := NewConnLimiter(2, 1)
	if !l.TryAcquire("1.1.1.1") {
		t.Fatal("第一个连接应拿到名额")
	}
	if l.TryAcquire("1.1.1.1") {
		t.Fatal("同一 IP 第二条连接应被单 IP 上限挡住")
	}
	if !l.TryAcquire("2.2.2.2") {
		t.Fatal("不同 IP 的连接应拿到全局剩下的名额")
	}
	if l.TryAcquire("3.3.3.3") {
		t.Fatal("全局满了，第三个 IP 的连接应被拒绝")
	}
	// 归还一个名额后能再拿。
	l.Release("1.1.1.1")
	if !l.TryAcquire("3.3.3.3") {
		t.Fatal("归还名额后应能再拿到")
	}
	l.Release("2.2.2.2")
	l.Release("3.3.3.3")
	if !l.TryAcquire("1.1.1.1") {
		t.Fatal("全部归还后应能再拿到名额")
	}
	if l.TryAcquire("1.1.1.1") {
		t.Fatal("单 IP 上限 1，同一 IP 第二条应被拒绝")
	}
	// nil 限制器 = 不设防。
	var nilLimiter *ConnLimiter
	if !nilLimiter.TryAcquire("9.9.9.9") {
		t.Fatal("nil 限制器应永远放行")
	}
	nilLimiter.Release("9.9.9.9") // 不应 panic
}
