package mmx

import (
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	testPSK1 = []byte("0123456789abcdef0123456789abcdef") // 32 字节
	testPSK2 = []byte("fedcba9876543210fedcba9876543210") // 32 字节，另一把密钥
)

// newTestTracker 返回一个告警回调可捕获的检测器。
func newTestTracker() (*PSKLeakTracker, *[]string) {
	var alerts []string
	t := NewPSKLeakTracker()
	t.onAlert = func(keyID string, ips []string) {
		alerts = append(alerts, keyID+"|"+strings.Join(ips, ","))
	}
	return t, &alerts
}

// 单一 IP 多会话：不告警。
func TestPSKLeakTrackerSingleIPNoAlert(t *testing.T) {
	tr, alerts := newTestTracker()
	tr.Record(testPSK1, "1.2.3.4")
	tr.Record(testPSK1, "1.2.3.4")
	tr.Record(testPSK1, "1.2.3.4")
	if len(*alerts) != 0 {
		t.Fatalf("同一 IP 三个会话却告警了：%v", *alerts)
	}
	tr.End(testPSK1, "1.2.3.4")
	tr.End(testPSK1, "1.2.3.4")
	tr.End(testPSK1, "1.2.3.4")
}

// 两 IP 同时在线：告警一次，带密钥指纹和两个 IP。
func TestPSKLeakTrackerTwoIPsOverlapAlerts(t *testing.T) {
	tr, alerts := newTestTracker()
	tr.Record(testPSK1, "1.2.3.4")
	tr.Record(testPSK1, "5.6.7.8")
	if len(*alerts) != 1 {
		t.Fatalf("两 IP 重叠应告警 1 次，实际 %d 次：%v", len(*alerts), *alerts)
	}
	wantID := KeyFingerprint(testPSK1)
	if !strings.HasPrefix((*alerts)[0], wantID+"|") {
		t.Fatalf("告警里密钥指纹不对：%q，应以 %q 开头", (*alerts)[0], wantID)
	}
	if !strings.Contains((*alerts)[0], "1.2.3.4") || !strings.Contains((*alerts)[0], "5.6.7.8") {
		t.Fatalf("告警里应同时包含两个 IP：%q", (*alerts)[0])
	}
	if len(wantID) != 8 {
		t.Fatalf("指纹应为 8 位十六进制，实际 %q", wantID)
	}
	// 指纹里不能出现 PSK 本身（防误把密钥打进日志的回归）。
	if strings.Contains((*alerts)[0], string(testPSK1)) {
		t.Fatalf("告警里出现了 PSK 本身：%q", (*alerts)[0])
	}
}

// 先后使用（旧会话已结束才从新 IP 连）：不告警——
// 手机换网干净重连不该误报。
func TestPSKLeakTrackerSequentialIPsNoAlert(t *testing.T) {
	tr, alerts := newTestTracker()
	tr.Record(testPSK1, "1.2.3.4")
	tr.End(testPSK1, "1.2.3.4")
	tr.Record(testPSK1, "5.6.7.8")
	if len(*alerts) != 0 {
		t.Fatalf("先后使用两个 IP 却告警了：%v", *alerts)
	}
	// 一个 IP 先断、另一个还在时再连回第一个 IP：仍重叠，要告警。
	tr.Record(testPSK1, "1.2.3.4")
	if len(*alerts) != 1 {
		t.Fatalf("两 IP 再次重叠应告警，实际 %d 次", len(*alerts))
	}
}

// 不同密钥各用一个 IP：互不干扰，不告警。
func TestPSKLeakTrackerDifferentKeysIndependent(t *testing.T) {
	tr, alerts := newTestTracker()
	tr.Record(testPSK1, "1.2.3.4")
	tr.Record(testPSK2, "5.6.7.8")
	if len(*alerts) != 0 {
		t.Fatalf("不同密钥各一个 IP 却告警了：%v", *alerts)
	}
}

// 告警限流：重叠期间连续建会话，一分钟内只告警一次；
// 间隔一过再建会话，才告警第二次。
func TestPSKLeakTrackerAlertRateLimited(t *testing.T) {
	tr, alerts := newTestTracker()
	tr.Record(testPSK1, "1.2.3.4")
	tr.Record(testPSK1, "5.6.7.8")
	for i := 0; i < 5; i++ {
		tr.Record(testPSK1, "1.2.3.4")
		tr.Record(testPSK1, "5.6.7.8")
	}
	if len(*alerts) != 1 {
		t.Fatalf("一分钟内重叠连接多次建会话，应只告警 1 次，实际 %d 次", len(*alerts))
	}
	// 把上次告警时间拨回两分钟前，模拟间隔已过。
	tr.mu.Lock()
	for k := range tr.lastAlert {
		tr.lastAlert[k] = time.Now().Add(-2 * time.Minute)
	}
	tr.mu.Unlock()
	tr.Record(testPSK1, "1.2.3.4")
	if len(*alerts) != 2 {
		t.Fatalf("间隔过后再次重叠应告警第 2 次，实际 %d 次", len(*alerts))
	}
}

// End 清理：计数归零后条目删干净，之后再从别的 IP 连不告警；
// 多调一次 End 也不会把计数减成负数（下一次 Record 不会立刻告警）。
func TestPSKLeakTrackerEndCleansUp(t *testing.T) {
	tr, alerts := newTestTracker()
	tr.Record(testPSK1, "1.2.3.4")
	tr.Record(testPSK1, "1.2.3.4")
	tr.End(testPSK1, "1.2.3.4")
	tr.End(testPSK1, "1.2.3.4")
	tr.End(testPSK1, "1.2.3.4") // 多调一次
	tr.mu.Lock()
	if len(tr.sessions) != 0 {
		tr.mu.Unlock()
		t.Fatalf("会话全结束后 sessions 应为空，实际 %v", tr.sessions)
	}
	tr.mu.Unlock()
	tr.Record(testPSK1, "5.6.7.8")
	if len(*alerts) != 0 {
		t.Fatalf("旧会话清干净后从新 IP 连却告警了：%v", *alerts)
	}
}

// 并发安全：多 goroutine 同时 Record/End 不应 race、不应 panic，
// 且同一 IP 的计数最终归零（-race 下跑）。
func TestPSKLeakTrackerConcurrent(t *testing.T) {
	tr, alerts := newTestTracker()
	var wg sync.WaitGroup
	ips := []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				ip := ips[(g+i)%len(ips)]
				tr.Record(testPSK1, ip)
				tr.End(testPSK1, ip)
			}
		}(g)
	}
	wg.Wait()
	tr.mu.Lock()
	if len(tr.sessions) != 0 {
		tr.mu.Unlock()
		t.Fatalf("并发 Record/End 成对执行后 sessions 应为空，实际 %v", tr.sessions)
	}
	tr.mu.Unlock()
	// 并发重叠期间告警可能触发，但每密钥一分钟内最多一次。
	if len(*alerts) > 1 {
		t.Fatalf("一分钟内告警超过 1 次：%v", *alerts)
	}
}

// 空 PSK / 空 IP 是 no-op，不 panic。
func TestPSKLeakTrackerNilSafe(t *testing.T) {
	tr, _ := newTestTracker()
	tr.Record(nil, "1.2.3.4")
	tr.Record(testPSK1, "")
	tr.End(nil, "1.2.3.4")
	tr.End(testPSK1, "")
	var nilTr *PSKLeakTracker
	nilTr.Record(testPSK1, "1.2.3.4")
	nilTr.End(testPSK1, "1.2.3.4")
}
