package mmx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustTime(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, time.Local)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseTrafficMode(t *testing.T) {
	cases := map[string]TrafficMode{
		"out": TrafficModeOutbound, "outbound": TrafficModeOutbound, "出站": TrafficModeOutbound,
		"in": TrafficModeInbound, "inbound": TrafficModeInbound, "入站": TrafficModeInbound,
		"total": TrafficModeTotal, "总计": TrafficModeTotal, "": TrafficModeTotal,
		"max": TrafficModeMax, "最大值": TrafficModeMax,
	}
	for in, want := range cases {
		// 空字符串是 ParseTrafficMode 的非法输入（不走这条路），单独处理：
		// 这里只测非空。
		if in == "" {
			continue
		}
		got, err := ParseTrafficMode(in)
		if err != nil || got != want {
			t.Errorf("ParseTrafficMode(%q) = %v, %v；想要 %v", in, got, err, want)
		}
	}
	if _, err := ParseTrafficMode("foo"); err == nil {
		t.Error("ParseTrafficMode(foo) 应报错")
	}
	if _, err := ParseTrafficMode(""); err == nil {
		t.Error("ParseTrafficMode(\"\") 应报错")
	}
	if got := TrafficModeTotal.String(); got != "total" {
		t.Errorf("TrafficModeTotal.String() = %q，想要 total", got)
	}
	if got := TrafficModeOutbound.Label(); got != "出站" {
		t.Errorf("TrafficModeOutbound.Label() = %q，想要 出站", got)
	}
}

func TestParseTrafficPeriod(t *testing.T) {
	cases := map[string]TrafficPeriod{
		"monthly": TrafficPeriodMonthly, "月": TrafficPeriodMonthly,
		"quarterly": TrafficPeriodQuarterly, "季": TrafficPeriodQuarterly,
		"yearly": TrafficPeriodYearly, "年": TrafficPeriodYearly,
	}
	for in, want := range cases {
		got, err := ParseTrafficPeriod(in)
		if err != nil || got != want {
			t.Errorf("ParseTrafficPeriod(%q) = %v, %v；想要 %v", in, got, err, want)
		}
	}
	if _, err := ParseTrafficPeriod("week"); err == nil {
		t.Error("ParseTrafficPeriod(week) 应报错")
	}
}

func TestParseTrafficLimitMode(t *testing.T) {
	cases := map[string]TrafficLimitMode{
		"block": TrafficLimitBlock, "阻断": TrafficLimitBlock,
		"throttle": TrafficLimitThrottle, "tc": TrafficLimitThrottle,
		"限速": TrafficLimitThrottle, "tc限速": TrafficLimitThrottle,
	}
	for in, want := range cases {
		got, err := ParseTrafficLimitMode(in)
		if err != nil || got != want {
			t.Errorf("ParseTrafficLimitMode(%q) = %v, %v；想要 %v", in, got, err, want)
		}
	}
	if _, err := ParseTrafficLimitMode("cut"); err == nil {
		t.Error("ParseTrafficLimitMode(cut) 应报错")
	}
}

func TestParseBytes(t *testing.T) {
	cases := map[string]int64{
		"": 0, "0": 0, "500": 500,
		"1K": 1024, "125K": 125 * 1024, "512M": 512 * 1024 * 1024,
		"500G": 500 * 1024 * 1024 * 1024, "1T": 1024 * 1024 * 1024 * 1024,
		"2t": 2 * 1024 * 1024 * 1024 * 1024,
	}
	for in, want := range cases {
		got, err := ParseBytes(in)
		if err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v；想要 %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"-1", "-5G", "abc", "1.5G", "1P"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("ParseBytes(%q) 应报错", bad)
		}
	}
	if got := FormatBytes(500 * 1024 * 1024 * 1024); got != "500G" {
		t.Errorf("FormatBytes(500G) = %q，想要 500G", got)
	}
	if got := FormatBytesHuman(1536); got != "1.50 KB" {
		t.Errorf("FormatBytesHuman(1536) = %q，想要 1.50 KB", got)
	}
	if got := FormatBytesHuman(-1); got != "不限" {
		t.Errorf("FormatBytesHuman(-1) = %q，想要 不限", got)
	}
}

// TestPeriodBounds 覆盖周期计算：月/季/年、起始日钳制、闰年。
func TestPeriodBounds(t *testing.T) {
	cases := []struct {
		now      string
		period   TrafficPeriod
		startDay int
		wantS    string // 周期开始
		wantE    string // 周期结束
	}{
		// 月：当月 15 日起，11 月 20 日在 11 月 15 日–12 月 15 日。
		{"2026-11-20 10:00", TrafficPeriodMonthly, 15, "2026-11-15 00:00", "2026-12-15 00:00"},
		// 月：今天 11 月 10 日、起始日 15 号 → 上个周期（10 月 15 日–11 月 15 日）。
		{"2026-11-10 10:00", TrafficPeriodMonthly, 15, "2026-10-15 00:00", "2026-11-15 00:00"},
		// 月：起始日 1 号，默认。
		{"2026-11-24 19:00", TrafficPeriodMonthly, 1, "2026-11-01 00:00", "2026-12-01 00:00"},
		// 月：起始日 31 号，3 月 → 3 月 31 日–4 月 30 日（4 月没有 31 号，钳到 30 号）。
		{"2026-03-31 12:00", TrafficPeriodMonthly, 31, "2026-03-31 00:00", "2026-04-30 00:00"},
		// 月：起始日 31 号，2 月（2026 不是闰年）→ 2 月 28 日–3 月 31 日。
		{"2026-02-15 12:00", TrafficPeriodMonthly, 31, "2026-01-31 00:00", "2026-02-28 00:00"},
		// 月：起始日 31 号，闰年 2 月 → 2 月 29 日。
		{"2024-02-15 12:00", TrafficPeriodMonthly, 31, "2024-01-31 00:00", "2024-02-29 00:00"},
		// 月：12 月跨年。
		{"2026-12-20 12:00", TrafficPeriodMonthly, 15, "2026-12-15 00:00", "2027-01-15 00:00"},
		{"2027-01-10 12:00", TrafficPeriodMonthly, 15, "2026-12-15 00:00", "2027-01-15 00:00"},
		// 季：11 月在 Q4（10 月 1 日–1 月 1 日）。
		{"2026-11-20 10:00", TrafficPeriodQuarterly, 1, "2026-10-01 00:00", "2027-01-01 00:00"},
		// 季：起始日 15 号，5 月 → Q2（4 月 15 日–7 月 15 日）。
		{"2026-05-20 10:00", TrafficPeriodQuarterly, 15, "2026-04-15 00:00", "2026-07-15 00:00"},
		// 季：今天 4 月 1 日、起始日 15 号 → 上个季度（1 月 15 日–4 月 15 日）。
		{"2026-04-01 10:00", TrafficPeriodQuarterly, 15, "2026-01-15 00:00", "2026-04-15 00:00"},
		// 年：11 月 → 今年 1 月 1 日–明年 1 月 1 日。
		{"2026-11-20 10:00", TrafficPeriodYearly, 1, "2026-01-01 00:00", "2027-01-01 00:00"},
		// 年：起始日 15 号，今天 1 月 10 日 → 去年 1 月 15 日–今年 1 月 15 日。
		{"2027-01-10 10:00", TrafficPeriodYearly, 15, "2026-01-15 00:00", "2027-01-15 00:00"},
	}
	for _, c := range cases {
		s, e := PeriodBounds(mustTime(c.now), c.period, c.startDay)
		if s.Format("2006-01-02 15:04") != c.wantS || e.Format("2006-01-02 15:04") != c.wantE {
			t.Errorf("PeriodBounds(%s, %v, %d) = %s–%s；想要 %s–%s",
				c.now, c.period, c.startDay,
				s.Format("2006-01-02 15:04"), e.Format("2006-01-02 15:04"), c.wantS, c.wantE)
		}
	}
}

func TestTrafficConfigValidate(t *testing.T) {
	cfg := DefaultTrafficConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("默认配置应合法：%v", err)
	}
	cfg.StartDay = 0
	if err := cfg.Validate(); err == nil {
		t.Error("起始日 0 应报错")
	}
	cfg = DefaultTrafficConfig()
	cfg.StartDay = 32
	if err := cfg.Validate(); err == nil {
		t.Error("起始日 32 应报错")
	}
	cfg = DefaultTrafficConfig()
	cfg.LimitMode = TrafficLimitThrottle
	cfg.ThrottleRate = 0
	if err := cfg.Validate(); err == nil {
		t.Error("TC 限速模式下限速值 0 应报错")
	}
	cfg.ThrottleRate = 125 * 1024
	if err := cfg.Validate(); err != nil {
		t.Errorf("TC 限速模式下限速值 125K 应合法：%v", err)
	}
	cfg = DefaultTrafficConfig()
	cfg.Quota = -1
	if err := cfg.Validate(); err == nil {
		t.Error("限额 -1 应报错")
	}
}

// TestTrafficCounterModes 验证 4 种统计模式的计数。
func TestTrafficCounterModes(t *testing.T) {
	newCounter := func(mode TrafficMode) *TrafficCounter {
		cfg := DefaultTrafficConfig()
		cfg.Mode = mode
		return NewTrafficCounter(cfg)
	}
	c := newCounter(TrafficModeTotal)
	c.AddIn(100)
	c.AddOut(300)
	if got := c.Counted(); got != 400 {
		t.Errorf("总计应为 400，实际 %d", got)
	}
	c = newCounter(TrafficModeOutbound)
	c.AddIn(100)
	c.AddOut(300)
	if got := c.Counted(); got != 300 {
		t.Errorf("出站应为 300，实际 %d", got)
	}
	c = newCounter(TrafficModeInbound)
	c.AddIn(100)
	c.AddOut(300)
	if got := c.Counted(); got != 100 {
		t.Errorf("入站应为 100，实际 %d", got)
	}
	c = newCounter(TrafficModeMax)
	c.AddIn(100)
	c.AddOut(300)
	if got := c.Counted(); got != 300 {
		t.Errorf("最大值应为 300，实际 %d", got)
	}
	c.AddIn(500)
	if got := c.Counted(); got != 600 {
		t.Errorf("最大值应为 600（入站 600 > 出站 300），实际 %d", got)
	}
}

// TestTrafficCounterExceeded 验证超限判断与两种限制模式。
func TestTrafficCounterExceeded(t *testing.T) {
	cfg := DefaultTrafficConfig()
	cfg.Quota = 1000
	cfg.LimitMode = TrafficLimitBlock
	c := NewTrafficCounter(cfg)
	if c.Exceeded() || c.Blocked() || c.Throttled() {
		t.Error("没流量时不应超限")
	}
	c.AddOut(999)
	if c.Exceeded() {
		t.Error("999/1000 不应超限")
	}
	c.AddOut(1)
	if !c.Exceeded() || !c.Blocked() {
		t.Error("1000/1000 应超限且阻断")
	}
	if c.Throttled() {
		t.Error("阻断模式不应是 TC 限速状态")
	}
	// TC 限速模式。
	cfg.LimitMode = TrafficLimitThrottle
	c2 := NewTrafficCounter(cfg)
	c2.AddOut(1000)
	if !c2.Exceeded() || !c2.Throttled() {
		t.Error("1000/1000 在 TC 限速模式下应超限且限速")
	}
	if c2.Blocked() {
		t.Error("TC 限速模式不应是阻断状态")
	}
	// 限额 0 = 不限，永远不超限。
	cfg.Quota = 0
	c3 := NewTrafficCounter(cfg)
	c3.AddOut(1 << 40)
	if c3.Exceeded() || c3.Blocked() || c3.Throttled() {
		t.Error("限额 0 时永远不应超限")
	}
	// nil 计数器不 panic、不超限。
	var nilCounter *TrafficCounter
	nilCounter.AddIn(100)
	nilCounter.AddOut(100)
	nilCounter.Wait(100)
	if nilCounter.Exceeded() || nilCounter.Blocked() || nilCounter.Throttled() {
		t.Error("nil 计数器不应超限")
	}
	if got := nilCounter.Counted(); got != 0 {
		t.Errorf("nil 计数器 Counted 应为 0，实际 %d", got)
	}
}

// TestTrafficCounterPersistence 验证计数持久化：写盘 → 新计数器读回；
// 周期已过 → 重算；统计口径变了 → 重算。
func TestTrafficCounterPersistence(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "traffic.json")
	cfg := DefaultTrafficConfig()
	cfg.File = file
	c := NewTrafficCounter(cfg)
	c.AddIn(12345)
	c.AddOut(67890)
	c.Flush()
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("持久化文件没写出来：%v", err)
	}
	c2 := NewTrafficCounter(cfg)
	if got := c2.Counted(); got != 12345+67890 {
		t.Errorf("读回的计数应为 %d，实际 %d", 12345+67890, got)
	}
	st := c2.Status()
	if st.In != 12345 || st.Out != 67890 {
		t.Errorf("读回的入站/出站应为 12345/67890，实际 %d/%d", st.In, st.Out)
	}
	if st.Remaining != -1 {
		t.Errorf("不限额时剩余应为 -1，实际 %d", st.Remaining)
	}
	// 统计口径变了（模式改成出站）→ 计数重置。
	cfg.Mode = TrafficModeOutbound
	c3 := NewTrafficCounter(cfg)
	if got := c3.Counted(); got != 0 {
		t.Errorf("统计模式变了应重置计数，实际 %d", got)
	}
	// 周期已过 → 重算：把文件里的周期改成上个月。
	cfg = DefaultTrafficConfig()
	cfg.File = file
	c4 := NewTrafficCounter(cfg)
	c4.AddOut(100)
	c4.Flush()
	// 手工把文件里的 period_end 改成昨天。
	b, _ := os.ReadFile(file)
	var st4 trafficState
	if err := json.Unmarshal(b, &st4); err != nil {
		t.Fatalf("读持久化文件失败：%v", err)
	}
	st4.PeriodEnd = time.Now().AddDate(0, 0, -1)
	b2, _ := json.Marshal(st4)
	_ = os.WriteFile(file, b2, 0o644)
	c5 := NewTrafficCounter(cfg)
	if got := c5.Counted(); got != 0 {
		t.Errorf("周期已过应重置计数，实际 %d", got)
	}
}

// TestTrafficCounterRollover 验证周期边界一到自动清零
// （直接改计数器的 end 到过去，再记一笔就触发重算）。
func TestTrafficCounterRollover(t *testing.T) {
	cfg := DefaultTrafficConfig()
	c := NewTrafficCounter(cfg)
	c.AddOut(500)
	c.mu.Lock()
	c.end = time.Now().Add(-time.Second) // 周期已过
	c.mu.Unlock()
	c.AddOut(100)
	if got := c.Counted(); got != 100 {
		t.Errorf("周期切换后计数应为 100（只剩新周期的一笔），实际 %d", got)
	}
}

// TestTrafficStatusFormat 验证查看流量的输出里有关键字段。
func TestTrafficStatusFormat(t *testing.T) {
	cfg := DefaultTrafficConfig()
	cfg.Quota = 500 * 1024 * 1024 * 1024
	cfg.LimitMode = TrafficLimitBlock
	c := NewTrafficCounter(cfg)
	c.AddIn(100 * 1024 * 1024)
	c.AddOut(200 * 1024 * 1024)
	out := c.Status().FormatStatus()
	for _, want := range []string{"总计", "月", "已用", "限额", "剩余", "阻断", "状态：正常", "300.00 MB"} {
		if !strings.Contains(out, want) {
			t.Errorf("流量状态输出里缺 %q：\n%s", want, out)
		}
	}
	// 超限后的状态行。
	c.AddOut(500 * 1024 * 1024 * 1024)
	out = c.Status().FormatStatus()
	if !strings.Contains(out, "已超限") {
		t.Errorf("超限后状态输出应含“已超限”：\n%s", out)
	}
	// 不限额时的限额行。
	c2 := NewTrafficCounter(DefaultTrafficConfig())
	out = c2.Status().FormatStatus()
	if !strings.Contains(out, "不限（只统计，不限制）") {
		t.Errorf("不限额时状态输出应含“不限”：\n%s", out)
	}
}
