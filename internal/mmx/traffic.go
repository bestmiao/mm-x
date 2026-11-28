// 流量统计与限额：全服务总量（单用户单 PSK，不分用户）。
//
// 设计选择：
//   - 只统计中继层真实转发的字节数（双向分开记），不计握手开销，
//     也不计 yamux 流头——握手包很小，计进去只会让限额虚耗。
//   - 方向定义（从服务端看）：出站 = 服务端发给客户端（下载方向），
//     入站 = 客户端发给服务端（上传方向）；总计 = 入站 + 出站；
//     最大值 = 取入站、出站中大的那个（和某些 VPS 商按单向最大值计费一致）。
//   - 周期锚点：月 = 每月起始日；季 = 1/4/7/10 月的起始日；
//     年 = 每年 1 月的起始日。起始日 1–31 号，月份天数不够时钳到
//     当月最后一天（31 号在 2 月按 28/29 号算）。
//   - 计数器持久化到磁盘（默认 /etc/mmx/traffic.json），服务重启不丢；
//     周期边界一到自动清零并开始新周期；配置里的统计模式/周期/
//     起始日变了（文件里的签名对不上），计数按新配置重算——
//     旧模式下的已用数在新模式下没有可比性，留着反而误导。
//     只改限额/限制模式/TC 限速值不重置计数。
//   - 限额 0 = 不限（功能关闭）：只统计，不限制——
//     默认就是这个状态，不改变现有行为。
//   - 限制模式：block（阻断）= 超限后拒绝新连接并断开现有连接；
//     throttle（TC 限速）= 超限后全站降到设定的速度继续用，
//     用一只全服务共享的令牌桶实现（双向共用一个桶，总量就是限速值，
//     和 v3 会话级限速“一个桶 cap 总量”的思路一致）；
//     限速只影响超限后的流量，超限前不触发，正常限速逻辑（--rate）
//     不受影响——当前 RATE=0 不限速时，超限前仍不限速。
package mmx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 统计模式 / 统计周期 / 限制模式
// ---------------------------------------------------------------------------

// TrafficMode 是流量统计模式。
type TrafficMode int

const (
	// TrafficModeOutbound 出站：服务端发给客户端（下载方向）。
	TrafficModeOutbound TrafficMode = iota
	// TrafficModeInbound 入站：客户端发给服务端（上传方向）。
	TrafficModeInbound
	// TrafficModeTotal 总计：入站 + 出站（默认）。
	TrafficModeTotal
	// TrafficModeMax 最大值：取入站、出站中大的那个。
	TrafficModeMax
)

// ParseTrafficMode 解析统计模式：英文规范值 + 中文别名都认。
func ParseTrafficMode(s string) (TrafficMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "out", "outbound", "出站":
		return TrafficModeOutbound, nil
	case "in", "inbound", "入站":
		return TrafficModeInbound, nil
	case "total", "总计":
		return TrafficModeTotal, nil
	case "max", "最大值":
		return TrafficModeMax, nil
	default:
		return TrafficModeTotal, fmt.Errorf("流量统计模式不合法：%q，应为 outbound（出站）/ inbound（入站）/ total（总计）/ max（最大值）", s)
	}
}

// String 返回规范值（写配置、写服务启动参数用）。
func (m TrafficMode) String() string {
	switch m {
	case TrafficModeOutbound:
		return "outbound"
	case TrafficModeInbound:
		return "inbound"
	case TrafficModeMax:
		return "max"
	default:
		return "total"
	}
}

// Label 返回中文名（显示用）。
func (m TrafficMode) Label() string {
	switch m {
	case TrafficModeOutbound:
		return "出站"
	case TrafficModeInbound:
		return "入站"
	case TrafficModeMax:
		return "最大值"
	default:
		return "总计"
	}
}

// Desc 返回模式说明（显示用）。
func (m TrafficMode) Desc() string {
	switch m {
	case TrafficModeOutbound:
		return "出站（服务端→客户端，下载方向）"
	case TrafficModeInbound:
		return "入站（客户端→服务端，上传方向）"
	case TrafficModeMax:
		return "最大值（取入站、出站中大的那个）"
	default:
		return "总计（入站 + 出站）"
	}
}

// TrafficPeriod 是统计周期。
type TrafficPeriod int

const (
	// TrafficPeriodMonthly 月（默认）。
	TrafficPeriodMonthly TrafficPeriod = iota
	// TrafficPeriodQuarterly 季：3 个月。
	TrafficPeriodQuarterly
	// TrafficPeriodYearly 年：12 个月。
	TrafficPeriodYearly
)

// ParseTrafficPeriod 解析统计周期：英文规范值 + 中文别名都认。
func ParseTrafficPeriod(s string) (TrafficPeriod, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "monthly", "month", "月":
		return TrafficPeriodMonthly, nil
	case "quarterly", "quarter", "季":
		return TrafficPeriodQuarterly, nil
	case "yearly", "year", "年":
		return TrafficPeriodYearly, nil
	default:
		return TrafficPeriodMonthly, fmt.Errorf("统计周期不合法：%q，应为 monthly（月）/ quarterly（季）/ yearly（年）", s)
	}
}

// String 返回规范值（写配置、写服务启动参数用）。
func (p TrafficPeriod) String() string {
	switch p {
	case TrafficPeriodQuarterly:
		return "quarterly"
	case TrafficPeriodYearly:
		return "yearly"
	default:
		return "monthly"
	}
}

// Label 返回中文名（显示用）。
func (p TrafficPeriod) Label() string {
	switch p {
	case TrafficPeriodQuarterly:
		return "季"
	case TrafficPeriodYearly:
		return "年"
	default:
		return "月"
	}
}

// TrafficLimitMode 是超限后的限制模式。
type TrafficLimitMode int

const (
	// TrafficLimitBlock 阻断（默认）：拒绝新连接并断开现有连接。
	TrafficLimitBlock TrafficLimitMode = iota
	// TrafficLimitThrottle TC 限速：降到设定的速度继续用。
	TrafficLimitThrottle
)

// ParseTrafficLimitMode 解析限制模式：英文规范值 + 中文别名都认。
func ParseTrafficLimitMode(s string) (TrafficLimitMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block", "阻断":
		return TrafficLimitBlock, nil
	case "throttle", "tc", "限速", "tc限速", "tc-限速":
		return TrafficLimitThrottle, nil
	default:
		return TrafficLimitBlock, fmt.Errorf("限制模式不合法：%q，应为 block（阻断）/ throttle（TC 限速）", s)
	}
}

// String 返回规范值（写配置、写服务启动参数用）。
func (m TrafficLimitMode) String() string {
	if m == TrafficLimitThrottle {
		return "throttle"
	}
	return "block"
}

// Label 返回中文名（显示用）。
func (m TrafficLimitMode) Label() string {
	if m == TrafficLimitThrottle {
		return "TC 限速"
	}
	return "阻断"
}

// Desc 返回限制模式说明（显示用）。
func (m TrafficLimitMode) Desc() string {
	if m == TrafficLimitThrottle {
		return "TC 限速（超限后全站降到设定速度继续用）"
	}
	return "阻断（超限后拒绝新连接并断开现有连接）"
}

// ---------------------------------------------------------------------------
// 字节数解析 / 格式化
// ---------------------------------------------------------------------------

// ParseBytes 解析流量字节数：纯数字 = 字节；后缀 K/M/G/T = 1024 的倍数；
// "0" 或空 = 0（不限）。和 rate.go 的 ParseRate 同一风格，
// 多一个 T（限额到 TB 级才用得上，限速用不到 T）。
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	up := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(up, "K"):
		mult = 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(up, "M"):
		mult = 1024 * 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(up, "G"):
		mult = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(up, "T"):
		mult = 1024 * 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("流量值不合法：%q，应为 0（不限）或数字加 K/M/G/T，例如 500G", s)
	}
	return n * mult, nil
}

// FormatBytes 把字节数写回人类可读形式（限额回显用）：
// 能整除就用整单位（500G），否则保留两位小数（1.23 GB）。
func FormatBytes(b int64) string {
	if b <= 0 {
		return "0"
	}
	const (
		k = 1024
		m = 1024 * 1024
		g = 1024 * 1024 * 1024
		t = 1024 * 1024 * 1024 * 1024
	)
	switch {
	case b%t == 0:
		return fmt.Sprintf("%dT", b/t)
	case b%g == 0:
		return fmt.Sprintf("%dG", b/g)
	case b%m == 0:
		return fmt.Sprintf("%dM", b/m)
	case b%k == 0:
		return fmt.Sprintf("%dK", b/k)
	default:
		return FormatBytesHuman(b)
	}
}

// FormatBytesHuman 把字节数写成带单位的人类可读形式（显示用）：
// 1.23 GB、512.00 MB、0 B。b < 0 表示“不限”。
func FormatBytesHuman(b int64) string {
	if b < 0 {
		return "不限"
	}
	const (
		k = 1024.0
		m = 1024.0 * 1024
		g = 1024.0 * 1024 * 1024
		t = 1024.0 * 1024 * 1024 * 1024
	)
	f := float64(b)
	switch {
	case f < k:
		return fmt.Sprintf("%d B", b)
	case f < m:
		return fmt.Sprintf("%.2f KB", f/k)
	case f < g:
		return fmt.Sprintf("%.2f MB", f/m)
	case f < t:
		return fmt.Sprintf("%.2f GB", f/g)
	default:
		return fmt.Sprintf("%.2f TB", f/t)
	}
}

// ---------------------------------------------------------------------------
// 周期计算
// ---------------------------------------------------------------------------

func daysInMonth(year int, month time.Month) int {
	// 下月 1 号减 1 天就是本月最后一天。
	return time.Date(year, month+1, 1, 0, 0, 0, 0, time.Local).AddDate(0, 0, -1).Day()
}

// anchorTime 返回某年某月起始日对应的时刻（0 点）：
// 起始日超过当月天数时钳到当月最后一天（31 号在 2 月按 28/29 号算）。
func anchorTime(year int, month time.Month, startDay int) time.Time {
	day := startDay
	if last := daysInMonth(year, month); day > last {
		day = last
	}
	return time.Date(year, month, day, 0, 0, 0, 0, time.Local)
}

// addMonths 返回 y 年 m 月前后 n 个月的年月（处理跨年；
// 不用 time.AddDate——AddDate 在 31 号上会钳日期再进位，
// 例如 3 月 31 日减 1 个月会变成 3 月 3 日，而不是 2 月 28 日）。
func addMonths(year int, month time.Month, n int) (int, time.Month) {
	total := year*12 + int(month) - 1 + n
	y := total / 12
	m := time.Month(total%12 + 1)
	return y, m
}

// PeriodBounds 返回 now 所在的统计周期 [start, end)：
// 月 = 每月起始日；季 = 1/4/7/10 月的起始日；年 = 每年 1 月的起始日。
// startDay 必须在 1–31 之间（调用方校验）。
func PeriodBounds(now time.Time, period TrafficPeriod, startDay int) (start, end time.Time) {
	y, m, _ := now.Date()
	switch period {
	case TrafficPeriodQuarterly:
		// 季度起始月：1、4、7、10。
		qm := time.Month((int(m)-1)/3*3 + 1)
		start = anchorTime(y, qm, startDay)
		if start.After(now) {
			// 起始日在今后（例如今天 4 月 1 日、起始日 15 号 → 本季度还没开始），
			// 往回退一个季度。
			py, pm := addMonths(y, qm, -3)
			start = anchorTime(py, pm, startDay)
		}
		ey, em := addMonths(start.Year(), start.Month(), 3)
		end = anchorTime(ey, em, startDay)
		return start, end
	case TrafficPeriodYearly:
		start = anchorTime(y, time.January, startDay)
		if start.After(now) {
			start = anchorTime(y-1, time.January, startDay)
		}
		end = anchorTime(start.Year()+1, time.January, startDay)
		return start, end
	default: // 月
		start = anchorTime(y, m, startDay)
		if start.After(now) {
			py, pm := addMonths(y, m, -1)
			start = anchorTime(py, pm, startDay)
		}
		ey, em := addMonths(start.Year(), start.Month(), 1)
		end = anchorTime(ey, em, startDay)
		return start, end
	}
}

// PeriodDesc 返回周期的人类可读说明（显示用，不含“月/季/年”本身，
// 和 Label 拼起来用，例如“月（每月 1 日起）”）。
func PeriodDesc(period TrafficPeriod, startDay int) string {
	switch period {
	case TrafficPeriodQuarterly:
		return fmt.Sprintf("1/4/7/10 月 %d 日起", startDay)
	case TrafficPeriodYearly:
		return fmt.Sprintf("每年 1 月 %d 日起", startDay)
	default:
		return fmt.Sprintf("每月 %d 日起", startDay)
	}
}

// ---------------------------------------------------------------------------
// 计数器
// ---------------------------------------------------------------------------

// TrafficConfig 是流量统计与限额的完整配置。
type TrafficConfig struct {
	Mode         TrafficMode
	Period       TrafficPeriod
	StartDay     int // 1–31
	LimitMode    TrafficLimitMode
	Quota        int64  // 每周期限额（字节），0 = 不限（功能关闭）
	ThrottleRate int64  // TC 限速值（字节/秒），超限后全站降到的速度
	File         string // 计数持久化文件路径，"" = 不持久化
}

// DefaultTrafficConfig 返回默认配置：只统计、不限制，
// 和没加这个功能之前的行为完全一致。
func DefaultTrafficConfig() TrafficConfig {
	return TrafficConfig{
		Mode:         TrafficModeTotal,
		Period:       TrafficPeriodMonthly,
		StartDay:     1,
		LimitMode:    TrafficLimitBlock,
		Quota:        0,
		ThrottleRate: 125 * 1024, // 125K B/s ≈ 1 Mbps
		File:         "",
	}
}

// Validate 校验配置：起始日 1–31；TC 限速模式下限速值必须大于 0
// （限速值 0 = 不限速，超限后还“不限速”等于没限制，配错了）。
func (c TrafficConfig) Validate() error {
	if c.StartDay < 1 || c.StartDay > 31 {
		return fmt.Errorf("周期起始日不合法：%d，应为 1–31 号", c.StartDay)
	}
	if c.Quota < 0 {
		return fmt.Errorf("流量限额不合法：%d，不能为负数", c.Quota)
	}
	if c.LimitMode == TrafficLimitThrottle && c.ThrottleRate <= 0 {
		return fmt.Errorf("TC 限速值不合法：%s，TC 限速模式下必须大于 0", FormatRate(c.ThrottleRate))
	}
	return nil
}

// signature 是写进持久化文件的配置签名：模式/周期/起始日。
// 只有这三项变了才重置计数（限额/限制模式/TC 限速值变了不重置）。
func (c TrafficConfig) signature() string {
	return fmt.Sprintf("%s|%s|%d", c.Mode.String(), c.Period.String(), c.StartDay)
}

// trafficState 是持久化文件的 JSON 结构。
type trafficState struct {
	In          int64     `json:"in"`
	Out         int64     `json:"out"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Mode        string    `json:"mode"`
	Period      string    `json:"period"`
	StartDay    int       `json:"start_day"`
}

// TrafficCounter 是全服务流量的计数器：线程安全，
// 中继层每转发一块数据调 AddIn/AddOut 记一次。
// 方法对 nil 接收者都安全（测试/客户端路径不传计数器时直接返回），
// 所以调用方不用到处判空。
type TrafficCounter struct {
	mu       sync.Mutex
	cfg      TrafficConfig
	in, out  int64
	start    time.Time // 本周期开始（含）
	end      time.Time // 本周期结束（不含）
	throttle *Limiter  // TC 限速模式下超限后用的共享令牌桶（双向共用）
	dirty    bool      // 自上次持久化后计数变了
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewTrafficCounter 按配置新建计数器：有持久化文件就接着上次的数，
// 没有就从本周期 0 开始。文件里的周期已过或配置签名对不上时重算。
func NewTrafficCounter(cfg TrafficConfig) *TrafficCounter {
	now := time.Now()
	start, end := PeriodBounds(now, cfg.Period, cfg.StartDay)
	tc := &TrafficCounter{
		cfg:    cfg,
		start:  start,
		end:    end,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if cfg.File != "" {
		tc.load(now)
	}
	return tc
}

// load 从持久化文件恢复计数（只在构造时调，还没有并发）。
// 文件不存在/损坏/签名对不上/周期已过 → 从本周期 0 开始，
// 绝不能因为一个统计文件读不了就让服务端起不来。
func (c *TrafficCounter) load(now time.Time) {
	b, err := os.ReadFile(c.cfg.File)
	if err != nil {
		return
	}
	var st trafficState
	if err := json.Unmarshal(b, &st); err != nil {
		return
	}
	if st.Mode != c.cfg.Mode.String() || st.Period != c.cfg.Period.String() || st.StartDay != c.cfg.StartDay {
		return // 统计口径变了，旧数没法沿用，重算
	}
	if now.After(st.PeriodEnd) || now.Before(st.PeriodStart) {
		return // 上个周期已过，重算（新周期的边界由 PeriodBounds 定）
	}
	if st.In < 0 || st.Out < 0 {
		return
	}
	c.in, c.out = st.In, st.Out
	c.start, c.end = st.PeriodStart, st.PeriodEnd
}

// saveLocked 把当前计数写盘（调用时必须持有 c.mu）：
// 先写临时文件再改名，写一半崩了也不会把旧文件毁掉。
func (c *TrafficCounter) saveLocked() {
	if c.cfg.File == "" {
		c.dirty = false
		return
	}
	st := trafficState{
		In: c.in, Out: c.out,
		PeriodStart: c.start, PeriodEnd: c.end,
		Mode: c.cfg.Mode.String(), Period: c.cfg.Period.String(), StartDay: c.cfg.StartDay,
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	dir := filepath.Dir(c.cfg.File)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp := c.cfg.File + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, c.cfg.File); err != nil {
		return
	}
	c.dirty = false
}

// Flush 立刻把计数写盘（信号处理、关机前调）；没有脏数据就不写。
func (c *TrafficCounter) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dirty {
		c.saveLocked()
	}
}

// StartAutoSave 启动后台定期写盘：每 interval 检查一次，
// 有脏数据才写——中继层每 32KB 记一次数，不可能每次都写盘。
func (c *TrafficCounter) StartAutoSave(interval time.Duration) {
	if c == nil {
		return
	}
	go func() {
		defer close(c.doneCh)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				c.Flush()
			case <-c.stopCh:
				c.Flush()
				return
			}
		}
	}()
}

// StopAutoSave 停掉后台写盘（会先把最后一次脏数据写掉）。
func (c *TrafficCounter) StopAutoSave() {
	if c == nil {
		return
	}
	close(c.stopCh)
	<-c.doneCh
}

// rolloverLocked 检查周期边界：到了新周期就清零并重算边界
// （调用时必须持有 c.mu；清零后立刻写盘，周期切换不能丢）。
func (c *TrafficCounter) rolloverLocked(now time.Time) {
	if now.Before(c.end) {
		return
	}
	c.in, c.out = 0, 0
	c.start, c.end = PeriodBounds(now, c.cfg.Period, c.cfg.StartDay)
	c.dirty = true
	c.saveLocked()
}

// AddIn 记一笔入站字节（客户端→服务端→目标）。
func (c *TrafficCounter) AddIn(n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.mu.Lock()
	c.rolloverLocked(time.Now())
	c.in += n
	c.dirty = true
	c.mu.Unlock()
}

// AddOut 记一笔出站字节（目标→服务端→客户端）。
func (c *TrafficCounter) AddOut(n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.mu.Lock()
	c.rolloverLocked(time.Now())
	c.out += n
	c.dirty = true
	c.mu.Unlock()
}

// Counted 返回本周期按当前统计模式算的已用流量。
func (c *TrafficCounter) Counted() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rolloverLocked(time.Now())
	switch c.cfg.Mode {
	case TrafficModeOutbound:
		return c.out
	case TrafficModeInbound:
		return c.in
	case TrafficModeMax:
		if c.in > c.out {
			return c.in
		}
		return c.out
	default:
		return c.in + c.out
	}
}

// Exceeded 本周期已用是否达到限额（限额 0 = 不限，永远 false）。
func (c *TrafficCounter) Exceeded() bool {
	if c == nil || c.cfg.Quota <= 0 {
		return false
	}
	return c.Counted() >= c.cfg.Quota
}

// Blocked 是否处于阻断状态（超限 + 阻断模式）。
func (c *TrafficCounter) Blocked() bool {
	if c == nil {
		return false
	}
	return c.cfg.LimitMode == TrafficLimitBlock && c.Exceeded()
}

// Throttled 是否处于 TC 限速状态（超限 + TC 限速模式）。
func (c *TrafficCounter) Throttled() bool {
	if c == nil {
		return false
	}
	return c.cfg.LimitMode == TrafficLimitThrottle && c.Exceeded()
}

// throttleLimiterLocked 返回超限后用的共享令牌桶（调用时必须持有 c.mu）：
// burst=0——桶一开始是空的，每字节都按平均速率等令牌，
// 超限后第一块数据不能靠突发先冲一把（否则 1MB 的限额配 5MB 的
// 默认突发，超限后还能全速跑 5MB，限速就形同虚设）。
func (c *TrafficCounter) throttleLimiterLocked() *Limiter {
	if c.throttle == nil {
		c.throttle = NewLimiter(c.cfg.ThrottleRate, 0)
	}
	return c.throttle
}

// Wait 超限后才起作用：TC 限速模式下把这 n 个字节按限速值排队，
// 其余情况（没超限、阻断模式、不限额）直接返回，不拖慢正常流量。
func (c *TrafficCounter) Wait(n int) {
	if c == nil || n <= 0 {
		return
	}
	if !c.Throttled() {
		return
	}
	c.mu.Lock()
	lim := c.throttleLimiterLocked()
	c.mu.Unlock()
	lim.Wait(n)
}

// TrafficStatus 是本周期流量的一次快照（菜单“查看流量”用）。
type TrafficStatus struct {
	In, Out      int64  // 入站 / 出站已用（字节）
	Counted      int64  // 按统计模式算的已用（字节）
	Quota        int64  // 限额（字节），0 = 不限
	Remaining    int64  // 剩余（字节），-1 = 不限
	Mode         string // 规范值
	ModeLabel    string // 中文名
	Period       string // 规范值
	PeriodLabel  string // 中文名
	PeriodDesc   string // 周期说明
	StartDay     int
	LimitMode    string // 规范值
	LimitLabel   string // 中文名
	ThrottleRate int64  // TC 限速值（字节/秒）
	PeriodStart  time.Time
	PeriodEnd    time.Time
	Exceeded     bool
	Blocked      bool
}

// Status 返回本周期流量快照。
func (c *TrafficCounter) Status() TrafficStatus {
	if c == nil {
		cfg := DefaultTrafficConfig()
		now := time.Now()
		s, e := PeriodBounds(now, cfg.Period, cfg.StartDay)
		return TrafficStatus{
			Quota: 0, Remaining: -1,
			Mode: cfg.Mode.String(), ModeLabel: cfg.Mode.Label(),
			Period: cfg.Period.String(), PeriodLabel: cfg.Period.Label(),
			PeriodDesc: PeriodDesc(cfg.Period, cfg.StartDay), StartDay: cfg.StartDay,
			LimitMode: cfg.LimitMode.String(), LimitLabel: cfg.LimitMode.Label(),
			ThrottleRate: cfg.ThrottleRate, PeriodStart: s, PeriodEnd: e,
		}
	}
	c.mu.Lock()
	c.rolloverLocked(time.Now())
	in, out := c.in, c.out
	start, end := c.start, c.end
	cfg := c.cfg
	c.mu.Unlock()
	var counted int64
	switch cfg.Mode {
	case TrafficModeOutbound:
		counted = out
	case TrafficModeInbound:
		counted = in
	case TrafficModeMax:
		if in > out {
			counted = in
		} else {
			counted = out
		}
	default:
		counted = in + out
	}
	remaining := int64(-1)
	if cfg.Quota > 0 {
		remaining = cfg.Quota - counted
		if remaining < 0 {
			remaining = 0
		}
	}
	return TrafficStatus{
		In: in, Out: out, Counted: counted, Quota: cfg.Quota, Remaining: remaining,
		Mode: cfg.Mode.String(), ModeLabel: cfg.Mode.Label(),
		Period: cfg.Period.String(), PeriodLabel: cfg.Period.Label(),
		PeriodDesc: PeriodDesc(cfg.Period, cfg.StartDay), StartDay: cfg.StartDay,
		LimitMode: cfg.LimitMode.String(), LimitLabel: cfg.LimitMode.Label(),
		ThrottleRate: cfg.ThrottleRate, PeriodStart: start, PeriodEnd: end,
		Exceeded: cfg.Quota > 0 && counted >= cfg.Quota,
		Blocked:  cfg.LimitMode == TrafficLimitBlock && cfg.Quota > 0 && counted >= cfg.Quota,
	}
}

// FormatStatus 返回人类可读的流量统计（mm 菜单“查看流量”和
// mmx-server --traffic-status 直接打印这个）。
func (s TrafficStatus) FormatStatus() string {
	const tf = "2006-01-02 15:04"
	var b strings.Builder
	b.WriteString("流量统计（本周期）\n")
	fmt.Fprintf(&b, "  统计模式：%s（%s）\n", s.ModeLabel, map[string]string{
		"outbound": "服务端→客户端，下载方向",
		"inbound":  "客户端→服务端，上传方向",
		"total":    "入站 + 出站",
		"max":      "取入站、出站中大的那个",
	}[s.Mode])
	fmt.Fprintf(&b, "  统计周期：%s（%s）\n", s.PeriodLabel, s.PeriodDesc)
	fmt.Fprintf(&b, "  本周期：%s 至 %s\n", s.PeriodStart.Format(tf), s.PeriodEnd.Format(tf))
	fmt.Fprintf(&b, "  已用：%s（入站 %s / 出站 %s）\n",
		FormatBytesHuman(s.Counted), FormatBytesHuman(s.In), FormatBytesHuman(s.Out))
	if s.Quota > 0 {
		fmt.Fprintf(&b, "  限额：%s\n", FormatBytesHuman(s.Quota))
		fmt.Fprintf(&b, "  剩余：%s\n", FormatBytesHuman(s.Remaining))
	} else {
		b.WriteString("  限额：不限（只统计，不限制）\n")
		b.WriteString("  剩余：不限\n")
	}
	if s.LimitMode == "throttle" {
		fmt.Fprintf(&b, "  限制模式：TC 限速（超限后全站降到 %s/s 继续用）\n", FormatBytesHuman(s.ThrottleRate))
	} else {
		b.WriteString("  限制模式：阻断（超限后拒绝新连接并断开现有连接）\n")
	}
	switch {
	case s.Exceeded && s.Blocked:
		b.WriteString("  状态：已超限（阻断模式：新连接被拒绝，现有连接已断开）\n")
	case s.Exceeded:
		fmt.Fprintf(&b, "  状态：已超限（TC 限速模式：全站限速 %s/s）\n", FormatBytesHuman(s.ThrottleRate))
	default:
		b.WriteString("  状态：正常\n")
	}
	return b.String()
}
