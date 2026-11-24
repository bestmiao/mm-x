// 限速：令牌桶（按字节数），默认不限速。
//
// 设计选择：
//   - 双向都限：上行和下行各一个令牌桶。理由：限速的目的是让流量平稳，
//     不起峰、不引人注意；只限下行的话，上行（上传文件、回包）仍可能
//     出现突发峰值，照样会被流量分析盯上。
//   - 两端都限：客户端按链接里的 rate 限自己的发送和接收；服务端按
//     min(服务端 --rate，链接 rate) 限两个方向。服务端说了算——
//     客户端改大链接里的 rate 也突破不了服务端的上限。
//   - 只限转发的数据帧，不限握手：握手包很小，不计入流量；
//     否则 rate 设得很低时连握手都可能被拖慢甚至超时。
//   - 突发（burst）：桶的容量就是一次能冲的量。连接刚建立时桶是满的，
//     播放器可以在网好的时候一次多拿数据、把缓冲填满；突发额度用完后
//     回到平均限速。突发额度与限速一样取两端最小，服务端说了算。
//     burst = -1（未指定）时用默认值 DefaultBurst；burst = 0 表示
//     不许突发，严格按平均限速走；burst > 0 是突发字节数。
package mm1

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ParseRate 解析限速值：纯数字 = 每秒字节数；后缀 K/M/G = 1024 的倍数；
// "0" 或空 = 不限速。返回每秒字节数。
func ParseRate(s string) (int64, error) {
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
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("限速值不合法：%q，应为 0（不限速）或数字加 K/M/G，例如 512K", s)
	}
	return n * mult, nil
}

// FormatRate 把每秒字节数写回人类可读形式（链接里用）。
func FormatRate(bps int64) string {
	switch {
	case bps <= 0:
		return "0"
	case bps%(1024*1024*1024) == 0:
		return fmt.Sprintf("%dG", bps/(1024*1024*1024))
	case bps%(1024*1024) == 0:
		return fmt.Sprintf("%dM", bps/(1024*1024))
	case bps%1024 == 0:
		return fmt.Sprintf("%dK", bps/1024)
	default:
		return strconv.FormatInt(bps, 10)
	}
}

// BurstUnset 表示“没写 burst 参数”，用默认值 DefaultBurst。
const BurstUnset int64 = -1

// DefaultBurst 是不写 burst 时的默认突发额度：5MB。
// 按 1080p 平均 10 Mbps（约 1.25 MB/s）算，5MB 够一次多缓冲约 4 秒的
// 视频数据；建议范围 3–10MB，太大容易被流量分析注意到（等于把限速
// 压平峰值的意义抵消了）。
const DefaultBurst int64 = 5 * 1024 * 1024

// MinRate 取两个限速中更小的那个为准；0 表示不限速，
// 所以一方不限速时以另一方为准，双方都不限速则不限速。
func MinRate(a, b int64) int64 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// EffectiveBurst 取两个突发额度中更小的那个为准，服务端说了算。
// -1 表示“未指定”：双方都没指定时用默认值 DefaultBurst；
// 一方未指定时以另一方为准；0 是明确指定“不许突发”，
// 所以一方写 0 时生效值就是 0（min 里 0 最小）。
func EffectiveBurst(serverBurst, linkBurst int64) int64 {
	if serverBurst < 0 && linkBurst < 0 {
		return DefaultBurst
	}
	if serverBurst < 0 {
		return linkBurst
	}
	if linkBurst < 0 {
		return serverBurst
	}
	if serverBurst < linkBurst {
		return serverBurst
	}
	return linkBurst
}

// Limiter 是按字节数的令牌桶限速器。rate <= 0 表示不限速。
type Limiter struct {
	rate   int64
	burst  float64
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewLimiter 新建限速器。burst 是桶的容量（一次能冲的字节数）：
// burst < 0 用默认值 DefaultBurst；burst = 0 不许突发，
// 桶一开始就是空的，每字节都按平均速率等令牌；burst > 0 时
// 桶一开始是满的，连接刚建立就能一次冲 burst 字节，
// 用完后回到平均速率。rate <= 0 时不限速，burst 没有意义。
func NewLimiter(bytesPerSec, burst int64) *Limiter {
	if bytesPerSec <= 0 {
		return &Limiter{rate: 0}
	}
	if burst < 0 {
		burst = DefaultBurst
	}
	return &Limiter{
		rate:   bytesPerSec,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// Wait 等到有 n 个字节的令牌再返回；不限速时直接返回。
// 严格模式：循环里每次重新算令牌——睡醒后先重算再决定够不够，
// 不假设“睡了多久就攒了多少令牌”。两个方向共用一个桶时也不会
// 因为同时睡醒、同时放行而透支（一个方向先把攒下的令牌拿走，
// 另一个方向重算后发现不够就继续睡）。
func (l *Limiter) Wait(n int) {
	if l == nil || l.rate <= 0 || n <= 0 {
		return
	}
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.tokens += elapsed * float64(l.rate)
		// 桶容量取 max(burst, n)：burst=0 时桶不能锁死在 0——否则令牌永远
		// 攒不够一次 Wait，循环死等（已实测挂起）；但闲置时最多也只攒够
		// 当前这一次的 n，攒不出一整段突发；burst>0 时仍按 burst 封顶。
		cap := l.burst
		if cap < float64(n) {
			cap = float64(n)
		}
		if l.tokens > cap {
			l.tokens = cap
		}
		l.last = now
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return
		}
		need := float64(n) - l.tokens
		wait := time.Duration(need / float64(l.rate) * float64(time.Second))
		l.mu.Unlock()
		time.Sleep(wait)
	}
}

// Rate 返回限速值（每秒字节数，0 = 不限速）。
func (l *Limiter) Rate() int64 {
	if l == nil {
		return 0
	}
	return l.rate
}

// Burst 返回突发额度（字节数，0 = 不许突发）。
func (l *Limiter) Burst() int64 {
	if l == nil {
		return 0
	}
	return int64(l.burst)
}
