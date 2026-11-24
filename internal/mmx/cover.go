// 掩护流量（chaff，v5）：会话空闲时发的假流量。
//
// 针对的特征：一条长会话在没数据时是“死寂”的，只剩 yamux 固定
// 30 秒一次的 keepalive——严格周期的小记录本身就是时序特征，
// 而真实浏览器的连接要么在传数据、要么干脆没有连接。
// 掩护流量在空闲时按随机间隔发一帧小记录（载荷是随机字节，
// 尺寸 64–512B，像一次小的应用数据）：
//   - 严格周期被随机间隔抹掉（不再是 30.0 秒整）；
//   - 空闲连接看起来像“后台偶尔有动静的浏览器”，而不是一条死隧道。
//
// 代价：low 档空闲时每小时最多约 20KB，几乎不花流量；有数据在传时
// 一帧都不发，速度不受影响。档位是部署偏好，不进链接、不上线路：
// 服务端 --cover-traffic、客户端 --cover-traffic，默认 low。
// 接收方在 ReadFrame 里直接丢弃掩护帧（见 mmx.go），调用方看不见它；
// 老版本会话（v4 及以前）不发也不收，互通不受影响。
package mmx

import (
	"crypto/rand"
	"fmt"
	"time"
)

// CoverMode 是掩护流量的档位。
type CoverMode int

const (
	CoverOff  CoverMode = iota // 不发掩护帧
	CoverLow                   // 默认：空闲时平均约 45 秒一帧小记录
	CoverHigh                  // 空闲时平均约 20 秒一帧小记录
)

// ParseCoverMode 解析 --cover-traffic 的值：off/low/high（也接受中文 关/低/高）。
func ParseCoverMode(s string) (CoverMode, error) {
	switch s {
	case "", "low", "低":
		return CoverLow, nil
	case "off", "关":
		return CoverOff, nil
	case "high", "高":
		return CoverHigh, nil
	default:
		return CoverOff, fmt.Errorf("掩护流量档位不合法：%q，应为 off（关）/ low（低，默认）/ high（高）", s)
	}
}

// DefaultCoverMode 是 NewConn 建 v5 连接时默认的掩护档位：
// 服务端/客户端启动时由 --cover-traffic 改写；测试可直接改。
var DefaultCoverMode = CoverLow

// 掩护流量的时间/尺寸参数（包级变量，测试可改小后验证行为，
// 用完记得恢复）：
//   - coverIdleMin：上次写帧距今超过这么久才算空闲、值得发掩护帧；
//   - coverSleepLo/Hi：两次掩护帧之间的睡眠在 [lo, hi] 内均匀随机；
//   - coverSizeLo/Hi：掩护帧载荷在 [lo, hi] 字节内均匀随机。
var (
	coverIdleMin = map[CoverMode]time.Duration{CoverLow: 15 * time.Second, CoverHigh: 8 * time.Second}
	coverSleepLo = map[CoverMode]time.Duration{CoverLow: 20 * time.Second, CoverHigh: 8 * time.Second}
	coverSleepHi = map[CoverMode]time.Duration{CoverLow: 70 * time.Second, CoverHigh: 32 * time.Second}
	coverSizeLo  = map[CoverMode]int{CoverLow: 64, CoverHigh: 128}
	coverSizeHi  = map[CoverMode]int{CoverLow: 320, CoverHigh: 512}
)

// StartCoverTraffic 在 v5 会话上启动掩护流量 goroutine（只启动一次）。
// mode 是 CoverOff 或版本不是 v5 时什么都不做；连接关掉（Close）或
// 写帧出错时 goroutine 自己停。
func (c *Conn) StartCoverTraffic(mode CoverMode) {
	if mode == CoverOff || c.version < VersionV5 {
		return
	}
	c.coverStartOnce.Do(func() { go c.coverLoop(mode) })
}

// coverLoop：睡一段随机时间 → 空闲够久就发一帧掩护帧 → 再睡。
// 睡眠用 time.After + coverStop 做退出：连接一关就停，不等睡完。
func (c *Conn) coverLoop(mode CoverMode) {
	lo, hi := coverSleepLo[mode], coverSleepHi[mode]
	if hi <= lo {
		hi = lo + time.Second
	}
	idleMin := coverIdleMin[mode]
	sizeLo, sizeHi := coverSizeLo[mode], coverSizeHi[mode]
	if sizeHi <= sizeLo {
		sizeHi = sizeLo + 1
	}
	for {
		// 在 [lo, hi] 内均匀随机取一个睡眠时长：hi-lo 本身已是
		// Duration（纳秒计），randIntn 的结果直接当纳秒加，不再乘秒——
		// 否则一次睡眠会变成几百年，掩护帧永远发不出来。
		d := lo + time.Duration(randIntn(int(hi-lo)+1))
		select {
		case <-c.coverStop:
			return
		case <-time.After(d):
		}
		c.mu.Lock()
		idle := time.Since(c.lastWrite)
		c.mu.Unlock()
		if idle < idleMin {
			continue
		}
		payload := make([]byte, sizeLo+randIntn(sizeHi-sizeLo+1))
		if _, err := rand.Read(payload); err != nil {
			return
		}
		if err := c.WriteFrame(FrameChaff, payload); err != nil {
			return
		}
	}
}
