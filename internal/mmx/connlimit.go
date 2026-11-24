// 连接数上限：防资源耗尽。
// 以前 handleConn 是无限制起 goroutine 的——
// 攻击者能开无限条连接，每条都占一个 goroutine 和一条会话。
// 两层上限：全局总量（默认 1024）和单 IP 并发（默认 64），
// 单用户正常用只有个位数连接，这两个数都很宽松；
// 超了就静默丢弃（不回包、不记失败进拉黑——超限不是握手失败）。
package mmx

import "sync"

// ConnLimiter 是全局 + 单 IP 的连接数限制器。
// TryAcquire 在 accept 循环里调（起 goroutine 之前）；
// Release 在连接处理结束时调（handleConn 的 defer 里）。
type ConnLimiter struct {
	global chan struct{}
	maxIP  int
	mu     sync.Mutex
	perIP  map[string]int
}

// NewConnLimiter 新建限制器：maxGlobal 是全局并发上限，
// maxPerIP 是单个来源 IP 的并发上限（<=0 表示不限单 IP）。
func NewConnLimiter(maxGlobal, maxPerIP int) *ConnLimiter {
	if maxGlobal <= 0 {
		maxGlobal = 1024
	}
	return &ConnLimiter{
		global: make(chan struct{}, maxGlobal),
		maxIP:  maxPerIP,
		perIP:  make(map[string]int),
	}
}

// TryAcquire 尝试占一个连接名额：全局满了或该 IP 满了返回 false
// （调用方应直接关掉这条连接）；成功返回 true，之后必须调 Release。
func (l *ConnLimiter) TryAcquire(ip string) bool {
	if l == nil {
		return true
	}
	select {
	case l.global <- struct{}{}:
	default:
		return false
	}
	if l.maxIP > 0 {
		l.mu.Lock()
		if l.perIP[ip] >= l.maxIP {
			l.mu.Unlock()
			<-l.global
			return false
		}
		l.perIP[ip]++
		l.mu.Unlock()
	}
	return true
}

// Release 归还一个连接名额。
func (l *ConnLimiter) Release(ip string) {
	if l == nil {
		return
	}
	<-l.global
	if l.maxIP > 0 {
		l.mu.Lock()
		if l.perIP[ip] <= 1 {
			delete(l.perIP, ip)
		} else {
			l.perIP[ip]--
		}
		l.mu.Unlock()
	}
}
