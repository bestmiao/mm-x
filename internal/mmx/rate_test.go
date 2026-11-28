package mmx

import (
	"sync"
	"testing"
	"time"
)

// burst=0 严格模式：桶一开始是空的，每字节都按平均速率等令牌。
// 10KB 以 100KB/s 传，至少要 0.1 秒；太快（< 0.08s）说明透支了。
func TestLimiterBurstZeroStrict(t *testing.T) {
	l := NewLimiter(100*1024, 0)
	start := time.Now()
	for i := 0; i < 10; i++ {
		l.Wait(1024)
	}
	if el := time.Since(start); el < 80*time.Millisecond {
		t.Fatalf("burst=0 应严格按平均限速走：10KB 以 100KB/s 至少 0.1s，实际只用了 %v", el)
	}
}

// burst>0 时开头可以冲：10KB 以 100KB/s、突发 10KB，第一把不用等。
func TestLimiterBurstAllowsInitialBurst(t *testing.T) {
	l := NewLimiter(100*1024, 10*1024)
	start := time.Now()
	l.Wait(10 * 1024)
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Fatalf("突发额度内不应等待：10KB 在突发 10KB 内应立即通过，实际用了 %v", el)
	}
}

// 两个方向共用一个桶时，并发 Wait 也不能透支：
// 两个 goroutine 各发 20KB（共 40KB），以 100KB/s 算至少要 0.4 秒；
// 旧实现里两边可能同时睡醒、同时放行，跑出 2 倍速。
func TestLimiterConcurrentNoOverdraft(t *testing.T) {
	l := NewLimiter(100*1024, 0)
	var wg sync.WaitGroup
	start := time.Now()
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				l.Wait(1024)
			}
		}()
	}
	wg.Wait()
	if el := time.Since(start); el < 320*time.Millisecond {
		t.Fatalf("并发 Wait 透支了：40KB 以 100KB/s 至少 0.4s，实际只用了 %v", el)
	}
}

// 不限速时 Wait 立即返回。
func TestLimiterUnlimited(t *testing.T) {
	l := NewLimiter(0, 0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		l.Wait(32 * 1024)
	}
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Fatalf("不限速时 Wait 应立即返回，实际用了 %v", el)
	}
}
