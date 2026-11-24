// 握手重放防护：时间戳 + 盐缓存。
//
// 问题：握手没有时间戳、服务端也不记见过的盐——
// 截到一次握手就能原样重放，每次都开一个完整会话；
// 更糟的是重放的握手会成功，攻击者的 IP 还会被记成“信任”。
//
// 修法（两层，都向后兼容，不用升版本）：
//  1. 时间戳：客户端把 Unix 秒数写进握手随机数的前 8 字节
//     （random 字段共 16 字节，后 8 字节仍是随机数）。
//     时间戳在鉴权标签的覆盖范围内（tag = HMAC(psk, label || pub || random)），
//     改不了；老客户端的 random 是纯随机数，服务端按“没有时间戳”
//     当作旧版握手照常接受——v2/v3 老链接、老客户端不用动。
//     服务端收到带时间戳的握手时，要求时间戳在现在前后 120 秒内
//     （容忍客户端时钟偏差）；太旧或太超前都拒绝。
//     误判概率可以忽略：随机 8 字节恰好落在“现在前后 30 分钟”
//     内的概率约 3600/2^64。
//  2. 盐缓存：服务端记住最近 10 分钟内见过的握手盐（salt，8 字节随机数），
//     同一个盐第二次出现就是重放，直接拒绝。合法握手的盐每次随机，
//     撞上的概率可以忽略；缓存只在握手成功时记（失败的握手不记，
//     免得攻击者拿垃圾盐把缓存塞满）。
package mmx

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	// handshakeTimestampWindow 是带时间戳的握手允许的时钟偏差：
	// 时间戳在现在前后 120 秒内才接受（手机一般自动对时，偏差很小；
	// 120 秒足够宽松，又不至于让重放窗口变大）。
	handshakeTimestampWindow = 120 * time.Second
	// handshakeTimestampDetect 是“这 8 字节像不像时间戳”的判断范围：
	// 落在现在前后 30 分钟内就当它是时间戳，否则当作老客户端的随机数。
	handshakeTimestampDetect = 30 * time.Minute
	// replaySaltTTL 是盐缓存的保留时间：比时间戳窗口长得多，
	// 保证时间戳窗口内的重放一定撞上缓存。
	replaySaltTTL = 10 * time.Minute
)

// withHandshakeTimestamp 把 Unix 秒数写进 16 字节随机数的前 8 字节，
// 返回一份拷贝（原 random 不动）。调用方要在握手载荷组装和密钥派生
// 两处都用返回的这份——两边用的 random 必须完全一致，
// 否则派生出的会话密钥对不上。
func withHandshakeTimestamp(random []byte) []byte {
	if len(random) != 16 {
		return random
	}
	out := append([]byte(nil), random...)
	binary.BigEndian.PutUint64(out[:8], uint64(time.Now().Unix()))
	return out
}

// handshakeTimestamp 从 16 字节随机数里读时间戳：
// 前 8 字节落在“现在前后 30 分钟”内就认为是时间戳，返回它；
// 否则是老客户端的纯随机数，返回 false（当作没有时间戳处理）。
func handshakeTimestamp(random []byte) (int64, bool) {
	if len(random) != 16 {
		return 0, false
	}
	ts := int64(binary.BigEndian.Uint64(random[:8]))
	now := time.Now().Unix()
	if ts < now-int64(handshakeTimestampDetect/time.Second) ||
		ts > now+int64(handshakeTimestampDetect/time.Second) {
		return 0, false
	}
	return ts, true
}

// checkHandshakeTimestamp 校验握手随机数里的时间戳：
// 没有时间戳（老客户端）直接放行；有时间戳时要求在现在前后 120 秒内，
// 太旧（重放的旧握手）或太超前（时钟偏差太大）都拒绝。
func checkHandshakeTimestamp(random []byte) error {
	ts, ok := handshakeTimestamp(random)
	if !ok {
		return nil // 老客户端：没有时间戳，按旧版接受
	}
	now := time.Now().Unix()
	if ts < now-int64(handshakeTimestampWindow/time.Second) {
		return errors.New("握手时间戳太旧（可能是重放的握手）")
	}
	if ts > now+int64(handshakeTimestampWindow/time.Second) {
		return errors.New("握手时间戳超前太多（客户端时钟偏差太大）")
	}
	return nil
}

// ReplayCache 记住最近见过的握手盐：同一个盐第二次出现就是重放。
// 只记握手成功的盐；条目过期（TTL）后自动清理（每次操作时顺带扫一遍）。
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time // salt -> 过期时间
	ttl  time.Duration
}

// NewReplayCache 新建盐缓存：ttl 是盐的保留时间。
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{seen: make(map[string]time.Time), ttl: ttl}
}

// CheckAndAdd 查一个盐是不是已经见过：见过返回 true（重放）；
// 没见过返回 false，并把它记下来。
// cache 为 nil 时永远返回 false（不设防——测试里没配缓存的握手照常过）。
func (c *ReplayCache) CheckAndAdd(salt []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	key := string(salt)
	if _, ok := c.seen[key]; ok {
		return true
	}
	c.seen[key] = now.Add(c.ttl)
	return false
}
