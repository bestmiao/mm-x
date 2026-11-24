// 流量画像（traffic profile）：只学 Snell v6 的思路，不引入 Snell 的
// 协议、代码或服务端。mm-x 仍是自己的协议，握手魔数、
// 版本字节、帧结构、mmx:// 链接格式一律不变。
//
// 思路：每次会话由 PSK + 会话盐（握手载荷前 8 字节）派生出一份画像，
// 画像决定填充长度的分布和 DATA 分片大小。同一 PSK 每次会话的盐都
// 不同，画像每次会话都可能不同——这样全网不再共用同一套“均匀随机”
// 填充分布，单个部署长期看也不再是稳定指纹（A2 之前是 PSK 派生固定画像）。
//
// 关键兼容性：
//   - 填充长度写在加密明文里（握手载荷的填充长度字节、帧头的填充
//     长度字节），接收方只读这个字段，从不依赖画像；分片大小也只
//     影响发送方一次写多少，接收方按帧读回、流语义不变。
//   - 所以新旧 v2 互通：新画像的发送方 → 旧均匀接收方能正常解析，
//     旧均匀发送方 → 新接收方也一样。升级顺序无所谓，不用换链接。
package mmx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
)

// padBucket 是填充长度分布里的一个加权区间 [lo, hi]（闭区间）。
type padBucket struct {
	lo, hi int
	weight int
}

// TrafficProfile 是一份由 PSK 派生的流量画像。
type TrafficProfile struct {
	Index int    // 0..len(trafficProfiles)-1
	Name  string // 画像名，仅用于日志/文档，不上线路

	handshakePad []padBucket // 握手填充长度分布（0–255）
	framePad     []padBucket // 帧填充长度分布（0–63）

	// MaxDataPayload 是 DATA 帧单帧载荷上限（分片大小）。
	// 必须 <= 16000，保证每条 TLS 记录 <= 16384 字节：
	// 记录体 = nonce(12) + 明文(6 + 填充<=63 + 载荷) + 标签(16)。
	MaxDataPayload int
}

var trafficProfiles = []TrafficProfile{
	{
		Index: 0, Name: "均匀",
		handshakePad:   []padBucket{{0, 255, 100}},
		framePad:       []padBucket{{0, 63, 100}},
		MaxDataPayload: 16000,
	},
	{
		Index: 1, Name: "偏小",
		handshakePad:   []padBucket{{0, 63, 70}, {64, 255, 30}},
		framePad:       []padBucket{{0, 15, 70}, {16, 63, 30}},
		MaxDataPayload: 8192,
	},
	{
		Index: 2, Name: "偏大",
		handshakePad:   []padBucket{{0, 127, 30}, {128, 255, 70}},
		framePad:       []padBucket{{0, 47, 30}, {48, 63, 70}},
		MaxDataPayload: 12288,
	},
	{
		Index: 3, Name: "居中",
		handshakePad:   []padBucket{{0, 63, 25}, {64, 191, 50}, {192, 255, 25}},
		framePad:       []padBucket{{0, 15, 20}, {16, 47, 60}, {48, 63, 20}},
		MaxDataPayload: 10240,
	},
	{
		Index: 4, Name: "极小为主",
		handshakePad:   []padBucket{{0, 31, 80}, {32, 255, 20}},
		framePad:       []padBucket{{0, 7, 80}, {8, 63, 20}},
		MaxDataPayload: 6144,
	},
	{
		Index: 5, Name: "极大为主",
		handshakePad:   []padBucket{{0, 191, 20}, {192, 255, 80}},
		framePad:       []padBucket{{0, 55, 20}, {56, 63, 80}},
		MaxDataPayload: 14336,
	},
}

// DeriveTrafficProfile 从 PSK 派生画像：
// index = HMAC-SHA256(psk, "MM-1 profile v2") 首字节 % 画像数。
// 同一 PSK 永远得到同一画像；不同 PSK 大概率得到不同画像。
// PSK 为空时返回 0 号画像（均匀），不报错。
// （兼容旧接口：等于 DeriveSessionProfile(psk, nil)。）
func DeriveTrafficProfile(psk []byte) TrafficProfile {
	return DeriveSessionProfile(psk, nil)
}

// DeriveSessionProfile 从 PSK + 会话盐派生画像（A2）：
// index = HMAC-SHA256(psk, "MM-1 profile v2" || salt) 首字节 % 画像数。
// 同一 PSK 的每次会话用不同的盐（握手载荷前 8 字节），画像每次会话
// 都可能不同——长期看不再是稳定指纹。salt 为空时和
// DeriveTrafficProfile(psk) 完全一致（HMAC 输入里不加盐）。
// 接收方只读填充长度字段，从不依赖画像，所以新旧互通。
func DeriveSessionProfile(psk, salt []byte) TrafficProfile {
	if len(psk) == 0 {
		return trafficProfiles[0]
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("MM-1 profile v2"))
	mac.Write(salt)
	sum := mac.Sum(nil)
	return trafficProfiles[int(sum[0])%len(trafficProfiles)]
}

// samplePadLen 按加权区间分布抽一个填充长度（闭区间内均匀）。
// 用 crypto/rand 做无偏抽样：先按权重选区间，再在区间内均匀取数。
func samplePadLen(buckets []padBucket, src io.Reader) (int, error) {
	total := 0
	for _, b := range buckets {
		if b.weight <= 0 || b.hi < b.lo {
			return 0, errors.New("画像填充区间不合法")
		}
		total += b.weight
	}
	roll, err := rand.Int(src, big.NewInt(int64(total)))
	if err != nil {
		return 0, err
	}
	r := int(roll.Int64())
	for _, b := range buckets {
		if r < b.weight {
			span := b.hi - b.lo + 1
			if span == 1 {
				return b.lo, nil
			}
			v, err := rand.Int(src, big.NewInt(int64(span)))
			if err != nil {
				return 0, err
			}
			return b.lo + int(v.Int64()), nil
		}
		r -= b.weight
	}
	return buckets[len(buckets)-1].hi, nil
}

// SampleHandshakePadLen 按本画像抽一个握手填充长度（0–255）。
func (p TrafficProfile) SampleHandshakePadLen() (int, error) {
	buckets := p.handshakePad
	if len(buckets) == 0 {
		buckets = trafficProfiles[0].handshakePad
	}
	return samplePadLen(buckets, rand.Reader)
}

// v4 握手填充长度区间：v4 握手包总长要落在 400–600 字节
// （像真实 ClientHello），固定字段 78 字节，填充取 322–522。
const (
	v4HandshakePadMin = 322
	v4HandshakePadMax = 522
)

// SampleHandshakePadLenV4 按本画像抽一个 v4 握手填充长度（322–522）：
// 把画像在 0–255 上的抽样结果线性映射到这个区间，画像的分布形状不变
// （偏小的画像抽到的还是偏小的值，只是整体平移到了 v4 的长度区间）。
func (p TrafficProfile) SampleHandshakePadLenV4() (int, error) {
	n, err := p.SampleHandshakePadLen()
	if err != nil {
		return 0, err
	}
	return v4HandshakePadMin + n*(v4HandshakePadMax-v4HandshakePadMin)/255, nil
}

// SampleFramePadLen 按本画像抽一个帧填充长度（0–63）。
func (p TrafficProfile) SampleFramePadLen() (int, error) {
	buckets := p.framePad
	if len(buckets) == 0 {
		buckets = trafficProfiles[0].framePad
	}
	return samplePadLen(buckets, rand.Reader)
}
