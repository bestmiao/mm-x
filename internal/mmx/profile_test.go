// 流量画像的单元测试：确定性、分布形状、新旧互通。
package mmx

import (
	"bytes"
	"net"
	"testing"
)

// profilePSKForIndex 找一个能派生出指定画像的 PSK（逐字节试，确定性）。
func profilePSKForIndex(t *testing.T, want int) []byte {
	t.Helper()
	for i := 0; i < 256; i++ {
		psk := make([]byte, 32)
		psk[0] = byte(i)
		psk[1] = 0x42
		if p := DeriveTrafficProfile(psk); p.Index == want {
			return psk
		}
	}
	t.Fatalf("256 个候选 PSK 里没找到画像 %d", want)
	return nil
}

func TestProfileDeterminism(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	p1 := DeriveTrafficProfile(psk)
	p2 := DeriveTrafficProfile(psk)
	if p1.Index != p2.Index || p1.Name != p2.Name || p1.MaxDataPayload != p2.MaxDataPayload {
		t.Fatalf("同一 PSK 两次派生画像不同：%+v vs %+v", p1, p2)
	}
	// 空 PSK 不报错，退回 0 号画像。
	if p := DeriveTrafficProfile(nil); p.Index != 0 {
		t.Fatalf("空 PSK 应得 0 号画像，实际 %d", p.Index)
	}
	// 20 个不同 PSK 里至少出现 2 种画像（6 种画像均匀分布时，
	// 20 次全抽到同一种的概率约 6^-19，基本不可能）。
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		psk := make([]byte, 32)
		psk[0] = byte(i)
		seen[DeriveTrafficProfile(psk).Index] = true
	}
	if len(seen) < 2 {
		t.Fatalf("20 个不同 PSK 只得到 %d 种画像，派生没有区分度", len(seen))
	}
}

func TestProfileDistribution(t *testing.T) {
	// 每个画像抽 2000 次：填充长度必须仍跨一个很宽的范围
	// （不能坍缩成单值或很小的区间），且均值要符合画像的倾向。
	for _, p := range trafficProfiles {
		var hsMin, hsMax, hsSum int
		hsMin = 256
		hsSeen := map[int]bool{}
		for i := 0; i < 2000; i++ {
			n, err := p.SampleHandshakePadLen()
			if err != nil {
				t.Fatalf("画像 %d 抽握手填充失败：%v", p.Index, err)
			}
			if n < 0 || n > 255 {
				t.Fatalf("画像 %d 握手填充 %d 越界（应为 0–255）", p.Index, n)
			}
			hsSeen[n] = true
			if n < hsMin {
				hsMin = n
			}
			if n > hsMax {
				hsMax = n
			}
			hsSum += n
		}
		if len(hsSeen) < 100 || hsMax-hsMin < 200 {
			t.Fatalf("画像 %d 握手填充坍缩：只出现 %d 个不同值，范围 %d–%d", p.Index, len(hsSeen), hsMin, hsMax)
		}
		hsMean := float64(hsSum) / 2000
		var frMin, frMax, frSum int
		frMin = 64
		frSeen := map[int]bool{}
		for i := 0; i < 2000; i++ {
			n, err := p.SampleFramePadLen()
			if err != nil {
				t.Fatalf("画像 %d 抽帧填充失败：%v", p.Index, err)
			}
			if n < 0 || n > 63 {
				t.Fatalf("画像 %d 帧填充 %d 越界（应为 0–63）", p.Index, n)
			}
			frSeen[n] = true
			if n < frMin {
				frMin = n
			}
			if n > frMax {
				frMax = n
			}
			frSum += n
		}
		if len(frSeen) < 40 || frMax-frMin < 50 {
			t.Fatalf("画像 %d 帧填充坍缩：只出现 %d 个不同值，范围 %d–%d", p.Index, len(frSeen), frMin, frMax)
		}
		frMean := float64(frSum) / 2000
		// 均值倾向（2000 次抽样，标准误很小，留足余量）：
		switch p.Index {
		case 1: // 偏小
			if hsMean >= 128 || frMean >= 32 {
				t.Fatalf("画像 1 偏小：握手均值 %.1f / 帧均值 %.1f，应分别 <128 / <32", hsMean, frMean)
			}
		case 2: // 偏大
			if hsMean <= 128 || frMean <= 32 {
				t.Fatalf("画像 2 偏大：握手均值 %.1f / 帧均值 %.1f，应分别 >128 / >32", hsMean, frMean)
			}
		case 4: // 极小为主
			if hsMean >= 100 || frMean >= 20 {
				t.Fatalf("画像 4 极小为主：握手均值 %.1f / 帧均值 %.1f，应分别 <100 / <20", hsMean, frMean)
			}
		case 5: // 极大为主
			if hsMean <= 150 || frMean <= 40 {
				t.Fatalf("画像 5 极大为主：握手均值 %.1f / 帧均值 %.1f，应分别 >150 / >40", hsMean, frMean)
			}
		}
		if p.MaxDataPayload <= 0 || p.MaxDataPayload > 16000 {
			t.Fatalf("画像 %d 分片上限 %d 不合法（应为 1–16000）", p.Index, p.MaxDataPayload)
		}
	}
}

func TestProfileInteropNewSenderOldReceiver(t *testing.T) {
	// 发送方和接收方按 A2 各自从同一盐派生同一画像（画像号随会话而变，
	// 不再等于 PSK 派生）；接收方画像清零模拟旧版接收方：
	// ReadFrame 完全不依赖画像，必须把 20000 字节原样读回，
	// 且每帧载荷都不超过发送方的分片上限。
	psk := profilePSKForIndex(t, 4)
	cc, sc := handshakePairWithPSK(t, psk)
	defer cc.Close()
	defer sc.Close()
	maxPayload := cc.Profile().MaxDataPayload
	if maxPayload <= 0 || maxPayload > 16000 {
		t.Fatalf("会话画像分片上限 %d 不合法（应为 1–16000）", maxPayload)
	}
	// 模拟旧接收方：画像清零（等同旧版均匀发送/接收逻辑）。
	sc.profile = TrafficProfile{}

	data := make([]byte, 20000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	done := make(chan error, 1)
	go func() { done <- cc.WriteFrame(FrameData, data) }()
	var got []byte
	frames := 0
	for len(got) < len(data) {
		ft, payload, err := sc.ReadFrame()
		if err != nil {
			t.Fatalf("旧接收方读第 %d 帧失败：%v", frames+1, err)
		}
		if ft != FrameData {
			t.Fatalf("第 %d 帧类型不对：%d", frames+1, ft)
		}
		if len(payload) > maxPayload {
			t.Fatalf("第 %d 帧载荷 %d 字节，超过发送方画像分片上限 %d", frames+1, len(payload), maxPayload)
		}
		got = append(got, payload...)
		frames++
		if frames > 10 {
			t.Fatalf("20000 字节按 %d 分片应为 %d 帧，已读 %d 帧还没读完", maxPayload, (len(data)+maxPayload-1)/maxPayload, frames)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("新发送方写帧失败：%v", err)
	}
	wantFrames := (len(data) + maxPayload - 1) / maxPayload
	if frames != wantFrames {
		t.Fatalf("20000 字节按 %d 分片应为 %d 帧，实际 %d 帧", maxPayload, wantFrames, frames)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("新旧互通后重组数据不一致（收到 %d 字节，应为 %d）", len(got), len(data))
	}
	// 反方向也一样：旧（均匀）发送方 → 新画像接收方。
	sc.profile = cc.Profile()
	cc.profile = TrafficProfile{}
	data2 := []byte("hello-old-to-new-interop")
	done2 := make(chan error, 1)
	go func() { done2 <- cc.WriteFrame(FrameData, data2) }()
	ft, payload, err := sc.ReadFrame()
	if err != nil || ft != FrameData || !bytes.Equal(payload, data2) {
		t.Fatalf("旧发送方 → 新接收方失败：type=%d err=%v payload=%q", ft, err, payload)
	}
	if err := <-done2; err != nil {
		t.Fatalf("旧发送方写帧失败：%v", err)
	}
}

// handshakePairWithPSK 与 stealth_test.go 的 handshakePair 一样，
// 只是用指定的 PSK 握手。
func handshakePairWithPSK(t *testing.T, psk []byte) (*Conn, *Conn) {
	t.Helper()
	cSide, sSide := net.Pipe()
	errCh := make(chan error, 1)
	var sKeys *SessionKeys
	go func() {
		var err error
		sKeys, err = ServerHandshake(sSide, psk)
		errCh <- err
	}()
	cKeys, err := ClientHandshake(cSide, psk, false, false)
	if err != nil {
		t.Fatalf("客户端握手失败：%v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("服务端握手失败：%v", err)
	}
	cc, err := NewConn(cSide, cKeys, true)
	if err != nil {
		t.Fatalf("客户端 NewConn 失败：%v", err)
	}
	sc, err := NewConn(sSide, sKeys, false)
	if err != nil {
		t.Fatalf("服务端 NewConn 失败：%v", err)
	}
	// A2：同一会话两侧从同一盐派生同一画像（画像号随会话而变，
	// 不再等于 PSK 单独派生——这正是每会话画像的意义）。
	if cc.Profile().Index != sc.Profile().Index {
		t.Fatalf("同一会话两侧画像不一致：客户端 %d，服务端 %d", cc.Profile().Index, sc.Profile().Index)
	}
	return cc, sc
}
