// 握手重放防护的测试：时间戳、盐缓存、端到端重放拒绝、
// 老客户端（没有时间戳）仍能握手。
package mmx

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHandshakeTimestamp(t *testing.T) {
	// 带时间戳的 random：能读出“现在”，校验通过。
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	stamped := withHandshakeTimestamp(random)
	ts, ok := handshakeTimestamp(stamped)
	if !ok {
		t.Fatal("带时间戳的 random 应被识别出时间戳")
	}
	if now := time.Now().Unix(); ts < now-5 || ts > now+5 {
		t.Fatalf("读出的时间戳 %d 离现在太远（现在 %d）", ts, now)
	}
	if err := checkHandshakeTimestamp(stamped); err != nil {
		t.Fatalf("新鲜的时间戳应通过校验：%v", err)
	}
	// 原 random 不动（withHandshakeTimestamp 返回的是拷贝）。
	if string(random) == string(stamped) {
		t.Fatal("withHandshakeTimestamp 不应改原 random（调用方两处用的必须是同一份）")
	}
	// 纯随机数：不识别为时间戳，校验放行（老客户端）。
	if _, ok := handshakeTimestamp(random); ok {
		t.Fatal("纯随机数不应被识别为时间戳")
	}
	if err := checkHandshakeTimestamp(random); err != nil {
		t.Fatalf("没有时间戳的老握手应放行：%v", err)
	}
	// 太旧的时间戳：拒绝。
	old := make([]byte, 16)
	if _, err := rand.Read(old); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(old[:8], uint64(time.Now().Add(-10*time.Minute).Unix()))
	if err := checkHandshakeTimestamp(old); err == nil {
		t.Fatal("10 分钟前的时间戳应被拒绝")
	}
	// 太超前的时间戳：拒绝。
	future := make([]byte, 16)
	if _, err := rand.Read(future); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(future[:8], uint64(time.Now().Add(10*time.Minute).Unix()))
	if err := checkHandshakeTimestamp(future); err == nil {
		t.Fatal("超前 10 分钟的时间戳应被拒绝")
	}
}

func TestReplayCache(t *testing.T) {
	cache := NewReplayCache(time.Minute)
	salt := []byte("12345678")
	if cache.CheckAndAdd(salt) {
		t.Fatal("第一次见的盐不应算重放")
	}
	if !cache.CheckAndAdd(salt) {
		t.Fatal("第二次见同一个盐应算重放")
	}
	if cache.CheckAndAdd([]byte("87654321")) {
		t.Fatal("不同的盐不应算重放")
	}
	// nil 缓存 = 不设防，永远放行。
	var nilCache *ReplayCache
	if nilCache.CheckAndAdd(salt) {
		t.Fatal("nil 缓存应永远放行")
	}
	// TTL 过了就忘掉。
	short := NewReplayCache(50 * time.Millisecond)
	if short.CheckAndAdd(salt) {
		t.Fatal("第一次见的盐不应算重放")
	}
	time.Sleep(80 * time.Millisecond)
	if short.CheckAndAdd(salt) {
		t.Fatal("TTL 过后盐应被忘掉，不应算重放")
	}
}

// recordingConn 记下所有写出去的字节（用来原样重放一次客户端握手）。
type recordingConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (r *recordingConn) Write(b []byte) (int, error) {
	r.buf.Write(b)
	return r.Conn.Write(b)
}

// TestHandshakeReplayRejected：端到端——
// 第一次握手成功；把客户端发过的字节原样再发一次，服务端必须拒绝，
// 且不回任何握手回应（重放者拿不到会话）。
func TestHandshakeReplayRejected(t *testing.T) {
	cache := NewReplayCache(replaySaltTTL)

	// 第一次：真实客户端握手，录下客户端发出的字节。
	cRaw, sRaw := net.Pipe()
	var rec bytes.Buffer
	recConn := &recordingConn{Conn: cRaw, buf: &rec}
	errCh := make(chan error, 2)
	go func() {
		_, err := ClientHandshakeVersion(recConn, testPSK, VersionV3, false, false)
		errCh <- err
	}()
	go func() {
		_, err := ServerHandshakeWithKeysAndReplay(sRaw, [][]byte{testPSK}, cache)
		errCh <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("第一次握手应成功：%v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("第一次握手超时")
		}
	}
	cRaw.Close()
	sRaw.Close()
	if rec.Len() == 0 {
		t.Fatal("没录到客户端握手字节")
	}
	replayed := append([]byte(nil), rec.Bytes()...)

	// 第二次：把录下的字节原样重放。
	cRaw2, sRaw2 := net.Pipe()
	replayErrCh := make(chan error, 1)
	go func() {
		_, err := ServerHandshakeWithKeysAndReplay(sRaw2, [][]byte{testPSK}, cache)
		replayErrCh <- err
	}()
	_ = cRaw2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cRaw2.Write(replayed); err != nil {
		t.Fatalf("重放写握手字节失败：%v", err)
	}
	// 读回应放到另一个 goroutine：服务端拒绝后不回包，
	// 读会一直等到连接关掉才失败——所以先等服务端拒绝，
	// 再关服务端连接，读就立刻失败（而不是等 5 秒超时）。
	readErrCh := make(chan error, 1)
	go func() {
		one := make([]byte, 1)
		_, err := cRaw2.Read(one)
		readErrCh <- err
	}()
	select {
	case err := <-replayErrCh:
		if err == nil {
			t.Fatal("重放的握手应被拒绝")
		}
		if !strings.Contains(err.Error(), "重放") {
			t.Fatalf("重放拒绝的错误应提到“重放”，实际：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("重放握手处理超时")
	}
	sRaw2.Close()
	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("重放的握手不应收到服务端回应")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("重放后客户端读超时（应立刻失败）")
	}
	cRaw2.Close()
}

// TestLegacyHandshakeStillAccepted：老客户端（random 里没有时间戳）
// 发出的握手，服务端照常接受（只受盐缓存保护）。
func TestLegacyHandshakeStillAccepted(t *testing.T) {
	cache := NewReplayCache(replaySaltTTL)
	cRaw, sRaw := net.Pipe()
	errCh := make(chan error, 2)
	go func() {
		// 手动走一遍客户端握手，但 random 不带时间戳（模拟老客户端）。
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			errCh <- err
			return
		}
		legacyRand := make([]byte, 16)
		if _, err := rand.Read(legacyRand); err != nil {
			errCh <- err
			return
		}
		payload := buildHandshakePayload(priv.PublicKey().Bytes(), legacyRand, testPSK, "MM-1 auth c", VersionV3, false, false)
		if err := writeTLSRecord(cRaw, fakeHandshakeType, payload); err != nil {
			errCh <- err
			return
		}
		resp, err := readTLSRecord(cRaw, fakeHandshakeType)
		if err != nil {
			errCh <- err
			return
		}
		serverRand := make([]byte, 16)
		if _, _, _, err := parseHandshakePayload(resp, testPSK, "MM-1 auth s", serverRand); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	go func() {
		_, err := ServerHandshakeWithKeysAndReplay(sRaw, [][]byte{testPSK}, cache)
		errCh <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("老客户端握手应被接受：%v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("老客户端握手超时")
		}
	}
	cRaw.Close()
	sRaw.Close()
}
