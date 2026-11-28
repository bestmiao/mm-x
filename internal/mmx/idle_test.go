// v3 会话空闲超时的测试。
package mmx

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// pipeConnPair 在 net.Pipe 上做一次真实 v3 握手，返回两端的加密连接。
// 和 v3_test.go 的 pipeSessionPair 不同：这里要的是底层的 *Conn，
// 因为空闲超时在 ServeMuxSession 里（它自己建 yamux 会话）。
func pipeConnPair(t *testing.T) (*Conn, *Conn) {
	return pipeConnPairVersion(t, VersionV3)
}

// pipeConnPairVersion 和 pipeConnPair 一样，只是握手版本可指定
// （v4 测试用它建 v4 加密连接）。
func pipeConnPairVersion(t *testing.T, version int) (*Conn, *Conn) {
	t.Helper()
	cRaw, sRaw := net.Pipe()
	errCh := make(chan error, 2)
	var cConn, sConn *Conn
	go func() {
		keys, err := ClientHandshakeVersion(cRaw, testPSK, version, false, false)
		if err != nil {
			errCh <- err
			return
		}
		mc, err := NewConn(cRaw, keys, true)
		if err != nil {
			errCh <- err
			return
		}
		cConn = mc
		errCh <- nil
	}()
	go func() {
		keys, err := ServerHandshakeWithKeys(sRaw, [][]byte{testPSK})
		if err != nil {
			errCh <- err
			return
		}
		mc, err := NewConn(sRaw, keys, false)
		if err != nil {
			errCh <- err
			return
		}
		sConn = mc
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("握手失败：%v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("握手超时")
		}
	}
	return cConn, sConn
}

func TestSessionIdleTimeoutClosesIdleSession(t *testing.T) {
	cConn, sConn := pipeConnPair(t)
	defer cConn.Close()
	done := make(chan error, 1)
	go func() {
		done <- ServeMuxSession(sConn, 0, BurstUnset, "test", TargetPolicy{AllowPrivate: true}, 300*time.Millisecond, nil)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("空闲会话结束不应报错：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("空闲会话应在超时后关闭（300ms 超时，等了 5 秒还没关）")
	}
}

func TestSessionIdleTimeoutKeepsBusySession(t *testing.T) {
	cConn, sConn := pipeConnPair(t)
	defer cConn.Close()
	// 客户端 yamux 会话（和 pipeSessionPair 里的做法一样）。
	cli, err := yamux.Client(NewFrameConn(cConn), YamuxConfig())
	if err != nil {
		t.Fatalf("建客户端复用会话失败：%v", err)
	}
	defer cli.Close()
	echoAddr, cleanup := startTCPEcho(t)
	defer cleanup()

	done := make(chan error, 1)
	go func() {
		done <- ServeMuxSession(sConn, 0, BurstUnset, "test", TargetPolicy{AllowPrivate: true}, 300*time.Millisecond, nil)
	}()
	// 开一条流并一直占着：回显服务会一直等数据，流不结束。
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("开流失败：%v", err)
	}
	defer st.Close()
	if _, err := st.Write(EncodeStreamHeader(StreamKindTCP, echoAddr, 0, BurstUnset)); err != nil {
		t.Fatalf("写流头失败：%v", err)
	}
	if err := ReadStreamAck(st); err != nil {
		t.Fatalf("流 ACK 失败：%v", err)
	}
	// 流开着（有流在跑），等 2 倍超时：会话不应被关。
	select {
	case err := <-done:
		t.Fatalf("有流在跑时会话不应被空闲超时关掉（err=%v）", err)
	case <-time.After(700 * time.Millisecond):
	}
	// 流关掉、会话断开后，ServeMuxSession 应很快返回。
	st.Close()
	cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("流和会话都关了，ServeMuxSession 应返回")
	}
}
