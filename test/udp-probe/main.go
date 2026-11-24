// udp-probe：探测本机 loopback UDP 能不能收发。
// 沙箱会静默丢弃 UDP 包（Go 的 sendto 不报错但包到不了对端，
// Python 的 sendto 直接 EPERM），所以 UDP 端到端测试在沙箱里
// 没法跑——run-tests.sh 先跑这个，通不过就 SKIP UDP 测试，
// 真测放在 VPS 部署验证里（test/udp-test.sh）。
// 用法：go run ./test/udp-probe.go；exit 0 = UDP 通，exit 1 = 不通。
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("UDP 监听失败：", err)
		os.Exit(1)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = srv.WriteTo(append([]byte("ok:"), buf[:n]...), addr)
		}
	}()
	c, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		fmt.Println("UDP 拨号失败：", err)
		os.Exit(1)
	}
	defer c.Close()
	if _, err := c.Write([]byte("probe")); err != nil {
		fmt.Println("UDP 发送失败：", err)
		os.Exit(1)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "ok:probe" {
		fmt.Printf("UDP 回包没回来（err=%v），本机 UDP 不通\n", err)
		os.Exit(1)
	}
	fmt.Println("本机 UDP 收发正常")
}
