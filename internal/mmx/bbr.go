// BBR：服务端启动时默认尝试开启 TCP BBR 拥塞控制。
//
// BBR 是 Google 的 TCP 拥塞控制算法：不靠丢包来判断拥塞，
// 而是测量带宽和往返时间，在丢包多、抖动大的链路上比默认的 cubic
// 更稳、延迟更低。对 mm-x 这种代理协议，BBR 的意义是让发包更平滑，
// 和令牌桶限速配合：限速定上限，BBR 让上限之内的发送不突发、不堆队列。
//
// 注意：这是整台机器的系统设置（/proc/sys），不是只对 mm-x 生效，
// 开了之后 VPS 上其他程序的 TCP 也会走 BBR——这是常规做法，
// 和 VLESS 脚本里的一键 BBR 是一回事。
//
// 开启失败绝不影响服务端启动：不是 Linux、没有权限、
// 内核没有编译 BBR，都只记一条警告日志，继续跑。
package mmx

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	ccPath    = "/proc/sys/net/ipv4/tcp_congestion_control"
	ccAvail   = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	qdiscPath = "/proc/sys/net/core/default_qdisc"
)

func readSysctl(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}

// EnableBBR 尝试开启 BBR，返回一条中文状态（一定不返回致命错误）。
// 返回值：(是否已开启，状态描述)。
func EnableBBR() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "BBR 未开启：不是 Linux 系统，跳过 BBR 设置，继续运行"
	}
	avail, err := readSysctl(ccAvail)
	if err != nil {
		return false, fmt.Sprintf("BBR 未开启：读不到内核可用拥塞算法列表（%v），继续运行", err)
	}
	supported := false
	for _, name := range strings.Fields(avail) {
		if name == "bbr" {
			supported = true
			break
		}
	}
	if !supported {
		return false, fmt.Sprintf("BBR 未开启：内核不支持 BBR（当前可用：%s），继续运行", avail)
	}
	before, _ := readSysctl(ccPath)
	if before == "bbr" {
		if q, err := readSysctl(qdiscPath); err == nil && q != "fq" {
			if werr := writeSysctl(qdiscPath, "fq"); werr != nil {
				return false, fmt.Sprintf("BBR 已开启（tcp_congestion_control 已是 bbr），但 default_qdisc 改 fq 失败（%v），继续运行", werr)
			}
		}
		return true, "BBR 已开启：tcp_congestion_control=bbr（启动前已是 bbr）"
	}
	if err := writeSysctl(ccPath, "bbr"); err != nil {
		return false, fmt.Sprintf("BBR 未开启：写 tcp_congestion_control 失败（%v，可能没有权限），继续运行", err)
	}
	if q, err := readSysctl(qdiscPath); err == nil && q != "fq" {
		if werr := writeSysctl(qdiscPath, "fq"); werr != nil {
			return false, fmt.Sprintf("BBR 部分开启：tcp_congestion_control 已是 bbr，但 default_qdisc 改 fq 失败（%v），继续运行", werr)
		}
	}
	after, err := readSysctl(ccPath)
	if err != nil || after != "bbr" {
		return false, fmt.Sprintf("BBR 开启后校验失败：读回 tcp_congestion_control=%q，继续运行", after)
	}
	return true, "BBR 已开启：tcp_congestion_control=bbr，default_qdisc=fq（写前：" + before + "）"
}
