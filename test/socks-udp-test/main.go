// socks-udp-test：经 mm1-client 的 SOCKS5 UDP ASSOCIATE 做
// UDP 端到端测试（回显 + DNS 形状查询）。
// 自己起一个 UDP 回显服务和一个假 DNS 服务（任意查询都回一个
// 固定 A 记录），再经隧道发数据报过去、验回包。
// 用法：go run ./test/socks-udp-test.go --socks 127.0.0.1:18180
// exit 0 = 全过，exit 1 = 有失败（打印原因）。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	socksAddr := flag.String("socks", "", "mm1-client 的 SOCKS5 监听地址（必填）")
	realDNS := flag.Bool("real-dns", false, "DNS 测试改查真实 8.8.8.8:53（VPS 部署验证用；默认查本地假 DNS）")
	flag.Parse()
	if *socksAddr == "" {
		fmt.Println("缺少 --socks 参数")
		os.Exit(1)
	}
	echoAddr := startUDPEcho()
	var dnsAddr string
	if *realDNS {
		dnsAddr = "8.8.8.8:53"
	} else {
		dnsAddr = startFakeDNS()
	}
	fmt.Println("回显服务：", echoAddr, "DNS 服务：", dnsAddr)

	relay, tcpConn, err := socksUDPAssociate(*socksAddr)
	if err != nil {
		fmt.Println("SOCKS5 UDP ASSOCIATE 失败：", err)
		os.Exit(1)
	}
	defer tcpConn.Close()
	fmt.Println("UDP 中继地址：", relay)

	// 测试 A：回显（数据报完整性）。
	if err := udpRoundTrip(relay, echoAddr, []byte("udp-test-payload"), []byte("ECHO:udp-test-payload")); err != nil {
		fmt.Println("UDP 回显失败：", err)
		os.Exit(1)
	}
	fmt.Println("UDP 回显：PASS")

	// 测试 B：DNS 形状查询（ID 0x1234 查 example.com A 记录）。
	query := buildDNSQuery(0x1234, "example.com")
	resp, err := udpExchange(relay, dnsAddr, query)
	if err != nil {
		fmt.Println("UDP DNS 查询失败：", err)
		os.Exit(1)
	}
	if len(resp) < 12 || binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		fmt.Printf("DNS 回包 ID 不对（len=%d，头 %x）\n", len(resp), resp)
		os.Exit(1)
	}
	if *realDNS {
		// 真 DNS：只验 QR=1 且至少 1 个答案（答案内容随解析结果变，不硬编码）。
		if resp[2]&0x80 == 0 || binary.BigEndian.Uint16(resp[6:8]) == 0 {
			fmt.Printf("真 DNS 回包不像应答（flags=%x，答案数=%d）\n", resp[2], binary.BigEndian.Uint16(resp[6:8]))
			os.Exit(1)
		}
		fmt.Println("UDP DNS 查询：PASS（真 8.8.8.8，ID 对得上，有答案）")
	} else {
		if len(resp) < 4 || string(resp[len(resp)-4:]) != string([]byte{1, 2, 3, 4}) {
			fmt.Printf("DNS 回包答案不对（尾 4 字节 %x，想要 01020304）\n", resp[len(resp)-4:])
			os.Exit(1)
		}
		fmt.Println("UDP DNS 查询：PASS（ID 对得上，答案 1.2.3.4）")
	}
}

// startUDPEcho 起一个 UDP 回显服务：收到什么就回 "ECHO:"+原文。
func startUDPEcho() string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("起回显服务失败：", err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("ECHO:"), buf[:n]...), addr)
		}
	}()
	return pc.LocalAddr().String()
}

// startFakeDNS 起一个假 DNS 服务：任意查询都回固定应答
// （ID 原样，QR=1，1 个 A 记录答案 1.2.3.4）。
func startFakeDNS() string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("起假 DNS 服务失败：", err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if len(q) < 12 {
				continue
			}
			resp := make([]byte, 0, len(q)+16)
			resp = append(resp, q[0], q[1])             // ID 原样
			resp = append(resp, 0x81, 0x80)             // QR=1 AA=0 RD=1 RA=1，无错误
			resp = append(resp, 0x00, 0x01)             // QDCOUNT=1
			resp = append(resp, 0x00, 0x01)             // ANCOUNT=1
			resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT=0 ARCOUNT=0
			resp = append(resp, q[12:]...)              // 问题原样
			resp = append(resp, 0xC0, 0x0C)             // 指向问题的压缩指针
			resp = append(resp, 0x00, 0x01)             // TYPE=A
			resp = append(resp, 0x00, 0x01)             // CLASS=IN
			resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // TTL=60
			resp = append(resp, 0x00, 0x04)             // RDLENGTH=4
			resp = append(resp, 1, 2, 3, 4)             // RDATA=1.2.3.4
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// buildDNSQuery 拼一个最简 DNS 查询：ID + RD + 1 个问题（A 记录）。
func buildDNSQuery(id uint16, domain string) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range splitLabels(domain) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01) // 结束 + QTYPE=A + QCLASS=IN
	return q
}

func splitLabels(domain string) []string {
	var out []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			out = append(out, domain[start:i])
			start = i + 1
		}
	}
	return append(out, domain[start:])
}

// socksUDPAssociate 做 SOCKS5 握手 + UDP ASSOCIATE，
// 返回 UDP 中继地址和必须一直开着的 TCP 连接。
func socksUDPAssociate(socksAddr string) (string, net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return "", nil, err
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return "", nil, err
	}
	rep := make([]byte, 2)
	if _, err := readFull(c, rep); err != nil {
		c.Close()
		return "", nil, fmt.Errorf("握手回复读失败：%v", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		c.Close()
		return "", nil, fmt.Errorf("握手被拒：%x", rep)
	}
	// UDP ASSOCIATE，客户端 UDP 端点写 0.0.0.0:0（用 TCP 连接的源地址）。
	if _, err := c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		c.Close()
		return "", nil, err
	}
	hdr := make([]byte, 4)
	if _, err := readFull(c, hdr); err != nil {
		c.Close()
		return "", nil, fmt.Errorf("ASSOCIATE 回复读失败：%v", err)
	}
	if hdr[1] != 0x00 {
		c.Close()
		return "", nil, fmt.Errorf("ASSOCIATE 被拒 REP=0x%02x", hdr[1])
	}
	var host string
	switch hdr[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := readFull(c, b); err != nil {
			c.Close()
			return "", nil, err
		}
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := readFull(c, b); err != nil {
			c.Close()
			return "", nil, err
		}
		host = net.IP(b).String()
	default:
		c.Close()
		return "", nil, fmt.Errorf("ASSOCIATE 回复地址类型不支持：0x%02x", hdr[3])
	}
	pb := make([]byte, 2)
	if _, err := readFull(c, pb); err != nil {
		c.Close()
		return "", nil, err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(pb))), c, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// udpExchange 经中继发一个 SOCKS5 UDP 数据报给目标，等回包。
func udpExchange(relay, target string, payload []byte) ([]byte, error) {
	u, err := net.DialTimeout("udp", relay, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer u.Close()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	pkt := []byte{0x00, 0x00, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			pkt = append(pkt, 0x01)
			pkt = append(pkt, ip4...)
		} else {
			pkt = append(pkt, 0x04)
			pkt = append(pkt, ip.To16()...)
		}
	} else {
		pkt = append(pkt, 0x03, byte(len(host)))
		pkt = append(pkt, host...)
	}
	pkt = append(pkt, byte(port>>8), byte(port))
	pkt = append(pkt, payload...)
	if _, err := u.Write(pkt); err != nil {
		return nil, fmt.Errorf("发数据报失败：%v", err)
	}
	_ = u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, err := u.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("等回包失败（5s 超时或被拒）：%v", err)
	}
	resp := buf[:n]
	if len(resp) < 10 || resp[2] != 0x00 {
		return nil, fmt.Errorf("回包头不对：%x", resp)
	}
	// 跳过回包头（RSV+FRAG+ATYP+地址+端口），只验数据部分。
	off := 4
	switch resp[3] {
	case 0x01:
		off += 4 + 2
	case 0x03:
		off += 1 + int(resp[4]) + 2
	case 0x04:
		off += 16 + 2
	default:
		return nil, fmt.Errorf("回包地址类型不对：0x%02x", resp[3])
	}
	if off > len(resp) {
		return nil, fmt.Errorf("回包太短")
	}
	return resp[off:], nil
}

// udpRoundTrip 发一个数据报、验回包等于预期。
func udpRoundTrip(relay, target string, payload, want []byte) error {
	got, err := udpExchange(relay, target, payload)
	if err != nil {
		return err
	}
	if string(got) != string(want) {
		return fmt.Errorf("回包内容不对：得到 %q，想要 %q", got, want)
	}
	return nil
}
