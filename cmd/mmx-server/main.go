// mmx-server：mm-x 协议服务端原型。
// 监听一个端口，接受 mm-x 握手，按客户端发来的目标地址转发 TCP。
// 启动时打印自己对应的 mmx:// 链接。
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"mmxpoc/internal/mmx"
)

// stringList 是可重复写的字符串 flag：--whitelist 1.2.3.4 --whitelist 5.6.7.8
type stringList []string

func (s *stringList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	listenAddr := flag.String("listen", "127.0.0.1:18081", "监听地址")
	pskHex := flag.String("psk", "", "预共享密钥：64 位十六进制（32 字节），不填则随机生成")
	pskFile := flag.String("psk-file", "", "密钥文件路径：文件里写 64 位十六进制密钥；轮换密钥时直接改文件内容，服务端下次握手前自动发现并轮换（不用重启）")
	graceStr := flag.String("grace", "24h", "密钥轮换后旧密钥的宽限期，例如 24h / 1h / 30m，0 = 换了就立即失效")
	printLink := flag.Bool("print-link", false, "只打印当前密钥对应的 mmx:// 链接然后退出（轮换后生成新链接用）")
	linkFormat := flag.String("link-format", "plain", "打印链接的格式：plain（mmx:// 短格式，默认）或 opaque（mmx:// 不透明链接，一串乱码，只有新版客户端能认）")
	name := flag.String("name", "mm-x", "节点名（用于生成的 mmx:// 链接）")
	advertiseHost := flag.String("host", "127.0.0.1", "mmx:// 链接里显示的服务器地址")
	rateStr := flag.String("rate", "0", "服务端限速上限，例如 512K / 10M，0 = 不限速；最终生效值 = min(服务端 --rate，链接 rate)，服务端说了算")
	burstStr := flag.String("burst", "", "服务端突发额度上限，例如 5M / 10M / 0（不许突发）；不写 = 默认 5MB；最终生效值 = min(服务端 --burst，链接 burst)，服务端说了算")
	blockFails := flag.Int("block-fails", 5, "拉黑阈值：窗口内握手失败达到这么多次就拉黑该 IP")
	blockWindowStr := flag.String("block-window", "1m", "拉黑统计窗口，例如 1m / 30s")
	blockDurationStr := flag.String("block-duration", "10m", "拉黑时长，例如 10m / 1h，到期自动解除")
	// --whitelist 可重复写多个：--whitelist 1.2.3.4 --whitelist 5.6.7.8
	var whitelistIPs stringList
	flag.Var(&whitelistIPs, "whitelist", "拉黑白名单 IP（可重复写多个）：白名单里的 IP 永远不拉黑，失败也不计数；用来放自己家的中转机（realm）的出口 IP")
	whitelistFile := flag.String("whitelist-file", "", "拉黑白名单文件路径：每行一个 IP，空行和 # 注释跳过；写错一行服务端就启动失败并指明行号")
	// 连接白名单（和拉黑白名单是两回事）：填了就只允许里面的 IP 连接，其他 IP
	// 在握手之前直接丢弃、不回包；不填 = 默认关闭，谁都能连（仍要过密钥校验）。
	var allowlistEntries stringList
	flag.Var(&allowlistEntries, "allowlist", "连接白名单（可重复写多个）：单个 IP 或 CIDR 段（例如 1.2.3.0/24）；填了就只允许这些 IP 连接，其他 IP 在握手前直接丢弃")
	allowlistFile := flag.String("allowlist-file", "", "连接白名单文件路径：每行一个 IP 或 CIDR，空行和 # 注释跳过；写错一行服务端就启动失败并指明行号")
	// 目标地址过滤：默认只替客户端拨公网目标（内网/回环/链路本地/
	// 云元数据地址一律拒绝，防 SSRF）；--allow-private 显式放开。
	allowPrivate := flag.Bool("allow-private", false, "允许经代理访问内网/保留地址目标（默认只允许公网目标；没有内网服务要走代理时不要开）")
	// 连接数上限：全局并发 + 单 IP 并发，防资源耗尽（默认 1024 / 64，
	// 单用户正常用只有个位数连接，这两个数都很宽松）。
	maxConns := flag.Int("max-conns", 1024, "全局最大并发连接数，超了静默丢弃")
	maxConnsPerIP := flag.Int("max-conns-per-ip", 64, "单个来源 IP 的最大并发连接数，超了静默丢弃")
	// 诱饵回退：非 mm-x 连接看到什么。site（默认）= 回一个像网站的页面/400 页；
	// silent = 老样子，0 字节回包、直接断开。
	fallback := flag.String("fallback", "site", "非 mm-x 连接的回退方式：site（默认，回一个像网站的页面/400 页）或 silent（0 字节回包、直接断开）")
	// 真 TLS 包装：外面套一层真 TLS，流量看起来就是正常 HTTPS。
	// 两种模式（二选一）：
	//   1. 真证书模式：--tls-domain 域名 + --tls-cert/--tls-key 证书文件
	//      （Let's Encrypt）；--tls-cert/--tls-key 给证书文件路径。
	//   2. 自签模式：--tls-auto，证书文件不存在时首次启动自动生成
	//      自签证书并存下来（没域名时用；客户端靠链接里的 pin 锁定验证）。
	// v3 起是双模式单端口：同一个端口同时接受明文 mm-x 和真实 TLS
	//（靠首记录分流），所以不再用 tls.Listen 单独监听。
	tlsDomain := flag.String("tls-domain", "", "真 TLS 模式的域名：填了就开启真 TLS 包装，mmx:// 链接的 host 也用这个域名；DNS 必须先指到这台 VPS")
	tlsCert := flag.String("tls-cert", "", "TLS 证书文件：真证书模式给 fullchain.pem；自签模式给存放路径（默认 tls-cert.pem）")
	tlsKey := flag.String("tls-key", "", "TLS 私钥文件：真证书模式给 privkey.pem；自签模式给存放路径（默认 tls-key.pem）")
	tlsAuto := flag.Bool("tls-auto", false, "自签 TLS 模式：证书文件不存在时自动生成自签证书并存下来（没域名时用；和 --tls-domain 二选一）")
	tlsSNI := flag.String("tls-sni", mmx.DefaultSNI, "TLS 握手用的默认 SNI（没域名时用常见域名；链接里写了 sni 参数就以链接为准；真证书模式默认用 --tls-domain 的域名）")
	// 流量统计与限额（全服务总量，单用户单 PSK）：只统计中继层真实转发的
	// 字节数，不计握手；计数持久化到文件，服务重启不丢；周期边界一到
	// 自动清零。限额 0 = 不限（默认，只统计不限制，不改变现有行为）。
	trafficModeStr := flag.String("traffic-mode", "total", "流量统计模式：outbound（出站，服务端→客户端，下载方向）/ inbound（入站）/ total（总计，默认）/ max（最大值，取两者中大的）")
	trafficPeriodStr := flag.String("traffic-period", "monthly", "统计周期：monthly（月，默认）/ quarterly（季，1/4/7/10 月起）/ yearly（年）")
	trafficStartDay := flag.Int("traffic-start-day", 1, "周期起始日：1–31 号，月不足天数时按当月最后一天算（例如 31 号在 2 月按 28/29 号算）")
	trafficLimitModeStr := flag.String("traffic-limit-mode", "block", "超限后的限制模式：block（阻断，默认，拒绝新连接并断开现有连接）/ throttle（TC 限速，降到 --traffic-throttle-rate 继续用）")
	trafficQuotaStr := flag.String("traffic-quota", "0", "每周期流量限额，例如 500G / 1T，0 = 不限（功能关闭，默认）")
	trafficThrottleStr := flag.String("traffic-throttle-rate", "125K", "TC 限速值：超限后全站降到的速度，例如 1M，默认 125K（约 1 Mbps）")
	trafficFile := flag.String("traffic-file", "/etc/mmx/traffic.json", "流量计数持久化文件：服务重启不丢计数；空字符串 = 不持久化")
	trafficStatus := flag.Bool("traffic-status", false, "只打印本周期流量统计然后退出（mm 菜单查看流量用）")
	coverStr := flag.String("cover-traffic", "low", "掩护流量（v5 会话）：off（关）/ low（默认，空闲时平均约 45 秒一帧小记录）/ high（空闲时平均约 20 秒一帧）")
	printPin := flag.Bool("print-pin", false, "打印 TLS 证书的 SPKI 指纹（base64url）并退出（mm 菜单查指纹用）")
	flag.Parse()

	if *fallback != "site" && *fallback != "silent" {
		log.Fatalf("回退方式不合法：%q，应为 site（默认）或 silent", *fallback)
	}
	// TLS 模式判定：真证书模式和自签模式二选一，不能同时开。
	tlsDomainMode := *tlsDomain != "" || (*tlsCert != "" && *tlsKey != "" && !*tlsAuto)
	tlsAutoMode := *tlsAuto
	if tlsDomainMode && tlsAutoMode {
		log.Fatalf("真 TLS（--tls-domain）和自签 TLS（--tls-auto）不能同时开，二选一")
	}
	tlsMode := tlsDomainMode || tlsAutoMode
	if tlsDomainMode {
		if *tlsDomain == "" {
			log.Fatalf("真 TLS 模式需要 --tls-domain（域名），DNS 必须先指到这台 VPS")
		}
		if (*tlsCert == "") != (*tlsKey == "") {
			log.Fatalf("真 TLS 模式的证书和私钥要一起给：--tls-cert 和 --tls-key")
		}
		if *tlsCert == "" {
			log.Fatalf("真 TLS 模式需要证书文件：--tls-cert 证书（fullchain.pem）--tls-key 私钥（privkey.pem）；没有证书先用 certbot 申请（见 README）")
		}
	}
	if tlsAutoMode && *tlsCert == "" {
		*tlsCert = "tls-cert.pem"
	}
	if tlsAutoMode && *tlsKey == "" {
		*tlsKey = "tls-key.pem"
	}
	// SNI 默认值：真证书模式用域名；自签模式用 --tls-sni（默认常见域名）。
	tlsSNIValue := *tlsSNI
	if tlsDomainMode && *tlsSNI == mmx.DefaultSNI {
		tlsSNIValue = *tlsDomain
	}

	grace, err := time.ParseDuration(*graceStr)
	if err != nil || grace < 0 {
		log.Fatalf("宽限期参数不合法：%q，应为 24h / 1h / 30m 这类时长，0 = 立即失效", *graceStr)
	}
	blockWindow, err := time.ParseDuration(*blockWindowStr)
	if err != nil || blockWindow <= 0 {
		log.Fatalf("拉黑窗口参数不合法：%q", *blockWindowStr)
	}
	blockDuration, err := time.ParseDuration(*blockDurationStr)
	if err != nil || blockDuration <= 0 {
		log.Fatalf("拉黑时长参数不合法：%q", *blockDurationStr)
	}
	blocklist := mmx.NewBlocklist(*blockFails, blockWindow, blockDuration)
	// 白名单：命令行 --whitelist（可重复）+ --whitelist-file（每行一个 IP）
	if *whitelistFile != "" {
		ips, err := mmx.LoadWhitelistFile(*whitelistFile)
		if err != nil {
			log.Fatalf("白名单：%v", err)
		}
		whitelistIPs = append(whitelistIPs, ips...)
	}
	for _, ip := range whitelistIPs {
		if net.ParseIP(ip) == nil {
			log.Fatalf("白名单 IP 不合法：%q，应为单个 IP 地址（例如 1.2.3.4）", ip)
		}
		blocklist.AddWhitelist(net.ParseIP(ip).String())
	}
	// 连接白名单：命令行 --allowlist（可重复，IP 或 CIDR）+ --allowlist-file
	allowlist := mmx.NewAllowlist()
	if *allowlistFile != "" {
		entries, err := mmx.LoadAllowlistFile(*allowlistFile)
		if err != nil {
			log.Fatalf("连接白名单：%v", err)
		}
		allowlistEntries = append(allowlistEntries, entries...)
	}
	for _, e := range allowlistEntries {
		if err := allowlist.Add(e); err != nil {
			log.Fatalf("连接白名单：%v", err)
		}
	}

	// 服务端限速上限（0 = 不限速）
	serverRate, err := mmx.ParseRate(*rateStr)
	if err != nil {
		log.Fatalf("限速参数不合法：%v", err)
	}
	// 服务端突发额度上限（-1 = 未指定，用默认 5MB；0 = 不许突发）
	serverBurst := mmx.BurstUnset
	if *burstStr != "" {
		serverBurst, err = mmx.ParseRate(*burstStr)
		if err != nil {
			log.Fatalf("突发参数不合法：%v", err)
		}
	}

	// 掩护流量档位（v5 会话）：校验失败直接启动失败。
	coverMode, err := mmx.ParseCoverMode(*coverStr)
	if err != nil {
		log.Fatalf("掩护流量：%v", err)
	}
	mmx.DefaultCoverMode = coverMode

	// 流量统计与限额配置（校验失败直接启动失败，指明错在哪一项）。
	trafficCfg := mmx.DefaultTrafficConfig()
	trafficCfg.Mode, err = mmx.ParseTrafficMode(*trafficModeStr)
	if err != nil {
		log.Fatalf("流量统计：%v", err)
	}
	trafficCfg.Period, err = mmx.ParseTrafficPeriod(*trafficPeriodStr)
	if err != nil {
		log.Fatalf("流量统计：%v", err)
	}
	trafficCfg.StartDay = *trafficStartDay
	trafficCfg.LimitMode, err = mmx.ParseTrafficLimitMode(*trafficLimitModeStr)
	if err != nil {
		log.Fatalf("流量统计：%v", err)
	}
	trafficCfg.Quota, err = mmx.ParseBytes(*trafficQuotaStr)
	if err != nil {
		log.Fatalf("流量统计：%v", err)
	}
	trafficCfg.ThrottleRate, err = mmx.ParseRate(*trafficThrottleStr)
	if err != nil {
		log.Fatalf("流量统计：%v", err)
	}
	trafficCfg.File = *trafficFile
	if err := trafficCfg.Validate(); err != nil {
		log.Fatalf("流量统计：%v", err)
	}
	// 只打印流量统计然后退出（mm 菜单“查看流量”走这里）：
	// 不碰密钥、不监听端口，读持久化文件里的计数现算。
	if *trafficStatus {
		tc := mmx.NewTrafficCounter(trafficCfg)
		fmt.Print(tc.Status().FormatStatus())
		return
	}

	var psk []byte
	keySource := ""
	if *pskFile != "" {
		// 密钥文件优先：轮换密钥时直接改文件，服务端自动发现
		b, err := mmx.ReadKeyFile(*pskFile)
		if err != nil {
			log.Fatalf("密钥文件读失败：%v", err)
		}
		psk = b
		keySource = "文件 " + *pskFile
	} else {
		if *pskHex == "" {
			*pskHex = os.Getenv("MMX_PSK") // 也可以用环境变量传密钥，避免写进命令行历史
		}
		if *pskHex == "" {
			psk = mmx.RandomPSK()
			fmt.Println("未指定 psk，已随机生成（请保存好这个链接，重启后会变）：")
			keySource = "随机生成"
		} else {
			b, err := decodeHexKey(*pskHex)
			if err != nil {
				log.Fatalf("psk 不合法：%v", err)
			}
			psk = b
			keySource = "启动参数"
		}
	}
	km := mmx.NewKeyManager(psk, *pskFile, grace)

	_, port, err := net.SplitHostPort(*listenAddr)
	if err != nil {
		log.Fatalf("监听地址不合法：%v", err)
	}
	var portNum int
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		log.Fatalf("端口不合法：%v", err)
	}
	// TLS 证书：开 TLS 就要先拿到证书（自签模式缺了就现场生成），
	// 因为链接里的 pin 指纹要从这张证书算——链接和服务端用的
	// 必须是同一张证书，否则客户端的 pin 校验永远过不了。
	// 注意：放在 BBR 和 --print-link 之前，避免 BBR 的日志行污染抓到的链接。
	var tlsCertObj tls.Certificate
	var tlsPIN string
	if tlsMode {
		var err error
		tlsCertObj, err = mmx.LoadOrGenerateCert(*tlsCert, *tlsKey, tlsSNIValue, tlsAutoMode)
		if err != nil {
			log.Fatalf("TLS 证书：%v", err)
		}
		pinBytes, err := mmx.SPKIPinOfCert(tlsCertObj)
		if err != nil {
			log.Fatalf("算证书指纹失败：%v", err)
		}
		tlsPIN = mmx.FormatPIN(pinBytes)
	}
	if *printPin {
		if !tlsMode {
			log.Fatalf("--print-pin 需要先开 TLS（--tls-auto 或 --tls-domain + 证书）")
		}
		fmt.Println(tlsPIN)
		return
	}
	linkObfs := "tls-fake"
	if tlsMode {
		linkObfs = "tls"
	}
	linkCfg := &mmx.LinkConfig{
		PSK: psk, Host: *advertiseHost, Port: portNum,
		Enc: "aes-256-gcm", Obfs: linkObfs, Version: mmx.Version, Name: *name,
		Rate: serverRate, Burst: serverBurst,
	}
	if tlsMode {
		linkCfg.SNI = tlsSNIValue
		linkCfg.PIN, _ = mmx.ParsePIN(tlsPIN)
	}
	// 链接格式：默认 plain（短格式）；opaque 是一串乱码，只有新版
	// 客户端能认——默认绝不能先切过去，要等客户端版本发了、确认能认
	// 之后再切。
	if *linkFormat != "plain" && *linkFormat != "opaque" {
		log.Fatalf("链接格式不合法：%q，应为 plain（短格式）或 opaque（不透明链接）", *linkFormat)
	}
	link := mmx.BuildLink(linkCfg)
	if *linkFormat == "opaque" {
		link = mmx.BuildOpaqueLink(linkCfg)
	}
	if *printLink {
		// 只打印链接然后退出（轮换后生成新链接用；mm 菜单的 --show-link
		// 和部署脚本都走这里）；
		// 注意：放在 BBR 之前，避免 BBR 的日志行污染抓到的链接
		fmt.Println(link)
		return
	}

	// BBR 默认开启：开不了只记警告，绝不影响启动
	_, bbrStatus := mmx.EnableBBR()
	log.Printf("BBR：%s", bbrStatus)

	maxFails, blockWindow, blockDuration := blocklist.Params()
	fmt.Printf("mm-x 服务端启动，监听 %s", *listenAddr)
	if serverRate > 0 {
		fmt.Printf("，服务端限速上限 %s/s，突发额度上限 %s", mmx.FormatRate(serverRate), mmx.FormatRate(mmx.EffectiveBurst(serverBurst, mmx.BurstUnset)))
	} else {
		fmt.Printf("，不限速")
	}
	fmt.Println()
	fmt.Printf("密钥来源：%s；旧密钥宽限期 %s；拉黑规则：%s 内握手失败 %d 次则拉黑 %s\n",
		keySource, grace, blockWindow, maxFails, blockDuration)
	if len(whitelistIPs) > 0 {
		fmt.Printf("拉黑白名单（永不拉黑）：%s\n", strings.Join(whitelistIPs, "、"))
	}
	if allowlist.Enabled() {
		fmt.Printf("连接白名单（只允许这些 IP 连接）：%s\n", strings.Join(allowlistEntries, "、"))
	}
	// 注意：启动时不打印节点链接和证书指纹——它们会进 systemd 日志，
	// 日志一直留着，等于把密钥和指纹写进了磁盘。
	// 要看链接用 --print-link（或 mm 菜单的 --show-link），
	// 要看指纹用 --print-pin（或 mm --show-pin），都是现用现查。
	if tlsDomainMode {
		fmt.Printf("真 TLS 模式：域名 %s，流量看起来就是正常 HTTPS 访问这个网站\n", *tlsDomain)
	}
	if tlsAutoMode {
		fmt.Printf("自签 TLS 模式：证书 %s（首次启动自动生成），SNI %s，流量看起来就是正常 HTTPS\n", *tlsCert, tlsSNIValue)
	}
	if *fallback == "site" {
		fmt.Println("诱饵回退：开（非 mm-x 连接会看到一个像网站的页面/400 页）")
	} else {
		fmt.Println("诱饵回退：关（silent，非 mm-x 连接 0 字节回包、直接断开）")
	}

	// 流量统计与限额：计数器建好就开始记；后台每 5 秒写盘一次，
	// 收到 SIGTERM/SIGINT（systemctl stop/restart）时先写盘再退出，
	// 计数不会因为重启丢掉。
	tc := mmx.NewTrafficCounter(trafficCfg)
	tc.StartAutoSave(5 * time.Second)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		tc.Flush()
		os.Exit(0)
	}()
	if trafficCfg.Quota > 0 {
		if trafficCfg.LimitMode == mmx.TrafficLimitThrottle {
			log.Printf("流量统计：模式 %s，周期 %s，限额 %s，超限后 TC 限速到 %s/s",
				trafficCfg.Mode.Label(), mmx.PeriodDesc(trafficCfg.Period, trafficCfg.StartDay),
				mmx.FormatBytesHuman(trafficCfg.Quota), mmx.FormatBytesHuman(trafficCfg.ThrottleRate))
		} else {
			log.Printf("流量统计：模式 %s，周期 %s，限额 %s，超限后阻断",
				trafficCfg.Mode.Label(), mmx.PeriodDesc(trafficCfg.Period, trafficCfg.StartDay),
				mmx.FormatBytesHuman(trafficCfg.Quota))
		}
	} else {
		log.Printf("流量统计：模式 %s，周期 %s，不限额（只统计，不限制）",
			trafficCfg.Mode.Label(), mmx.PeriodDesc(trafficCfg.Period, trafficCfg.StartDay))
	}

	// v3 起单端口双模式：同一个监听端口同时接受明文 mm-x 和真实 TLS，
	// handleConn 靠首记录分流——所以这里永远是明文监听，
	// TLS 只在分流后按需包上去（tlsCfg 为 nil = 没开 TLS）。
	var tlsCfg *tls.Config
	if tlsMode {
		tlsCfg = mmx.ServerTLSConfig(tlsCertObj)
	}
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("监听失败：%v", err)
	}
	defer ln.Close()
	// 拉黑表定期清理（A7）：过期条目不删 key 会一直涨，
	// 每 5 分钟清一次，清掉的条目数记一条日志（0 条就不记）。
	go func() {
		for range time.Tick(5 * time.Minute) {
			if f, b := blocklist.PurgeExpired(); f > 0 || b > 0 {
				log.Printf("拉黑表清理：清掉 %d 条过期失败记录、%d 条过期拉黑", f, b)
			}
		}
	}()

	// 密钥轮换监视：v3/v4/v5 会话是长连接，建好后不再握手——
	// 不处理的话，旧密钥能借着已建好的会话一直用下去，轮换失效。
	// 发现轮换就按旧密钥的宽限期排一个定时器：宽限期内旧会话照常用
	//（和 v2“宽限期内旧密钥仍能用”一致），宽限期一到只断开用旧密钥
	// 建的会话，用新密钥建的不受影响；客户端下次请求会重新握手。
	// v2 连接是按请求建的，下次握手自然用新密钥，不用登记断开。
	live := &liveConns{m: make(map[net.Conn][]byte)}
	go watchKeyRotation(km, live, *pskFile)
	// 流量阻断监视：限额一到就断开所有现有连接（新连接在 handleConn
	// 里直接丢弃）；只在“没超限 → 超限”的跳变时动作一次，
	// 否则每秒都断一次、日志每秒刷一条。
	go watchTrafficBlock(tc, live)
	// 握手重放防护：盐缓存（10 分钟）+ 连接数上限（全局/单 IP）。
	// 缓存和限制器都在主循环外建好，随连接传进去。
	replayCache := mmx.NewReplayCache(10 * time.Minute)
	connLimiter := mmx.NewConnLimiter(*maxConns, *maxConnsPerIP)
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Printf("接受连接失败：%v", err)
			continue
		}
		// 连接数上限：超了静默丢弃（不回包、不记失败进拉黑——
		// 超限不是握手失败，不该污染拉黑统计）。
		peerIP, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
		if !connLimiter.TryAcquire(peerIP) {
			log.Printf("连接数已满，丢弃来自 %s 的连接（全局上限 %d / 单 IP 上限 %d）", peerIP, *maxConns, *maxConnsPerIP)
			raw.Close()
			continue
		}
		go handleConn(raw, km, serverRate, serverBurst, blocklist, allowlist, *fallback, tlsCfg, live, replayCache, connLimiter, *allowPrivate, tc)
	}
}

// liveConns 登记正在服务的 v3 会话：底层连接 → 建会话时用的密钥。
// 密钥轮换的宽限期一到，只断开用旧密钥建的会话。
type liveConns struct {
	mu sync.Mutex
	m  map[net.Conn][]byte
}

func (r *liveConns) add(c net.Conn, psk []byte) {
	r.mu.Lock()
	r.m[c] = append([]byte(nil), psk...)
	r.mu.Unlock()
}

func (r *liveConns) remove(c net.Conn) {
	r.mu.Lock()
	delete(r.m, c)
	r.mu.Unlock()
}

// closeWithKey 断开所有用指定密钥建的 v3 会话，返回断开的条数。
func (r *liveConns) closeWithKey(psk []byte) int {
	r.mu.Lock()
	var conns []net.Conn
	for c, k := range r.m {
		if bytes.Equal(k, psk) {
			conns = append(conns, c)
		}
	}
	r.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return len(conns)
}

// closeAll 断开所有登记的连接（流量阻断模式超限时用），返回断开的条数。
func (r *liveConns) closeAll() int {
	r.mu.Lock()
	var conns []net.Conn
	for c := range r.m {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return len(conns)
}

// watchTrafficBlock 监视流量限额：阻断模式下超限就断开所有现有连接，
// 新连接在 handleConn 里直接丢弃。只在跳变时动作一次，
// 恢复（新周期 / 限额改大）后下次超限会再次动作。
func watchTrafficBlock(tc *mmx.TrafficCounter, live *liveConns) {
	enforced := false
	for range time.Tick(time.Second) {
		if tc.Blocked() {
			if !enforced {
				enforced = true
				n := live.closeAll()
				log.Printf("流量超限（阻断模式）：已断开 %d 条现有连接，本周期限额已用完，新连接将被拒绝", n)
			}
		} else {
			enforced = false
		}
	}
}

// watchKeyRotation 监视密钥轮换（A4）：密钥文件变了就按旧密钥的宽限期
// 安排断开用旧密钥建的 v3/v4/v5 会话。fsnotify 监听文件所在目录
// （文件本身可能被原子替换——写临时文件再改名，直接监听文件会丢监听，
// 监听目录就不会丢）；每次改动都触发一次轮换检查，500ms 内两次改动
// 以前会漏掉一次，现在不会。再加一个 30 秒的兜底轮询，
// 万一事件丢了也不会漏过一次轮换。
// pskFile 为空（没配密钥文件，不轮换）时直接返回。
func watchKeyRotation(km *mmx.KeyManager, live *liveConns, pskFile string) {
	if pskFile == "" {
		return
	}
	last := km.Rotations()
	checkRotation := func() {
		if n := km.Rotations(); n != last {
			last = n
			prevKey, expires := km.PrevKey()
			if prevKey == nil {
				return
			}
			delay := time.Until(expires)
			if delay <= 0 {
				closed := live.closeWithKey(prevKey)
				log.Printf("旧密钥宽限期已过，断开 %d 条用旧密钥建的 v3/v4/v5 会话", closed)
				return
			}
			time.AfterFunc(delay, func() {
				closed := live.closeWithKey(prevKey)
				log.Printf("旧密钥宽限期已过，断开 %d 条用旧密钥建的 v3/v4/v5 会话", closed)
			})
		}
	}
	// 监听失败就退回轮询：监听只是为了及时发现，轮询也能发现，
	// 只是慢一点，绝不能因为监听起不来就漏轮换。
	pollFallback := func() {
		for range time.Tick(30 * time.Second) {
			checkRotation()
		}
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("密钥轮换监听启动失败（%v），改用 30 秒轮询", err)
		pollFallback()
		return
	}
	defer watcher.Close()
	dir := filepath.Dir(pskFile)
	base := filepath.Base(pskFile)
	if err := watcher.Add(dir); err != nil {
		log.Printf("密钥轮换监听启动失败（%v），改用 30 秒轮询", err)
		pollFallback()
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) == base && ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) != 0 {
				checkRotation()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("密钥轮换监听出错：%v", err)
		case <-ticker.C:
			checkRotation()
		}
	}
}

func decodeHexKey(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("psk 应为 64 位十六进制字符（32 字节），实际 %d 位", len(s))
	}
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var v int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
			return nil, fmt.Errorf("psk 第 %d 字节不是十六进制：%v", i, err)
		}
		b[i] = byte(v)
	}
	return b, nil
}

// peekConn：带缓冲预读的连接。握手前先 peek 首字节分流（mm-x / HTTP / 乱字节），
// peek 过的字节留在缓冲里，握手函数照常用它读，不会丢。
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func handleConn(raw net.Conn, km *mmx.KeyManager, serverRate, serverBurst int64, bl *mmx.Blocklist, al *mmx.Allowlist, fallback string, tlsCfg *tls.Config, live *liveConns, replayCache *mmx.ReplayCache, connLimiter *mmx.ConnLimiter, allowPrivate bool, tc *mmx.TrafficCounter) {
	remote := raw.RemoteAddr().String()
	defer raw.Close()
	// 归还连接名额（accept 循环里占的）：无论哪条路返回都执行，
	// 包括白名单/拉黑丢弃——占了名额就得还，否则名额越占越少。
	ip, _, _ := net.SplitHostPort(remote)
	defer connLimiter.Release(ip)
	// 登记这条连接：流量阻断模式超限时监视 goroutine 会断开它
	//（v3 会话在 serveMMX 里还会再登记一次，带密钥——那是给
	// 密钥轮换用的，两条登记各管各的，互不干扰）。
	live.add(raw, nil)
	defer live.remove(raw)

	// 连接白名单检查：要在握手之前做——不在白名单就直接丢弃，不回应任何字节，
	// 也不记日志（避免扫描流量刷屏）；白名单里的 IP 仍要过后面的正常握手和密钥校验，
	// 白名单不是代替密钥，只是多一层。
	if !al.Contains(ip) {
		return
	}

	// 拉黑检查：被拉黑的 IP 直接丢弃，不回应任何字节，也不记日志（避免日志刷屏）
	if bl.IsBlocked(ip) {
		return
	}

	// 流量阻断：超限后新连接直接丢弃（不握手、不回包、不记日志，
	// 和拉黑一个路子——避免拒绝日志刷屏；已有连接由监视 goroutine 断开）。
	if tc.Blocked() {
		return
	}

	// 记一次失败：任何非 mm-x 的首次接触都算一次握手失败（进拉黑统计），
	// 和以前一样——诱饵站只负责让单次探测看到“网站”，多次敲门照样拉黑。
	recordFail := func(reason string) {
		maxFails, window, duration := bl.Params()
		if bl.RecordFailure(ip) {
			until := bl.BlockedUntil(ip)
			log.Printf("拉黑 IP %s：%s 内握手失败 %d 次，拉黑 %s（到 %s 自动解除）",
				ip, window, maxFails, duration, until.Format("2006-01-02 15:04:05"))
		} else {
			log.Printf("[%s] 握手失败，已拒绝：%s", remote, reason)
		}
	}

	// v3 双模式单端口：先 peek 首记录分流。
	// 缓冲 32KB：一条 TLS 记录最大 16KB+5 字节头，整条首记录
	// peek 进来才分得清 mm-x 握手还是真实 ClientHello。
	pc := &peekConn{Conn: raw, r: bufio.NewReaderSize(raw, 32768)}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	head, err := pc.r.Peek(5)
	_ = raw.SetReadDeadline(time.Time{})
	if err != nil {
		return // 5 秒内没发来 5 个字节：静默断开
	}

	// HTTP 请求 → 诱饵站 200（site）或静默（silent）
	if mmx.LooksLikeHTTP(head) {
		if fallback == "site" {
			_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
			_ = mmx.ServeDecoySite(pc.r, pc)
			_ = raw.SetReadDeadline(time.Time{})
			log.Printf("[%s] 诱饵站响应了一次 HTTP 请求", remote)
		}
		recordFail("不是 mm-x 握手（HTTP 请求）")
		return
	}

	// 不是 TLS 记录头 → 乱字节：回一个像网站的 400 页（site）或静默（silent）
	if !mmx.LooksLikeTLSRecord(head) {
		if fallback == "site" {
			_ = mmx.ServeDecoy400(pc)
		}
		recordFail("不是 mm-x 握手（乱字节）")
		return
	}

	// 是 TLS 记录：把整条首记录 peek 进来，靠魔数/鉴权分清
	// 明文 mm-x 握手还是真实 TLS ClientHello。
	// 注意：mm-x 握手和 ClientHello 都以 0x16 0x03 0x01 开头，
	// 但 mm-x 的魔数是带密钥的 HMAC——没有密钥算不出合法魔数，
	// 所以先验 mm-x 魔数（密码学判定，绝不会把明文 mm-x 误判成 TLS），
	// 再看 ClientHello 形状；两者都不是才回诱饵 400。
	recLen := int(head[3])<<8 | int(head[4])
	if recLen <= 0 || recLen > 16384 {
		if fallback == "site" {
			_ = mmx.ServeDecoy400(pc)
		}
		recordFail("TLS 记录长度不合法")
		return
	}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	rec, err := pc.r.Peek(5 + recLen)
	_ = raw.SetReadDeadline(time.Time{})
	if err != nil {
		return // 首记录没发全：静默断开
	}
	payload := rec[5:]
	if mmx.LooksLikeMMXHandshake(payload, km.Keys()) != 0 {
		serveMMX(pc, km, serverRate, serverBurst, bl, remote, ip, fallback, recordFail, live, replayCache, allowPrivate, tc)
		return
	}
	if tlsCfg != nil && mmx.LooksLikeClientHello(payload) {
		// 真实 TLS：包一层 TLS 服务端，完成握手后再看隧道里面。
		// 外层 bufio 里可能已缓冲了 ClientHello 之后的密文，
		// 它们经 tls.Conn 的 Read 照样能读到，不会丢；内层再建一个
		// peekConn 读解密后的明文，两层缓冲各管各的。
		tlsConn := tls.Server(pc, tlsCfg)
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			return // TLS 握手没完成：静默断开（crypto/tls 会按 TLS 规范回 alert，这是正常行为）
		}
		_ = tlsConn.SetDeadline(time.Time{})
		serveInnerTLS(tlsConn, km, serverRate, serverBurst, bl, remote, ip, fallback, recordFail, live, replayCache, allowPrivate, tc)
		return
	}
	// 既不是 mm-x 也不是 ClientHello：site 模式回一个像网站的 400 页
	// （看起来像一台普通 Web 服务器收到乱请求），silent 模式什么都不回。
	if fallback == "site" {
		_ = mmx.ServeDecoy400(pc)
	}
	recordFail("魔数不对：不是 mm-x 协议")
}

// serveInnerTLS 处理 TLS 会话里面的内容：TLS 握手已完成，
// 再看解密后的首字节是 mm-x 握手还是 HTTP（诱饵站）。
func serveInnerTLS(tc *tls.Conn, km *mmx.KeyManager, serverRate, serverBurst int64, bl *mmx.Blocklist, remote, ip, fallback string, recordFail func(string), live *liveConns, replayCache *mmx.ReplayCache, allowPrivate bool, traf *mmx.TrafficCounter) {
	defer tc.Close()
	innerPC := &peekConn{Conn: tc, r: bufio.NewReaderSize(tc, 32768)}
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	head, err := innerPC.r.Peek(5)
	_ = tc.SetReadDeadline(time.Time{})
	if err != nil {
		return // TLS 里 5 秒没发来数据：静默断开
	}
	// TLS 里面的 HTTP 请求 → 诱饵站 200（同一张证书，
	// 探测者看到的是一个真网站）
	if mmx.LooksLikeHTTP(head) {
		if fallback == "site" {
			_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
			_ = mmx.ServeDecoySite(innerPC.r, innerPC)
			_ = tc.SetReadDeadline(time.Time{})
			log.Printf("[%s] 诱饵站（TLS 内）响应了一次 HTTP 请求", remote)
		}
		recordFail("不是 mm-x 握手（TLS 内 HTTP 请求）")
		return
	}
	// TLS 里不是 mm-x 记录头（例如协商到 h2 后发来的 HTTP/2 前缀，
	// 诱饵站只会 HTTP/1.1，回不了页面）→ 400 页。
	if !mmx.LooksLikeTLSRecord(head) {
		if fallback == "site" {
			_ = mmx.ServeDecoy400(innerPC)
		}
		recordFail("不是 mm-x 握手（TLS 内乱字节）")
		return
	}
	serveMMX(innerPC, km, serverRate, serverBurst, bl, remote, ip, fallback, recordFail, live, replayCache, allowPrivate, traf)
}

// serveMMX 在一条已分流确认是 mm-x 的连接上做握手，
// 按协商出的版本分流：v3 走复用会话，v2 走老 CONNECT 单连接。
// 握手带重放防护（盐缓存 + 时间戳）：重放的握手在这里失败，
// 不会走到后面的 RecordSuccess，攻击者 IP 不会被标成信任。
func serveMMX(pc *peekConn, km *mmx.KeyManager, serverRate, serverBurst int64, bl *mmx.Blocklist, remote, ip, fallback string, recordFail func(string), live *liveConns, replayCache *mmx.ReplayCache, allowPrivate bool, tc *mmx.TrafficCounter) {
	keys, err := mmx.ServerHandshakeWithKeysAndReplay(pc, km.Keys(), replayCache)
	if err != nil {
		if fallback == "site" {
			_ = mmx.ServeDecoy400(pc)
		}
		recordFail(err.Error())
		return
	}
	// 握手成功：这个 IP 进入信任状态，之后失败不再计入拉黑；
	// 之前攒的失败计数清零（RecordSuccess 里做）。
	bl.RecordSuccess(ip)
	mc, err := mmx.NewConn(pc, keys, false)
	if err != nil {
		log.Printf("[%s] 建立加密连接失败：%v", remote, err)
		return
	}
	log.Printf("[%s] 握手成功（ver=%d）", remote, keys.Version)
	if mmx.IsMuxVersion(keys.Version) {
		// 登记这条 v3/v4/v5 会话和它用的密钥：旧密钥宽限期一到，
		// 监视 goroutine 只断开用旧密钥建的会话。
		live.add(pc, keys.PSK)
		defer live.remove(pc)
		if err := mmx.ServeMuxSession(mc, serverRate, serverBurst, remote, allowPrivate, mmx.SessionIdleTimeout, tc); err != nil {
			log.Printf("[%s] v3/v4/v5 会话结束：%v", remote, err)
		} else {
			log.Printf("[%s] v3/v4/v5 会话结束", remote)
		}
		return
	}
	serveV2(mc, serverRate, serverBurst, remote, allowPrivate, tc)
}

// serveV2 是 v2 的老流程：等 CONNECT 帧 → 拨目标 → 双向转发。
// v3 不走这里（v3 没有 CONNECT 帧，流头在 yamux 流里）。
func serveV2(mc *mmx.Conn, serverRate, serverBurst int64, remote string, allowPrivate bool, tc *mmx.TrafficCounter) {
	// 等 CONNECT 帧
	ftype, payload, err := mc.ReadFrame()
	if err != nil {
		log.Printf("[%s] 读取 CONNECT 失败：%v", remote, err)
		return
	}
	if ftype != mmx.FrameConnect {
		log.Printf("[%s] 首帧不是 CONNECT（type=0x%02x），已断开", remote, ftype)
		return
	}
	target, clientRate, clientBurst, err := mmx.DecodeConnectRequest(payload)
	if err != nil {
		log.Printf("[%s] CONNECT 载荷不合法：%v", remote, err)
		return
	}
	// 限速和突发都取两者中更小的那个：服务端说了算，
	// 客户端改大链接里的 rate / burst 也突破不了上限
	effRate := mmx.MinRate(serverRate, clientRate)
	effBurst := mmx.EffectiveBurst(serverBurst, clientBurst)
	lim := mmx.NewLimiter(effRate, effBurst)
	if effRate > 0 {
		log.Printf("[%s] 本连接限速 %s/s，突发额度 %s（服务端上限 %s/s / %s，链接要求 %s/s / %s）",
			remote, mmx.FormatRate(effRate), mmx.FormatRate(effBurst),
			mmx.FormatRate(serverRate), mmx.FormatRate(mmx.EffectiveBurst(serverBurst, mmx.BurstUnset)),
			mmx.FormatRate(clientRate), mmx.FormatRate(mmx.EffectiveBurst(clientBurst, mmx.BurstUnset)))
	}
	log.Printf("[%s] 收到转发请求", remote)

	// 目标过滤：默认只拨公网目标（内网/回环/链路本地/云元数据拒绝，
	// 防 SSRF）；--allow-private 时才放开。被拒绝时客户端收到的
	// ACK 是 "[目标不允许] …"，和普通拨号失败区分开。
	targetConn, err := mmx.DialTarget("tcp", target, 10*time.Second, allowPrivate)
	if err != nil {
		// CONNECT 报错分类（ACK 文本带 "[错误码] …" 前缀，老客户端
		// 按 string(payload[1:]) 读仍是可读中文，新客户端可解析错误码；
		// 握手失败不走这里，仍静默丢弃/回诱饵页。
		// 目标地址不记进日志（A6）：服务端日志只留错误码，
		// 完整原因在客户端的 ACK 里（客户端是用户自己的机器）。
		code := mmx.ClassifyDialError(err)
		log.Printf("[%s] 连接目标失败 [%s]", remote, code)
		_ = mc.WriteFrame(mmx.FrameAck, append([]byte{0x01}, []byte(mmx.FormatConnectError(code, err))...))
		return
	}
	defer targetConn.Close()
	if err := mc.WriteFrame(mmx.FrameAck, []byte{0x00}); err != nil {
		log.Printf("[%s] 发送 ACK 失败：%v", remote, err)
		return
	}
	log.Printf("[%s] 已接通目标，开始转发", remote)

	// 任一方向结束（对端关闭、出错）就立刻关闭两端连接，
	// 否则另一方向会一直阻塞读，连接永远挂起。
	done := make(chan struct{}, 2)
	go func() { pumpMMXToRaw(mc, targetConn, lim, tc); done <- struct{}{} }()
	go func() { pumpRawToMMX(targetConn, mc, lim, tc); done <- struct{}{} }()
	<-done
	targetConn.Close()
	<-done
	log.Printf("[%s] 连接结束", remote)
}

func pumpMMXToRaw(mc *mmx.Conn, target net.Conn, lim *mmx.Limiter, tc *mmx.TrafficCounter) {
	for {
		ftype, payload, err := mc.ReadFrame()
		if err != nil {
			return
		}
		if ftype == mmx.FrameClose {
			return
		}
		if ftype != mmx.FrameData {
			continue
		}
		lim.Wait(len(payload)) // 上行限速：客户端发来、要转发给目标的每个字节都过令牌桶
		tc.Wait(len(payload))  // 超限后 TC 限速才起作用（其余情况直接返回）
		if _, err := target.Write(payload); err != nil {
			return
		}
		tc.AddIn(int64(len(payload))) // 入站：客户端→服务端→目标
	}
}

func pumpRawToMMX(raw net.Conn, mc *mmx.Conn, lim *mmx.Limiter, tc *mmx.TrafficCounter) {
	buf := make([]byte, 32*1024)
	for {
		n, err := raw.Read(buf)
		if n > 0 {
			lim.Wait(n) // 下行限速：目标返回、要发给客户端的每个字节都过令牌桶
			tc.Wait(n)  // 超限后 TC 限速才起作用（其余情况直接返回）
			if werr := mc.WriteFrame(mmx.FrameData, buf[:n]); werr != nil {
				return
			}
			tc.AddOut(int64(n)) // 出站：目标→服务端→客户端
		}
		if err != nil {
			if err != io.EOF {
				// 只记错误类型，不记 %v：网络读错误的文本里带本地/对端地址，
				// 记进日志就等于记了目标地址（A6）。
				log.Printf("读取目标数据失败：%T", err)
			}
			_ = mc.WriteFrame(mmx.FrameClose, nil)
			return
		}
	}
}
