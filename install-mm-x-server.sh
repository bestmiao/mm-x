#!/bin/bash
# mm-x 服务端一键部署脚本（在 VPS 上用 sudo 运行）。
# 用法（一键）：
#   curl -fsSL https://raw.githubusercontent.com/bestmiao/mm-x/main/install-mm-x-server.sh | sudo bash
#   （没找到本地二进制时脚本自己从 GitHub 下载；想手动装也可以把本脚本和
#   预编译的 mmx-server-linux-amd64 放到同一个目录再 sudo 运行）
#   sudo ./install-mm-x-server.sh [--port 端口] [--rate 限速] [--burst 突发] [--name 节点名] [--host 公网IP或域名]
#      [--fallback site|silent] [--tls-domain 域名 --tls-cert 证书 --tls-key 私钥]
#      [--tls-auto [--tls-sni 域名]] [--domain 域名]（没域名时用自签 TLS + SPKI 锁定，和真 TLS 二选一；
#      --domain 是一键：装完自动申请 Let's Encrypt 证书并切真 TLS，DNS 须先指到本机、80 端口空闲）
# 默认：端口 443（没传 --port 时用 443；443 被 nginx/Apache 等占了会报错停下，
# 先停掉占用的服务或传 --port 换端口）、不限速（rate=0；想限速再传 --rate，例如 6250K = 50 Mbps）、突发 0（严格模式：限速时任何时候都不超过限速；旧默认 15M 会让每条新连接开头先冲 15MB 再限速，实测 30MB 文件平均跑到 96 Mbps、峰值 1300 Mbps，等于没限——YouTube 这种多连接、分段取数据的流量，每段都落在突发里，更是全程不限）。
# 全新安装只装程序：二进制到 /usr/local/bin/mmx-server + 管理菜单 /usr/local/bin/mmx（输入 mmx 呼出），
# 不建节点、不生成密钥、不写 /etc/mmx/config、不写服务文件、不启动服务；装完有终端就进入主菜单，
# 用菜单第 1 项添加节点（问端口、节点名、流量限额、域名还是 IP，建好后服务自动启动）。
# 非交互（管道/自动化）时不进菜单，只打印"输入 mmx 打开菜单添加节点"后退出。
# --reinstall 重装节点时才做全套：生成/保留 /etc/mmx/psk（重装不换密钥，
#   旧密钥靠服务端的 24 小时宽限期继续用）；默认开 BBR（开不了只警告）；放行防火墙端口；
#   写 /etc/mmx/config（全部参数都在这里，菜单改参数就改这个文件）；写服务文件
#   （systemd 用单元文件，OpenRC/Alpine 用 /etc/init.d/mmx-server；开机自启、崩溃自动重启）。
# 安装完不打印 mmx:// 链接——链接在 mm 菜单第 5 项里看。
# 再跑一次本脚本：默认只更新程序文件（服务端二进制、管理菜单、服务文件），
# 节点配置（端口/密钥/TLS/流量设置）原样保留，不会重置；彻底重装节点（换端口/
# 重置配置）必须显式加 --reinstall（交互终端里还会再确认一次，默认不重装）。
set -euo pipefail

# 测试钩子：MMX_TEST_ROOT 设置时，所有路径都改到该目录下（不碰真实系统），
# BBR 步骤跳过；systemctl/rc-service/journalctl/ss 由测试替身提供。生产环境不要设置这个变量。
ROOT="${MMX_TEST_ROOT:-}"
CFG_DIR="$ROOT/etc/mmx"
CFG_FILE="$CFG_DIR/config"
PSK_FILE="$CFG_DIR/psk"
BIN_DIR="$ROOT/usr/local/bin"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/mmx-server.service"
INIT_DIR="$ROOT/etc/init.d"
INIT_FILE="$INIT_DIR/mmx-server"

# 服务管理方式：systemd（Debian/Ubuntu）或 OpenRC（Alpine）。
# 有 systemctl 用 systemd；没有 systemctl 但有 rc-service 用 OpenRC；
# 都没有就警告并默认 systemd（Debian 行为不变）。
# （测试模式下替身只提供 systemctl，所以走 systemd，和原来一样。）
# 注意：下面这组检测 + 服务操作函数在部署脚本和菜单脚本里各有一份（菜单是独立脚本），改动时两边同步。
detect_init() {
  if command -v systemctl >/dev/null 2>&1; then echo "systemd"; return 0; fi
  if command -v rc-service >/dev/null 2>&1; then echo "openrc"; return 0; fi
  echo "警告：没找到 systemctl 也没找到 rc-service，默认按 systemd 处理" >&2
  echo "systemd"
}
INIT_SYS="$(detect_init)"
# 当前系统实际用的服务文件（systemd 用 UNIT_FILE，OpenRC 用 INIT_FILE）
if [ "$INIT_SYS" = "openrc" ]; then SVC_FILE="$INIT_FILE"; SVC_DIR="$INIT_DIR"; else SVC_FILE="$UNIT_FILE"; SVC_DIR="$UNIT_DIR"; fi

# 服务操作封装：按 INIT_SYS 分发到 systemctl 或 rc-service/rc-update。
# 返回值和原来直接调 systemctl 时一致（成功 0，失败非 0），方便 if 判断。
svc_reload() {
  if [ "$INIT_SYS" = "openrc" ]; then return 0; fi
  systemctl daemon-reload 2>/dev/null
}
svc_restart() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server restart 2>/dev/null; else systemctl restart mmx-server 2>/dev/null; fi
}
svc_is_active() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server status >/dev/null 2>&1; else systemctl is-active --quiet mmx-server 2>/dev/null; fi
}
svc_start() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server start 2>/dev/null; else systemctl start mmx-server 2>/dev/null; fi
}
svc_stop() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server stop 2>/dev/null; else systemctl stop mmx-server 2>/dev/null; fi
}
svc_status() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server status 2>&1 | head -20 || true; else systemctl status mmx-server --no-pager 2>&1 | head -20 || true; fi
}
svc_enable() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-update add mmx-server default 2>/dev/null; else systemctl enable mmx-server >/dev/null 2>&1; fi
}
svc_disable() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-update del mmx-server default 2>/dev/null; else systemctl disable mmx-server 2>/dev/null; fi
}
# 提示文字里用的服务命令（按当前系统显示正确那条）
svc_status_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "rc-service mmx-server status"; else echo "systemctl status mmx-server"; fi
}
svc_log_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "tail -n 50 /var/log/messages"; else echo "journalctl -u mmx-server -n 50"; fi
}
svc_log_follow_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "tail -f /var/log/messages"; else echo "journalctl -u mmx-server -f"; fi
}
svc_stop_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "rc-service $1 stop"; else echo "systemctl stop $1"; fi
}
# 装 certbot 的命令（提示文字用）
certbot_install_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "apk add certbot"; else echo "apt install certbot -y"; fi
}

PORT=""
REINSTALL="0" # --reinstall 传过就置 1（彻底重装节点）；不传时已安装就只更新程序文件
RATE="0"
BURST="0"
NAME="mm-x"
NAME_SET="0" # --name 传过就置 1，没传时安装会交互问一句（只在终端里问）
HOST=""
BIN=""
FALLBACK="site"
TLS_DOMAIN=""
TLS_CERT=""
TLS_KEY=""
TLS_AUTO="0"
TLS_SNI=""
DOMAIN_SETUP="" # --domain 传过就置为域名：装完一键申请证书并切真 TLS（只在全新安装/--reinstall 时跑）
WHITELIST_IPS=()
WHITELIST_FILE=""
ALLOW_IPS=()
ALLOWLIST_FILE=""
# 流量统计与限额（全服务总量）：默认不限额（只统计，不限制），
# 不改变现有行为；想限制时用下面 6 个参数或 mm 菜单第 3 项（编辑节点）里的流量设置。
TRAFFIC_MODE="total"
TRAFFIC_PERIOD="monthly"
TRAFFIC_START_DAY="1"
TRAFFIC_LIMIT_MODE="throttle"
TRAFFIC_QUOTA="0"
TRAFFIC_THROTTLE_RATE="125K"
# 掩护流量（v5 会话）：默认 low（空闲时平均约 45 秒一帧小记录）；
# off = 关，high = 空闲时平均约 20 秒一帧。
COVER_TRAFFIC="low"
# 目标域名白名单：默认关（""）；google = 只放行谷歌系域名
# （GCP 预设用，保 GCP 每月 200 GiB 免费额度不被非谷歌流量吃掉）。
DOMAIN_WHITELIST=""

# 预设的流量设置（和菜单第 2 项“载入预设”同一份值；只改流量相关字段、RATE
# 和域名白名单，不动端口/密钥/TLS/SNI；180G = 阿桑说的 200G 减 20G 余量；125K ≈ 1 Mbps）。
# GCP 多开一个域名白名单（只放行谷歌系域名，保免费额度）；阿里云CDT 不开。
set_preset_vars() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    gcp|1|谷歌|谷歌云)
      TRAFFIC_MODE="total"; TRAFFIC_PERIOD="monthly"; TRAFFIC_START_DAY="1"
      TRAFFIC_LIMIT_MODE="throttle"; TRAFFIC_QUOTA="180G"; TRAFFIC_THROTTLE_RATE="125K"; RATE="0"
      DOMAIN_WHITELIST="google"
      ;;
    cdt|2|阿里云|阿里云cdt)
      TRAFFIC_MODE="max"; TRAFFIC_PERIOD="monthly"; TRAFFIC_START_DAY="1"
      TRAFFIC_LIMIT_MODE="throttle"; TRAFFIC_QUOTA="180G"; TRAFFIC_THROTTLE_RATE="125K"; RATE="0"
      DOMAIN_WHITELIST=""
      ;;
    *)
      echo "预设不对：$1，应为 gcp（GCP）或 cdt（阿里云CDT）"; exit 1 ;;
  esac
}

# 域名格式：每段 1-63 字符（字母数字或连字符，不以连字符开头/结尾），
# 至少两段，最后一段（TLD）是至少 2 位字母，总长不超过 253。
valid_domain() {
  local d="$1" tld
  [ -n "$d" ] || return 1
  [ "${#d}" -le 253 ] || return 1
  printf '%s' "$d" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$' || return 1
  tld="${d##*.}"
  [ "${#tld}" -ge 2 ] || return 1
  case "$tld" in *[!A-Za-z]*) return 1;; esac
  return 0
}

usage() {
  echo "用法：sudo $0 [--port 端口] [--rate 限速] [--burst 突发] [--name 节点名] [--host 公网IP或域名] [--bin 服务端二进制路径] [--whitelist-ip 中转机IP] [--whitelist-file 白名单文件] [--fallback site|silent] [--tls-domain 域名 --tls-cert 证书 --tls-key 私钥] [--preset gcp|cdt] [--domain 域名] [--reinstall]"
  echo "  --port   监听端口，默认 443（更像正常 HTTPS；不要用一眼能猜到的端口）"
  echo "           443 被占时本脚本会直接报错停下，先停掉占用的服务（例如 $(svc_stop_cmd nginx)）或换个端口再装"
  echo "  --reinstall 彻底重装节点：按本次传入参数重写 /etc/mmx/config（端口/限速/TLS/流量设置都会重置；"
  echo "           密钥文件保留不变）。不加时：已安装就只更新程序文件（服务端二进制、管理菜单、服务文件），"
  echo "           节点配置原样保留，再跑一遍也不会把服务重置掉；全新安装（没节点）时不建节点，只装程序，"
  echo "           节点在菜单第 1 项添加——只有加了 --reinstall 才会按传入参数建节点"
  echo "  --rate   服务端限速上限，默认 0（不限速；想限速再填，例如 6250K = 50 Mbps，约 6.25 MB/s）"
  echo "  --burst  服务端突发额度上限，默认 0（严格模式：任何时候都不超过限速；想允许开头冲一把再填，例如 --burst 5M）"
  echo "  --name   节点名，默认 mm-x；不传时安装会问一句（留空用默认 mm-x），"
  echo "           只在终端里问——一键命令管道/自动化时不问，直接用默认，不卡住等输入"
  echo "  --host   mmx:// 链接里的服务器地址，默认自动探测公网 IP；可以填域名或 IP，填了域名就按域名生成链接"
  echo "  --bin    服务端二进制路径，默认用脚本同目录下的 mmx-server-linux-amd64"
  echo "  --whitelist-ip   拉黑白名单 IP（可重复写多个）：白名单里的 IP 永远不拉黑；"
  echo "                   用 realm 中转流量时，把 realm 中转机的出口 IP 写进来，否则它一旦握手失败就可能被拉黑断流"
  echo "  --whitelist-file 拉黑白名单文件路径（每行一个 IP）：会复制到 /etc/mmx/whitelist，写进服务启动参数"
  echo "  --allow-ip       连接白名单 IP 或 CIDR 段（可重复写多个，例如 --allow-ip 1.2.3.4 --allow-ip 5.6.7.0/24）："
  echo "                   填了就只允许这些 IP 连接落地机，其他 IP 在握手前直接丢弃；不填 = 谁都能连（仍要过密钥校验）"
  echo "                   填你自己的 VPS 入口 IP、realm 中转机 IP；入口是机场节点时别填单个 IP——机场出口 IP 会变、还可能是多人共用，"
  echo "                   容易把自己挡住，填机场出口 IP 段（CIDR）或入口改用自己的 VPS"
  echo "  --allowlist-file 连接白名单文件路径（每行一个 IP 或 CIDR）：会复制到 /etc/mmx/allowlist，写进服务启动参数"
  echo "  --fallback       非 mm-x 连接的回退方式，默认 site：site = 回一个像网站的页面/400 页（探测看到一台普通 Web 服务器）；"
  echo "                   silent = 0 字节回包、直接断开（老样子，更隐蔽但探测者会觉得端口是死的）"
  echo "  --tls-domain     真 TLS 模式的域名：填了就开启真 TLS 包装，流量看起来就是正常 HTTPS 访问这个网站；"
  echo "                   DNS 必须先指到这台 VPS；要和 --tls-cert/--tls-key 一起给"
  echo "  --tls-cert       真 TLS 模式的证书文件（fullchain.pem）"
  echo "  --tls-key        真 TLS 模式的私钥文件（privkey.pem）"
  echo "                   没有证书时先申请 Let's Encrypt：$(certbot_install_cmd) && certbot certonly --standalone -d 你的域名"
  echo "                   （证书一般在 /etc/letsencrypt/live/你的域名/fullchain.pem 和 privkey.pem）"
  echo "  --tls-auto       自签 TLS 模式（没域名时用）：首次启动自动生成自签证书并存到 /etc/mmx/tls-cert.pem 和"
  echo "                   /etc/mmx/tls-key.pem；客户端靠 mmx:// 链接里的 pin（SPKI 指纹）锁定验证，不跳过验证。"
  echo "                   和 --tls-domain 二选一；以后有了域名再用菜单第 3 项（编辑节点）→ 第 10 子项换成真 TLS"
  echo "  --tls-sni        自签 TLS 的默认 SNI（一个常见域名，例如 www.microsoft.com，默认就是它）；"
  echo "                   链接里写了 sni 参数就以链接为准"
  echo "  --domain   一键设置域名：装完自动申请 Let's Encrypt 证书并切到真 TLS（只在 --reinstall 重装节点时跑；"
  echo "           全新安装不建节点，所以 --domain 会被忽略，域名在菜单第 1 项添加节点时选；再跑脚本只更新程序文件时忽略，"
  echo "           改域名请用 mmx 菜单第 3 项（编辑节点）→ 第 10 子项）。"
  echo "           域名 DNS 必须先指到这台 VPS，80 端口要空着（certbot standalone 校验用）；"
  echo "           续期用 --reuse-key（密钥不变，pin 不变，链接不失效），续期后自动重启服务。"
  echo "           申请失败时服务仍用自签 TLS 继续跑，不会留半切的配置；和 --tls-domain 不能同时用"
  echo "  流量统计与限额（默认不限额，只统计不限制；改了限额才限制）："
  echo "  --traffic-mode   统计模式，默认 total：outbound（出站，下载方向）/ inbound（入站，上传方向）/"
  echo "                   total（总计，入站+出站）/ max（最大值，取两者中大的那个）"
  echo "  --traffic-period 统计周期，默认 monthly：monthly（月）/ quarterly（季，1/4/7/10 月起）/ yearly（年）"
  echo "  --traffic-start-day 周期起始日，默认 1：1–31 号，月不足天数时按当月最后一天算（31 号在 2 月按 28/29 号算）"
  echo "  --traffic-limit-mode 超限后的限制模式，默认 throttle：throttle（TC 限速，降到 --traffic-throttle-rate 继续用）/"
  echo "                   block（阻断，拒绝新连接并断开现有连接）"
  echo "  --traffic-quota  每周期流量限额，默认 0（不限）：数字 + K/M/G/T，例如 500G、1T"
  echo "  --traffic-throttle-rate TC 限速值，默认 125K（约 1 Mbps）：超限后全站降到的速度，例如 1M"
  echo "  --cover-traffic  掩护流量（v5 会话），默认 low：off（关）/ low（空闲时平均约 45 秒一帧小记录）/"
  echo "                   high（空闲时平均约 20 秒一帧）"
  echo "  --domain-whitelist 目标域名白名单，默认关：off（关）/ google（只放行谷歌系域名，其他目标直接拒绝；"
  echo "                   IP 字面量目标只放行 Google 公共 DNS 8.8.8.8/8.8.4.4，其余拒绝）"
  echo "  --preset   载入预设的流量设置（和菜单第 2 项一样）：gcp（GCP：180G / 总计 / 月 / 1日 / TC 限速 / 不限速 / 白名单仅谷歌系）"
  echo "           或 cdt（阿里云CDT：180G / 最大值 / 月 / 1日 / TC 限速 / 不限速 / 无白名单）；只改流量设置和域名白名单，不动端口/密钥/TLS；"
  echo "           后面再传 --traffic-* / --domain-whitelist 可以单独再改其中一项"
  exit 1
}

# 全新安装判定（无配置、不是 --reinstall）：不建节点，只装二进制 + 菜单；节点在菜单第 1 项添加。
# 必须在参数解析前算出来：--preset 的校验在解析时跑，全新安装时要跳过它，所以得提前知道；
# --reinstall 本身是参数之一，先预扫描一遍（解析循环里还会再置一次，无害）。
FRESH_NO_NODE="0"
NODE_FLAGS_GIVEN=""
for _a in "$@"; do
  if [ "$_a" = "--reinstall" ]; then REINSTALL="1"; fi
done
if [ ! -f "$CFG_FILE" ] && [ "$REINSTALL" != "1" ]; then FRESH_NO_NODE="1"; fi

while [ $# -gt 0 ]; do
  case "$1" in
    --port) NODE_FLAGS_GIVEN=1; PORT="$2"; shift 2 ;;
    --rate) NODE_FLAGS_GIVEN=1; RATE="$2"; shift 2 ;;
    --burst) NODE_FLAGS_GIVEN=1; BURST="$2"; shift 2 ;;
    --name) NODE_FLAGS_GIVEN=1; NAME="$2"; NAME_SET="1"; shift 2 ;;
    --host) NODE_FLAGS_GIVEN=1; HOST="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --whitelist-ip) NODE_FLAGS_GIVEN=1; WHITELIST_IPS+=("$2"); shift 2 ;;
    --whitelist-file) NODE_FLAGS_GIVEN=1; WHITELIST_FILE="$2"; shift 2 ;;
    --allow-ip) NODE_FLAGS_GIVEN=1; ALLOW_IPS+=("$2"); shift 2 ;;
    --allowlist-file) NODE_FLAGS_GIVEN=1; ALLOWLIST_FILE="$2"; shift 2 ;;
    --fallback) NODE_FLAGS_GIVEN=1; FALLBACK="$2"; shift 2 ;;
    --tls-domain) NODE_FLAGS_GIVEN=1; TLS_DOMAIN="$2"; shift 2 ;;
    --tls-cert) NODE_FLAGS_GIVEN=1; TLS_CERT="$2"; shift 2 ;;
    --tls-key) NODE_FLAGS_GIVEN=1; TLS_KEY="$2"; shift 2 ;;
    --tls-auto) NODE_FLAGS_GIVEN=1; TLS_AUTO="1"; shift ;;
    --tls-sni) NODE_FLAGS_GIVEN=1; TLS_SNI="$2"; shift 2 ;;
    --domain) NODE_FLAGS_GIVEN=1; DOMAIN_SETUP="$2"; shift 2 ;;
    --traffic-mode) NODE_FLAGS_GIVEN=1; TRAFFIC_MODE="$2"; shift 2 ;;
    --traffic-period) NODE_FLAGS_GIVEN=1; TRAFFIC_PERIOD="$2"; shift 2 ;;
    --traffic-start-day) NODE_FLAGS_GIVEN=1; TRAFFIC_START_DAY="$2"; shift 2 ;;
    --traffic-limit-mode) NODE_FLAGS_GIVEN=1; TRAFFIC_LIMIT_MODE="$2"; shift 2 ;;
    --traffic-quota) NODE_FLAGS_GIVEN=1; TRAFFIC_QUOTA="$2"; shift 2 ;;
    --traffic-throttle-rate) NODE_FLAGS_GIVEN=1; TRAFFIC_THROTTLE_RATE="$2"; shift 2 ;;
    --cover-traffic) NODE_FLAGS_GIVEN=1; COVER_TRAFFIC="$2"; shift 2 ;;
    --domain-whitelist) NODE_FLAGS_GIVEN=1; DOMAIN_WHITELIST="$2"; shift 2 ;;
    --preset) NODE_FLAGS_GIVEN=1; if [ "$FRESH_NO_NODE" = "1" ]; then shift 2; else set_preset_vars "$2"; shift 2; fi ;;
    --reinstall) REINSTALL="1"; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：$1"; usage ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 sudo 运行：sudo $0"
  exit 1
fi

# 已安装检测：/etc/mmx/config 已存在且没加 --reinstall 时，再跑本脚本只更新程序文件，
# 不装节点、不改配置。读出现有配置：后面流程里的端口/限速/TLS 等全部沿用现有的值，
# 命令行给的安装参数（--port/--rate/--preset/--traffic-* 等）一律忽略。
UPDATE_ONLY="0"
if [ -f "$CFG_FILE" ] && [ "$REINSTALL" != "1" ]; then
  UPDATE_ONLY="1"
  . "$CFG_FILE"
  echo "检测到已安装的 mm-x 节点（端口 ${PORT:-未知}），本次只更新程序文件（服务端二进制、管理菜单、服务文件），不改节点配置。"
  echo "安装参数（--port/--rate/--preset/--traffic-*/--domain 等）已忽略；改节点参数请用 mmx 菜单；要彻底重装节点请加 --reinstall。"
  if [ -n "${DOMAIN_SETUP:-}" ]; then
    echo "已忽略 --domain $DOMAIN_SETUP：只更新程序文件时不改 TLS 设置；要设置域名请用 mmx 菜单第 3 项（编辑节点）→ 第 10 子项，或加 --reinstall 重装时再传 --domain。"
  fi
fi
# --reinstall 是显式重装：交互终端里再确认一次（默认不重装）；管道/自动化里直接执行。
if [ "$REINSTALL" = "1" ] && [ -f "$CFG_FILE" ] && [ -t 0 ]; then
  echo "警告：--reinstall 会重装节点：按本次传入参数重写 $CFG_FILE（端口/限速/TLS/流量设置都会按本次参数重置；密钥文件保留不变）。"
  read -r -p "确认重装吗？输入 y 确认（直接回车 = 取消）： " _yn || true
  if [ "${_yn:-}" != "y" ] && [ "${_yn:-}" != "Y" ]; then
    echo "已取消重装，现有节点未动。"
    exit 0
  fi
fi

# 节点参数校验（全新安装不建节点，全部跳过：参数照单收、不报错、不校验；
# 只有 --reinstall 建节点时才校验）。
if [ "$FRESH_NO_NODE" != "1" ]; then
# --domain：一键申请证书并切真 TLS（只在 --reinstall 重装节点时跑；
# 更新模式上面已经忽略该参数，不走这里）。和手动给证书的
# --tls-domain/--tls-cert/--tls-key 不能同时用。先以自签 TLS 起服务，
# 装完再调菜单的 setup_domain 申请证书——申请失败服务仍用自签 TLS，
# 不会留半切的配置。
if [ -n "$DOMAIN_SETUP" ] && [ "$UPDATE_ONLY" = "0" ]; then
  if [ -n "$TLS_DOMAIN" ] || [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
    echo "--domain（一键申请证书）和 --tls-domain/--tls-cert/--tls-key（手动给证书）不能同时用，二选一"
    exit 1
  fi
  valid_domain "$DOMAIN_SETUP" || { echo "域名不对：$DOMAIN_SETUP（应为域名，例如 example.com；不要带 http:// 或端口）"; exit 1; }
  TLS_AUTO="1"
fi

# 回退模式与真 TLS 参数校验
if [ "$FALLBACK" != "site" ] && [ "$FALLBACK" != "silent" ]; then
  echo "回退方式不合法：$FALLBACK，应为 site（默认）或 silent"
  exit 1
fi
if [ "$COVER_TRAFFIC" != "off" ] && [ "$COVER_TRAFFIC" != "low" ] && [ "$COVER_TRAFFIC" != "high" ] && [ "$COVER_TRAFFIC" != "关" ] && [ "$COVER_TRAFFIC" != "低" ] && [ "$COVER_TRAFFIC" != "高" ]; then
  echo "掩护流量档位不合法：$COVER_TRAFFIC，应为 off（关）/ low（低，默认）/ high（高）"
  exit 1
fi
if [ -n "$TLS_DOMAIN" ] || [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
  if [ -z "$TLS_DOMAIN" ]; then echo "开了真 TLS 就要给域名：--tls-domain 你的域名（DNS 必须先指到这台 VPS）"; exit 1; fi
  if [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ]; then echo "真 TLS 的证书和私钥要一起给：--tls-cert 证书文件 --tls-key 私钥文件"; exit 1; fi
  if [ ! -f "$TLS_CERT" ]; then echo "证书文件不存在：$TLS_CERT"; exit 1; fi
  if [ ! -f "$TLS_KEY" ]; then echo "私钥文件不存在：$TLS_KEY"; exit 1; fi
fi
# 自签 TLS 和真 TLS 二选一；--tls-sni 只在自签模式下有意义
if [ "$TLS_AUTO" = "1" ]; then
  if [ -n "$TLS_DOMAIN" ] || [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
    echo "自签 TLS（--tls-auto）和真 TLS（--tls-domain/--tls-cert/--tls-key）不能同时开，二选一"
    exit 1
  fi
fi
if [ -n "$TLS_SNI" ] && [ "$TLS_AUTO" != "1" ]; then
  echo "--tls-sni 只在自签 TLS（--tls-auto）模式下用"
  exit 1
fi

# 流量统计参数校验（中文别名也认，统一转成英文规范值写进配置）
case "$TRAFFIC_MODE" in
  out|outbound|出站) TRAFFIC_MODE="outbound" ;;
  in|inbound|入站) TRAFFIC_MODE="inbound" ;;
  total|总计) TRAFFIC_MODE="total" ;;
  max|最大值) TRAFFIC_MODE="max" ;;
  *) echo "流量统计模式不合法：$TRAFFIC_MODE，应为 outbound（出站）/ inbound（入站）/ total（总计）/ max（最大值）"; exit 1 ;;
esac
case "$TRAFFIC_PERIOD" in
  monthly|month|月) TRAFFIC_PERIOD="monthly" ;;
  quarterly|quarter|季) TRAFFIC_PERIOD="quarterly" ;;
  yearly|year|年) TRAFFIC_PERIOD="yearly" ;;
  *) echo "统计周期不合法：$TRAFFIC_PERIOD，应为 monthly（月）/ quarterly（季）/ yearly（年）"; exit 1 ;;
esac
case "$TRAFFIC_LIMIT_MODE" in
  block|阻断) TRAFFIC_LIMIT_MODE="block" ;;
  throttle|tc|限速|tc限速) TRAFFIC_LIMIT_MODE="throttle" ;;
  *) echo "限制模式不合法：$TRAFFIC_LIMIT_MODE，应为 block（阻断）/ throttle（TC 限速）"; exit 1 ;;
esac
case "$TRAFFIC_START_DAY" in ''|*[!0-9]*) echo "周期起始日不合法：$TRAFFIC_START_DAY，应为 1–31 号"; exit 1;; esac
if [ "$TRAFFIC_START_DAY" -lt 1 ] || [ "$TRAFFIC_START_DAY" -gt 31 ]; then echo "周期起始日不合法：$TRAFFIC_START_DAY，应为 1–31 号"; exit 1; fi
printf '%s' "$TRAFFIC_QUOTA" | grep -Eq '^[0-9]+[KkMmGgTt]?$' || { echo "流量限额格式不对：$TRAFFIC_QUOTA（应为数字 + 可选 K/M/G/T，例如 500G、0）"; exit 1; }
printf '%s' "$TRAFFIC_THROTTLE_RATE" | grep -Eq '^[0-9]+[KkMmGg]?$' || { echo "TC 限速值格式不对：$TRAFFIC_THROTTLE_RATE（应为数字 + 可选 K/M/G，例如 125K）"; exit 1; }
if [ "$TRAFFIC_LIMIT_MODE" = "throttle" ] && [ "$TRAFFIC_THROTTLE_RATE" = "0" ]; then echo "TC 限速模式下限速值不能为 0（0 = 不限速，等于没限制）"; exit 1; fi
# 域名白名单取值：off/空 = 关，google = 只放行谷歌系域名
case "$(printf '%s' "$DOMAIN_WHITELIST" | tr '[:upper:]' '[:lower:]')" in
  ""|off|none) DOMAIN_WHITELIST="" ;;
  google) DOMAIN_WHITELIST="google" ;;
  *) echo "域名白名单不合法：$DOMAIN_WHITELIST，应为 off（关，默认）或 google（只放行谷歌系域名）"; exit 1 ;;
esac

# 默认端口 443（没传 --port 时用 443；已安装时前面已从现有配置读出端口，不走这里）
if [ -z "$PORT" ]; then
  PORT=443
fi
case "$PORT" in ''|*[!0-9]*|0) echo "端口不合法：$PORT，应为 1-65535 之间的数字"; exit 1;; esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then echo "端口不合法：$PORT，应为 1-65535 之间的数字"; exit 1; fi

# 端口占用检查：被别的服务占了就报错停下（443 常见占用是 nginx/Apache）；
# 自己的旧服务在用这个端口（重装）则放行。
if command -v ss >/dev/null 2>&1; then
  if ss -tln 2>/dev/null | grep -q ":$PORT[[:space:]]"; then
    if [ -f "$CFG_FILE" ] && grep -q "^PORT=$PORT$" "$CFG_FILE" 2>/dev/null; then
      echo "端口 $PORT 正被本机的旧 mm-x 服务占用，重装会重启它，继续。"
    else
      echo "端口 $PORT 已被别的服务占用，装不下去。"
      echo "443 端口常见占用：nginx / Apache / 其他 Web 服务；高位端口被占：可能是之前装的别的服务。"
      echo "处理办法：换一个端口（--port 新端口），或先停掉占用的服务再装。"
      exit 1
    fi
  fi
fi
fi # FRESH_NO_NODE：全新安装跳过全部节点参数校验

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "$BIN" ]; then
  if [ -f "$SCRIPT_DIR/mmx-server-linux-amd64" ]; then
    BIN="$SCRIPT_DIR/mmx-server-linux-amd64"
  elif [ -f "$SCRIPT_DIR/mmx-server" ]; then
    BIN="$SCRIPT_DIR/mmx-server"
  elif [ -x "$BIN_DIR/mmx-server" ]; then
    BIN="$BIN_DIR/mmx-server"  # 更新模式：只重装服务配置，不换二进制
  else
    # 没找到二进制：自己从 GitHub 下一个（供一键命令 curl | bash 用）
    echo "本地没有服务端二进制，正在从 GitHub 下载…"
    if ! command -v curl >/dev/null 2>&1; then
      echo "下载二进制需要 curl，请先安装 curl，或把 mmx-server-linux-amd64 和本脚本放在同一个目录再运行。"
      exit 1
    fi
    DL_DIR="$(mktemp -d)"
    if curl -fsSL -o "$DL_DIR/mmx-server-linux-amd64" "https://raw.githubusercontent.com/bestmiao/mm-x/main/mmx-server-linux-amd64"; then
      chmod +x "$DL_DIR/mmx-server-linux-amd64"
      BIN="$DL_DIR/mmx-server-linux-amd64"
    else
      echo "下载服务端二进制失败，请检查网络，或把 mmx-server-linux-amd64 和本脚本放在同一个目录再运行。"
      exit 1
    fi
  fi
fi
if [ ! -f "$BIN" ]; then echo "服务端二进制不存在：$BIN"; exit 1; fi

# 节点名：--reinstall 重装节点时，没传 --name 就交互问一句，留空用默认 mm-x；
# 只在 stdin 是终端时才问——一键命令是管道（curl | bash）、
# 自动化脚本的 stdin 也不是终端，这时直接用默认，不许卡住等输入。
# 全新安装不建节点、不问；已安装更新模式不问（节点名沿用现有配置）。
if [ "$UPDATE_ONLY" = "0" ] && [ "$FRESH_NO_NODE" != "1" ] && [ "$NAME_SET" = "0" ] && [ -t 0 ]; then
  read -r -p "节点名（留空用默认 mm-x）： " NAME_INPUT || true
  if [ -n "$NAME_INPUT" ]; then NAME="$NAME_INPUT"; fi
fi

if [ "$FRESH_NO_NODE" = "1" ]; then
echo "== 安装 mm-x 服务端（只装程序，不建节点） =="
echo "本次只安装服务端二进制和管理菜单，不创建节点；装完进入菜单，用第 1 项添加节点。"
else
echo "== 安装 mm-x 服务端 =="
TLS_MODE_DESC="关"
[ -n "$TLS_DOMAIN" ] && TLS_MODE_DESC="真 TLS（$TLS_DOMAIN）"
[ "$TLS_AUTO" = "1" ] && TLS_MODE_DESC="自签 TLS（SNI ${TLS_SNI:-www.microsoft.com}）"
echo "端口：$PORT；限速：$RATE；突发：$BURST；节点名：$NAME；回退：$FALLBACK；TLS：$TLS_MODE_DESC"
if [ "$TRAFFIC_QUOTA" = "0" ]; then
  echo "流量统计：模式 $TRAFFIC_MODE，周期 $TRAFFIC_PERIOD（每月 $TRAFFIC_START_DAY 日起），不限额（只统计，不限制）"
else
  echo "流量统计：模式 $TRAFFIC_MODE，周期 $TRAFFIC_PERIOD（每月 $TRAFFIC_START_DAY 日起），限额 $TRAFFIC_QUOTA，超限后 $TRAFFIC_LIMIT_MODE"
fi
fi

# 1) 装二进制（更新模式下 BIN 就是已安装的文件，跳过自复制）
mkdir -p "$BIN_DIR"
# 已安装更新模式：先备份旧二进制——新二进制重启失败时可以还原，服务不会停在起不来的状态
BIN_BAK=""
if [ "$UPDATE_ONLY" = "1" ] && [ -x "$BIN_DIR/mmx-server" ]; then
  BIN_BAK="$BIN_DIR/mmx-server.bak"
  cp -f "$BIN_DIR/mmx-server" "$BIN_BAK"
fi
if [ "$BIN" != "$BIN_DIR/mmx-server" ]; then
  install -m 755 "$BIN" "$BIN_DIR/mmx-server"
  echo "二进制已安装：$BIN_DIR/mmx-server"
else
  echo "更新模式：二进制已在安装位置，不重复安装"
fi

# 2) 密钥：/etc/mmx/psk 没有就生成（64 位十六进制，32 字节），有了就保留——
#    重装/更新不换密钥；轮换密钥已从主菜单移除（直接改 /etc/mmx/psk，服务端自动识别，24 小时内新旧密钥都能用）
#    全新安装不建节点，跳过（密钥在菜单第 1 项添加节点时生成）。
if [ "$FRESH_NO_NODE" != "1" ]; then
mkdir -p "$CFG_DIR"
if [ -f "$PSK_FILE" ]; then
  echo "密钥文件已存在（$PSK_FILE），保留旧密钥，不重新生成"
else
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "$PSK_FILE"
  else
    od -An -tx1 -N 32 /dev/urandom | tr -d ' \n' > "$PSK_FILE"
  fi
  chmod 600 "$PSK_FILE"
  echo "已生成新密钥：$PSK_FILE（只保存在这台机器上，不要发给别人）"
fi
fi

# BBR：系统调优，节点用。开不了只警告，绝不因此失败（测试模式跳过）。
enable_bbr() {
  echo "== 开启 BBR =="
  if [ -n "${MMX_TEST_ROOT:-}" ]; then
    echo "测试模式：跳过 BBR"
    return 0
  fi
  local BBR_OK=0
  if sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null && sysctl -w net.core.default_qdisc=fq 2>/dev/null; then
    if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" = "bbr" ]; then
      BBR_OK=1
      mkdir -p /etc/sysctl.d
      printf 'net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\n' > /etc/sysctl.d/99-mmx-bbr.conf
    fi
  fi
  if [ "$BBR_OK" -eq 1 ]; then
    echo "BBR 已开启"
  else
    echo "警告：BBR 没开成（内核不支持或没有权限），服务端照常运行，只是少了 BBR 的平滑效果"
  fi
}

# 防火墙放行端口：有哪个工具用哪个，都没有就只提醒。
open_firewall_port() {
  echo "== 防火墙放行 $PORT/tcp =="
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$PORT/tcp" >/dev/null 2>&1 || echo "警告：ufw 放行失败，请手动放行 $PORT/tcp"
    echo "已用 ufw 放行 $PORT/tcp"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --add-port="$PORT/tcp" --permanent >/dev/null 2>&1 || echo "警告：firewalld 放行失败，请手动放行 $PORT/tcp"
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "已用 firewalld 放行 $PORT/tcp"
  else
    echo "警告：没找到 ufw/firewall-cmd，请在云服务商的安全组 / 防火墙里手动放行 $PORT/tcp，否则连不上"
  fi
}

# 3) BBR 默认开：开不了只警告，绝不因为开不了就装失败（测试模式跳过）
#    全新安装不建节点，跳过（BBR 在菜单第 1 项添加节点时开；--reinstall 建节点时也开）。
if [ "$FRESH_NO_NODE" != "1" ]; then
  enable_bbr
fi

# 4) 防火墙放行端口（有哪个工具用哪个，都没有就只提醒）
#    全新安装不建节点、没端口可放，跳过（在菜单第 1 项添加节点时按它的端口放行）。
if [ "$FRESH_NO_NODE" != "1" ]; then
  open_firewall_port
fi

# 5) 拉黑白名单：--whitelist-ip（可重复）写进启动参数；--whitelist-file 复制到 /etc/mmx/whitelist 再写进启动参数
#    全新安装不建节点，跳过（白名单文件没配置可写）。
WHITELIST_FILE_INSTALLED=""
if [ "$FRESH_NO_NODE" != "1" ] && [ -n "$WHITELIST_FILE" ]; then
  if [ ! -f "$WHITELIST_FILE" ]; then echo "拉黑白名单文件不存在：$WHITELIST_FILE"; exit 1; fi
  install -m 600 "$WHITELIST_FILE" "$CFG_DIR/whitelist"
  WHITELIST_FILE_INSTALLED="$CFG_DIR/whitelist"
  echo "拉黑白名单文件已安装：$CFG_DIR/whitelist（重装脚本时不会被覆盖，除非再传 --whitelist-file）"
fi

# 5b) 连接白名单：--allow-ip（可重复，IP 或 CIDR）写进启动参数；--allowlist-file 复制到 /etc/mmx/allowlist 再写进启动参数
#    全新安装不建节点，跳过。
ALLOWLIST_FILE_INSTALLED=""
if [ "$FRESH_NO_NODE" != "1" ] && [ -n "$ALLOWLIST_FILE" ]; then
  if [ ! -f "$ALLOWLIST_FILE" ]; then echo "连接白名单文件不存在：$ALLOWLIST_FILE"; exit 1; fi
  install -m 600 "$ALLOWLIST_FILE" "$CFG_DIR/allowlist"
  ALLOWLIST_FILE_INSTALLED="$CFG_DIR/allowlist"
  echo "连接白名单文件已安装：$CFG_DIR/allowlist（重装脚本时不会被覆盖，除非再传 --allowlist-file）"
fi

# 6) 探测公网 IP（--host 优先），写进配置文件（菜单拼链接时用）
#    全新安装不建节点、不写配置，跳过（菜单第 1 项添加节点时会再探测）。
if [ "$FRESH_NO_NODE" != "1" ]; then
if [ -z "$HOST" ]; then
  HOST="$(curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true)"
  if [ -z "$HOST" ]; then HOST="$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"; fi
  # BusyBox hostname（Alpine）没有 -I 选项，会直接报错退出 1；
  # set -euo pipefail 下必须加 || true，否则安装会在这里中断（Debian 的 hostname -I 正常，不受影响）。
  if [ -z "$HOST" ]; then HOST="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"; fi
fi
# 127.0.0.1/内网 IP 不能当链接地址（hostname -I 有时先返回它）；
# 探到这种地址就当没探到，菜单里用占位地址提醒用户改。
case "$HOST" in
  127.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) HOST="" ;;
esac
if [ -z "$HOST" ]; then
  echo "警告：探测不到公网 IP，菜单里拼链接时会用占位地址，记得在菜单第 3 项里把服务器地址改成你的 VPS 公网 IP 或域名"
  HOST=""
fi
fi

# 7) 写配置文件 /etc/mmx/config：全部参数都在这里，菜单改参数就改这个文件，
#    再由菜单按它重新生成服务文件（改错了重启失败会自动回滚）。
#    只在 --reinstall 重装节点时写；已安装更新模式跳过，节点配置原样保留；
#    全新安装不建节点，不写配置（节点在菜单第 1 项添加时写）。
if [ "$UPDATE_ONLY" = "1" ]; then
echo "已安装节点：跳过写配置（$CFG_FILE 原样保留）"
elif [ "$REINSTALL" = "1" ]; then
WHITELIST_IPS_STR="${WHITELIST_IPS[*]:-}"
ALLOW_IPS_STR="${ALLOW_IPS[*]:-}"
{
  printf '%s=%q\n' PORT "$PORT" RATE "$RATE" BURST "$BURST" NAME "$NAME" HOST "$HOST" FALLBACK "$FALLBACK" TLS_DOMAIN "$TLS_DOMAIN" TLS_CERT "$TLS_CERT" TLS_KEY "$TLS_KEY" TLS_AUTO "$TLS_AUTO" TLS_SNI "$TLS_SNI" WHITELIST_IPS "$WHITELIST_IPS_STR" WHITELIST_FILE "$WHITELIST_FILE_INSTALLED" ALLOW_IPS "$ALLOW_IPS_STR" ALLOWLIST_FILE "$ALLOWLIST_FILE_INSTALLED" TRAFFIC_MODE "$TRAFFIC_MODE" TRAFFIC_PERIOD "$TRAFFIC_PERIOD" TRAFFIC_START_DAY "$TRAFFIC_START_DAY" TRAFFIC_LIMIT_MODE "$TRAFFIC_LIMIT_MODE" TRAFFIC_QUOTA "$TRAFFIC_QUOTA" TRAFFIC_THROTTLE_RATE "$TRAFFIC_THROTTLE_RATE" COVER_TRAFFIC "$COVER_TRAFFIC" DOMAIN_WHITELIST "$DOMAIN_WHITELIST"
} > "$CFG_FILE"
chmod 600 "$CFG_FILE"
echo "配置文件已写入：$CFG_FILE"
else
echo "全新安装：不创建节点，不写配置文件（节点在菜单第 1 项添加）。"
fi

# 8) 写管理菜单 /usr/local/bin/mmx：输入 mmx 呼出。
#    菜单是一个独立的 bash 脚本；配置存在 /etc/mmx/config，密钥在 /etc/mmx/psk，
#    服务文件由菜单按配置文件生成（改参数后自动重载 + 重启，重启失败自动回滚）。
echo "== 安装管理菜单 =="
cat > "$BIN_DIR/mmx" <<'MM_MENU_EOF'
#!/bin/bash
# mm-x 服务端管理菜单：在 VPS 上输入 mmx 呼出。
# 功能：1 添加节点  2 载入预设（GCP / 阿里云CDT 的流量设置）  3 编辑节点（含流量设置、域名白名单）
#       4 删除节点  5 查看节点  6 服务状态  7 重启服务  8 修改限速
#       9 查看日志  10 卸载  11 退出
# （更换密钥、诱饵回退 / TLS 设置已从主菜单移除，函数保留在脚本内；TLS 入口在第 3 项编辑节点第 10 子项）
# 全部配置存在 /etc/mmx/config，密钥在 /etc/mmx/psk；
# 服务文件由本脚本按配置文件生成，改参数后自动重载 + 重启，
# 重启失败自动回滚到改之前的配置，不会让服务起不来。
# 隐藏用法（给部署脚本和脚本调用）：mmx --write-service（按配置写服务文件）、mmx --show-link [plain|opaque]（只打印链接，
# 默认 opaque 不透明链接；plain 是短格式，只在显式指定时用）、
# mmx --show-pin（只打印 TLS 证书的 SPKI 指纹）、mmx --show-traffic（打印本周期流量统计）、
# mmx --preset <gcp|cdt>（不进菜单直接载入预设，GCP 或阿里云CDT）、
# mmx --setup-domain <域名>（一键申请 Let's Encrypt 证书并切真 TLS，部署脚本的 --domain 也走这里）。
set -u

ROOT="${MMX_TEST_ROOT:-}"
CFG_DIR="$ROOT/etc/mmx"
CFG_FILE="$CFG_DIR/config"
PSK_FILE="$CFG_DIR/psk"
BIN_DIR="$ROOT/usr/local/bin"
SERVER_BIN="$BIN_DIR/mmx-server"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/mmx-server.service"
MYNAME="$(basename "$0")"

# 服务管理方式：systemd（Debian/Ubuntu）或 OpenRC（Alpine）。
# 有 systemctl 用 systemd；没有 systemctl 但有 rc-service 用 OpenRC；
# 都没有就警告并默认 systemd（Debian 行为不变）。
# （测试模式下替身只提供 systemctl，所以走 systemd，和原来一样。）
# 注意：下面这组检测 + 服务操作函数在部署脚本和菜单脚本里各有一份（菜单是独立脚本），改动时两边同步。
detect_init() {
  if command -v systemctl >/dev/null 2>&1; then echo "systemd"; return 0; fi
  if command -v rc-service >/dev/null 2>&1; then echo "openrc"; return 0; fi
  echo "警告：没找到 systemctl 也没找到 rc-service，默认按 systemd 处理" >&2
  echo "systemd"
}
INIT_SYS="$(detect_init)"
INIT_DIR="$ROOT/etc/init.d"
INIT_FILE="$INIT_DIR/mmx-server"
# 当前系统实际用的服务文件（systemd 用 UNIT_FILE，OpenRC 用 INIT_FILE）
if [ "$INIT_SYS" = "openrc" ]; then SVC_FILE="$INIT_FILE"; SVC_DIR="$INIT_DIR"; else SVC_FILE="$UNIT_FILE"; SVC_DIR="$UNIT_DIR"; fi

# 服务操作封装：按 INIT_SYS 分发到 systemctl 或 rc-service/rc-update。
# 返回值和原来直接调 systemctl 时一致（成功 0，失败非 0），方便 if 判断。
svc_reload() {
  if [ "$INIT_SYS" = "openrc" ]; then return 0; fi
  systemctl daemon-reload 2>/dev/null
}
svc_restart() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server restart 2>/dev/null; else systemctl restart mmx-server 2>/dev/null; fi
}
svc_is_active() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server status >/dev/null 2>&1; else systemctl is-active --quiet mmx-server 2>/dev/null; fi
}
svc_start() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server start 2>/dev/null; else systemctl start mmx-server 2>/dev/null; fi
}
svc_stop() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server stop 2>/dev/null; else systemctl stop mmx-server 2>/dev/null; fi
}
svc_status() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service mmx-server status 2>&1 | head -20 || true; else systemctl status mmx-server --no-pager 2>&1 | head -20 || true; fi
}
svc_enable() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-update add mmx-server default 2>/dev/null; else systemctl enable mmx-server >/dev/null 2>&1; fi
}
svc_disable() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-update del mmx-server default 2>/dev/null; else systemctl disable mmx-server 2>/dev/null; fi
}
# 提示文字里用的服务命令（按当前系统显示正确那条）
svc_status_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "rc-service mmx-server status"; else echo "systemctl status mmx-server"; fi
}
svc_log_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "tail -n 50 /var/log/messages"; else echo "journalctl -u mmx-server -n 50"; fi
}
svc_log_follow_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "tail -f /var/log/messages"; else echo "journalctl -u mmx-server -f"; fi
}
svc_stop_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "rc-service $1 stop"; else echo "systemctl stop $1"; fi
}
# 装 certbot 的命令（提示文字用）
certbot_install_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "apk add certbot"; else echo "apt install certbot -y"; fi
}

# 默认值（配置文件缺失时用；老配置没有流量字段时也按这些默认走）
PORT=""; RATE="0"; BURST="0"; NAME="mm-x"; HOST=""
FALLBACK="site"; TLS_DOMAIN=""; TLS_CERT=""; TLS_KEY=""
TLS_AUTO="0"; TLS_SNI=""
WHITELIST_IPS=""; WHITELIST_FILE=""; ALLOW_IPS=""; ALLOWLIST_FILE=""
TRAFFIC_MODE="total"; TRAFFIC_PERIOD="monthly"; TRAFFIC_START_DAY="1"
TRAFFIC_LIMIT_MODE="throttle"; TRAFFIC_QUOTA="0"; TRAFFIC_THROTTLE_RATE="125K"
COVER_TRAFFIC="low"
DOMAIN_WHITELIST=""
# 第 5 项查看节点里是否同时显示 IP 地址的链接（默认不显示，只显示域名/服务器地址那条）；
# IP 链接是同一台服务器的 IP 写法，不是第二个独立节点，只有用户在编辑节点里打开才显示。
SHOW_IP_LINK="0"

load_config() {
  if [ -f "$CFG_FILE" ]; then
    # 配置文件是本脚本自己写的 key=value（值已转义），直接 source
    . "$CFG_FILE"
  fi
}

save_config() {
  mkdir -p "$CFG_DIR"
  {
    printf '%s=%q\n' PORT "$PORT" RATE "$RATE" BURST "$BURST" NAME "$NAME" HOST "$HOST" FALLBACK "$FALLBACK" TLS_DOMAIN "$TLS_DOMAIN" TLS_CERT "$TLS_CERT" TLS_KEY "$TLS_KEY" TLS_AUTO "$TLS_AUTO" TLS_SNI "$TLS_SNI" WHITELIST_IPS "$WHITELIST_IPS" WHITELIST_FILE "$WHITELIST_FILE" ALLOW_IPS "$ALLOW_IPS" ALLOWLIST_FILE "$ALLOWLIST_FILE" TRAFFIC_MODE "$TRAFFIC_MODE" TRAFFIC_PERIOD "$TRAFFIC_PERIOD" TRAFFIC_START_DAY "$TRAFFIC_START_DAY" TRAFFIC_LIMIT_MODE "$TRAFFIC_LIMIT_MODE" TRAFFIC_QUOTA "$TRAFFIC_QUOTA" TRAFFIC_THROTTLE_RATE "$TRAFFIC_THROTTLE_RATE" COVER_TRAFFIC "$COVER_TRAFFIC" DOMAIN_WHITELIST "$DOMAIN_WHITELIST" SHOW_IP_LINK "$SHOW_IP_LINK"
  } > "$CFG_FILE"
  chmod 600 "$CFG_FILE"
}

# 按当前配置写服务文件（不重载、不重启，只写文件）：
# systemd 写 $UNIT_FILE（单元文件），OpenRC 写 $INIT_FILE（init 脚本）。
# 启动参数只拼一次，两边用同一份（字节一致）；OpenRC 的 command_args 经 eval 处理，引号正常解析。
write_service() {
  local tls_args="" wl_args="" al_args="" traffic_args="" ip e
  if [ -n "$TLS_DOMAIN" ]; then
    tls_args=" --tls-domain $TLS_DOMAIN --tls-cert $TLS_CERT --tls-key $TLS_KEY"
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    # 自签模式：证书路径必须写绝对路径——服务端不给路径时默认相对路径 tls-cert.pem，
    # systemd 下工作目录是 /，会写到根目录去，所以这里固定写 /etc/mmx 下。
    tls_args=" --tls-auto --tls-cert $CFG_DIR/tls-cert.pem --tls-key $CFG_DIR/tls-key.pem"
    if [ -n "${TLS_SNI:-}" ]; then tls_args="$tls_args --tls-sni $TLS_SNI"; fi
  fi
  for ip in $WHITELIST_IPS; do wl_args="$wl_args --whitelist $ip"; done
  if [ -n "$WHITELIST_FILE" ]; then wl_args="$wl_args --whitelist-file $WHITELIST_FILE"; fi
  for e in $ALLOW_IPS; do al_args="$al_args --allowlist $e"; done
  if [ -n "$ALLOWLIST_FILE" ]; then al_args="$al_args --allowlist-file $ALLOWLIST_FILE"; fi
  # 流量统计与限额：一直写进启动参数（限额 0 = 不限，只统计不限制）；
  # 计数持久化文件固定在配置目录下（/etc/mmx/traffic.json）。
  traffic_args=" --traffic-mode ${TRAFFIC_MODE:-total} --traffic-period ${TRAFFIC_PERIOD:-monthly} --traffic-start-day ${TRAFFIC_START_DAY:-1} --traffic-limit-mode ${TRAFFIC_LIMIT_MODE:-throttle} --traffic-quota ${TRAFFIC_QUOTA:-0} --traffic-throttle-rate ${TRAFFIC_THROTTLE_RATE:-125K} --traffic-file $CFG_DIR/traffic.json"
  # 掩护流量（v5 会话）：一直写进启动参数，默认 low。
  cover_args=" --cover-traffic ${COVER_TRAFFIC:-low}"
  # 目标域名白名单：只在开了时写进启动参数（默认关，不写）。
  local domain_whitelist_args=""
  if [ -n "${DOMAIN_WHITELIST:-}" ]; then domain_whitelist_args=" --domain-whitelist $DOMAIN_WHITELIST"; fi
  # 启动参数（不含二进制路径）：systemd 的 ExecStart 和 OpenRC 的 command_args 用同一份。
  local args="--psk-file $PSK_FILE --listen 0.0.0.0:$PORT --rate $RATE --burst $BURST --name \"$NAME\" --fallback $FALLBACK$tls_args$wl_args$al_args$traffic_args$cover_args$domain_whitelist_args"
  if [ "$INIT_SYS" = "openrc" ]; then
    mkdir -p "$INIT_DIR"
    # command_args 写进双引号里，里面的特殊字符要转义；openrc-run 用 eval 处理 command_args，转义后正常解析。
    # 先转义反斜杠，再转义双引号、$ 和反引号（顺序不能乱）。
    local esc_args="$args"
    esc_args="${esc_args//\\/\\\\}"
    esc_args="${esc_args//\"/\\\"}"
    esc_args="${esc_args//\$/\\\$}"
    esc_args="${esc_args//\`/\\\`}"
    cat > "$INIT_FILE" <<OPENRC_EOF
#!/sbin/openrc-run
# mm-x private proxy server
command="$SERVER_BIN"
command_args="$esc_args"
command_background=true
pidfile="/run/mmx-server.pid"
depend() {
  need net
  after firewall
}
OPENRC_EOF
    chmod +x "$INIT_FILE"
    return 0
  fi
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_FILE" <<UNIT_EOF
[Unit]
Description=mm-x private proxy server
After=network-online.target
Wants=network-online.target
# 保活：不限重启次数——默认 10 秒内重启 5 次就停，崩溃循环时会彻底停掉；
# RestartSec=5 已限速（最多约 12 次/分钟），不会空转打爆 CPU。
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$SERVER_BIN $args
Restart=always
RestartSec=5
# 密钥文件只让 root 读，服务以 root 跑（只监听一个端口，不写别的目录）

[Install]
WantedBy=multi-user.target
UNIT_EOF
}

# 改完配置统一走这里：备份 → 写配置 → 写服务 → 重载 → 重启 → 检查；
# 重启失败就恢复备份、再重启一次，绝不让服务停在起不来的状态。
# $1=操作说明（用于提示）
apply_config() {
  local desc="$1"
  cp -f "$CFG_FILE" "$CFG_FILE.bak" 2>/dev/null || true
  cp -f "$SVC_FILE" "$SVC_FILE.bak" 2>/dev/null || true
  save_config
  write_service
  svc_enable || true
  svc_reload || true
  if svc_restart && svc_is_active; then
    rm -f "$CFG_FILE.bak" "$SVC_FILE.bak"
    echo "已生效：$desc，服务已重启并正常运行"
    return 0
  fi
  echo "重启失败！正在回滚到改之前的配置……"
  cp -f "$CFG_FILE.bak" "$CFG_FILE" 2>/dev/null || true
  cp -f "$SVC_FILE.bak" "$SVC_FILE" 2>/dev/null || true
  load_config
  svc_reload || true
  svc_restart || true
  if svc_is_active; then
    echo "已回滚：服务用原配置恢复运行。请检查输入的参数再改。"
  else
    echo "回滚后服务仍未运行！请手动检查：$(svc_status_cmd)；日志：$(svc_log_cmd)"
  fi
  return 1
}

pause() {
  # 只在真人交互时停一下等回车；管道/脚本调用时不暂停
  if [ -t 0 ]; then read -r -p "按回车回菜单…" _dummy || true; fi
}

valid_port() {
  case "$1" in ''|*[!0-9]*) return 1;; esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# 限速/突发格式：数字 + 可选 K/M/G（不区分大小写），0 表示不限/不突发
valid_rate() {
  case "$1" in 0) return 0;; esac
  printf '%s' "$1" | grep -Eq '^[0-9]+[KkMmGg]?$'
}

# 流量限额格式：数字 + 可选 K/M/G/T（不区分大小写），0 表示不限额
valid_bytes() {
  case "$1" in 0) return 0;; esac
  printf '%s' "$1" | grep -Eq '^[0-9]+[KkMmGgTt]?$'
}

# 流量统计模式/周期/限制模式的中文名（菜单显示用；配置里存英文规范值）
traffic_mode_label() {
  case "${TRAFFIC_MODE:-total}" in
    outbound) echo "出站" ;; inbound) echo "入站" ;;
    max) echo "最大值" ;; *) echo "总计" ;;
  esac
}
traffic_period_label() {
  case "${TRAFFIC_PERIOD:-monthly}" in
    quarterly) echo "季" ;; yearly) echo "年" ;; *) echo "月" ;;
  esac
}
traffic_limit_label() {
  case "${TRAFFIC_LIMIT_MODE:-throttle}" in
    throttle) echo "TC 限速" ;; *) echo "阻断" ;;
  esac
}

# IPv4 或 IPv4/CIDR（例如 1.2.3.4、5.6.7.0/24）
valid_ip_cidr() {
  printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
}

# 域名格式：每段 1-63 字符（字母数字或连字符，不以连字符开头/结尾），
# 至少两段，最后一段（TLD）是至少 2 位字母，总长不超过 253。
valid_domain() {
  local d="$1" tld
  [ -n "$d" ] || return 1
  [ "${#d}" -le 253 ] || return 1
  printf '%s' "$d" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$' || return 1
  tld="${d##*.}"
  [ "${#tld}" -ge 2 ] || return 1
  case "$tld" in *[!A-Za-z]*) return 1;; esac
  return 0
}

port_in_use() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -tln 2>/dev/null | grep -q ":$1[[:space:]]"
}

# 拼一条节点链接的核心（给 show_link 和 show_nodes 共用）：
#    用法：build_link <地址> [plain|opaque]，默认 opaque（不透明链接，一串乱码）；
#    plain 是短格式，只在显式指定时用。只把链接打到标准输出（成功时一行
#    mmx://，失败时空）；调用方自己判断空链接再报错。地址是链接里用的
#    host（域名或 IP），TLS 分支仍按配置走（真 TLS / 自签 / 明文），
#    和原来 show_link 的三路分支一致。密钥文件没有就先生成一个再拼。
build_link() {
  local host="${1:-}" fmt="${2:-opaque}"
  case "$fmt" in
    plain|opaque) ;;
    *) return 1 ;;
  esac
  load_config
  [ -x "$SERVER_BIN" ] || return 1
  [ -n "$PORT" ] || return 1
  if [ ! -s "$PSK_FILE" ]; then
    echo "密钥文件不存在，先生成一个……" >&2
    mkdir -p "$CFG_DIR"
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32 > "$PSK_FILE";
    else od -An -tx1 -N 32 /dev/urandom | tr -d ' \n' > "$PSK_FILE"; fi
    chmod 600 "$PSK_FILE"
    svc_restart || true
  fi
  local psk link
  psk="$(cat "$PSK_FILE")"
  if [ -z "$host" ]; then host="${HOST:-}"; fi
  if [ -z "$host" ]; then host="<你的 VPS 公网 IP>"; fi
  if [ -n "$TLS_DOMAIN" ]; then
    link="$("$SERVER_BIN" --print-link --link-format "$fmt" --psk "$psk" --host "$host" --listen "0.0.0.0:$PORT" --rate "$RATE" --burst "$BURST" --name "$NAME" --tls-domain "$TLS_DOMAIN" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" 2>/dev/null)"
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    # 自签模式：--print-link 会按路径加载证书（没有就现场生成），
    # 链接默认是不透明格式（ver=5 + pin，obfs=tls 和默认 sni 不写进链接）。
    local sni_args=()
    if [ -n "${TLS_SNI:-}" ]; then sni_args=(--tls-sni "$TLS_SNI"); fi
    link="$("$SERVER_BIN" --print-link --link-format "$fmt" --psk "$psk" --host "$host" --listen "0.0.0.0:$PORT" --rate "$RATE" --burst "$BURST" --name "$NAME" --tls-auto --tls-cert "$CFG_DIR/tls-cert.pem" --tls-key "$CFG_DIR/tls-key.pem" "${sni_args[@]}" 2>/dev/null)"
  else
    link="$("$SERVER_BIN" --print-link --link-format "$fmt" --psk "$psk" --host "$host" --listen "0.0.0.0:$PORT" --rate "$RATE" --burst "$BURST" --name "$NAME" 2>/dev/null)"
  fi
  [ -n "$link" ] && printf '%s\n' "$link"
  return 0
}

# 单条链接（隐藏用法 --show-link / 换密钥 / 设域名后沿用这个输出）：
#    从配置文件读密钥现拼（mmx-server --print-link）。安装完不打印链接，
#    就是为了让链接只在这里出现。
#    用法：show_link [plain|opaque]，默认 opaque（不透明链接，一串乱码）；
#    plain 是短格式，只在显式指定时用。
show_link() {
  local fmt="${1:-opaque}"
  case "$fmt" in
    plain|opaque) ;;
    *) echo "链接格式不对：$fmt，应为 plain（短格式）或 opaque（不透明链接）"; return 1 ;;
  esac
  load_config
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -z "$PORT" ]; then echo "还没有节点，请用第 1 项添加节点。"; return 1; fi
  local host link
  if [ -n "$TLS_DOMAIN" ]; then host="$TLS_DOMAIN"; else host="${HOST:-}"; fi
  link="$(build_link "$host" "$fmt")"
  if [ -z "$link" ]; then echo "拼链接失败（密钥或参数有问题），请看第 9 项日志。"; return 1; fi
  echo ""
  echo "节点链接（粘贴到 mm-x 客户端就能用，绝不要分享给第二个人）："
  echo "$link"
  echo ""
}

# 5) 查看节点（主菜单第 5 项）：按节点列表显示，每条节点两行——
#    第一行是地址（域名或 IP），第二行是它的链接。默认只显示本节点
#    （域名 / 服务器地址）；IP 链接默认不显示，只有在第 3 项编辑节点
#    第 14 子项里打开了才同时显示（同一台服务器的 IP 写法链接，
#    不是第二个独立节点）。公网 IP 探不到、或和第一条地址一样时不显示第二条。
show_nodes() {
  load_config
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -z "$PORT" ]; then echo "还没有节点，请用第 1 项添加节点。"; return 1; fi
  local host1 link1
  if [ -n "$TLS_DOMAIN" ]; then host1="$TLS_DOMAIN"
  elif [ -n "${HOST:-}" ]; then host1="$HOST"
  else host1="$(detect_public_ip)"; [ -z "$host1" ] && host1="<你的 VPS 公网 IP>"; fi
  link1="$(build_link "$host1" opaque)"
  if [ -z "$link1" ]; then echo "拼链接失败（密钥或参数有问题），请看第 9 项日志。"; return 1; fi
  echo ""
  echo "查看节点"
  echo "1. $host1"
  echo "$link1"
  if [ "${SHOW_IP_LINK:-0}" = "1" ]; then
    local pubip link2
    pubip="$(detect_public_ip)"
    if [ -n "$pubip" ] && [ "$pubip" != "$host1" ]; then
      link2="$(build_link "$pubip" opaque)"
      if [ -n "$link2" ]; then
        echo "2. $pubip"
        echo "$link2"
      fi
    fi
  fi
  echo ""
}

# 1b) 显示 TLS 证书的 SPKI 指纹（pin）：客户端锁定验证就靠它；换了证书指纹会变，
#     链接也要重新生成（第 5 项）。TLS 没开时无指纹。
show_pin() {
  load_config
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -n "$TLS_DOMAIN" ]; then
    "$SERVER_BIN" --print-pin --tls-domain "$TLS_DOMAIN" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" 2>&1
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    local sni_args=()
    if [ -n "${TLS_SNI:-}" ]; then sni_args=(--tls-sni "$TLS_SNI"); fi
    "$SERVER_BIN" --print-pin --tls-auto --tls-cert "$CFG_DIR/tls-cert.pem" --tls-key "$CFG_DIR/tls-key.pem" "${sni_args[@]}" 2>&1
  else
    echo "TLS 没开（真 TLS 和自签 TLS 都关着），没有指纹。想开去第 3 项（编辑节点）→ 第 10 子项。"
    return 1
  fi
}

# 6) 服务状态
show_status() {
  load_config
  if svc_is_active; then
    echo "服务状态：正在运行"
  else
    echo "服务状态：未运行（用第 7 项重启，或看第 9 项日志找原因）"
  fi
  svc_status
  if command -v ss >/dev/null 2>&1 && [ -n "$PORT" ]; then
    if port_in_use "$PORT"; then echo "端口 $PORT 正在监听"; else echo "端口 $PORT 没在监听"; fi
  fi
}

# 7) 重启服务
restart_svc() {
  if svc_restart && svc_is_active; then
    echo "重启成功，服务正在运行"
  else
    echo "重启失败！请看第 9 项日志：$(svc_log_cmd)"
    return 1
  fi
}

# 更换密钥（已从主菜单移除，函数保留）：写新密钥进 /etc/mmx/psk，服务端按 24 小时宽限期自动识别新密钥，
#    不用重启；旧链接 24 小时内仍能用，之后作废。
rotate_key() {
  load_config
  local new
  if command -v openssl >/dev/null 2>&1; then new="$(openssl rand -hex 32)";
  else new="$(od -An -tx1 -N 32 /dev/urandom | tr -d ' \n')"; fi
  mkdir -p "$CFG_DIR"
  printf '%s' "$new" > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
  echo "密钥已更换（旧密钥 24 小时内仍能用，之后作废）。"
  echo "请用下面的新链接更新客户端："
  show_nodes
}

# 8) 修改限速：显示当前值，rate/burst 一起改；严格 50 Mbps = rate=6250K burst=0
change_rate() {
  load_config
  # 没节点时没东西可改，拒绝（否则会写出端口为空的坏配置）。
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点。"; return 0; fi
  echo "当前限速：rate=$RATE（字节/秒），burst=$BURST"
  echo "严格 50 Mbps：rate=6250K burst=0；不限速：rate=0"
  local nr nb
  read -r -p "新 rate（留空不变，例如 6250K / 0）： " nr || return 0
  read -r -p "新 burst（留空不变，例如 0 / 5M）： " nb || return 0
  if [ -z "$nr" ] && [ -z "$nb" ]; then echo "没改。"; return 0; fi
  if [ -n "$nr" ]; then
    valid_rate "$nr" || { echo "rate 格式不对：$nr（应为数字 + 可选 K/M/G，例如 6250K、0）"; return 1; }
    RATE="$nr"
  fi
  if [ -n "$nb" ]; then
    valid_rate "$nb" || { echo "burst 格式不对：$nb（应为数字 + 可选 K/M/G，例如 0、5M）"; return 1; }
    BURST="$nb"
  fi
  apply_config "限速改为 rate=$RATE burst=$BURST"
}

# 9) 查看日志
show_logs() {
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u mmx-server -n 50 --no-pager 2>&1 || echo "读日志失败"
  else
    echo "没有 journalctl，请直接看：$(svc_status_cmd)"
  fi
}

# 查看流量：调服务端程序现算（mmx-server --traffic-status），
# 计数存在 /etc/mmx/traffic.json，服务重启不丢；服务还没跑过时显示 0。
# 用法：show_traffic（交互菜单里用），隐藏用法 mmx --show-traffic 也走这里。
show_traffic() {
  load_config
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  "$SERVER_BIN" --traffic-status --traffic-mode "${TRAFFIC_MODE:-total}" --traffic-period "${TRAFFIC_PERIOD:-monthly}" --traffic-start-day "${TRAFFIC_START_DAY:-1}" --traffic-limit-mode "${TRAFFIC_LIMIT_MODE:-throttle}" --traffic-quota "${TRAFFIC_QUOTA:-0}" --traffic-throttle-rate "${TRAFFIC_THROTTLE_RATE:-125K}" --traffic-file "$CFG_DIR/traffic.json" 2>&1
}

# 流量设置：统计模式 / 周期 / 起始日 / 限制模式 / 限额 / TC 限速值都能改，
# 改完走 apply_config（重载 + 重启，失败自动回滚）；只改限额/限制模式/
# TC 限速值不重置计数，改统计模式/周期/起始日会按新口径重算。
# 入口在第 3 项“编辑节点”子菜单第 11 项。
traffic_menu() {
  while true; do
    load_config
    echo ""
    echo "--- 流量设置 ---"
    show_traffic
    echo "统计模式：$(traffic_mode_label)　统计周期：$(traffic_period_label)　起始日：${TRAFFIC_START_DAY:-1} 日"
    echo "限制模式：$(traffic_limit_label)　限额：${TRAFFIC_QUOTA:-0}　TC 限速值：${TRAFFIC_THROTTLE_RATE:-125K}"
    echo "1) 查看流量"
    echo "2) 统计模式（出站 / 入站 / 总计 / 最大值）"
    echo "3) 统计周期（月 / 季 / 年）"
    echo "4) 周期起始日（1–31 号）"
    echo "5) 限制模式（阻断 / TC 限速）"
    echo "6) 限额（例如 500G，0 = 不限）"
    echo "7) TC 限速值（例如 1M，默认 125K）"
    echo "8) 清零本周期流量"
    echo "0) 返回"
    local c
    read -r -p "选一项： " c || return 0
    case "$c" in
      1) show_traffic ;;
      2)
        local nm
        echo "出站 = 下载方向，入站 = 上传方向，总计 = 入站+出站，最大值 = 取两者中大的那个"
        read -r -p "新统计模式（outbound/inbound/total/max，留空不变）： " nm || continue
        [ -z "$nm" ] && { echo "没改。"; pause; continue; }
        case "$nm" in
          out|outbound|出站) TRAFFIC_MODE="outbound" ;;
          in|inbound|入站) TRAFFIC_MODE="inbound" ;;
          total|总计) TRAFFIC_MODE="total" ;;
          max|最大值) TRAFFIC_MODE="max" ;;
          *) echo "统计模式不对：$nm（应为 outbound/inbound/total/max）"; pause; continue ;;
        esac
        apply_config "流量统计模式改为 $(traffic_mode_label)（计数按新口径重算）"
        ;;
      3)
        local np
        read -r -p "新统计周期（monthly/quarterly/yearly，留空不变）： " np || continue
        [ -z "$np" ] && { echo "没改。"; pause; continue; }
        case "$np" in
          monthly|month|月) TRAFFIC_PERIOD="monthly" ;;
          quarterly|quarter|季) TRAFFIC_PERIOD="quarterly" ;;
          yearly|year|年) TRAFFIC_PERIOD="yearly" ;;
          *) echo "统计周期不对：$np（应为 monthly/quarterly/yearly）"; pause; continue ;;
        esac
        apply_config "流量统计周期改为 $(traffic_period_label)（计数按新口径重算）"
        ;;
      4)
        local nd
        read -r -p "新周期起始日（1–31 号，留空不变）： " nd || continue
        [ -z "$nd" ] && { echo "没改。"; pause; continue; }
        case "$nd" in ''|*[!0-9]*) echo "起始日不对：$nd（应为 1–31 号）"; pause; continue;; esac
        if [ "$nd" -lt 1 ] || [ "$nd" -gt 31 ]; then echo "起始日不对：$nd（应为 1–31 号）"; pause; continue; fi
        TRAFFIC_START_DAY="$nd"
        apply_config "流量周期起始日改为 $TRAFFIC_START_DAY 日（计数按新口径重算）"
        ;;
      5)
        local nl
        read -r -p "新限制模式（block=阻断 / throttle=TC 限速，留空不变）： " nl || continue
        [ -z "$nl" ] && { echo "没改。"; pause; continue; }
        case "$nl" in
          block|阻断) TRAFFIC_LIMIT_MODE="block" ;;
          throttle|tc|限速|tc限速) TRAFFIC_LIMIT_MODE="throttle" ;;
          *) echo "限制模式不对：$nl（应为 block/throttle）"; pause; continue ;;
        esac
        if [ "$TRAFFIC_LIMIT_MODE" = "throttle" ] && [ "${TRAFFIC_THROTTLE_RATE:-125K}" = "0" ]; then
          echo "TC 限速模式下限速值不能为 0，先用第 7 项把 TC 限速值改成大于 0 的数。"
          TRAFFIC_LIMIT_MODE="block"
          pause; continue
        fi
        apply_config "流量限制模式改为 $(traffic_limit_label)"
        ;;
      6)
        local nq
        read -r -p "新限额（数字 + K/M/G/T，例如 500G，0 = 不限，留空不变）： " nq || continue
        [ -z "$nq" ] && { echo "没改。"; pause; continue; }
        valid_bytes "$nq" || { echo "限额格式不对：$nq（应为数字 + 可选 K/M/G/T，例如 500G、0）"; pause; continue; }
        TRAFFIC_QUOTA="$nq"
        apply_config "流量限额改为 $TRAFFIC_QUOTA"
        ;;
      7)
        local nt
        read -r -p "新 TC 限速值（数字 + K/M/G，例如 1M，默认 125K，留空不变）： " nt || continue
        [ -z "$nt" ] && { echo "没改。"; pause; continue; }
        valid_rate "$nt" || { echo "TC 限速值格式不对：$nt（应为数字 + 可选 K/M/G，例如 1M、125K）"; pause; continue; }
        if [ "$nt" = "0" ] && [ "${TRAFFIC_LIMIT_MODE:-block}" = "throttle" ]; then
          echo "TC 限速模式下限速值不能为 0（0 = 不限速，等于没限制）"
          pause; continue
        fi
        TRAFFIC_THROTTLE_RATE="$nt"
        apply_config "TC 限速值改为 $TRAFFIC_THROTTLE_RATE"
        ;;
      8)
        local yn
        echo "要清零本周期已统计的流量（计数从 0 重新开始），限额和设置不变。"
        read -r -p "确认清零吗？输入 y 确认： " yn || continue
        case "$yn" in y|Y) ;; *) echo "已取消。"; pause; continue;; esac
        svc_stop || true
        rm -f "$CFG_DIR/traffic.json"
        if svc_restart && svc_is_active; then
          echo "已清零：本周期流量从 0 重新开始统计"
        else
          echo "清零后服务没起来！请看日志：$(svc_log_cmd)"
        fi
        ;;
      0|"") return 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

# 2) 载入预设：GCP / 阿里云CDT 的流量设置（和 vx 的载入预设同一份值）。
#    GCP：180G / 总计 / 月 / 1日 / TC 限速 / 不限速 / 白名单仅谷歌系；
#    阿里云CDT：180G / 最大值 / 月 / 1日 / TC 限速 / 不限速 / 无白名单。
#    180G = 阿桑说的 200G 减 20G 余量；125K ≈ 1 Mbps（超限后 TC 限速值）。
#    只改流量相关字段（TRAFFIC_* 和 RATE）和域名白名单，不动端口/密钥/SNI；
#    选完预设后可顺手选域名还是 IP：选域名就先跑 setup_domain 申请证书
#    切真 TLS（失败也不影响载入预设，域名可稍后再设），选 IP 就只载入预设。
#    （vx 的地区/SNI 是 VLESS 专属，mm-x 没有，不带过来；白名单是服务端
#    按域名过滤，和 vx 的 geosite:google 路由效果一样。）
apply_preset() {
  local name="$1"
  load_config
  # 没节点时没端口可写，拒绝（否则会写出端口为空的坏配置）。
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点，再载入预设。"; return 1; fi
  case "$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" in
    gcp|1|谷歌|谷歌云)
      TRAFFIC_MODE="total"; TRAFFIC_PERIOD="monthly"; TRAFFIC_START_DAY="1"
      TRAFFIC_LIMIT_MODE="throttle"; TRAFFIC_QUOTA="180G"; TRAFFIC_THROTTLE_RATE="125K"; RATE="0"
      DOMAIN_WHITELIST="google"
      ;;
    cdt|2|阿里云|阿里云cdt)
      TRAFFIC_MODE="max"; TRAFFIC_PERIOD="monthly"; TRAFFIC_START_DAY="1"
      TRAFFIC_LIMIT_MODE="throttle"; TRAFFIC_QUOTA="180G"; TRAFFIC_THROTTLE_RATE="125K"; RATE="0"
      DOMAIN_WHITELIST=""
      ;;
    *)
      echo "没有这个预设：$name"
      return 1
      ;;
  esac
  local wl_desc="无白名单"; [ -n "$DOMAIN_WHITELIST" ] && wl_desc="白名单仅谷歌系域名"
  apply_config "载入预设 $name（限额 $TRAFFIC_QUOTA，统计模式 $TRAFFIC_MODE，超限 TC 限速，$wl_desc）"
}

preset_menu() {
  load_config
  # 没节点时先拒绝，别让用户走完一整套选择才发现预设没处可载。
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点，再载入预设。"; return 0; fi
  while true; do
    load_config
    echo ""
    echo "--- 载入预设 ---"
    echo "当前：限额 ${TRAFFIC_QUOTA:-0}　统计模式：$(traffic_mode_label)　周期：$(traffic_period_label)　限制模式：$(traffic_limit_label)　域名白名单：$([ -n "${DOMAIN_WHITELIST:-}" ] && echo "仅谷歌系域名" || echo "关闭")"
    echo "1) GCP：180G / 总计 / 月 / 1日 / TC 限速 / 不限速 / 白名单仅谷歌系"
    echo "2) 阿里云CDT：180G / 最大值 / 月 / 1日 / TC 限速 / 不限速 / 无白名单"
    echo "选完预设后会问域名还是 IP：选域名就同时申请证书切真 TLS，选 IP 就只载入预设。"
    echo "0) 返回"
    local c
    read -r -p "选一项： " c || return 0
    case "$c" in
      1|2)
        local pname="GCP"; [ "$c" = "2" ] && pname="阿里云CDT"
        # 用域名还是 IP：明确选（替代原来"设置域名、留空跳过"）。
        ask_domain_or_ip || continue
        local dom="$ASK_DOM"
        local tls_note="不动端口/密钥/TLS"
        [ -n "$dom" ] && tls_note="不动端口/密钥；同时设置域名 $dom（申请 Let's Encrypt 证书并切真 TLS）"
        if [ "$c" = "1" ]; then
          echo "要载入 $pname：限额 180G，超限后 TC 限速，并打开域名白名单（只放行谷歌系域名）；只改流量设置和白名单，$tls_note。"
        else
          echo "要载入 $pname：限额 180G，超限后 TC 限速，域名白名单关闭；只改流量设置和白名单，$tls_note。"
        fi
        local yn
        read -r -p "确认载入吗？输入 y 确认： " yn || continue
        case "$yn" in y|Y) ;; *) echo "已取消。"; pause; continue;; esac
        if [ -n "$dom" ]; then
          if ! setup_domain "$dom"; then
            echo "域名设置失败（$dom），预设照常载入；域名可稍后在载入预设里再设。"
            load_config
          fi
        fi
        if [ "$c" = "1" ]; then apply_preset gcp; else apply_preset cdt; fi
        ;;
      0|"") return 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

# 诱饵回退 / TLS 设置（主菜单已移除；入口在第 3 项“编辑节点”第 10 子项）：真 TLS（有域名）和自签 TLS（没域名）二选一；
#    自签证书首次启动自动生成并存到 /etc/mmx/tls-cert.pem、tls-key.pem，
#    客户端靠链接里的 pin（SPKI 指纹）锁定验证；换证书要重新生成链接（第 5 项）。
# 本机公网 IPv4：配置里的 HOST 是 IP 就用它，否则现探测（和部署脚本一样的办法）；
# 探不到或只探到内网地址就返回空。
detect_public_ip() {
  local ip=""
  case "${HOST:-}" in
    ''|*[!0-9.]*) ;;
    *) ip="$HOST" ;;
  esac
  case "$ip" in 127.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) ip="";; esac
  if [ -z "$ip" ] && command -v curl >/dev/null 2>&1; then
    ip="$(curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true)"
    [ -z "$ip" ] && ip="$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"
  fi
  case "$ip" in 127.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) ip="";; esac
  printf '%s' "$ip"
}

# 域名解析到的 IPv4 列表（每行一个）：先 getent，没有就 dig，没有就 nslookup。
resolve_domain_ips() {
  local dom="$1" out=""
  if command -v getent >/dev/null 2>&1; then
    out="$(getent hosts "$dom" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')"
  fi
  if [ -z "$out" ] && command -v dig >/dev/null 2>&1; then
    out="$(dig +short "$dom" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')"
  fi
  if [ -z "$out" ] && command -v nslookup >/dev/null 2>&1; then
    out="$(nslookup "$dom" 2>/dev/null | awk '/^Address: /{print $2}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')"
  fi
  printf '%s' "$out"
}

# 域名一键设置：申请 Let's Encrypt 证书并切到真 TLS（交互入口在第 3 项编辑节点 → 第 10 子项 → 第 6 子项；
# 隐藏用法 mmx --setup-domain <域名>，部署脚本的 --domain 也走这里）。
# 步骤：校验域名 → DNS 解析到本机公网 IP → 80 端口空闲 → 装 certbot
# → certbot certonly --standalone --reuse-key（续期密钥不变，pin 不变）
# → 校验续期配置 reuse_key → 写续期 deploy-hook（重启服务）
# → 切真 TLS（apply_config，失败自动回滚）→ 校验新链接能生成。
# 任何一步失败都返回 1，配置不动，服务仍用原来的 TLS（自签或关）继续跑。
# 用法：setup_domain <域名>
setup_domain() {
  local dom="${1:-}"
  load_config
  # 没节点时没端口可写，拒绝（否则会写出端口为空的坏配置）。
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点。"; return 1; fi
  valid_domain "$dom" || { echo "域名不对：$dom（应为域名，例如 example.com；不要带 http:// 或端口）"; return 1; }
  if [ -n "${TLS_DOMAIN:-}" ]; then
    if [ "$TLS_DOMAIN" = "$dom" ]; then
      echo "真 TLS 已经是这个域名（$dom），不用重复设置。"
      return 0
    fi
    echo "真 TLS 已经开了（域名 $TLS_DOMAIN），先用第 3 项编辑节点 → 第 10 子项 → 第 3 子项关闭再设置新域名。"
    return 1
  fi
  # DNS 必须先指到本机公网 IP，否则 Let's Encrypt 校验通不过
  local my_ip resolved
  my_ip="$(detect_public_ip)"
  if [ -z "$my_ip" ]; then echo "探测不到本机公网 IP，无法校验 DNS；请确认域名已解析到这台 VPS 再试。"; return 1; fi
  resolved="$(resolve_domain_ips "$dom")"
  if [ -z "$resolved" ]; then
    echo "域名 $dom 还没解析（查不到 A 记录），请先在域名商那里把 A 记录指到本机 IP $my_ip，等解析生效再试。"
    return 1
  fi
  local hit=0 ip
  for ip in $resolved; do [ "$ip" = "$my_ip" ] && hit=1; done
  if [ "$hit" -ne 1 ]; then
    echo "域名 $dom 解析到的 IP（$resolved）不是本机公网 IP（$my_ip），Let's Encrypt 校验通不过。"
    echo "请把 A 记录改成 $my_ip，等解析生效再试。"
    return 1
  fi
  # certbot standalone 要占 80 端口做校验
  if port_in_use 80; then
    echo "80 端口已被别的服务占用，certbot standalone 校验需要 80 端口。"
    echo "请先停掉占用 80 端口的服务（例如 $(svc_stop_cmd nginx)），再试。"
    return 1
  fi
  # 装 certbot（没有就装；测试模式下如果包管理器也没替身，才直接返回，不调真包管理器）
  if ! command -v certbot >/dev/null 2>&1; then
    if [ -n "${MMX_TEST_ROOT:-}" ] && ! command -v apt-get >/dev/null 2>&1 && ! command -v apk >/dev/null 2>&1; then
      echo "测试模式：没有 certbot（也没有替身），装不了证书。"
      return 1
    fi
    echo "正在安装 certbot……"
    if command -v apt-get >/dev/null 2>&1; then
      if ! (apt-get update -qq && apt-get install -y -qq certbot) >/dev/null 2>&1; then
        echo "certbot 安装失败，请手动安装：apt install certbot -y"
        return 1
      fi
    elif command -v apk >/dev/null 2>&1; then
      if ! apk add --no-cache certbot >/dev/null 2>&1; then
        echo "certbot 安装失败，请手动安装：apk add certbot"
        return 1
      fi
    else
      echo "certbot 没装，也没找到 apt-get 或 apk，请手动安装：apt install certbot -y（Debian/Ubuntu）或 apk add certbot（Alpine）"
      return 1
    fi
  fi
  # 申请证书：--reuse-key 是关键——续期时密钥不变，pin 不变，链接才不会每 90 天断一次
  echo "正在申请 Let's Encrypt 证书（$dom）……"
  local le_dir="$ROOT/etc/letsencrypt"
  if ! certbot certonly --standalone --reuse-key --non-interactive --agree-tos --register-unsafely-without-email -d "$dom" >/dev/null 2>&1; then
    echo "证书申请失败（域名 $dom）：请确认 DNS 已生效、80 端口对外可达、且该域名没被 Let's Encrypt 限速。"
    return 1
  fi
  local cert_file="$le_dir/live/$dom/fullchain.pem"
  local key_file="$le_dir/live/$dom/privkey.pem"
  if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
    echo "证书申请好像成功了，但找不到证书文件（$cert_file），请检查 certbot 日志。"
    return 1
  fi
  # 续期配置必须带 reuse_key，否则续期换密钥、pin 变、链接断
  local renewal_conf="$le_dir/renewal/$dom.conf"
  if [ -f "$renewal_conf" ]; then
    if ! grep -q "^reuse_key[[:space:]]*=[[:space:]]*True" "$renewal_conf"; then
      if grep -q "^\[renewalparams\]" "$renewal_conf"; then
        sed -i '/^\[renewalparams\]/a reuse_key = True' "$renewal_conf"
      else
        printf '[renewalparams]\nreuse_key = True\n' >> "$renewal_conf"
      fi
      grep -q "^reuse_key[[:space:]]*=[[:space:]]*True" "$renewal_conf" || { echo "续期配置里写不进 reuse_key，证书以后续期会换密钥；请手动检查 $renewal_conf。"; return 1; }
    fi
  else
    echo "找不到续期配置（$renewal_conf），请检查 certbot 安装。"
    return 1
  fi
  # 续期后重启服务，让它加载新证书（密钥复用，pin 不变，链接不用重印）
  local hook_dir="$le_dir/renewal-hooks/deploy"
  mkdir -p "$hook_dir"
  local hook_cmd
  if [ "$INIT_SYS" = "openrc" ]; then hook_cmd="rc-service mmx-server restart"; else hook_cmd="systemctl restart mmx-server"; fi
  cat > "$hook_dir/restart-mmx-server.sh" <<HOOK_EOF
#!/bin/bash
# certbot 续期后重启 mmx-server，让它加载新证书（密钥复用，pin 不变）。
$hook_cmd
HOOK_EOF
  chmod +x "$hook_dir/restart-mmx-server.sh"
  # 切真 TLS（apply_config：备份 → 写配置 → 写服务 → 重启，失败自动回滚）
  TLS_DOMAIN="$dom"; TLS_CERT="$cert_file"; TLS_KEY="$key_file"; TLS_AUTO="0"; TLS_SNI=""
  if ! apply_config "开启真 TLS（域名 $dom，Let's Encrypt）"; then
    return 1
  fi
  # 校验：新链接能生成且地址是域名（plain 格式里域名明文可见；opaque 格式是乱码，看不到域名）
  local link_check
  link_check="$(show_link plain 2>&1)" || true
  case "$link_check" in
    *"$dom"*) ;;
    *) echo "警告：服务已切到真 TLS，但新链接生成异常（见上面），请用菜单第 5 项查看节点。" ;;
  esac
  echo "域名设置完成：真 TLS（$dom），证书由 Let's Encrypt 签发，续期自动重启服务、密钥不变、链接不失效。"
  echo "旧链接已失效（换了证书，pin 变了），请用下面的新链接更新客户端："
  show_link
  return 0
}

tls_menu() {
  while true; do
    load_config
    echo ""
    echo "--- 诱饵回退 / TLS ---"
    echo "回退模式：$FALLBACK（site=非 mm-x 连接看到一个像网站的页面/400 页；silent=0 字节回包、直接断开）"
    if [ -n "$TLS_DOMAIN" ]; then
      echo "真 TLS：开，域名 $TLS_DOMAIN（流量看起来就是正常 HTTPS 访问这个网站）"
    elif [ "${TLS_AUTO:-0}" = "1" ]; then
      echo "自签 TLS：开，SNI ${TLS_SNI:-www.microsoft.com}（没域名时用；客户端靠链接里的 pin 锁定验证）"
    else
      echo "TLS：关（用的是浅层 TLS 外壳，看起来像加密流量）"
    fi
    echo "1) 切换回退模式（site ↔ silent）"
    echo "2) 开启真 TLS（需要域名 + 证书）"
    echo "3) 关闭 TLS（真 TLS 和自签 TLS 都关）"
    echo "4) 开启自签 TLS（没域名时用，证书自动生成，客户端用指纹锁定）"
    echo "5) 查看 TLS 指纹（pin）"
    echo "6) 一键设置域名（申请 Let's Encrypt 证书并切真 TLS，DNS 须先指到本机、80 端口空闲）"
    echo "0) 返回"
    local c
    read -r -p "选一项： " c || return 0
    case "$c" in
      1)
        if [ "$FALLBACK" = "site" ]; then FALLBACK="silent"; else FALLBACK="site"; fi
        apply_config "回退模式改为 $FALLBACK"
        ;;
      2)
        if [ -n "$TLS_DOMAIN" ]; then echo "真 TLS 已经开了（域名 $TLS_DOMAIN），先用第 3 项关闭再重开。"; pause; continue; fi
        if [ "${TLS_AUTO:-0}" = "1" ]; then echo "自签 TLS 已经开了，先用第 3 项关闭再开真 TLS。"; pause; continue; fi
        local dom cert key
        read -r -p "域名（DNS 必须先指到这台 VPS）： " dom || continue
        case "$dom" in ""|*" "*|*"/"*) echo "域名不对：$dom"; pause; continue;; esac
        read -r -p "证书文件路径（fullchain.pem）： " cert || continue
        read -r -p "私钥文件路径（privkey.pem）： " key || continue
        if [ ! -f "$cert" ]; then
          echo "证书文件不存在：$cert"
          echo "没有证书时先申请 Let's Encrypt（域名 DNS 必须先指到这台 VPS）："
          echo "  $(certbot_install_cmd) && certbot certonly --standalone -d $dom"
          echo "证书一般在 /etc/letsencrypt/live/$dom/fullchain.pem 和 privkey.pem，拿到后再回来填这两个路径。"
          pause; continue
        fi
        if [ ! -f "$key" ]; then echo "私钥文件不存在：$key"; pause; continue; fi
        TLS_DOMAIN="$dom"; TLS_CERT="$cert"; TLS_KEY="$key"
        if [ "$PORT" != "443" ]; then
          echo "提示：真 TLS 开了，但端口不是 443（当前 $PORT）；443 更像正常 HTTPS，想改去第 3 项改端口。"
        fi
        apply_config "开启真 TLS（域名 $TLS_DOMAIN）"
        ;;
      3)
        if [ -z "$TLS_DOMAIN" ] && [ "${TLS_AUTO:-0}" != "1" ]; then echo "TLS 本来就没开。"; pause; continue; fi
        local desc="关闭自签 TLS"
        if [ -n "$TLS_DOMAIN" ]; then desc="关闭真 TLS"; fi
        TLS_DOMAIN=""; TLS_CERT=""; TLS_KEY=""; TLS_AUTO="0"; TLS_SNI=""
        apply_config "$desc"
        ;;
      4)
        if [ "${TLS_AUTO:-0}" = "1" ]; then echo "自签 TLS 已经开了（SNI ${TLS_SNI:-www.microsoft.com}），先用第 3 项关闭再重开。"; pause; continue; fi
        if [ -n "$TLS_DOMAIN" ]; then echo "真 TLS 已经开了（域名 $TLS_DOMAIN），先用第 3 项关闭再开自签 TLS。"; pause; continue; fi
        local sni
        read -r -p "默认 SNI（一个常见域名，留空用 www.microsoft.com）： " sni || continue
        case "$sni" in ""|"www.microsoft.com") TLS_SNI="";; *) TLS_SNI="$sni";; esac
        TLS_AUTO="1"
        apply_config "开启自签 TLS（SNI ${TLS_SNI:-www.microsoft.com}）"
        echo "证书首次启动自动生成，存在 /etc/mmx/tls-cert.pem 和 tls-key.pem；"
        echo "链接里的 pin 就是证书指纹（第 5 项的链接已带上，换了证书要重新生成链接）。"
        ;;
      5)
        show_pin
        ;;
      6)
        local dom
        read -r -p "域名（DNS 必须先指到这台 VPS，80 端口要空着）： " dom || continue
        setup_domain "$dom"
        ;;
      0|"") return 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

# 1) 添加节点：向导式新建节点，依次问端口 / 节点名 / 流量限额 /
#    周期起始日 / 超限模式 / TC 限速值 / 域名，空输入用默认值；每项都校验，
#    不合法就重问；已有节点时先确认覆盖；写完走 apply_config
#    （重载 + 重启，失败自动回滚），再跑 setup_domain（填了域名才跑，
#    失败也不影响已建好的节点，域名可稍后在载入预设里再设）。
#    服务器地址空着时自动探测公网 IP；密钥文件没有就生成一个（和安装流程一样）。
# 问用域名还是 IP：明确选，不再是"域名可选、留空跳过"。
# 选域名：接着问域名（不能为空），走 setup_domain 申请证书切真 TLS；
# 选 IP：不问域名、不跑 setup_domain，用探测到的公网 IP、TLS 关。
# 成功返回 0，域名写进 $ASK_DOM（选 IP 时为空）；EOF/取消返回 1。
# 用法：ask_domain_or_ip || return 0（向导里）/ || continue（菜单循环里）
ASK_DOM=""
ask_domain_or_ip() {
  ASK_DOM=""
  local choice
  while true; do
    echo "用域名还是 IP 安装节点？"
    echo "  1) 域名：用域名安装，自动申请 Let's Encrypt 证书并切真 TLS（DNS 须先指到本机、80 端口空闲）"
    echo "  2) IP：用公网 IP 安装，不设域名、不申请证书（TLS 关）"
    read -r -p "选一项 [1/2]： " choice || return 1
    case "$choice" in
      1)
        while true; do
          read -r -p "域名： " ASK_DOM || return 1
          [ -n "$ASK_DOM" ] && break
          echo "域名不能为空，请输入域名（或按 Ctrl-C 取消）。"
        done
        return 0 ;;
      2) ASK_DOM=""; return 0 ;;
      *) echo "没有这个选项，请输入 1 或 2。" ;;
    esac
  done
}

add_node() {
  load_config
  if [ -f "$CFG_FILE" ]; then
    echo "已有节点（端口 ${PORT:-?}，节点名 ${NAME:-?}），重新添加会覆盖当前节点配置。"
    local yn
    read -r -p "继续吗？[y/N] " yn || return 0
    case "$yn" in y|Y) ;; *) echo "已取消。"; return 0;; esac
  fi
  local np nm nq nd nl nt
  while true; do
    read -r -p "端口（默认 443）： " np || return 0
    [ -z "$np" ] && np="443"
    valid_port "$np" && break
    echo "端口不合法：$np，应为 1-65535 之间的数字"
  done
  if [ "$np" != "${PORT:-}" ] && port_in_use "$np"; then
    echo "端口 $np 已被别的服务占用！"
    if [ "$np" = "443" ]; then echo "443 常见占用：nginx / Apache / 其他 Web 服务，先停掉它（$(svc_stop_cmd nginx)）再添加。"; fi
    local yn2
    read -r -p "仍要用 $np 吗？（服务可能起不来，失败会自动回滚）[y/N] " yn2 || return 0
    case "$yn2" in y|Y) ;; *) echo "已取消。"; return 0;; esac
  fi
  read -r -p "节点名（默认 mm-x）： " nm || return 0
  [ -z "$nm" ] && nm="mm-x"
  while true; do
    read -r -p "流量限额（默认 0 = 不限，例如 180G、500G、1T）： " nq || return 0
    [ -z "$nq" ] && nq="0"
    valid_bytes "$nq" && break
    echo "流量限额格式不对：$nq（应为数字 + 可选 K/M/G/T，例如 500G、1T、0）"
  done
  while true; do
    read -r -p "周期起始日（默认 1，1–31 号）： " nd || return 0
    [ -z "$nd" ] && nd="1"
    case "$nd" in ''|*[!0-9]*) echo "周期起始日不合法：$nd，应为 1–31 号"; continue;; esac
    [ "$nd" -ge 1 ] && [ "$nd" -le 31 ] && break
    echo "周期起始日不合法：$nd，应为 1–31 号"
  done
  while true; do
    read -r -p "超限模式（throttle 限速 / block 阻断，默认 throttle）： " nl || return 0
    [ -z "$nl" ] && nl="throttle"
    case "$(printf '%s' "$nl" | tr '[:upper:]' '[:lower:]')" in
      throttle|tc|限速|tc限速) TRAFFIC_LIMIT_MODE="throttle"; break ;;
      block|阻断) TRAFFIC_LIMIT_MODE="block"; break ;;
      *) echo "超限模式不对：$nl，应为 throttle（限速）或 block（阻断）" ;;
    esac
  done
  while true; do
    read -r -p "TC 限速值（默认 125K，约 1 Mbps）： " nt || return 0
    [ -z "$nt" ] && nt="125K"
    valid_rate "$nt" || { echo "TC 限速值格式不对：$nt（应为数字 + 可选 K/M/G，例如 125K、1M）"; continue; }
    if [ "$TRAFFIC_LIMIT_MODE" = "throttle" ] && [ "$nt" = "0" ]; then
      echo "TC 限速模式下限速值不能为 0（0 = 不限速，等于没限制），请重填。"
      continue
    fi
    break
  done
  if [ -z "${HOST:-}" ]; then HOST="$(detect_public_ip)"; fi
  if [ ! -s "$PSK_FILE" ]; then
    mkdir -p "$CFG_DIR"
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32 > "$PSK_FILE";
    else od -An -tx1 -N 32 /dev/urandom | tr -d ' \n' > "$PSK_FILE"; fi
    chmod 600 "$PSK_FILE"
  fi
  PORT="$np"; NAME="$nm"; TRAFFIC_QUOTA="$nq"; TRAFFIC_START_DAY="$nd"; TRAFFIC_THROTTLE_RATE="$nt"
  # 用域名还是 IP：明确选（替代原来末尾"域名可选、留空跳过"）。
  ask_domain_or_ip || return 0
  local dom="$ASK_DOM"
  if [ -z "$dom" ]; then
    # 选 IP：不用域名，TLS 关——不沿用旧节点的真 TLS/自签设置（IP 节点就是 TLS 关）。
    TLS_DOMAIN=""; TLS_CERT=""; TLS_KEY=""; TLS_AUTO="0"; TLS_SNI=""
  fi
  local summary="添加节点：端口 $PORT，节点名 $NAME，限额 $TRAFFIC_QUOTA，起始日 $TRAFFIC_START_DAY 日，超限 $(traffic_limit_label)"
  [ -n "$dom" ] && summary="$summary，域名 $dom"
  if apply_config "$summary"; then
    if [ -n "$dom" ]; then
      if ! setup_domain "$dom"; then
        echo "域名设置失败（$dom），节点已建好；域名可稍后在载入预设里再设，或用 mmx --setup-domain $dom。"
        load_config
      fi
    fi
    # 节点建好了：开 BBR + 按它的端口放行防火墙（全新安装时这两步跳过，建节点时补上）。
    enable_bbr
    open_firewall_port
  fi
}

# 3) 编辑节点：按项改；改完校验，写回配置，
#    重载 + 重启，重启失败自动回滚。第 11 项是流量设置（统计模式/周期/
#    起始日/限制模式/限额/TC 限速值 + 查看流量），第 12 项是掩护流量档位，
#    第 13 项是域名白名单（off 关 / google 只放行谷歌系域名），
#    第 14 项是 IP 链接开关（在第 5 项查看节点里同时显示 IP 地址的链接）。
edit_params() {
  load_config
  # 没节点时没东西可改，拒绝（否则会写出端口为空的坏配置）。
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点。"; return 0; fi
  while true; do
    load_config
    echo ""
    echo "--- 编辑节点 ---"
    echo "1) 端口（当前 $PORT）"
    echo "2) 限速 rate（当前 $RATE）"
    echo "3) 突发 burst（当前 $BURST）"
    echo "4) 节点名（当前 $NAME）"
    echo "5) 服务器地址（当前 ${HOST:-未设置}，链接里用的地址）"
    echo "6) 拉黑白名单 IP（当前 ${WHITELIST_IPS:-未设置}，空格分隔）"
    echo "7) 连接白名单 IP（当前 ${ALLOW_IPS:-未设置}，空格分隔）"
    echo "8) 拉黑白名单文件（当前 ${WHITELIST_FILE:-未设置}）"
    echo "9) 连接白名单文件（当前 ${ALLOWLIST_FILE:-未设置}）"
    echo "10) 诱饵回退 / TLS 设置"
    echo "11) 流量设置（统计模式 / 周期 / 限额 / 查看流量）"
    echo "12) 掩护流量（当前 ${COVER_TRAFFIC:-low}：off 关 / low 空闲约 45 秒一帧 / high 空闲约 20 秒一帧）"
    echo "13) 域名白名单（当前 $([ -n "${DOMAIN_WHITELIST:-}" ] && echo "仅谷歌系域名" || echo "关闭")：只放行谷歌系域名时，非谷歌目标直接拒绝）"
    echo "14) IP 链接（当前 $([ "${SHOW_IP_LINK:-0}" = "1" ] && echo "显示" || echo "不显示")：在第 5 项查看节点里同时显示 IP 地址的链接）"
    echo "0) 返回"
    local c
    read -r -p "改哪一项： " c || return 0
    case "$c" in
      1)
        local np
        read -r -p "新端口（1-65535，留空不变）： " np || continue
        [ -z "$np" ] && { echo "没改。"; pause; continue; }
        valid_port "$np" || { echo "端口不合法：$np，应为 1-65535 之间的数字"; pause; continue; }
        if [ "$np" != "$PORT" ] && port_in_use "$np"; then
          echo "端口 $np 已被别的服务占用！"
          if [ "$np" = "443" ]; then echo "443 常见占用：nginx / Apache / 其他 Web 服务，先停掉它（$(svc_stop_cmd nginx)）再改。"; fi
          local yn
          read -r -p "仍要改成 $np 吗？（服务可能起不来，失败会自动回滚）[y/N] " yn || continue
          case "$yn" in y|Y) ;; *) echo "没改。"; pause; continue;; esac
        fi
        PORT="$np"
        apply_config "端口改为 $PORT"
        ;;
      2)
        local nr
        read -r -p "新 rate（留空不变，例如 6250K / 0）： " nr || continue
        [ -z "$nr" ] && { echo "没改。"; pause; continue; }
        valid_rate "$nr" || { echo "rate 格式不对：$nr（应为数字 + 可选 K/M/G，例如 6250K、0）"; pause; continue; }
        RATE="$nr"
        apply_config "限速 rate 改为 $RATE"
        ;;
      3)
        local nb
        read -r -p "新 burst（留空不变，例如 0 / 5M）： " nb || continue
        [ -z "$nb" ] && { echo "没改。"; pause; continue; }
        valid_rate "$nb" || { echo "burst 格式不对：$nb（应为数字 + 可选 K/M/G，例如 0、5M）"; pause; continue; }
        BURST="$nb"
        apply_config "突发 burst 改为 $BURST"
        ;;
      4)
        local nm
        read -r -p "新节点名（留空不变）： " nm || continue
        [ -z "$nm" ] && { echo "没改。"; pause; continue; }
        NAME="$nm"
        apply_config "节点名改为 $NAME"
        ;;
      5)
        local hh
        read -r -p "新服务器地址（IP 或域名，留空不变）： " hh || continue
        [ -z "$hh" ] && { echo "没改。"; pause; continue; }
        case "$hh" in *" "*|*"/"*) echo "地址不对：$hh"; pause; continue;; esac
        HOST="$hh"
        apply_config "服务器地址改为 $HOST"
        ;;
      6)
        local wl
        read -r -p "拉黑白名单 IP（空格分隔多个，留空=清空，输入 - 保持不变）： " wl || continue
        [ "$wl" = "-" ] && { echo "没改。"; pause; continue; }
        if [ -n "$wl" ]; then
          local ok_list=1 ip
          for ip in $wl; do valid_ip_cidr "$ip" || { echo "IP 不对：$ip（应为 IP 或 IP/网段，例如 1.2.3.4、5.6.7.0/24）"; ok_list=0; }; done
          [ "$ok_list" -eq 1 ] || { pause; continue; }
        fi
        WHITELIST_IPS="$wl"
        apply_config "拉黑白名单改为 ${WHITELIST_IPS:-未设置}"
        ;;
      7)
        local al
        read -r -p "连接白名单 IP/CIDR（空格分隔多个，留空=清空，输入 - 保持不变）： " al || continue
        [ "$al" = "-" ] && { echo "没改。"; pause; continue; }
        if [ -n "$al" ]; then
          local ok_list=1 e
          for e in $al; do valid_ip_cidr "$e" || { echo "IP 不对：$e（应为 IP 或 IP/网段，例如 1.2.3.4、5.6.7.0/24）"; ok_list=0; }; done
          [ "$ok_list" -eq 1 ] || { pause; continue; }
        fi
        ALLOW_IPS="$al"
        apply_config "连接白名单改为 ${ALLOW_IPS:-未设置}"
        ;;
      8)
        local wf
        read -r -p "拉黑白名单文件路径（留空=清空，输入 - 保持不变）： " wf || continue
        [ "$wf" = "-" ] && { echo "没改。"; pause; continue; }
        if [ -n "$wf" ] && [ ! -f "$wf" ]; then echo "文件不存在：$wf"; pause; continue; fi
        WHITELIST_FILE="$wf"
        apply_config "拉黑白名单文件改为 ${WHITELIST_FILE:-未设置}"
        ;;
      9)
        local af
        read -r -p "连接白名单文件路径（留空=清空，输入 - 保持不变）： " af || continue
        [ "$af" = "-" ] && { echo "没改。"; pause; continue; }
        if [ -n "$af" ] && [ ! -f "$af" ]; then echo "文件不存在：$af"; pause; continue; fi
        ALLOWLIST_FILE="$af"
        apply_config "连接白名单文件改为 ${ALLOWLIST_FILE:-未设置}"
        ;;
      10) tls_menu ;;
      11) traffic_menu ;;
      12)
        local cv
        read -r -p "掩护流量档位（off 关 / low 低 / high 高，留空不变）： " cv || continue
        [ -z "$cv" ] && { echo "没改。"; pause; continue; }
        case "$cv" in
          off|low|high|关|低|高) COVER_TRAFFIC="$cv" ;;
          *) echo "档位不对：$cv，应为 off / low / high"; pause; continue;;
        esac
        apply_config "掩护流量改为 $COVER_TRAFFIC"
        ;;
      13)
        local dw
        read -r -p "域名白名单（off 关 / google 只放行谷歌系域名，留空不变）： " dw || continue
        [ -z "$dw" ] && { echo "没改。"; pause; continue; }
        case "$(printf '%s' "$dw" | tr '[:upper:]' '[:lower:]')" in
          ""|off|none|关) DOMAIN_WHITELIST="" ;;
          google|谷歌|谷歌系) DOMAIN_WHITELIST="google" ;;
          *) echo "白名单不对：$dw，应为 off（关）或 google（只放行谷歌系域名）"; pause; continue;;
        esac
        if [ -n "$DOMAIN_WHITELIST" ]; then
          echo "注意：白名单一开，非谷歌域名（GitHub、AI、视频站等）和 IP 字面量目标都会被拒绝，只剩谷歌系能走这台服务器。"
        fi
        apply_config "域名白名单改为 $([ -n "$DOMAIN_WHITELIST" ] && echo "仅谷歌系域名" || echo "关闭")"
        ;;
      14)
        if [ "${SHOW_IP_LINK:-0}" = "1" ]; then SHOW_IP_LINK="0"; else SHOW_IP_LINK="1"; fi
        apply_config "IP 链接改为 $([ "$SHOW_IP_LINK" = "1" ] && echo "显示" || echo "不显示")（第 5 项查看节点里同时显示 IP 地址的链接）"
        ;;
      0|"") return 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

# 4) 删除节点：停服务，删节点配置（含密钥、流量统计）；程序和菜单保留，
#    之后可用“添加节点”重新建节点。和卸载不同：卸载连程序和菜单一起删。
delete_node() {
  load_config
  if [ ! -f "$CFG_FILE" ]; then
    echo "没有节点配置，不用删除。"
    return 0
  fi
  echo "删除节点将停止服务并删除节点配置（含密钥、流量统计），程序和菜单保留，之后可用“添加节点”重新建节点。"
  local yn
  read -r -p "确认删除吗？输入 y 确认： " yn || return 0
  case "$yn" in y|Y) ;; *) echo "已取消。"; return 0;; esac
  svc_stop || true
  rm -f "$CFG_FILE" "$PSK_FILE" "$CFG_DIR/traffic.json"
  echo "节点已删除。"
}

# 10) 卸载：停服务、删服务文件、删程序、删菜单命令（mmx + mm）、删配置（含密钥）、
#    删本域名的 Let's Encrypt 证书 + 续期 hook、删 BBR 配置并还原内核设置、删备份文件；不留残留。
#    （端口 80 没有 ufw 规则可删：安装时只放行 $PORT/tcp，certbot standalone 校验
#    只检查 80 空闲、不开防火墙规则。）
uninstall() {
  load_config
  local le_dir="$ROOT/etc/letsencrypt"
  local bbr_conf="$ROOT/etc/sysctl.d/99-mmx-bbr.conf"
  local bbr_removed=0
  echo "要卸载 mm-x 服务端，将删除："
  echo "  服务 mmx-server（停用并删除服务文件）"
  echo "  程序 $SERVER_BIN、菜单命令 $BIN_DIR/mmx 和 $BIN_DIR/mm"
  echo "  配置 $CFG_DIR（含密钥、流量统计）"
  echo "  备份：$BIN_DIR/mmx.bak-preset、$BIN_DIR/mmx*.bak、$BIN_DIR/mm.bak、$SVC_FILE.bak、/tmp/mmx-server.bak-*"
  if [ -n "$TLS_DOMAIN" ]; then
    echo "  Let's Encrypt 证书（仅域名 $TLS_DOMAIN）：$le_dir/live/$TLS_DOMAIN、$le_dir/archive/$TLS_DOMAIN、$le_dir/renewal/$TLS_DOMAIN.conf"
    echo "  续期 hook：$le_dir/renewal-hooks/deploy/restart-mmx-server.sh"
  fi
  if [ -f "$bbr_conf" ]; then
    echo "  BBR 配置 $bbr_conf，并把内核拥塞算法还原为 cubic、队列算法还原为 pfifo_fast"
  fi
  if [ -n "$PORT" ]; then echo "  防火墙放行规则：ufw $PORT/tcp"; fi
  local yn
  read -r -p "确认卸载吗？输入 y 确认： " yn || return 0
  case "$yn" in y|Y) ;; *) echo "已取消。"; return 0;; esac
  svc_stop || true
  svc_disable || true
  rm -f "$SVC_FILE" "$SVC_FILE.bak"
  svc_reload || true
  if command -v ufw >/dev/null 2>&1 && [ -n "$PORT" ]; then ufw delete allow "$PORT/tcp" >/dev/null 2>&1 || true; fi
  rm -f "$SERVER_BIN" "$BIN_DIR/mmx" "$BIN_DIR/mm"
  rm -f "$BIN_DIR/mmx.bak-preset" "$BIN_DIR"/mmx*.bak "$BIN_DIR"/mm.bak
  if [ -n "$CFG_DIR" ] && [ "$CFG_DIR" != "/" ] && [ "$CFG_DIR" != "/etc" ]; then rm -rf "$CFG_DIR"; fi
  if [ -n "$TLS_DOMAIN" ]; then
    rm -rf "$le_dir/live/$TLS_DOMAIN" "$le_dir/archive/$TLS_DOMAIN"
    rm -f "$le_dir/renewal/$TLS_DOMAIN.conf"
  fi
  rm -f "$le_dir/renewal-hooks/deploy/restart-mmx-server.sh"
  if [ -f "$bbr_conf" ]; then
    rm -f "$bbr_conf"
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
    sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1 || true
    bbr_removed=1
  fi
  rm -f /tmp/mmx-server.bak-*
  echo "已卸载，无残留：服务、程序、菜单命令（mmx/mm）、配置、备份文件已删除。"
  if [ -n "$TLS_DOMAIN" ]; then echo "域名 $TLS_DOMAIN 的 Let's Encrypt 证书和续期 hook 已删除。"; fi
  if [ "$bbr_removed" = "1" ]; then echo "BBR 配置已删除，内核拥塞算法已还原为 cubic、队列算法已还原为 pfifo_fast。"; fi
  exit 0
}

main() {
  if [ "$(id -u)" -ne 0 ]; then echo "请用 sudo 运行：sudo $MYNAME"; exit 1; fi
  # 隐藏用法：部署脚本装完后按配置写服务文件；只打印链接；只打印 TLS 指纹；只打印流量统计；直接载入预设；一键设置域名
  if [ "${1:-}" = "--write-service" ]; then load_config; write_service; exit 0; fi
  if [ "${1:-}" = "--show-link" ]; then show_link "${2:-opaque}"; exit 0; fi
  if [ "${1:-}" = "--show-pin" ]; then show_pin; exit 0; fi
  if [ "${1:-}" = "--show-traffic" ]; then show_traffic; exit 0; fi
  if [ "${1:-}" = "--preset" ]; then load_config; apply_preset "${2:-}" || exit 1; exit 0; fi
  if [ "${1:-}" = "--setup-domain" ]; then load_config; setup_domain "${2:-}" || exit 1; exit 0; fi
  # 菜单界面统一绿色；退出（正常 / Ctrl-C）时复位终端颜色。
  # 放在隐藏用法之后：非交互调用（--show-link / --preset / --setup-domain 等）
  # 的输出里不能带颜色码，否则部署脚本抓到的链接会被污染。
  printf '\033[32m'
  trap 'printf "\033[0m"' EXIT
  while true; do
    load_config
    echo ""
    echo "== mm-x 服务端管理（输入 $MYNAME 呼出） =="
    local tls_desc="关"
    [ -n "$TLS_DOMAIN" ] && tls_desc="真 TLS（$TLS_DOMAIN）"
    [ "${TLS_AUTO:-0}" = "1" ] && tls_desc="自签 TLS（SNI ${TLS_SNI:-www.microsoft.com}）"
    if svc_is_active; then
      echo "服务：正在运行　端口：${PORT:-?}　限速：${RATE:-?}　突发：${BURST:-?}"
      echo "回退：${FALLBACK:-?}　TLS：$tls_desc"
    else
      echo "服务：未运行（用第 7 项重启，或看第 9 项日志）"
      echo "端口：${PORT:-?}　限速：${RATE:-?}"
    fi
    echo "1) 添加节点"
    echo "2) 载入预设"
    echo "3) 编辑节点"
    echo "4) 删除节点"
    echo "5) 查看节点"
    echo "6) 服务状态"
    echo "7) 重启服务"
    echo "8) 修改限速"
    echo "9) 查看日志"
    echo "10) 卸载"
    echo "11) 退出"
    local c
    read -r -p "选一项： " c || exit 0
    case "$c" in
      1) add_node ;;
      2) preset_menu ;;
      3) edit_params ;;
      4) delete_node ;;
      5) show_nodes ;;
      6) show_status ;;
      7) restart_svc ;;
      8) change_rate ;;
      9) show_logs ;;
      10) uninstall ;;
      11|"") exit 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

main "$@"
MM_MENU_EOF
chmod +x "$BIN_DIR/mmx"
# 兼容旧习惯：mm 仍可用（软链接到 mmx）
ln -sf "$BIN_DIR/mmx" "$BIN_DIR/mm"
echo "管理菜单已安装：$BIN_DIR/mmx（输入 mmx 呼出，旧的 mm 也能用）"

# 9) 服务文件：按配置文件生成（菜单改参数也是同一份逻辑），开机自启、崩溃自动重启
#    systemd 写单元文件，OpenRC 写 /etc/init.d/mmx-server。
#    全新安装不建节点、没配置可写，跳过（服务文件在菜单第 1 项添加节点时生成）。
if [ "$FRESH_NO_NODE" != "1" ]; then
echo "== 写入服务文件 =="
"$BIN_DIR/mmx" --write-service
mkdir -p "$SVC_DIR"
svc_reload
svc_enable
svc_restart
sleep 2
if svc_is_active; then
  echo "服务已启动：mmx-server 正在运行"
  # 更新成功，备份的旧二进制可以删了
  [ -n "$BIN_BAK" ] && rm -f "$BIN_BAK"
else
  # 更新模式且有旧二进制备份：新二进制起不来就还原旧的再起一次，不让服务停着
  if [ -n "$BIN_BAK" ] && [ -f "$BIN_BAK" ]; then
    echo "新二进制启动失败，正在还原旧二进制……"
    cp -f "$BIN_BAK" "$BIN_DIR/mmx-server"
    rm -f "$BIN_BAK"
    svc_reload
    svc_restart
    sleep 2
    if svc_is_active; then
      echo "已还原旧二进制，服务用原配置恢复运行（本次更新没生效，请检查新二进制再更新）。"
      exit 0
    fi
  fi
  echo "服务启动失败，请看日志：$(svc_log_cmd)"
  exit 1
fi
fi

if [ "$UPDATE_ONLY" = "1" ]; then
echo ""
echo "== 更新完成 =="
echo "程序文件已更新（服务端二进制、管理菜单、服务文件）；节点配置原样保留。"
echo "端口：$PORT（不变）；限速：$RATE；TLS：$TLS_MODE_DESC；节点名：$NAME"
echo "密钥文件：$PSK_FILE（未变）；配置文件：$CFG_FILE（未动）"
echo "想改节点参数用 mmx 菜单；想彻底重装节点请加 --reinstall。"
echo "服务状态：mm 菜单第 6 项，或 $(svc_status_cmd)；日志：mm 菜单第 9 项，或 $(svc_log_follow_cmd)"
elif [ "$FRESH_NO_NODE" = "1" ]; then
echo ""
echo "== 安装完成（只装了程序，未创建节点） =="
echo "已安装：服务端二进制 $BIN_DIR/mmx-server、管理菜单 $BIN_DIR/mmx（输入 mmx 呼出）。"
echo "未创建节点：没有密钥、没有配置文件、服务未启动。"
if [ -n "$NODE_FLAGS_GIVEN" ]; then
echo "安装参数（--port/--rate/--preset/--traffic-*/--domain 等）已忽略：全新安装不再创建节点，节点参数在菜单里设置（预设也可在菜单第 2 项或 mmx --preset 载入）。"
fi
echo "请在菜单第 1 项添加节点（会问端口、节点名、流量限额、域名还是 IP），节点建好后服务自动启动；"
echo "建好后在菜单第 5 项查看节点（粘贴到 mm-x 客户端就能用，绝不要分享给第二个人）。"
else
echo ""
echo "== 安装完成 =="
echo "监听端口：$PORT"
echo "限速上限：$RATE（0 = 不限速），突发额度：$BURST"
echo "回退模式：$FALLBACK；TLS：$TLS_MODE_DESC"
if [ "$TRAFFIC_QUOTA" = "0" ]; then
  echo "流量统计：不限额（只统计，不限制）；想限制去 mm 菜单第 3 项 → 流量设置"
else
  echo "流量统计：限额 $TRAFFIC_QUOTA，超限后 $TRAFFIC_LIMIT_MODE；查看用量去 mm 菜单第 3 项 → 流量设置 → 查看流量"
fi
echo "密钥文件：$PSK_FILE（重装不换密钥；换密钥请直接改此文件，服务端自动识别，24 小时内新旧密钥都能用）"
echo "配置文件：$CFG_FILE（菜单改参数就改这个文件）"
echo "服务状态：mm 菜单第 6 项，或 $(svc_status_cmd)；日志：mm 菜单第 9 项，或 $(svc_log_follow_cmd)"
echo ""
echo "输入 mmx 打开管理菜单，在菜单第 5 项查看节点（粘贴到 mm-x 客户端就能用，绝不要分享给第二个人）。"
fi

# --domain：一键申请证书并切真 TLS（只在 --reinstall 重装节点时跑；
# 全新安装不建节点、--domain 已忽略，不走这里；更新模式上面已经忽略该参数，不走这里）。
# 失败也不影响上面装好的自签服务。
if [ -n "${DOMAIN_SETUP:-}" ] && [ "$UPDATE_ONLY" = "0" ] && [ "$FRESH_NO_NODE" != "1" ]; then
echo ""
echo "== 一键设置域名 $DOMAIN_SETUP =="
if "$BIN_DIR/mmx" --setup-domain "$DOMAIN_SETUP"; then
  echo "域名已设置：真 TLS（$DOMAIN_SETUP），新链接见上面（旧链接已失效，请更新客户端）。"
else
  echo "域名设置失败：服务仍用自签 TLS 继续运行（见上面的报错）；之后可用 mmx 菜单第 3 项（编辑节点）→ 第 10 子项重试。"
  exit 1
fi
fi

# 装完进主菜单（全新安装 / 更新 / 重装都一样）：有终端就进菜单，
# 没终端（管道/自动化）就不挂起，只打印提示后退出。
# 一键命令 curl | bash 时 stdin 是管道不是终端，但控制终端还在，
# 这时从 /dev/tty 读菜单输入。测试模式（MMX_TEST_ROOT）下默认不进菜单，
# 只打印提示，避免测试挂起；MMX_TEST_ENTER_MENU=1 可强制进菜单，
# 供测试用 pty 覆盖交互路径（生产环境不要设置这个变量）。
ENTER_MENU=0
if [ -z "${MMX_TEST_ROOT:-}" ] || [ "${MMX_TEST_ENTER_MENU:-}" = "1" ]; then
  if [ -t 0 ]; then ENTER_MENU=1;
  elif { true < /dev/tty; } 2>/dev/null; then ENTER_MENU=1; fi
fi
if [ "$ENTER_MENU" = "1" ]; then
  if [ -t 0 ]; then
    exec "$BIN_DIR/mmx"
  else
    exec "$BIN_DIR/mmx" < /dev/tty
  fi
fi
if [ "$UPDATE_ONLY" = "1" ]; then
  echo "更新完成，输入 mmx 打开菜单。"
elif [ "$FRESH_NO_NODE" = "1" ]; then
  echo "安装完成，输入 mmx 打开菜单添加节点。"
else
  echo "安装完成，输入 mmx 打开菜单。"
fi
