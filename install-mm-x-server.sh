#!/bin/bash
# mm-x 服务端一键部署脚本（在 VPS 上用 sudo 运行）。
# 用法（一键）：
#   curl -fsSL https://raw.githubusercontent.com/bestmiao/mm-x/main/install-mm-x-server.sh | sudo bash
#   （没找到本地二进制时脚本自己从 GitHub 下载；想手动装也可以把本脚本和
#   预编译的 mmx-server-linux-amd64 放到同一个目录再 sudo 运行）
#   sudo ./install-mm-x-server.sh [--port 端口] [--rate 限速] [--burst 突发] [--host 公网IP或域名]
#      [--fallback site|silent] [--tls-domain 域名 --tls-cert 证书 --tls-key 私钥]
#      [--tls-auto [--tls-sni 域名]] [--domain 域名]（没域名时用自签 TLS + SPKI 锁定，和真 TLS 二选一；
#      --domain 是一键：装完自动申请 Let's Encrypt 证书并切真 TLS，DNS 须先指到本机、80 端口空闲）
# 默认：端口 443（没传 --port 时用 443；443 被 nginx/Apache 等占了会报错停下，
# 先停掉占用的服务或传 --port 换端口）、不限速（rate=0；想限速再传 --rate，例如 6250K = 50 Mbps）、突发 0（严格模式：限速时任何时候都不超过限速；旧默认 15M 会让每条新连接开头先冲 15MB 再限速，实测 30MB 文件平均跑到 96 Mbps、峰值 1300 Mbps，等于没限——YouTube 这种多连接、分段取数据的流量，每段都落在突发里，更是全程不限）。
# 全新安装只装程序：二进制到 /usr/local/bin/mmx-server + 管理菜单 /usr/local/bin/mmx（输入 mmx 呼出），
# 不建节点、不生成密钥、不写 /etc/mmx/config、不写服务文件、不启动服务；装完有终端就进入主菜单，
# 用菜单第 1 项添加节点（问端口、流量限额、域名还是 IP，建好后服务自动启动）。
# 非交互（管道/自动化）时不进菜单，只打印"输入 mmx 打开菜单添加节点"后退出。
# --reinstall 重装节点时才做全套：生成/保留 /etc/mmx/psk（重装不换密钥，
#   旧密钥靠服务端的 24 小时宽限期继续用）；默认开 BBR（开不了只警告）；放行防火墙端口；
#   写 /etc/mmx/config（全部参数都在这里，菜单改参数就改这个文件）；写服务文件
#   （systemd 用单元文件，OpenRC/Alpine 用 /etc/init.d/mmx-server；开机自启、崩溃自动重启）。
# 安装完不打印 mmx:// 链接——链接在 mmx 菜单第 5 项里看。
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
PROTO="mmx" # 节点协议：mmx（自有协议）| xhttp（VLESS+XHTTP，Xray）| ss2022（Shadowsocks 2022，Xray）。
# 部署脚本（--reinstall）只建 mmx 节点，PROTO 恒为 mmx；XHTTP/ss2022 在菜单第 1 项添加节点时选。
RATE="0"
BURST="0"
NAME="mm-x"
HOST=""
BIN=""
FALLBACK="site"
TLS_DOMAIN=""
TLS_CERT=""
TLS_KEY=""
TLS_AUTO="0"
TLS_SNI=""
DOMAIN_SETUP="" # --domain 传过就置为域名：装完一键申请证书并切真 TLS（只在全新安装/--reinstall 时跑）
# 流量统计与限额（全服务总量）：默认不限额（只统计，不限制），
# 不改变现有行为；想限制时用下面 6 个参数或 mmx 菜单第 3 项（编辑节点）里的流量设置。
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
# （菜单第 2 项“谷歌服务”开关；开着时只放行谷歌系域名，其他目标直接拒绝）。
DOMAIN_WHITELIST=""

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

# 流量值归一化（部署侧；菜单里另有一份，改动时两边同步）：
# 裸数字当 G（180 → 180G），小写单位转大写（180g → 180G）；0 和空不动；
# 非法值原样返回（由 valid_bytes / 校验报错）。
normalize_bytes() {
  local s="$1"
  case "$s" in
    ""|0) printf '%s' "$s"; return 0 ;;
  esac
  case "$s" in
    *[KkMmGgTt]) printf '%s' "$s" | tr '[:lower:]' '[:upper:]' ;;
    *[0-9]) printf '%sG' "$s" ;;
    *) printf '%s' "$s" ;;
  esac
}

usage() {
  echo "用法：sudo $0 [--port 端口] [--rate 限速] [--burst 突发] [--host 公网IP或域名] [--bin 服务端二进制路径] [--fallback site|silent] [--tls-domain 域名 --tls-cert 证书 --tls-key 私钥] [--domain 域名] [--reinstall]"
  echo "  --port   监听端口，默认 443（更像正常 HTTPS；不要用一眼能猜到的端口）"
  echo "           443 被占时本脚本会直接报错停下，先停掉占用的服务（例如 $(svc_stop_cmd nginx)）或换个端口再装"
  echo "  --reinstall 彻底重装节点：按本次传入参数重写 /etc/mmx/config（端口/限速/TLS/流量设置都会重置；"
  echo "           密钥文件保留不变）。不加时：已安装就只更新程序文件（服务端二进制、管理菜单、服务文件），"
  echo "           节点配置原样保留，再跑一遍也不会把服务重置掉；全新安装（没节点）时不建节点，只装程序，"
  echo "           节点在菜单第 1 项添加——只有加了 --reinstall 才会按传入参数建节点"
  echo "  --rate   服务端限速上限，默认 0（不限速；想限速再填，例如 6250K = 50 Mbps，约 6.25 MB/s）"
  echo "  --burst  服务端突发额度上限，默认 0（严格模式：任何时候都不超过限速；想允许开头冲一把再填，例如 --burst 5M）"
  echo "  --host   mmx:// 链接里的服务器地址，默认自动探测公网 IP；可以填域名或 IP，填了域名就按域名生成链接"
  echo "  --bin    服务端二进制路径，默认用脚本同目录下的 mmx-server-linux-amd64"
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
  echo "                   和 --tls-domain 二选一；以后有了域名，删除节点后用第 1 项重新添加（选域名）换成真 TLS"
  echo "  --tls-sni        自签 TLS 的默认 SNI（一个常见域名，例如 www.microsoft.com，默认就是它）；"
  echo "                   链接里写了 sni 参数就以链接为准"
  echo "  --domain   一键设置域名：装完自动申请 Let's Encrypt 证书并切到真 TLS（只在 --reinstall 重装节点时跑；"
  echo "           全新安装不建节点，所以 --domain 会被忽略，域名在菜单第 1 项添加节点时选；再跑脚本只更新程序文件时忽略，"
  echo "           改域名请删除节点后用第 1 项重新添加（选域名）。"
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
  exit 1
}

# 全新安装判定（无配置、不是 --reinstall）：不建节点，只装二进制 + 菜单；节点在菜单第 1 项添加。
# 必须在参数解析前算出来：--reinstall 本身是参数之一，先预扫描一遍（解析循环里还会再置一次，无害）。
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
    --host) NODE_FLAGS_GIVEN=1; HOST="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
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
    --traffic-quota) NODE_FLAGS_GIVEN=1; TRAFFIC_QUOTA="$(normalize_bytes "$2")"; shift 2 ;;
    --traffic-throttle-rate) NODE_FLAGS_GIVEN=1; TRAFFIC_THROTTLE_RATE="$2"; shift 2 ;;
    --cover-traffic) NODE_FLAGS_GIVEN=1; COVER_TRAFFIC="$2"; shift 2 ;;
    --domain-whitelist) NODE_FLAGS_GIVEN=1; DOMAIN_WHITELIST="$2"; shift 2 ;;
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
# 命令行给的安装参数（--port/--rate/--traffic-* 等）一律忽略。
UPDATE_ONLY="0"
if [ -f "$CFG_FILE" ] && [ "$REINSTALL" != "1" ]; then
  UPDATE_ONLY="1"
  . "$CFG_FILE"
  echo "检测到已安装的 mm-x 节点（端口 ${PORT:-未知}），本次只更新程序文件（服务端二进制、管理菜单、服务文件），不改节点配置。"
  echo "安装参数（--port/--rate/--traffic-*/--domain 等）已忽略；改节点参数请用 mmx 菜单；要彻底重装节点请加 --reinstall。"
  if [ -n "${DOMAIN_SETUP:-}" ]; then
    echo "已忽略 --domain $DOMAIN_SETUP：只更新程序文件时不改 TLS 设置；要设置域名请删除节点后用第 1 项重新添加（选域名），或加 --reinstall 重装时再传 --domain。"
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


if [ "$FRESH_NO_NODE" = "1" ]; then
echo "== 安装 mm-x 服务端（只装程序，不建节点） =="
echo "本次只安装服务端二进制和管理菜单，不创建节点；装完进入菜单，用第 1 项添加节点。"
else
echo "== 安装 mm-x 服务端 =="
TLS_MODE_DESC="关"
[ -n "$TLS_DOMAIN" ] && TLS_MODE_DESC="真 TLS（$TLS_DOMAIN）"
[ "$TLS_AUTO" = "1" ] && TLS_MODE_DESC="自签 TLS（SNI ${TLS_SNI:-www.microsoft.com}）"
echo "端口：$PORT；限速：$RATE；突发：$BURST；回退：$FALLBACK；TLS：$TLS_MODE_DESC"
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

# 防火墙放行端口：有哪个工具用哪个，都没有就跳过，不出声。
open_firewall_port() {
  if command -v ufw >/dev/null 2>&1; then
    echo "== 防火墙放行 $PORT/tcp =="
    ufw allow "$PORT/tcp" >/dev/null 2>&1 || echo "警告：ufw 放行失败，请手动放行 $PORT/tcp"
    echo "已用 ufw 放行 $PORT/tcp"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    echo "== 防火墙放行 $PORT/tcp =="
    firewall-cmd --add-port="$PORT/tcp" --permanent >/dev/null 2>&1 || echo "警告：firewalld 放行失败，请手动放行 $PORT/tcp"
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "已用 firewalld 放行 $PORT/tcp"
  fi
}

# 3) BBR 默认开：开不了只警告，绝不因为开不了就装失败（测试模式跳过）
#    全新安装不建节点，跳过（BBR 在菜单第 1 项添加节点时开；--reinstall 建节点时也开）。
if [ "$FRESH_NO_NODE" != "1" ]; then
  enable_bbr
fi

# 4) 防火墙放行端口（有哪个工具用哪个，都没有就跳过）
#    全新安装不建节点、没端口可放，跳过（在菜单第 1 项添加节点时按它的端口放行）。
if [ "$FRESH_NO_NODE" != "1" ]; then
  open_firewall_port
fi

# 5) 探测公网 IP（--host 优先），写进配置文件（菜单拼链接时用）
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

# 6) 写配置文件 /etc/mmx/config：全部参数都在这里，菜单改参数就改这个文件，
#    再由菜单按它重新生成服务文件（改错了重启失败会自动回滚）。
#    只在 --reinstall 重装节点时写；已安装更新模式跳过，节点配置原样保留；
#    全新安装不建节点，不写配置（节点在菜单第 1 项添加时写）。
if [ "$UPDATE_ONLY" = "1" ]; then
echo "已安装节点：跳过写配置（$CFG_FILE 原样保留）"
elif [ "$REINSTALL" = "1" ]; then
# 节点名自动取：--domain 优先，其次真 TLS 域名，再次服务器地址；都没有就保留现有名字，再没有就用 mm-x。
if [ -n "${DOMAIN_SETUP:-}" ]; then NAME="$DOMAIN_SETUP";
elif [ -n "${TLS_DOMAIN:-}" ]; then NAME="$TLS_DOMAIN";
elif [ -n "${HOST:-}" ]; then NAME="$HOST";
elif [ -z "${NAME:-}" ]; then NAME="mm-x";
fi
{
  printf '%s=%q\n' PROTO "$PROTO" PORT "$PORT" RATE "$RATE" BURST "$BURST" NAME "$NAME" HOST "$HOST" FALLBACK "$FALLBACK" TLS_DOMAIN "$TLS_DOMAIN" TLS_CERT "$TLS_CERT" TLS_KEY "$TLS_KEY" TLS_AUTO "$TLS_AUTO" TLS_SNI "$TLS_SNI" TRAFFIC_MODE "$TRAFFIC_MODE" TRAFFIC_PERIOD "$TRAFFIC_PERIOD" TRAFFIC_START_DAY "$TRAFFIC_START_DAY" TRAFFIC_LIMIT_MODE "$TRAFFIC_LIMIT_MODE" TRAFFIC_QUOTA "$TRAFFIC_QUOTA" TRAFFIC_THROTTLE_RATE "$TRAFFIC_THROTTLE_RATE" COVER_TRAFFIC "$COVER_TRAFFIC" DOMAIN_WHITELIST "$DOMAIN_WHITELIST"
} > "$CFG_FILE"
chmod 600 "$CFG_FILE"
echo "配置文件已写入：$CFG_FILE"
else
echo "全新安装：不创建节点，不写配置文件（节点在菜单第 1 项添加）。"
fi

# 7) 写管理菜单 /usr/local/bin/mmx：输入 mmx 呼出。
#    菜单是一个独立的 bash 脚本；配置存在 /etc/mmx/config，密钥在 /etc/mmx/psk，
#    服务文件由菜单按配置文件生成（改参数后自动重载 + 重启，重启失败自动回滚）。
echo "== 安装管理菜单 =="
cat > "$BIN_DIR/mmx" <<'MM_MENU_EOF'
#!/bin/bash
# mm-x 服务端管理菜单：在 VPS 上输入 mmx 呼出。
# 功能：1 添加节点  2 谷歌服务（仅谷歌系域名）  3 编辑节点（含流量设置）
#       4 删除节点  5 查看节点  6 查看日志  7 更新脚本
#       8 完全卸载  9 退出脚本
# （服务状态直接显示在菜单最上方，不用选；更换密钥、诱饵回退 / TLS 设置、
#  掩护流量、域名白名单已从菜单移除，全部自动设置；重启服务已删除，
#  改配置时 apply_config 自动重载 + 重启；tls_menu 函数保留在脚本内，
#  不再从菜单调用，域名在添加节点时选、TLS 自动设置）
# 全部配置存在 /etc/mmx/config，密钥在 /etc/mmx/psk；
# 服务文件由本脚本按配置文件生成，改参数后自动重载 + 重启，
# 重启失败自动回滚到改之前的配置，不会让服务起不来。
# 隐藏用法（给部署脚本和脚本调用）：mmx --write-service（按配置写服务文件）、mmx --show-link [plain|opaque]（只打印链接，
# 默认 opaque 不透明链接；plain 是短格式，只在显式指定时用）、
# mmx --show-pin（只打印 TLS 证书的 SPKI 指纹）、mmx --show-traffic（打印本周期流量统计）、
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

# BBR：系统调优，节点用。开不了只警告，绝不因此失败（测试模式跳过）。
# （和部署脚本里的同名函数各一份，菜单是独立脚本，改动时两边同步。）
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

# 防火墙放行端口：有哪个工具用哪个，都没有就跳过，不出声。
# （和部署脚本里的同名函数各一份，菜单是独立脚本，改动时两边同步。）
open_firewall_port() {
  if command -v ufw >/dev/null 2>&1; then
    echo "== 防火墙放行 $PORT/tcp =="
    ufw allow "$PORT/tcp" >/dev/null 2>&1 || echo "警告：ufw 放行失败，请手动放行 $PORT/tcp"
    echo "已用 ufw 放行 $PORT/tcp"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    echo "== 防火墙放行 $PORT/tcp =="
    firewall-cmd --add-port="$PORT/tcp" --permanent >/dev/null 2>&1 || echo "警告：firewalld 放行失败，请手动放行 $PORT/tcp"
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "已用 firewalld 放行 $PORT/tcp"
  fi
}

# 默认值（配置文件缺失时用；老配置没有流量字段时也按这些默认走）
PORT=""; RATE="0"; BURST="0"; NAME="mm-x"; HOST=""
PROTO="mmx" # 节点协议：mmx（自有协议，mmx-server）| xhttp（VLESS+XHTTP，Xray）| ss2022（Shadowsocks 2022，Xray）。
# 单节点模型：同一时间只有一个协议的节点在跑（mmx-server 和 xray 不同时运行，端口不会冲突）。
# Xray 的配置在 /usr/local/etc/xray/config.json（和 vx 同一份路径）；Xray 专属状态在 /etc/mmx/xray.conf。
# Xray 只在选了 XHTTP/ss2022 时才安装和启动；mmx 节点不碰 Xray。
XRAY_CONF="$CFG_DIR/xray.conf"
XRAY_CFG_FILE="$ROOT/usr/local/etc/xray/config.json"
XRAY_INFO_FILE="$CFG_DIR/xray-info.txt"
XRAY_SPLIT_A="$CFG_DIR/xhttp-split-a.json"
XRAY_SPLIT_B="$CFG_DIR/xhttp-split-b.json"
XRAY_TRAFFIC_FILE="$CFG_DIR/xray-traffic.json"
XRAY_INSTALLED_MARKER="$CFG_DIR/xray-installed"
# Xray 专属状态默认值（xray.conf 缺失时用）
XHTTP_MODE="reality"; XHTTP_PATH="/api"; XHTTP_UUID=""; XHTTP_SNI=""; XHTTP_REGION=""
XHTTP_PUBKEY=""; XHTTP_PRIVKEY=""; XHTTP_SHORTID=""; XHTTP_SPLIT="1"
XHTTP_CERT=""; XHTTP_KEY=""
SS_PASSWORD=""; SS_METHOD="2022-blake3-aes-256-gcm"
FALLBACK="site"; TLS_DOMAIN=""; TLS_CERT=""; TLS_KEY=""
TLS_AUTO="0"; TLS_SNI=""
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

# 节点名自动取：有域名取域名，没域名取服务器地址；都没了保留现有名字，再没有就用 mm-x。
# mmx 链接不带名字，XHTTP/ss2022 链接的 #fragment 用这个名字。
# save_config 是唯一写盘口（apply_config / apply_xray_config 都走它），放这里一个漏斗就够。
derive_name() {
  if [ -n "${TLS_DOMAIN:-}" ]; then NAME="$TLS_DOMAIN";
  elif [ -n "${HOST:-}" ]; then NAME="$HOST";
  elif [ -z "${NAME:-}" ]; then NAME="mm-x";
  fi
}

save_config() {
  derive_name
  mkdir -p "$CFG_DIR"
  {
    printf '%s=%q\n' PROTO "$PROTO" PORT "$PORT" RATE "$RATE" BURST "$BURST" NAME "$NAME" HOST "$HOST" FALLBACK "$FALLBACK" TLS_DOMAIN "$TLS_DOMAIN" TLS_CERT "$TLS_CERT" TLS_KEY "$TLS_KEY" TLS_AUTO "$TLS_AUTO" TLS_SNI "$TLS_SNI" TRAFFIC_MODE "$TRAFFIC_MODE" TRAFFIC_PERIOD "$TRAFFIC_PERIOD" TRAFFIC_START_DAY "$TRAFFIC_START_DAY" TRAFFIC_LIMIT_MODE "$TRAFFIC_LIMIT_MODE" TRAFFIC_QUOTA "$TRAFFIC_QUOTA" TRAFFIC_THROTTLE_RATE "$TRAFFIC_THROTTLE_RATE" COVER_TRAFFIC "$COVER_TRAFFIC" DOMAIN_WHITELIST "$DOMAIN_WHITELIST" SHOW_IP_LINK "$SHOW_IP_LINK"
  } > "$CFG_FILE"
  chmod 600 "$CFG_FILE"
}

# Xray 专属状态（/etc/mmx/xray.conf，key=value）：XHTTP_* / SS_*。
load_xray_config() {
  if [ -f "$XRAY_CONF" ]; then
    # 配置文件是本脚本自己写的 key=value（值已转义），直接 source
    . "$XRAY_CONF"
  fi
}

save_xray_config() {
  mkdir -p "$CFG_DIR"
  {
    printf '%s=%q\n' XHTTP_MODE "$XHTTP_MODE" XHTTP_PATH "$XHTTP_PATH" XHTTP_UUID "$XHTTP_UUID" XHTTP_SNI "$XHTTP_SNI" XHTTP_REGION "$XHTTP_REGION" XHTTP_PUBKEY "$XHTTP_PUBKEY" XHTTP_PRIVKEY "$XHTTP_PRIVKEY" XHTTP_SHORTID "$XHTTP_SHORTID" XHTTP_SPLIT "$XHTTP_SPLIT" XHTTP_CERT "$XHTTP_CERT" XHTTP_KEY "$XHTTP_KEY" SS_PASSWORD "$SS_PASSWORD" SS_METHOD "$SS_METHOD"
  } > "$XRAY_CONF"
  chmod 600 "$XRAY_CONF"
}

# 按当前配置写服务文件（不重载、不重启，只写文件）：
# systemd 写 $UNIT_FILE（单元文件），OpenRC 写 $INIT_FILE（init 脚本）。
# 启动参数只拼一次，两边用同一份（字节一致）；OpenRC 的 command_args 经 eval 处理，引号正常解析。
write_service() {
  local tls_args="" traffic_args=""
  if [ -n "$TLS_DOMAIN" ]; then
    tls_args=" --tls-domain $TLS_DOMAIN --tls-cert $TLS_CERT --tls-key $TLS_KEY"
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    # 自签模式：证书路径必须写绝对路径——服务端不给路径时默认相对路径 tls-cert.pem，
    # systemd 下工作目录是 /，会写到根目录去，所以这里固定写 /etc/mmx 下。
    tls_args=" --tls-auto --tls-cert $CFG_DIR/tls-cert.pem --tls-key $CFG_DIR/tls-key.pem"
    if [ -n "${TLS_SNI:-}" ]; then tls_args="$tls_args --tls-sni $TLS_SNI"; fi
  fi
  # 流量统计与限额：一直写进启动参数（限额 0 = 不限，只统计不限制）；
  # 计数持久化文件固定在配置目录下（/etc/mmx/traffic.json）。
  traffic_args=" --traffic-mode ${TRAFFIC_MODE:-total} --traffic-period ${TRAFFIC_PERIOD:-monthly} --traffic-start-day ${TRAFFIC_START_DAY:-1} --traffic-limit-mode ${TRAFFIC_LIMIT_MODE:-throttle} --traffic-quota ${TRAFFIC_QUOTA:-0} --traffic-throttle-rate ${TRAFFIC_THROTTLE_RATE:-125K} --traffic-file $CFG_DIR/traffic.json"
  # 掩护流量（v5 会话）：一直写进启动参数，默认 low。
  cover_args=" --cover-traffic ${COVER_TRAFFIC:-low}"
  # 目标域名白名单：只在开了时写进启动参数（默认关，不写）。
  local domain_whitelist_args=""
  if [ -n "${DOMAIN_WHITELIST:-}" ]; then domain_whitelist_args=" --domain-whitelist $DOMAIN_WHITELIST"; fi
  # 启动参数（不含二进制路径）：systemd 的 ExecStart 和 OpenRC 的 command_args 用同一份。
  local args="--psk-file $PSK_FILE --listen 0.0.0.0:$PORT --rate $RATE --burst $BURST --name \"$NAME\" --fallback $FALLBACK$tls_args$traffic_args$cover_args$domain_whitelist_args"
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
  # XHTTP/ss2022 节点走 Xray 那条路（apply_xray_config），不走 mmx-server 这条。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    apply_xray_config "$desc"
    return $?
  fi
  # 从 Xray 节点切回 mmx 节点时，先停掉 xray（否则它还占着端口，mmx-server 起不来）。
  if command -v xray >/dev/null 2>&1 && xray_is_active; then
    xray_stop 2>/dev/null || true
    xray_disable 2>/dev/null || true
  fi
  remove_xray_watch
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

# 流量值归一化（菜单侧；部署侧另有一份，改动时两边同步）：
# 裸数字当 G（180 → 180G），小写单位转大写（180g → 180G）；0 和空不动；
# 非法值原样返回（由 valid_bytes 报错）。
normalize_bytes() {
  local s="$1"
  case "$s" in
    ""|0) printf '%s' "$s"; return 0 ;;
  esac
  case "$s" in
    *[KkMmGgTt]) printf '%s' "$s" | tr '[:lower:]' '[:upper:]' ;;
    *[0-9]) printf '%sG' "$s" ;;
    *) printf '%s' "$s" ;;
  esac
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
  # XHTTP/ss2022 节点：链接是 vless:// / ss://，没有 plain/opaque 之分。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    load_xray_config
    if [ -z "$PORT" ]; then echo "还没有节点，请用第 1 项添加节点。"; return 1; fi
    local link
    link="$(build_xray_link)"
    if [ -z "$link" ]; then echo "拼链接失败（Xray 配置有问题），请看第 6 项日志。"; return 1; fi
    echo ""
    echo "节点链接（粘贴到客户端就能用，绝不要分享给第二个人）："
    echo "$link"
    echo ""
    return 0
  fi
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -z "$PORT" ]; then echo "还没有节点，请用第 1 项添加节点。"; return 1; fi
  local host link
  if [ -n "$TLS_DOMAIN" ]; then host="$TLS_DOMAIN"; else host="${HOST:-}"; fi
  link="$(build_link "$host" "$fmt")"
  if [ -z "$link" ]; then echo "拼链接失败（密钥或参数有问题），请看第 6 项日志。"; return 1; fi
  echo ""
  echo "节点链接（粘贴到 mm-x 客户端就能用，绝不要分享给第二个人）："
  echo "$link"
  echo ""
}

# 5) 查看节点（主菜单第 5 项）：按节点列表显示，每条节点两行——
#    第一行是地址（域名或 IP），第二行是它的链接。默认只显示本节点
#    （域名 / 服务器地址）；IP 链接默认不显示，只有在第 3 项编辑节点
#    第 6 子项里打开了才同时显示（同一台服务器的 IP 写法链接，
#    不是第二个独立节点）。公网 IP 探不到、或和第一条地址一样时不显示第二条。
show_nodes() {
  load_config
  # XHTTP/ss2022 节点：从 xray-info.txt 读（没有就现写一份）。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    load_xray_config
    if [ -z "$PORT" ]; then echo "还没有节点，请用第 1 项添加节点。"; return 1; fi
    if [ ! -s "$XRAY_INFO_FILE" ]; then write_xray_info; fi
    echo ""
    echo "查看节点"
    cat "$XRAY_INFO_FILE"
    echo ""
    return 0
  fi
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -z "$PORT" ]; then echo "还没有节点，请用第 1 项添加节点。"; return 1; fi
  local host1 link1
  if [ -n "$TLS_DOMAIN" ]; then host1="$TLS_DOMAIN"
  elif [ -n "${HOST:-}" ]; then host1="$HOST"
  else host1="$(detect_public_ip)"; [ -z "$host1" ] && host1="<你的 VPS 公网 IP>"; fi
  link1="$(build_link "$host1" opaque)"
  if [ -z "$link1" ]; then echo "拼链接失败（密钥或参数有问题），请看第 6 项日志。"; return 1; fi
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
  # XHTTP/ss2022 节点没有 mmx 的 TLS 指纹。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    echo "当前节点是 $(proto_label)，没有 mmx 的 TLS 指纹。"
    return 1
  fi
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -n "$TLS_DOMAIN" ]; then
    "$SERVER_BIN" --print-pin --tls-domain "$TLS_DOMAIN" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" 2>&1
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    local sni_args=()
    if [ -n "${TLS_SNI:-}" ]; then sni_args=(--tls-sni "$TLS_SNI"); fi
    "$SERVER_BIN" --print-pin --tls-auto --tls-cert "$CFG_DIR/tls-cert.pem" --tls-key "$CFG_DIR/tls-key.pem" "${sni_args[@]}" 2>&1
  else
    echo "TLS 没开（真 TLS 和自签 TLS 都关着），没有指纹。想开请删除节点后用第 1 项重新添加（选域名走真 TLS）。"
    return 1
  fi
}

# 服务状态直接显示在主菜单最上方（不用选）；重启服务已从菜单删除，
# 改配置时 apply_config 自动重载 + 重启。show_status / restart_svc
# 已删除（只被主菜单调用过）；底层 svc_status / svc_restart 仍在，
# apply_config 和安装流程继续用它们。

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

# 7) 更新脚本：重新跑一键安装（UPDATE_ONLY 模式：只更新程序文件——
#    服务端二进制、管理菜单、服务文件；节点配置/端口/密钥/TLS/流量保留
#    不变，结束显示“更新完成”）。安装脚本在交互终端下会自动打开新菜单，
#    这里随后退出旧菜单，避免新旧两个菜单叠在一起。
#    更新失败（下载不到脚本）时不退出，留在菜单里。
update_script() {
  echo "正在更新脚本与程序文件（节点配置保留不变）……"
  curl -fsSL https://raw.githubusercontent.com/bestmiao/mm-x/main/install-mm-x-server.sh | bash
  echo "更新完成，旧菜单退出，输入 mmx 打开新菜单。"
  exit 0
}

# 6) 查看日志
show_logs() {
  load_config
  # XHTTP/ss2022 节点：看 xray 的日志，不是 mmx-server 的。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    if [ "$INIT_SYS" = "openrc" ]; then
      echo "没有 journalctl，请直接看：$(xray_log_cmd)"
    elif command -v journalctl >/dev/null 2>&1; then
      journalctl -u xray -n 50 --no-pager 2>&1 || echo "读日志失败"
    else
      echo "没有 journalctl，请直接看：$(xray_log_cmd)"
    fi
    return 0
  fi
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
  # XHTTP/ss2022 节点：流量是整机口径的 xray 统计（mmx-server 的 --traffic-status 不管它）。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    show_xray_traffic
    return $?
  fi
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  "$SERVER_BIN" --traffic-status --traffic-mode "${TRAFFIC_MODE:-total}" --traffic-period "${TRAFFIC_PERIOD:-monthly}" --traffic-start-day "${TRAFFIC_START_DAY:-1}" --traffic-limit-mode "${TRAFFIC_LIMIT_MODE:-throttle}" --traffic-quota "${TRAFFIC_QUOTA:-0}" --traffic-throttle-rate "${TRAFFIC_THROTTLE_RATE:-125K}" --traffic-file "$CFG_DIR/traffic.json" 2>&1
}

# 流量设置：统计模式 / 周期 / 起始日 / 限制模式 / 限额 / TC 限速值都能改，
# 改完走 apply_config（重载 + 重启，失败自动回滚）；只改限额/限制模式/
# TC 限速值不重置计数，改统计模式/周期/起始日会按新口径重算。
# 入口在第 3 项“编辑节点”子菜单第 5 项。
traffic_menu() {
  while true; do
    load_config; load_xray_config
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
    read -r -p "选项： " c || return 0
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
        TRAFFIC_QUOTA="$(normalize_bytes "$nq")"
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
        # XHTTP/ss2022 节点：清 xray 的流量统计（xray-traffic.json），不停 mmx-server。
        if [ "${PROTO:-mmx}" != "mmx" ]; then
          xray_watch_clear
          pause; continue
        fi
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

# 2) 谷歌服务：开/关只放行谷歌系域名（对 mmx、XHTTP、ss2022 都生效）；
#    点一下就切换：DOMAIN_WHITELIST 在 ""（关，全部放行）和 "google"（开，仅谷歌系）之间翻转，
#    写回配置后重启当前在跑的服务（mmx-server 或 xray）生效。
#    没节点时拒绝（否则会写出端口为空的坏配置）。
toggle_whitelist() {
  load_config; load_xray_config
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点，再开关谷歌服务。"; return 0; fi
  if [ "${DOMAIN_WHITELIST:-}" = "google" ]; then
    DOMAIN_WHITELIST=""
    apply_config "谷歌服务已关（全部放行）"
  else
    DOMAIN_WHITELIST="google"
    apply_config "谷歌服务已开（仅谷歌系域名，其他目标直接拒绝）"
  fi
}

# 诱饵回退 / TLS 设置（已从菜单移除；域名在添加节点时选，TLS 自动设置）：真 TLS（有域名）和自签 TLS（没域名）二选一；
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

# 域名一键设置：申请 Let's Encrypt 证书并切到真 TLS（添加节点选域名时调用；
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
    echo "真 TLS 已经开了（域名 $TLS_DOMAIN），想换域名请先删除节点再重新添加（选新域名）。"
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

# 诱饵回退 / TLS 菜单已从编辑节点移除（不再从菜单调用，函数保留在脚本内；
# 诱饵回退默认 site、TLS 在添加节点时自动设置，域名在添加节点时选）。
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
    read -r -p "选项： " c || return 0
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

# 1) 添加节点：向导式新建节点，依次问端口 / 流量限额 /
#    周期起始日 / 超限模式 / TC 限速值 / 域名，空输入用默认值；每项都校验，
#    不合法就重问；已有节点时先确认覆盖；写完走 apply_config
#    （重载 + 重启，失败自动回滚），再跑 setup_domain（填了域名才跑，
#    失败也不影响已建好的节点，域名可稍后用 mmx --setup-domain 再设）。
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
    read -r -p "选项 [1/2]： " choice || return 1
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

# ============ 多协议：Xray（XHTTP / ss2022） ============
# 节点协议 PROTO：mmx（自有协议，mmx-server）| xhttp（VLESS+XHTTP，Xray）| ss2022（Shadowsocks 2022，Xray）。
# 单节点模型：同一时间只有一个协议的节点在跑（mmx-server 和 xray 不同时运行，端口不会冲突）。
# Xray 的配置在 /usr/local/etc/xray/config.json（和 vx 同一份路径）；Xray 专属状态在 /etc/mmx/xray.conf。
# Xray 只在选了 XHTTP/ss2022 时才安装和启动；mmx 节点不碰 Xray。

proto_label() {
  case "${PROTO:-mmx}" in
    xhttp) echo "XHTTP" ;;
    ss2022) echo "ss2022" ;;
    *) echo "mmx" ;;
  esac
}

# 问建哪个协议的节点：1) mmx 2) XHTTP（VLESS） 3) ss2022。
# 成功返回 0，选中的协议写进 $ASK_PROTO；EOF/取消返回 1。
# 用法：ask_protocol [默认协议]，默认用当前 PROTO（没有就是 mmx）。
ASK_PROTO=""
ask_protocol() {
  local def="${1:-${PROTO:-mmx}}" choice
  case "$def" in mmx|xhttp|ss2022) ;; *) def="mmx" ;; esac
  ASK_PROTO=""
  while true; do
    echo "建哪个协议的节点？"
    echo "  1) mmx：自有协议（mmx:// 链接）"
    echo "  2) XHTTP：VLESS + XHTTP（vless:// 链接，上下行分离）"
    echo "  3) ss2022：Shadowsocks 2022（ss:// 链接）"
    local def_num=1
    case "$def" in xhttp) def_num=2 ;; ss2022) def_num=3 ;; esac
    read -r -p "选项 [1/2/3，默认 $def_num]： " choice || return 1
    [ -z "$choice" ] && choice="$def_num"
    case "$choice" in
      1|mmx) ASK_PROTO="mmx"; return 0 ;;
      2|xhttp) ASK_PROTO="xhttp"; return 0 ;;
      3|ss2022) ASK_PROTO="ss2022"; return 0 ;;
      *) echo "没有这个选项，请输入 1、2 或 3。" ;;
    esac
  done
}

# UUID 生成（和 vx 的 gen_uuid 一样）：优先用内核的随机 UUID，没有就用 openssl 拼一个 v4。
gen_uuid() {
  if [ -r /proc/sys/kernel/random/uuid ]; then
    cat /proc/sys/kernel/random/uuid
    return 0
  fi
  local hex
  hex="$(openssl rand -hex 16)"
  printf '%s-%s-4%s-8%s-%s\n' "${hex:0:8}" "${hex:8:4}" "${hex:13:3}" "${hex:17:3}" "${hex:20:12}"
}

# Reality 的 SNI 池（和 vx 的 sni_pool 一份）：按地区挑一个常见域名当 SNI。
sni_pool() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    hk|hongkong|香港) echo "www.hkust.edu.hk www.gov.hk www.hko.gov.hk www.hkpl.gov.hk" ;;
    jp|japan|日本) echo "www.yahoo.co.jp www.rakuten.co.jp www.osaka-u.ac.jp www.kyushu-u.ac.jp" ;;
    sg|singapore|新加坡) echo "www.shopee.sg www.lazada.sg www.mti.gov.sg www.acm.org.sg" ;;
    us|usa|america|美国) echo "www.whitney.org www.okstate.edu www.oregonstate.edu www.ufl.edu" ;;
    *) echo "www.hkust.edu.hk www.osaka-u.ac.jp www.mti.gov.sg www.whitney.org" ;;
  esac
}
region_to_sni() {
  local pool arr pick
  pool="$(sni_pool "$1")"
  arr=($pool)
  [ "${#arr[@]}" -eq 0 ] && { printf '%s' "www.hkust.edu.hk"; return 0; }
  pick="${arr[$((RANDOM % ${#arr[@]}))]}"
  printf '%s' "$pick"
}
region_label() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    hk|hongkong|香港) echo "香港" ;;
    jp|japan|日本) echo "日本" ;;
    sg|singapore|新加坡) echo "新加坡" ;;
    us|usa|america|美国) echo "美国" ;;
    custom|自定义) echo "自定义" ;;
    *) echo "$1" ;;
  esac
}
# 问 Reality 用哪个地区（决定 SNI 池）：1 香港 2 日本 3 新加坡 4 美国 5 自定义。
# 选中的地区写进 $ASK_REGION，SNI 写进 $ASK_REGION_SNI；EOF/取消返回 1。
ASK_REGION=""; ASK_REGION_SNI=""
ask_region() {
  local choice=""
  ASK_REGION=""; ASK_REGION_SNI=""
  echo "Reality 目标站地区（SNI 从这个地区的常见域名里挑）："
  echo "  1) 香港"
  echo "  2) 日本"
  echo "  3) 新加坡"
  echo "  4) 美国"
  echo "  5) 自定义（自己填一个域名）"
  read -r -p "选项 [1-5，默认 4]： " choice || return 1
  [ -z "$choice" ] && choice="4"
  case "$choice" in
    1) ASK_REGION="hk" ;;
    2) ASK_REGION="jp" ;;
    3) ASK_REGION="sg" ;;
    4) ASK_REGION="us" ;;
    5) ASK_REGION="custom" ;;
    hk|jp|sg|us|custom) ASK_REGION="$choice" ;;
    *) echo "没有这个选项，默认用美国。"; ASK_REGION="us" ;;
  esac
  if [ "$ASK_REGION" = "custom" ]; then
    while true; do
      read -r -p "目标站域名： " ASK_REGION_SNI || return 1
      if valid_domain "$ASK_REGION_SNI"; then break; fi
      echo "域名不对：$ASK_REGION_SNI（应为域名，例如 example.com）"
    done
  else
    ASK_REGION_SNI="$(region_to_sni "$ASK_REGION")"
  fi
  return 0
}

# Xray 服务操作（和 mmx-server 的 svc_* 对应，分开写：两个服务不同时运行）。
xray_is_active() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service xray status >/dev/null 2>&1; else systemctl is-active --quiet xray 2>/dev/null; fi
}
xray_start() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service xray start 2>/dev/null; else systemctl start xray 2>/dev/null; fi
}
xray_stop() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service xray stop 2>/dev/null; else systemctl stop xray 2>/dev/null; fi
}
xray_restart() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-service xray restart 2>/dev/null; else systemctl restart xray 2>/dev/null; fi
}
xray_enable() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-update add xray default 2>/dev/null; else systemctl enable xray >/dev/null 2>&1; fi
}
xray_disable() {
  if [ "$INIT_SYS" = "openrc" ]; then rc-update del xray default 2>/dev/null; else systemctl disable xray 2>/dev/null; fi
}
xray_status_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "rc-service xray status"; else echo "systemctl status xray"; fi
}
xray_log_cmd() {
  if [ "$INIT_SYS" = "openrc" ]; then echo "tail -n 50 /var/log/messages"; else echo "journalctl -u xray -n 50"; fi
}

# 装 Xray（二进制 + jq）：XHTTP/ss2022 节点才需要；mmx 节点不装。
# 已装就直接用；测试模式（MMX_TEST_ROOT）下写一个替身 xray（不下载），
# 供测试覆盖 XHTTP/ss2022 流程；生产环境走官方 Xray-install 脚本。
# 装完在 /etc/mmx/xray-installed 留个标记（卸载时只删自己装的 xray）。
ensure_xray() {
  # 测试模式（MMX_TEST_ROOT）优先：不管系统里有没有真 xray，都装替身，
  # 否则测试会被系统 PATH 里的真 xray 抢走（输出格式、行为都不受控）。
  if [ -n "${MMX_TEST_ROOT:-}" ]; then
    echo "测试模式：安装替身 xray（不下载）"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/xray" <<'XRAY_STUB_EOF'
#!/bin/bash
# 测试替身 xray：只认 version / x25519 / run -test -config / tls ping。
# x25519 的输出格式和真 xray 一样（PrivateKey: / Password (PublicKey): / Hash32:）。
case "$1" in
  version) echo "Xray 25.11.9 (test stub)"; exit 0 ;;
  x25519)
    if [ "$2" = "-i" ]; then
      echo "Password (PublicKey): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    else
      echo "PrivateKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
      echo "Password (PublicKey): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      echo "Hash32: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    fi
    exit 0 ;;
  run)
    if [ "$2" = "-test" ]; then
      cfg=""; prev=""
      for a in "$@"; do
        if [ "$prev" = "-config" ]; then cfg="$a"; fi
        prev="$a"
      done
      [ -n "$cfg" ] || { echo "替身 xray：run -test 需要 -config" >&2; exit 1; }
      jq -e . "$cfg" >/dev/null 2>&1 || { echo "替身 xray：配置不是合法 JSON" >&2; exit 1; }
      exit 0
    fi
    exit 0 ;;
  tls) exit 0 ;;
  *) echo "替身 xray 不认识：$*" >&2; exit 1 ;;
esac
XRAY_STUB_EOF
    chmod +x "$BIN_DIR/xray"
    mkdir -p "$CFG_DIR"
    touch "$XRAY_INSTALLED_MARKER"
    # OpenRC：和生产分支一样，补一个 /etc/init.d/xray。
    if [ "$INIT_SYS" = "openrc" ]; then
      mkdir -p "$INIT_DIR"
      cat > "$INIT_DIR/xray" <<'XRAY_INIT_EOF'
#!/sbin/openrc-run
# xray server (managed by mmx menu)
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
depend() {
  need net
  after firewall
}
XRAY_INIT_EOF
      chmod +x "$INIT_DIR/xray"
    fi
    return 0
  fi
  if command -v xray >/dev/null 2>&1; then return 0; fi
  # 生产环境：先装依赖（curl/jq/unzip），再走官方 Xray-install 脚本。
  echo "正在安装 Xray（XHTTP/ss2022 节点需要）……"
  if command -v apt-get >/dev/null 2>&1; then
    (apt-get update -qq && apt-get install -y -qq curl jq unzip ca-certificates) >/dev/null 2>&1 || { echo "依赖安装失败（curl/jq/unzip），请手动安装后再试。"; return 1; }
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl jq unzip ca-certificates >/dev/null 2>&1 || { echo "依赖安装失败（curl/jq/unzip），请手动安装后再试。"; return 1; }
  else
    echo "没找到 apt-get 或 apk，装不了 Xray 依赖（curl/jq/unzip），请手动安装后再试。"
    return 1
  fi
  local tmpd
  tmpd="$(mktemp -d)"
  if ! curl -fsSL -o "$tmpd/install-release.sh" https://github.com/XTLS/Xray-install/raw/main/install-release.sh; then
    echo "下载 Xray 安装脚本失败，请检查网络。"
    rm -rf "$tmpd"
    return 1
  fi
  if ! bash "$tmpd/install-release.sh" install; then
    echo "Xray 安装失败，请检查网络或手动安装后再试。"
    rm -rf "$tmpd"
    return 1
  fi
  rm -rf "$tmpd"
  command -v xray >/dev/null 2>&1 || { echo "Xray 安装后仍找不到 xray 命令。"; return 1; }
  mkdir -p "$CFG_DIR"
  touch "$XRAY_INSTALLED_MARKER"
  # OpenRC/Alpine：官方安装脚本只写 systemd 单元，这里补一个 /etc/init.d/xray。
  if [ "$INIT_SYS" = "openrc" ]; then
    mkdir -p "$INIT_DIR"
    cat > "$INIT_DIR/xray" <<'XRAY_INIT_EOF'
#!/sbin/openrc-run
# xray server (managed by mmx menu)
command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
depend() {
  need net
  after firewall
}
XRAY_INIT_EOF
    chmod +x "$INIT_DIR/xray"
  fi
  echo "Xray 已安装：$(xray version 2>/dev/null | head -n 1)"
  return 0
}

# 白名单要用的 geosite.dat：没有就补装（和 vx 一样走 Xray-install 的 update-geodata）。
# 测试模式下跳过（不下载，配置里的路由规则照写，校验只看 JSON）。
ensure_geosite() {
  local dat="$ROOT/usr/local/share/xray/geosite.dat"
  [ -s "$dat" ] && return 0
  if [ -n "${MMX_TEST_ROOT:-}" ]; then
    echo "测试模式：跳过 geosite.dat 补装"
    return 0
  fi
  echo "正在补装 geosite.dat（白名单要用）……"
  local tmpd
  tmpd="$(mktemp -d)"
  curl -fsSL -o "$tmpd/install-release.sh" https://github.com/XTLS/Xray-install/raw/main/install-release.sh || { echo "下载 Xray 安装脚本失败。"; rm -rf "$tmpd"; return 1; }
  bash "$tmpd/install-release.sh" update-geodata || { echo "geosite.dat 补装失败。"; rm -rf "$tmpd"; return 1; }
  rm -rf "$tmpd"
  [ -s "$dat" ] || { echo "缺少 geosite.dat，白名单无法使用。"; return 1; }
  return 0
}

# 按当前配置写 Xray 配置（/usr/local/etc/xray/config.json）：
# XHTTP = VLESS 入站 + XHTTP 传输（Reality 或 TLS），ss2022 = Shadowsocks 入站。
# 只在 PROTO 是 xhttp/ss2022 时调用；写完用 xray run -test 校验（失败返回 1）。
write_xray_config() {
  load_config; load_xray_config
  command -v jq >/dev/null 2>&1 || { echo "写 Xray 配置需要 jq，请先安装 jq。"; return 1; }
  command -v xray >/dev/null 2>&1 || { echo "Xray 没装，请先安装 Xray。"; return 1; }
  [ -n "$PORT" ] || { echo "还没有节点，请先用第 1 项添加节点。"; return 1; }
  mkdir -p "$(dirname "$XRAY_CFG_FILE")"
  local wl="false"
  # 谷歌服务（菜单第 2 项）对 XHTTP 和 ss2022 都生效（geosite:google 路由，
  # 和 vx 一样；只放行谷歌系域名，其他目标直接拒绝）。
  case "$PROTO" in
    xhttp|ss2022)
      if [ "${DOMAIN_WHITELIST:-}" = "google" ]; then
        ensure_geosite || { echo "白名单需要 geosite.dat，补装失败。"; return 1; }
        wl="true"
      fi
      ;;
  esac
  if [ "$PROTO" = "xhttp" ]; then
    [ -n "$XHTTP_UUID" ] || { echo "XHTTP 配置不完整（缺 UUID），请重新添加节点。"; return 1; }
    if [ "$XHTTP_MODE" = "tls" ]; then
      [ -n "$XHTTP_SNI" ] && [ -n "$XHTTP_CERT" ] && [ -n "$XHTTP_KEY" ] || { echo "XHTTP TLS 模式配置不完整（缺域名/证书），请重新添加节点。"; return 1; }
      [ -f "$XHTTP_CERT" ] && [ -f "$XHTTP_KEY" ] || { echo "XHTTP TLS 证书文件不存在，请重新添加节点。"; return 1; }
      jq -n \
        --argjson port "$PORT" \
        --arg uuid "$XHTTP_UUID" \
        --arg path "$XHTTP_PATH" \
        --arg cert "$XHTTP_CERT" \
        --arg key "$XHTTP_KEY" \
        --argjson whitelist "$wl" \
        '{
          log: {loglevel: "warning"},
          inbounds: [{
            listen: "0.0.0.0",
            port: $port,
            protocol: "vless",
            settings: {clients: [{id: $uuid, email: "user"}], decryption: "none"},
            streamSettings: {
              network: "xhttp",
              xhttpSettings: {path: $path, mode: "auto"},
              security: "tls",
              tlsSettings: {certificates: [{certificateFile: $cert, keyFile: $key}]}
            },
            sniffing: {enabled: true, destOverride: ["http", "tls", "quic"]}
          }],
          outbounds: [
            {protocol: "freedom", tag: "direct"},
            {protocol: "blackhole", tag: "blocked"}
          ]
        } | if $whitelist then
          .routing = {rules: [
            {type: "field", domain: ["geosite:google"], outboundTag: "direct"},
            {type: "field", network: "tcp,udp", outboundTag: "blocked"}
          ]}
        else . end' > "$XRAY_CFG_FILE.tmp"
    else
      [ -n "$XHTTP_SNI" ] && [ -n "$XHTTP_PRIVKEY" ] && [ -n "$XHTTP_SHORTID" ] || { echo "XHTTP Reality 配置不完整（缺 SNI/密钥），请重新添加节点。"; return 1; }
      jq -n \
        --argjson port "$PORT" \
        --arg uuid "$XHTTP_UUID" \
        --arg path "$XHTTP_PATH" \
        --arg target "$XHTTP_SNI" \
        --arg priv "$XHTTP_PRIVKEY" \
        --arg sid "$XHTTP_SHORTID" \
        --argjson whitelist "$wl" \
        '{
          log: {loglevel: "warning"},
          inbounds: [{
            listen: "0.0.0.0",
            port: $port,
            protocol: "vless",
            settings: {clients: [{id: $uuid, email: "user"}], decryption: "none"},
            streamSettings: {
              network: "xhttp",
              xhttpSettings: {path: $path, mode: "auto"},
              security: "reality",
              realitySettings: {show: false, target: ($target + ":443"), xver: 0,
                serverNames: [$target], privateKey: $priv, shortIds: [$sid], maxTimeDiff: 60000}
            },
            sniffing: {enabled: true, destOverride: ["http", "tls", "quic"]}
          }],
          outbounds: [
            {protocol: "freedom", tag: "direct"},
            {protocol: "blackhole", tag: "blocked"}
          ]
        } | if $whitelist then
          .routing = {rules: [
            {type: "field", domain: ["geosite:google"], outboundTag: "direct"},
            {type: "field", network: "tcp,udp", outboundTag: "blocked"}
          ]}
        else . end' > "$XRAY_CFG_FILE.tmp"
    fi
  elif [ "$PROTO" = "ss2022" ]; then
    [ -n "$SS_PASSWORD" ] || { echo "ss2022 配置不完整（缺密码），请重新添加节点。"; return 1; }
    jq -n \
      --argjson port "$PORT" \
      --arg method "$SS_METHOD" \
      --arg password "$SS_PASSWORD" \
      --argjson whitelist "$wl" \
      '{
        log: {loglevel: "warning"},
        inbounds: [{
          listen: "0.0.0.0",
          port: $port,
          protocol: "shadowsocks",
          settings: {method: $method, password: $password, network: "tcp,udp"},
          sniffing: {enabled: true, destOverride: ["http", "tls", "quic"]}
        }],
        outbounds: [
          {protocol: "freedom", tag: "direct"},
          {protocol: "blackhole", tag: "blocked"}
        ]
      } | if $whitelist then
        .routing = {rules: [
          {type: "field", domain: ["geosite:google"], outboundTag: "direct"},
          {type: "field", network: "tcp,udp", outboundTag: "blocked"}
        ]}
      else . end' > "$XRAY_CFG_FILE.tmp"
  else
    echo "当前节点不是 Xray 协议（PROTO=$PROTO），不用写 Xray 配置。"
    return 1
  fi
  jq -e . "$XRAY_CFG_FILE.tmp" >/dev/null || { echo "Xray 配置不是合法 JSON"; return 1; }
  mv "$XRAY_CFG_FILE.tmp" "$XRAY_CFG_FILE"
  if ! xray run -test -config "$XRAY_CFG_FILE" >/dev/null 2>&1; then
    echo "Xray 配置校验失败（xray run -test），请看日志：$(xray_log_cmd)"
    return 1
  fi
  return 0
}

# 拼 Xray 节点的链接（给 show_link / show_nodes 用）：
# XHTTP = vless://UUID@地址:端口?...；ss2022 = ss://base64(方法:密码)@地址:端口#节点名。
# 只把链接打到标准输出；失败时空。地址是链接里用的 host（域名或 IP）。
build_xray_link() {
  local host="${1:-}"
  load_config; load_xray_config
  [ -n "$PORT" ] || return 1
  if [ -z "$host" ]; then host="${HOST:-}"; fi
  if [ -z "$host" ]; then host="$(detect_public_ip)"; fi
  if [ -z "$host" ]; then host="<你的 VPS 公网 IP>"; fi
  local name_enc
  name_enc="$(printf '%s' "$NAME" | sed 's/ /%20/g')"
  if [ "$PROTO" = "xhttp" ]; then
    [ -n "$XHTTP_UUID" ] && [ -n "$XHTTP_SNI" ] || return 1
    local enc_path link
    enc_path="$(printf '%s' "$XHTTP_PATH" | sed 's|/|%2F|g')"
    if [ "$XHTTP_MODE" = "reality" ]; then
      link="vless://$XHTTP_UUID@$host:$PORT?encryption=none&security=reality&sni=$XHTTP_SNI&fp=chrome&pbk=$XHTTP_PUBKEY&sid=$XHTTP_SHORTID&type=xhttp&path=$enc_path"
    else
      link="vless://$XHTTP_UUID@$host:$PORT?encryption=none&security=tls&sni=$XHTTP_SNI&fp=chrome&type=xhttp&path=$enc_path"
    fi
    if [ "${XHTTP_SPLIT:-1}" = "1" ]; then
      link="$link&mode=stream-up"
    else
      link="$link&mode=auto"
    fi
    link="$link#$name_enc"
    printf '%s\n' "$link"
    return 0
  elif [ "$PROTO" = "ss2022" ]; then
    [ -n "$SS_PASSWORD" ] || return 1
    local userinfo link
    userinfo="$(printf '%s:%s' "$SS_METHOD" "$SS_PASSWORD" | openssl base64 -A | tr '+/' '-_' | tr -d '=' | tr -d '\n')"
    link="ss://$userinfo@$host:$PORT#$name_enc"
    printf '%s\n' "$link"
    return 0
  fi
  return 1
}

# 写 XHTTP 上下行分离的客户端配置（和 vx 的 write_outputs 一样，单机分离：
# 上传和下载走同一台服务器、同一个入站、同一个路径，mode=stream-up）。
# 分离配置 A 是 Xray 客户端 JSON，B 是 sing-box JSON；分流关时删掉这两个文件。
# 只有 PROTO=xhttp 且 XHTTP_SPLIT=1 时写；失败返回 1。
write_split_files() {
  load_config; load_xray_config
  if [ "$PROTO" != "xhttp" ] || [ "${XHTTP_SPLIT:-1}" != "1" ]; then
    rm -f "$XRAY_SPLIT_A" "$XRAY_SPLIT_B"
    return 0
  fi
  command -v jq >/dev/null 2>&1 || { echo "写分离配置需要 jq，请先安装 jq。"; return 1; }
  [ -n "$XHTTP_UUID" ] && [ -n "$XHTTP_SNI" ] || { echo "XHTTP 配置不完整，写不了分离配置。"; return 1; }
  local addr
  if [ "$XHTTP_MODE" = "tls" ]; then
    addr="$XHTTP_SNI"
  elif [ -n "${HOST:-}" ]; then
    addr="$HOST"
  else
    addr="$(detect_public_ip)"
  fi
  [ -n "$addr" ] || { echo "探测不到服务器地址，写不了分离配置。"; return 1; }
  if [ "$XHTTP_MODE" = "reality" ]; then
    jq -n \
      --arg addr "$addr" --argjson port "$PORT" \
      --arg uuid "$XHTTP_UUID" --arg path "$XHTTP_PATH" \
      --arg sni "$XHTTP_SNI" --arg pub "$XHTTP_PUBKEY" --arg sid "$XHTTP_SHORTID" \
      --arg baddr "$addr" --argjson bport "$PORT" \
      '{
        outbounds: [{
          protocol: "vless",
          settings: {vnext: [{address: $addr, port: $port, users: [{id: $uuid, encryption: "none"}]}]},
          streamSettings: {
            network: "xhttp",
            security: "reality",
            realitySettings: {serverName: $sni, publicKey: $pub, shortId: $sid, fingerprint: "chrome"},
            xhttpSettings: {path: $path, mode: "stream-up",
              extra: {downloadSettings: {address: $baddr, port: $bport, network: "xhttp",
                security: "reality",
                realitySettings: {serverName: $sni, publicKey: $pub, shortId: $sid},
                xhttpSettings: {path: $path}}}}
          }
        }]
      }' > "$XRAY_SPLIT_A.tmp"
  else
    jq -n \
      --arg addr "$addr" --argjson port "$PORT" \
      --arg uuid "$XHTTP_UUID" --arg path "$XHTTP_PATH" \
      --arg sni "$XHTTP_SNI" \
      --arg baddr "$addr" --argjson bport "$PORT" \
      '{
        outbounds: [{
          protocol: "vless",
          settings: {vnext: [{address: $addr, port: $port, users: [{id: $uuid, encryption: "none"}]}]},
          streamSettings: {
            network: "xhttp",
            security: "tls",
            tlsSettings: {serverName: $sni},
            xhttpSettings: {path: $path, mode: "stream-up",
              extra: {downloadSettings: {address: $baddr, port: $bport, network: "xhttp",
                security: "tls",
                tlsSettings: {serverName: $sni},
                xhttpSettings: {path: $path}}}}
          }
        }]
      }' > "$XRAY_SPLIT_A.tmp"
  fi
  jq -e . "$XRAY_SPLIT_A.tmp" >/dev/null || { echo "分离配置 A 不是合法 JSON"; return 1; }
  mv "$XRAY_SPLIT_A.tmp" "$XRAY_SPLIT_A"
  if [ "$XHTTP_MODE" = "reality" ]; then
    jq -n \
      --arg server "$addr" --argjson server_port "$PORT" \
      --arg uuid "$XHTTP_UUID" --arg sni "$XHTTP_SNI" --arg pub "$XHTTP_PUBKEY" --arg sid "$XHTTP_SHORTID" \
      --arg path "$XHTTP_PATH" --arg dserver "$addr" --argjson dport "$PORT" \
      '{
        type: "vless",
        server: $server,
        server_port: $server_port,
        uuid: $uuid,
        tls: {enabled: true, server_name: $sni,
          reality: {enabled: true, public_key: $pub, short_id: $sid}},
        transport: {type: "xhttp", path: $path, mode: "stream-up",
          download_settings: {server: $dserver, server_port: $dport,
            tls: {enabled: true, server_name: $sni,
              reality: {enabled: true, public_key: $pub, short_id: $sid}},
            path: $path}}
      }' > "$XRAY_SPLIT_B.tmp"
  else
    jq -n \
      --arg server "$addr" --argjson server_port "$PORT" \
      --arg uuid "$XHTTP_UUID" --arg sni "$XHTTP_SNI" \
      --arg path "$XHTTP_PATH" --arg dserver "$addr" --argjson dport "$PORT" \
      '{
        type: "vless",
        server: $server,
        server_port: $server_port,
        uuid: $uuid,
        tls: {enabled: true, server_name: $sni},
        transport: {type: "xhttp", path: $path, mode: "stream-up",
          download_settings: {server: $dserver, server_port: $dport,
            tls: {enabled: true, server_name: $sni},
            path: $path}}
      }' > "$XRAY_SPLIT_B.tmp"
  fi
  jq -e . "$XRAY_SPLIT_B.tmp" >/dev/null || { echo "分离配置 B 不是合法 JSON"; return 1; }
  mv "$XRAY_SPLIT_B.tmp" "$XRAY_SPLIT_B"
  chmod 600 "$XRAY_SPLIT_A" "$XRAY_SPLIT_B"
  return 0
}

# 写 Xray 节点信息文件（/etc/mmx/xray-info.txt）：地址/端口/模式/链接/分离配置路径/流量设置。
# show_nodes 直接读它（和 vx 的 INFO_FILE 一样）。
write_xray_info() {
  load_config; load_xray_config
  local link addr
  link="$(build_xray_link)"
  if [ "$PROTO" = "xhttp" ] && [ "$XHTTP_MODE" = "tls" ]; then
    addr="$XHTTP_SNI"
  elif [ -n "${HOST:-}" ]; then
    addr="$HOST"
  else
    addr="$(detect_public_ip)"
    [ -z "$addr" ] && addr="<你的 VPS 公网 IP>"
  fi
  {
    echo "协议：$(proto_label)"
    echo "地址：$addr"
    echo "端口：$PORT"
    if [ "$PROTO" = "xhttp" ]; then
      if [ "$XHTTP_MODE" = "reality" ]; then echo "模式：Reality"; else echo "模式：TLS"; fi
      echo "SNI：$XHTTP_SNI"
      if [ "$XHTTP_MODE" = "reality" ]; then
        echo "公钥：$XHTTP_PUBKEY"
        echo "短 ID：$XHTTP_SHORTID"
        [ -n "$XHTTP_REGION" ] && echo "地区：$(region_label "$XHTTP_REGION")"
      fi
      echo "路径：$XHTTP_PATH"
      if [ "${XHTTP_SPLIT:-1}" = "1" ]; then
        echo "分流：开"
        echo "分离配置 A：$XRAY_SPLIT_A"
        echo "分离配置 B：$XRAY_SPLIT_B"
      else
        echo "分流：关"
      fi
    else
      echo "加密：$SS_METHOD"
    fi
    echo "统计：$(traffic_mode_label)"
    [ "${DOMAIN_WHITELIST:-}" = "google" ] && echo "白名单：仅谷歌系"
    echo "范围：整机"
    echo "周期：$(traffic_period_label)"
    echo "起始日：${TRAFFIC_START_DAY:-1}"
    echo "限制：$(traffic_limit_label)"
    if [ "${TRAFFIC_QUOTA:-0}" = "0" ]; then echo "限额：不限"; else echo "限额：$TRAFFIC_QUOTA"; fi
    echo "流量文件：$XRAY_TRAFFIC_FILE"
    echo "链接："
    echo "$link"
  } > "$XRAY_INFO_FILE"
  chmod 600 "$XRAY_INFO_FILE"
}

# ---- Xray 节点流量统计与限额（整机口径，和 vx 的 traffic-watch 同一个做法） ----
# 设置从 /etc/mmx/config 读（TRAFFIC_*）；计数存在 /etc/mmx/xray-traffic.json；
# 每分钟跑一次（systemd timer / OpenRC cron 调 mmx --xray-watch run）。
# 超限后：block = 停 xray；throttle = TC 限速（只针对 Xray 端口）。
# 周期算法（月/季/年、起始日）和 vx 的 period_bounds 一份。

# 数字 + K/M/G/T 转字节数（180G、125K、0）；非法返回 1。
xray_to_bytes() {
  local s mult=1
  s="$(printf '%s' "$1" | tr -d ' \t\r\n')"
  [ -z "$s" ] && { echo 0; return 0; }
  case "$s" in
    *K|*k) mult=1024; s="${s%?}" ;;
    *M|*m) mult=1048576; s="${s%?}" ;;
    *G|*g) mult=1073741824; s="${s%?}" ;;
    *T|*t) mult=1099511627776; s="${s%?}" ;;
  esac
  case "$s" in ''|*[!0-9]*) return 1 ;; esac
  awk -v n="$s" -v m="$mult" 'BEGIN { printf "%.0f", n * m }'
}

# 字节数转人类可读（和 mmx-server 的 FormatBytesHuman 对齐：500.00 GB）。
xray_fmt_bytes() {
  local b="$1"
  case "$b" in ''|*[!0-9]*) b=0 ;; esac
  if [ "$b" -lt 1024 ]; then printf '%s B' "$b"; return 0; fi
  awk -v b="$b" 'BEGIN {
    if (b < 1048576) printf "%.2f KB", b/1024;
    else if (b < 1073741824) printf "%.2f MB", b/1048576;
    else if (b < 1099511627776) printf "%.2f GB", b/1073741824;
    else printf "%.2f TB", b/1099511627776;
  }'
}

# 某年某月有几天
xray_dim() {
  date -d "$1-$2-01 +1 month -1 day" +%d
}
# 周期锚点：y 年 m 月 d 日（d 超出当月天数时按最后一天算），输出 epoch 秒
xray_anchor_epoch() {
  local y=$1 m=$2 d=$3 last
  last=$(xray_dim "$y" "$m")
  [ "$d" -gt "$last" ] && d=$last
  date -d "$y-$m-01 +$((d - 1)) days" +%s
}
xray_add_months() {
  local total=$(( $1 * 12 + $2 - 1 + $3 ))
  printf '%s %s' "$(( total / 12 ))" "$(( total % 12 + 1 ))"
}
# 周期边界：输入 now epoch、周期、起始日，输出 "开始 epoch 结束 epoch"
xray_period_bounds() {
  local now=$1 period=$2 d=$3 y m s e qm
  y=$(date -d "@$now" +%Y)
  m=$(date -d "@$now" +%m); m=$((10#$m))
  case "$period" in
    quarterly)
      qm=$(( (m - 1) / 3 * 3 + 1 ))
      s=$(xray_anchor_epoch "$y" "$qm" "$d")
      if [ "$s" -gt "$now" ]; then
        read -r y qm <<< "$(xray_add_months "$y" "$qm" -3)"
        s=$(xray_anchor_epoch "$y" "$qm" "$d")
      fi
      read -r y qm <<< "$(xray_add_months "$y" "$qm" 3)"
      e=$(xray_anchor_epoch "$y" "$qm" "$d")
      ;;
    yearly)
      s=$(xray_anchor_epoch "$y" 1 "$d")
      if [ "$s" -gt "$now" ]; then s=$(xray_anchor_epoch "$((y - 1))" 1 "$d"); fi
      e=$(xray_anchor_epoch "$(( $(date -d "@$s" +%Y) + 1 ))" 1 "$d")
      ;;
    *)
      s=$(xray_anchor_epoch "$y" "$m" "$d")
      if [ "$s" -gt "$now" ]; then
        read -r y m <<< "$(xray_add_months "$y" "$m" -1)"
        s=$(xray_anchor_epoch "$y" "$m" "$d")
      fi
      read -r y m <<< "$(xray_add_months "$y" "$m" 1)"
      e=$(xray_anchor_epoch "$y" "$m" "$d")
      ;;
  esac
  printf '%s %s' "$s" "$e"
}

# 流量统计的网卡：XRAY_IFACE 指定就用它，否则走默认路由的网卡。
xray_detect_iface() {
  local sysfs="${MMX_XRAY_SYSFS_ROOT:-/sys/class/net}" iface=""
  if [ -n "${XRAY_IFACE:-}" ] && [ -d "$sysfs/$XRAY_IFACE/statistics" ]; then
    printf '%s' "$XRAY_IFACE"; return 0
  fi
  iface="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i == "dev") {print $(i+1); exit}}')"
  [ -z "$iface" ] && iface="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
  [ -z "$iface" ] && iface="eth0"
  printf '%s' "$iface"
}

# TC 限速是否已生效（只看 Xray 端口的 HTB 规则在不在）
xray_tc_present() {
  local iface
  iface="$(xray_detect_iface)"
  command -v tc >/dev/null 2>&1 || return 1
  tc qdisc show dev "$iface" 2>/dev/null | grep -q "htb 1:"
}
# TC 限速：超限后把 Xray 端口的流量降到 TRAFFIC_THROTTLE_RATE（和 vx 的 tc_apply 一份）。
xray_tc_apply() {
  local rate_bps kbit iface
  rate_bps="$(xray_to_bytes "${TRAFFIC_THROTTLE_RATE:-125K}")" || return 0
  kbit=$(( rate_bps * 8 / 1024 ))
  [ "$kbit" -lt 8 ] && kbit=8
  command -v tc >/dev/null 2>&1 || return 0
  iface="$(xray_detect_iface)"
  tc qdisc replace dev "$iface" root handle 1: htb default 30 2>/dev/null || return 0
  tc class replace dev "$iface" parent 1: classid 1:1 htb rate 10000mbit 2>/dev/null || true
  tc class replace dev "$iface" parent 1:1 classid 1:10 htb rate "${kbit}kbit" ceil "${kbit}kbit" 2>/dev/null || true
  tc class replace dev "$iface" parent 1:1 classid 1:30 htb rate 10000mbit ceil 10000mbit 2>/dev/null || true
  tc qdisc replace dev "$iface" parent 1:10 handle 10: fq 2>/dev/null || true
  tc qdisc replace dev "$iface" parent 1:30 handle 30: fq 2>/dev/null || true
  tc filter replace dev "$iface" parent 1: protocol ip prio 1 u32 match ip sport "$PORT" 0xffff flowid 1:10 2>/dev/null || true
  tc qdisc replace dev "$iface" handle ffff: ingress 2>/dev/null || true
  tc filter replace dev "$iface" parent ffff: protocol ip prio 1 u32 match ip dport "$PORT" 0xffff police rate "${kbit}kbit" burst 64kbit drop 2>/dev/null || true
}
xray_tc_clear() {
  local iface
  command -v tc >/dev/null 2>&1 || return 0
  iface="$(xray_detect_iface)"
  tc qdisc del dev "$iface" root 2>/dev/null || true
  tc qdisc del dev "$iface" handle ffff: ingress 2>/dev/null || true
}

# 流量监视跑一次（定时任务调）：读网卡计数 → 累加 → 周期到了就重置 → 超限就执行限制。
# 只有 Xray 节点才跑；mmx 节点走 mmx-server 自己的流量统计。
xray_watch_run() {
  load_config
  if [ "${PROTO:-mmx}" = "mmx" ]; then return 0; fi
  [ -n "$PORT" ] || return 0
  command -v jq >/dev/null 2>&1 || return 0
  local sysfs iface rx tx now
  sysfs="${MMX_XRAY_SYSFS_ROOT:-/sys/class/net}"
  iface="$(xray_detect_iface)"
  [ -d "$sysfs/$iface/statistics" ] || return 0
  rx="$(cat "$sysfs/$iface/statistics/rx_bytes" 2>/dev/null || echo "")"
  tx="$(cat "$sysfs/$iface/statistics/tx_bytes" 2>/dev/null || echo "")"
  case "$rx" in ''|*[!0-9]*) return 0 ;; esac
  case "$tx" in ''|*[!0-9]*) return 0 ;; esac
  now="$(date +%s)"
  local in=0 out=0 last_in=0 last_out=0 p_start=0 p_end=0 enforced=""
  if [ -f "$XRAY_TRAFFIC_FILE" ]; then
    in="$(jq -r '.in // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    out="$(jq -r '.out // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    last_in="$(jq -r '.last_in // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    last_out="$(jq -r '.last_out // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    p_start="$(jq -r '.period_start // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    p_end="$(jq -r '.period_end // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    enforced="$(jq -r '.enforced // ""' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo "")"
  fi
  case "$in" in ''|*[!0-9]*) in=0 ;; esac
  case "$out" in ''|*[!0-9]*) out=0 ;; esac
  case "$last_in" in ''|*[!0-9]*) last_in=0 ;; esac
  case "$last_out" in ''|*[!0-9]*) last_out=0 ;; esac
  case "$p_start" in ''|*[!0-9]*) p_start=0 ;; esac
  case "$p_end" in ''|*[!0-9]*) p_end=0 ;; esac
  # 周期变了（设置改了 / 周期到了 / 首次跑）：计数清零，限制解除。
  if [ "$p_end" -le "$now" ] || [ "$p_start" -eq 0 ]; then
    if [ "$enforced" = "block" ]; then xray_start 2>/dev/null || true; fi
    if [ "$enforced" = "throttle" ]; then xray_tc_clear; fi
    in=0; out=0; enforced=""
    read -r p_start p_end <<< "$(xray_period_bounds "$now" "${TRAFFIC_PERIOD:-monthly}" "${TRAFFIC_START_DAY:-1}")"
    last_in=$rx; last_out=$tx
  fi
  if [ "$rx" -ge "$last_in" ]; then in=$(( in + rx - last_in )); fi
  if [ "$tx" -ge "$last_out" ]; then out=$(( out + tx - last_out )); fi
  last_in=$rx; last_out=$tx
  local counted quota_bps
  case "${TRAFFIC_MODE:-total}" in
    outbound) counted=$out ;;
    inbound) counted=$in ;;
    max) [ "$in" -gt "$out" ] && counted=$in || counted=$out ;;
    *) counted=$(( in + out )) ;;
  esac
  quota_bps="$(xray_to_bytes "${TRAFFIC_QUOTA:-0}")" || quota_bps=0
  if [ "$quota_bps" -gt 0 ] && [ "$counted" -ge "$quota_bps" ]; then
    if [ "${TRAFFIC_LIMIT_MODE:-throttle}" = "throttle" ]; then
      if [ "$enforced" != "throttle" ] || ! xray_tc_present; then xray_tc_apply; fi
      enforced="throttle"
    else
      if xray_is_active; then xray_stop 2>/dev/null || true; fi
      enforced="block"
    fi
  else
    if [ "$enforced" = "block" ]; then xray_start 2>/dev/null || true; fi
    if [ "$enforced" = "throttle" ]; then xray_tc_clear; fi
    enforced=""
  fi
  mkdir -p "$CFG_DIR"
  jq -n \
    --argjson in "$in" --argjson out "$out" \
    --argjson last_in "$last_in" --argjson last_out "$last_out" \
    --argjson period_start "$p_start" --argjson period_end "$p_end" \
    --arg enforced "$enforced" \
    '{in: $in, out: $out, last_in: $last_in, last_out: $last_out,
      period_start: $period_start, period_end: $period_end, enforced: $enforced}' > "$XRAY_TRAFFIC_FILE.tmp" 2>/dev/null || return 0
  mv "$XRAY_TRAFFIC_FILE.tmp" "$XRAY_TRAFFIC_FILE" 2>/dev/null || true
  chmod 600 "$XRAY_TRAFFIC_FILE" 2>/dev/null || true
  return 0
}

# 清零 Xray 节点本周期流量（解除限制，计数从 0 开始）。
xray_watch_clear() {
  load_config
  if [ "${PROTO:-mmx}" = "mmx" ]; then return 0; fi
  xray_stop 2>/dev/null || true
  rm -f "$XRAY_TRAFFIC_FILE"
  if xray_restart && xray_is_active; then
    echo "已清零：本周期流量从 0 重新开始统计"
  else
    echo "清零后服务没起来！请看日志：$(xray_log_cmd)"
    return 1
  fi
}

# 打印 Xray 节点本周期流量统计（格式和 mmx-server --traffic-status 对齐）。
show_xray_traffic() {
  load_config
  if [ "${PROTO:-mmx}" = "mmx" ]; then echo "当前节点不是 Xray 协议。"; return 1; fi
  xray_watch_run
  local in=0 out=0 counted=0 p_start=0 p_end=0 enforced="" quota_bps=0
  local now
  now="$(date +%s)"
  if [ -f "$XRAY_TRAFFIC_FILE" ] && command -v jq >/dev/null 2>&1; then
    in="$(jq -r '.in // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    out="$(jq -r '.out // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    p_start="$(jq -r '.period_start // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    p_end="$(jq -r '.period_end // 0' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo 0)"
    enforced="$(jq -r '.enforced // ""' "$XRAY_TRAFFIC_FILE" 2>/dev/null || echo "")"
  fi
  case "$in" in ''|*[!0-9]*) in=0 ;; esac
  case "$out" in ''|*[!0-9]*) out=0 ;; esac
  case "$p_start" in ''|*[!0-9]*) p_start=0 ;; esac
  case "$p_end" in ''|*[!0-9]*) p_end=0 ;; esac
  if [ "$p_end" -le "$now" ] || [ "$p_start" -eq 0 ]; then
    in=0; out=0
    read -r p_start p_end <<< "$(xray_period_bounds "$now" "${TRAFFIC_PERIOD:-monthly}" "${TRAFFIC_START_DAY:-1}")"
  fi
  case "${TRAFFIC_MODE:-total}" in
    outbound) counted=$out ;;
    inbound) counted=$in ;;
    max) [ "$in" -gt "$out" ] && counted=$in || counted=$out ;;
    *) counted=$(( in + out )) ;;
  esac
  quota_bps="$(xray_to_bytes "${TRAFFIC_QUOTA:-0}")" || quota_bps=0
  local throttle_bps
  throttle_bps="$(xray_to_bytes "${TRAFFIC_THROTTLE_RATE:-125K}")" || throttle_bps=0
  echo "流量统计（本周期）"
  case "${TRAFFIC_MODE:-total}" in
    outbound) echo "  统计模式：出站（服务端→客户端，下载方向）" ;;
    inbound) echo "  统计模式：入站（客户端→服务端，上传方向）" ;;
    max) echo "  统计模式：最大值（取入站、出站中大的那个）" ;;
    *) echo "  统计模式：总计（入站 + 出站）" ;;
  esac
  case "${TRAFFIC_PERIOD:-monthly}" in
    quarterly) echo "  统计周期：季（1/4/7/10 月 ${TRAFFIC_START_DAY:-1} 日起）" ;;
    yearly) echo "  统计周期：年（每年 1 月 ${TRAFFIC_START_DAY:-1} 日起）" ;;
    *) echo "  统计周期：月（每月 ${TRAFFIC_START_DAY:-1} 日起）" ;;
  esac
  echo "  本周期：$(date -d "@$p_start" +%Y-%m-%d\ %H:%M) 至 $(date -d "@$p_end" +%Y-%m-%d\ %H:%M)"
  echo "  已用：$(xray_fmt_bytes "$counted")（入站 $(xray_fmt_bytes "$in") / 出站 $(xray_fmt_bytes "$out")）"
  if [ "$quota_bps" -gt 0 ]; then
    local remain=$(( quota_bps - counted ))
    [ "$remain" -lt 0 ] && remain=0
    echo "  限额：$(xray_fmt_bytes "$quota_bps")"
    echo "  剩余：$(xray_fmt_bytes "$remain")"
  else
    echo "  限额：不限（只统计，不限制）"
    echo "  剩余：不限"
  fi
  if [ "${TRAFFIC_LIMIT_MODE:-throttle}" = "throttle" ]; then
    echo "  限制模式：TC 限速（超限后全站降到 $(xray_fmt_bytes "$throttle_bps")/s 继续用）"
  else
    echo "  限制模式：阻断（超限后拒绝新连接并断开现有连接）"
  fi
  if [ "$quota_bps" -gt 0 ] && [ "$counted" -ge "$quota_bps" ]; then
    if [ "$enforced" = "block" ]; then
      echo "  状态：已超限（阻断模式：新连接被拒绝，现有连接已断开）"
    else
      echo "  状态：已超限（TC 限速模式：全站限速 $(xray_fmt_bytes "$throttle_bps")/s）"
    fi
  else
    echo "  状态：正常"
  fi
  return 0
}

# 装 Xray 流量监视定时任务：systemd 写 service + timer（每分钟跑一次）；
# OpenRC 写 cron（/etc/crontabs/root，每分钟跑一次），没 crond 就只警告。
install_xray_watch() {
  if [ "$INIT_SYS" = "openrc" ]; then
    mkdir -p "$ROOT/etc/crontabs"
    local cron_file="$ROOT/etc/crontabs/root"
    local line="* * * * * $BIN_DIR/mmx --xray-watch run"
    if [ -f "$cron_file" ]; then
      grep -Fq -- "$line" "$cron_file" 2>/dev/null || printf '%s\n' "$line" >> "$cron_file"
    else
      printf '%s\n' "$line" > "$cron_file"
    fi
    chmod 600 "$cron_file" 2>/dev/null || true
    if command -v crond >/dev/null 2>&1; then
      rc-service crond restart 2>/dev/null || true
    else
      echo "警告：没找到 crond，Xray 流量监视的 cron 没生效（流量超限不会自动执行）；装个 cron 再重装监视。"
    fi
    return 0
  fi
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/mmx-xray-watch.service" <<WATCH_UNIT_EOF
[Unit]
Description=mmx Xray traffic watch (run once)

[Service]
Type=oneshot
ExecStart=$BIN_DIR/mmx --xray-watch run
WATCH_UNIT_EOF
  cat > "$UNIT_DIR/mmx-xray-watch.timer" <<WATCH_TIMER_EOF
[Unit]
Description=Run mmx Xray traffic watch every minute

[Timer]
OnCalendar=*:0/1
Persistent=true

[Install]
WantedBy=timers.target
WATCH_TIMER_EOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable mmx-xray-watch.timer >/dev/null 2>&1 || true
  systemctl start mmx-xray-watch.timer 2>/dev/null || true
  return 0
}

# 拆 Xray 流量监视定时任务（切回 mmx 节点 / 删除节点 / 卸载时调）。
remove_xray_watch() {
  if [ "$INIT_SYS" = "openrc" ]; then
    local cron_file="$ROOT/etc/crontabs/root"
    if [ -f "$cron_file" ]; then
      grep -v -F -- "$BIN_DIR/mmx --xray-watch run" "$cron_file" > "$cron_file.tmp" 2>/dev/null || true
      mv "$cron_file.tmp" "$cron_file" 2>/dev/null || true
    fi
    if command -v crond >/dev/null 2>&1; then
      rc-service crond restart 2>/dev/null || true
    fi
    return 0
  fi
  systemctl stop mmx-xray-watch.timer 2>/dev/null || true
  systemctl disable mmx-xray-watch.timer 2>/dev/null || true
  rm -f "$UNIT_DIR/mmx-xray-watch.service" "$UNIT_DIR/mmx-xray-watch.timer"
  systemctl daemon-reload 2>/dev/null || true
  return 0
}

# XHTTP TLS 模式的证书：域名 + certbot 拿 LE 证书，写进 xray.conf（XHTTP_CERT/KEY），
# 不碰主配置的 TLS_* 字段（那是 mmx 协议用的）。
# 需要域名 + certbot；失败返回 1。
# 注意：这里不调 load_config——调用方（add_xhttp_node）已经在内存里设好了
# PROTO/PORT/TLS_SNI，load_config 会把它们重置回磁盘旧值。
xhttp_setup_cert() {
  local domain="$1"
  [ -n "$domain" ] || { echo "TLS 模式需要域名。"; return 1; }
  if [ -z "${TLS_SNI:-}" ]; then
    echo "先要域名能解析到这台机器的公网 IP（$domain → $(detect_public_ip)）。请确认 DNS 解析正确后再装。"
  fi
  command -v certbot >/dev/null 2>&1 || {
    echo "装 certbot……"
    if [ -n "${MMX_TEST_ROOT:-}" ]; then
      echo "测试模式：certbot 不可用，跳过证书申请"
      return 1
    fi
    if command -v apt-get >/dev/null 2>&1; then
      (apt-get update -qq && apt-get install -y -qq certbot) >/dev/null 2>&1 || { echo "装 certbot 失败，请手动安装后再试。"; return 1; }
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache certbot >/dev/null 2>&1 || { echo "装 certbot 失败，请手动安装后再试。"; return 1; }
    else
      echo "没找到 apt-get 或 apk，装不了 certbot。"
      return 1
    fi
  }
  local le_dir
  le_dir="$ROOT/etc/letsencrypt/live/$domain"
  if [ -d "$le_dir" ]; then
    local cert="$le_dir/fullchain.pem" key="$le_dir/privkey.pem"
    if [ -s "$cert" ] && [ -s "$key" ]; then
      XHTTP_CERT="$cert"; XHTTP_KEY="$key"
      save_xray_config
      echo "已找到 $domain 的证书，直接用。"
      return 0
    fi
    echo "$domain 证书不完整，重新申请……"
  fi
  command -v systemctl >/dev/null 2>&1 && systemctl stop nginx 2>/dev/null || true
  rc-service nginx stop 2>/dev/null || true
  local certbot_args="certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d $domain"
  if ! certbot $certbot_args; then
    echo "证书申请失败：请检查域名是否解析到本机且 80 端口可达。"
    return 1
  fi
  if [ ! -s "$le_dir/fullchain.pem" ] || [ ! -s "$le_dir/privkey.pem" ]; then
    echo "证书申请后找不到证书文件。"
    return 1
  fi
  XHTTP_CERT="$le_dir/fullchain.pem"; XHTTP_KEY="$le_dir/privkey.pem"
  save_xray_config
  # 续期后重启 xray（只对 XHTTP 节点生效：换协议后它还会跑，但重启 xray 时它已停用，无影响）。
  local hook_dir="$ROOT/etc/letsencrypt/renewal-hooks/deploy"
  mkdir -p "$hook_dir"
  cat > "$hook_dir/restart-xray.sh" <<'XRAY_HOOK_EOF'
#!/bin/bash
# mmx 菜单自动写：证书续期后重启 xray。
if command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/xray ]; then
  rc-service xray restart 2>/dev/null || true
else
  systemctl restart xray 2>/dev/null || true
fi
XRAY_HOOK_EOF
  chmod +x "$hook_dir/restart-xray.sh"
  echo "证书已申请：$domain"
  return 0
}

# 应用 Xray 节点的配置（和 apply_config 的 mmx 分支对应）：
# 备份旧配置 → 保存新配置 → 写 Xray 配置 → 停 mmx-server → 重启 xray。
# 失败时回滚（主配置 + xray.conf + Xray 配置）并重启原来的服务。
# 用法：apply_xray_config [描述]，成功时打印“已生效：描述，服务已重启并正常运行”。
apply_xray_config() {
  local desc="${1:-}"
  if [ "${PROTO:-mmx}" = "mmx" ]; then
    echo "当前节点是 mmx，不用应用 Xray 配置。"
    return 1
  fi
  ensure_xray || { echo "Xray 安装失败。"; return 1; }
  local old_cfg_bak="" old_xray_bak="" old_xcfg_bak=""
  if [ -f "$CFG_FILE" ]; then
    old_cfg_bak="$(mktemp)"
    cp -f "$CFG_FILE" "$old_cfg_bak"
  fi
  if [ -f "$XRAY_CONF" ]; then
    old_xray_bak="$(mktemp)"
    cp -f "$XRAY_CONF" "$old_xray_bak"
  fi
  if [ -f "$XRAY_CFG_FILE" ]; then
    old_xcfg_bak="$(mktemp)"
    cp -f "$XRAY_CFG_FILE" "$old_xcfg_bak"
  fi
  local rollback=0
  # 停掉 mmx-server（如果它在跑），防止它占着端口。
  if svc_is_active; then
    svc_stop 2>/dev/null || true
    svc_disable 2>/dev/null || true
  fi
  save_config; save_xray_config
  if ! write_xray_config; then
    rollback=1
  elif ! write_split_files; then
    rollback=1
  else
    write_xray_info
    if ! xray_restart; then
      rollback=1
    elif ! xray_is_active; then
      rollback=1
    fi
  fi
  if [ "$rollback" -eq 1 ]; then
    echo "应用 Xray 配置失败，正在回滚……"
    [ -n "$old_cfg_bak" ] && cp -f "$old_cfg_bak" "$CFG_FILE" || rm -f "$CFG_FILE"
    [ -n "$old_xray_bak" ] && cp -f "$old_xray_bak" "$XRAY_CONF" || rm -f "$XRAY_CONF"
    [ -n "$old_xcfg_bak" ] && cp -f "$old_xcfg_bak" "$XRAY_CFG_FILE" || rm -f "$XRAY_CFG_FILE"
    load_config; load_xray_config
    if [ "${PROTO:-mmx}" = "mmx" ]; then
      apply_config || true
    else
      xray_restart 2>/dev/null || true
    fi
    [ -n "$old_cfg_bak" ] && rm -f "$old_cfg_bak"
    [ -n "$old_xray_bak" ] && rm -f "$old_xray_bak"
    [ -n "$old_xcfg_bak" ] && rm -f "$old_xcfg_bak"
    echo "回滚完成。请看日志：$(xray_log_cmd)"
    return 1
  fi
  install_xray_watch
  [ -n "$old_cfg_bak" ] && rm -f "$old_cfg_bak"
  [ -n "$old_xray_bak" ] && rm -f "$old_xray_bak"
  [ -n "$old_xcfg_bak" ] && rm -f "$old_xcfg_bak"
  [ -n "$desc" ] && echo "已生效：$desc，服务已重启并正常运行"
  return 0
}

# Reality 短 ID（和 vx 一样：openssl 随机 8 字节，16 位十六进制）。
gen_shortid() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 8
  else
    od -An -tx1 -N 8 /dev/urandom | tr -d ' \n'
  fi
}

# 端口能不能用：没被占就通过；被占时，如果是本服务（当前节点）在用也通过
# （换节点时会重启它）；被别的服务占了才拒绝。
port_free_or_ours() {
  port_in_use "$1" || return 0
  [ "$1" = "${PORT:-}" ]
}

# 流量提问（XHTTP/ss2022 添加节点时用）：限额、周期起始日、超限模式、TC 限速值。
# 和 add_node 里 mmx 的内联提问同一份问题/默认值，直接写 TRAFFIC_*；
# add_node 的内联循环保持原样（不动 mmx 流程），这里只给 Xray 节点用。
ask_traffic() {
  local nq nd nl nt
  while true; do
    read -r -p "流量限额（默认 0 = 不限，例如 180G、500G、1T）： " nq || return 1
    [ -z "$nq" ] && nq="0"
    valid_bytes "$nq" && break
    echo "流量限额格式不对：$nq（应为数字 + 可选 K/M/G/T，例如 500G、1T、0）"
  done
  while true; do
    read -r -p "周期起始日（默认 1，1–31 号）： " nd || return 1
    [ -z "$nd" ] && nd="1"
    case "$nd" in ''|*[!0-9]*) echo "周期起始日不合法：$nd，应为 1–31 号"; continue;; esac
    [ "$nd" -ge 1 ] && [ "$nd" -le 31 ] && break
    echo "周期起始日不合法：$nd，应为 1–31 号"
  done
  while true; do
    read -r -p "超限模式（throttle 限速 / block 阻断，默认 throttle）： " nl || return 1
    [ -z "$nl" ] && nl="throttle"
    case "$(printf '%s' "$nl" | tr '[:upper:]' '[:lower:]')" in
      throttle|tc|限速|tc限速) TRAFFIC_LIMIT_MODE="throttle"; break ;;
      block|阻断) TRAFFIC_LIMIT_MODE="block"; break ;;
      *) echo "超限模式不对：$nl，应为 throttle（限速）或 block（阻断）" ;;
    esac
  done
  while true; do
    read -r -p "TC 限速值（默认 125K，约 1 Mbps）： " nt || return 1
    [ -z "$nt" ] && nt="125K"
    valid_rate "$nt" || { echo "TC 限速值格式不对：$nt（应为数字 + 可选 K/M/G，例如 125K、1M）"; continue; }
    if [ "$TRAFFIC_LIMIT_MODE" = "throttle" ] && [ "$nt" = "0" ]; then
      echo "TC 限速模式下限速值不能为 0（0 = 不限速，等于没限制），请重填。"
      continue
    fi
    break
  done
  TRAFFIC_QUOTA="$(normalize_bytes "$nq")"; TRAFFIC_START_DAY="$nd"; TRAFFIC_THROTTLE_RATE="$nt"
  return 0
}

# 添加 XHTTP（VLESS）节点。
add_xhttp_node() {
  echo "=== 添加 XHTTP 节点（VLESS + XHTTP） ==="
  load_config; load_xray_config
  [ -n "$PORT" ] && [ "$PROTO" = "xhttp" ] && echo "已有 XHTTP 节点（$PORT 端口），再添加会覆盖它。"
  local old_proto="$PROTO"
  PROTO="xhttp"
  # 先装 Xray（后面生成 Reality 密钥要用 xray x25519）。
  ensure_xray || { PROTO="$old_proto"; return 1; }
  # 模式：Reality（默认）或 TLS（域名 + 证书）。
  local mode_choice=""
  while true; do
    echo "XHTTP 用哪种模式？"
    echo "  1) Reality（不用域名，推荐）"
    echo "  2) TLS（需要域名和证书）"
    read -r -p "选项 [1/2，默认 1]： " mode_choice || { PROTO="$old_proto"; return 1; }
    [ -z "$mode_choice" ] && mode_choice="1"
    case "$mode_choice" in
      1) XHTTP_MODE="reality"; break ;;
      2) XHTTP_MODE="tls"; break ;;
      *) echo "没有这个选项，请输入 1 或 2。" ;;
    esac
  done
  # 地区（决定 SNI 池）；TLS 模式下这个地区不用（SNI 就是域名），跳过。
  if [ "$XHTTP_MODE" = "reality" ]; then
    if ! ask_region; then PROTO="$old_proto"; return 1; fi
    XHTTP_REGION="$ASK_REGION"; XHTTP_SNI="$ASK_REGION_SNI"
  fi
  # 端口（默认 443；有现成节点时问是否继续用它，没有就默认 443）。
  local p=""
  while true; do
    if [ -n "$PORT" ]; then
      read -r -p "端口 [默认 $PORT]： " p || { PROTO="$old_proto"; return 1; }
      [ -z "$p" ] && p="$PORT"
    else
      read -r -p "端口 [默认 443]： " p || { PROTO="$old_proto"; return 1; }
      [ -z "$p" ] && p="443"
    fi
    if ! valid_port "$p"; then echo "端口不对：$p（应为 1-65535 的数字）"; continue; fi
    if ! port_free_or_ours "$p"; then echo "端口 $p 已被占用（非本服务），换个端口。"; continue; fi
    PORT="$p"
    break
  done
  # TLS 模式：问域名并申请证书。
  if [ "$XHTTP_MODE" = "tls" ]; then
    local dom=""
    while true; do
      read -r -p "域名（例如 example.com）： " dom || { PROTO="$old_proto"; return 1; }
      if valid_domain "$dom"; then break; fi
      echo "域名不对：$dom（应为域名，例如 example.com）"
    done
    XHTTP_SNI="$dom"
    if ! xhttp_setup_cert "$dom"; then
      echo "证书申请失败，XHTTP 节点没建。"
      PROTO="$old_proto"
      return 1
    fi
  fi
  # Reality 密钥（x25519）：输出格式按 vx 的办法解析（grep private/public 取末字段，
  # 真 xray 是 "PrivateKey: xxx" / "Password (PublicKey): yyy"，两种格式都兼容）。
  if [ "$XHTTP_MODE" = "reality" ]; then
    local keyout
    keyout="$(xray x25519)" || { echo "生成 Reality 密钥失败。"; PROTO="$old_proto"; return 1; }
    XHTTP_PRIVKEY="$(printf '%s\n' "$keyout" | grep -i private | awk '{print $NF}')"
    XHTTP_PUBKEY="$(printf '%s\n' "$keyout" | grep -i public | awk '{print $NF}')"
    [ -n "$XHTTP_PRIVKEY" ] && [ -n "$XHTTP_PUBKEY" ] || { echo "生成 Reality 密钥失败。"; PROTO="$old_proto"; return 1; }
    XHTTP_SHORTID="$(gen_shortid)"
  fi
  XHTTP_UUID="$(gen_uuid)"
  XHTTP_PATH="/api"
  # 分流：上下行分离（默认开；ss2022 没有分流，mmx 没有分流）。
  local split_choice=""
  read -r -p "上下行分离？（1 开 / 0 关，默认 1）： " split_choice || { PROTO="$old_proto"; return 1; }
  if [ -z "$split_choice" ]; then
    XHTTP_SPLIT="1"
  else
    case "$split_choice" in
      1|0) XHTTP_SPLIT="$split_choice" ;;
      *) echo "没有这个选项，默认开。"; XHTTP_SPLIT="1" ;;
    esac
  fi
  # 地址：域名（TLS 模式）或公网 IP。
  if [ "$XHTTP_MODE" = "tls" ]; then
    HOST="$XHTTP_SNI"
  else
    HOST="$(detect_public_ip)"
    [ -z "$HOST" ] && HOST=""
  fi
  # 流量（限额/周期/超限模式/TC 限速值）。
  if ! ask_traffic; then PROTO="$old_proto"; return 1; fi
  if ! apply_xray_config; then
    echo "XHTTP 节点添加失败。"
    PROTO="$old_proto"
    return 1
  fi
  echo ""
  echo "XHTTP 节点已添加（$(proto_label)）"
  show_nodes
  return 0
}

# 添加 ss2022 节点。
add_ss_node() {
  echo "=== 添加 ss2022 节点（Shadowsocks 2022） ==="
  load_config; load_xray_config
  [ -n "$PORT" ] && [ "$PROTO" = "ss2022" ] && echo "已有 ss2022 节点（$PORT 端口），再添加会覆盖它。"
  local old_proto="$PROTO"
  PROTO="ss2022"
  SS_METHOD="2022-blake3-aes-256-gcm"
  # 端口（默认 443；有现成节点时问是否继续用它，没有就默认 443）。
  local p=""
  while true; do
    if [ -n "$PORT" ]; then
      read -r -p "端口 [默认 $PORT]： " p || { PROTO="$old_proto"; return 1; }
      [ -z "$p" ] && p="$PORT"
    else
      read -r -p "端口 [默认 443]： " p || { PROTO="$old_proto"; return 1; }
      [ -z "$p" ] && p="443"
    fi
    if ! valid_port "$p"; then echo "端口不对：$p（应为 1-65535 的数字）"; continue; fi
    if ! port_free_or_ours "$p"; then echo "端口 $p 已被占用（非本服务），换个端口。"; continue; fi
    PORT="$p"
    break
  done
  # 密码：随机 base64（32 字节密钥）。
  SS_PASSWORD="$(openssl rand -base64 32)"
  HOST="$(detect_public_ip)"
  [ -z "$HOST" ] && HOST=""
  # 流量（限额/周期/超限模式/TC 限速值）。
  if ! ask_traffic; then PROTO="$old_proto"; return 1; fi
  ensure_xray || { PROTO="$old_proto"; return 1; }
  if ! apply_xray_config; then
    echo "ss2022 节点添加失败。"
    PROTO="$old_proto"
    return 1
  fi
  echo ""
  echo "ss2022 节点已添加（$(proto_label)）"
  show_nodes
  return 0
}

add_node() {
  load_config
  if [ -f "$CFG_FILE" ]; then
    echo "已有节点（端口 ${PORT:-?}，节点名 ${NAME:-?}），重新添加会覆盖当前节点配置。"
    local yn
    read -r -p "继续吗？[y/N] " yn || return 0
    case "$yn" in y|Y) ;; *) echo "已取消。"; return 0;; esac
  fi
  # 先问协议：mmx 走下面的原流程；XHTTP/ss2022 分派到各自的添加函数。
  if ! ask_protocol "${PROTO:-mmx}"; then
    echo "已取消。"
    return 0
  fi
  case "$ASK_PROTO" in
    xhttp) add_xhttp_node; return $? ;;
    ss2022) add_ss_node; return $? ;;
  esac
  # 走到这里是 mmx 流程：把 PROTO 明确设回 mmx（从 Xray 节点切回来时，
  # load_config 读到的还是旧协议，不设的话 apply_config 会错走 Xray 分支）。
  PROTO="mmx"
  local np nq nd nl nt
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
  PORT="$np"
  TRAFFIC_QUOTA="$(normalize_bytes "$nq")"; TRAFFIC_START_DAY="$nd"; TRAFFIC_THROTTLE_RATE="$nt"
  # 用域名还是 IP：明确选（替代原来末尾"域名可选、留空跳过"）。
  ask_domain_or_ip || return 0
  local dom="$ASK_DOM"
  if [ -z "$dom" ]; then
    # 选 IP：不用域名，TLS 关——不沿用旧节点的真 TLS/自签设置（IP 节点就是 TLS 关）。
    TLS_DOMAIN=""; TLS_CERT=""; TLS_KEY=""; TLS_AUTO="0"; TLS_SNI=""
  fi
  local summary="添加节点：端口 $PORT，限额 $TRAFFIC_QUOTA，起始日 $TRAFFIC_START_DAY 日，超限 $(traffic_limit_label)"
  [ -n "$dom" ] && summary="$summary，域名 $dom"
  if apply_config "$summary"; then
    if [ -n "$dom" ]; then
      if ! setup_domain "$dom"; then
        echo "域名设置失败（$dom），节点已建好；域名可稍后用 mmx --setup-domain $dom 再设。"
        load_config
      fi
    fi
    # 节点建好了：开 BBR + 按它的端口放行防火墙（全新安装时这两步跳过，建节点时补上）。
    enable_bbr
    open_firewall_port
  fi
}

# 3) 编辑节点：按项改；改完校验，写回配置，
#    重载 + 重启，重启失败自动回滚。第 5 项是流量设置（统计模式/周期/
#    起始日/限制模式/限额/TC 限速值 + 查看流量），
#    第 6 项是 IP 链接开关（在第 5 项查看节点里同时显示 IP 地址的链接）。
#    （诱饵回退 / TLS、掩护流量、域名白名单已从编辑节点移除，全部自动设置：
#    诱饵默认 site、TLS 添加节点时自动设置、掩护流量默认 low、
#    域名白名单默认关，用主菜单第 2 项谷歌服务开关。）
edit_params() {
  load_config; load_xray_config
  # 没节点时没东西可改，拒绝（否则会写出端口为空的坏配置）。
  if [ -z "$PORT" ]; then echo "还没有节点，请先用第 1 项添加节点。"; return 0; fi
  while true; do
    load_config; load_xray_config
    echo ""
    echo "--- 编辑节点 ---"
    echo "1) 端口（当前 $PORT）"
    echo "2) 限速 rate（当前 $RATE）"
    echo "3) 突发 burst（当前 $BURST）"
    echo "4) 服务器地址（当前 ${HOST:-未设置}，链接里用的地址）"
    echo "5) 流量设置（统计模式 / 周期 / 限额 / 查看流量）"
    echo "6) IP 链接（当前 $([ "${SHOW_IP_LINK:-0}" = "1" ] && echo "显示" || echo "不显示")：在第 5 项查看节点里同时显示 IP 地址的链接）"
    echo "0) 返回"
    local c
    read -r -p "改哪一项： " c || return 0
    # mmx 专属项（rate/burst、IP 链接）：
    # XHTTP/ss2022 节点没有这些设置，选了就提示，不进下面的分支。
    case "$c" in
      2|3|6)
        if [ "${PROTO:-mmx}" != "mmx" ]; then
          echo "这一项是 mmx 节点专属的，当前节点是 $(proto_label)，没有这个设置。"
          pause; continue
        fi
        ;;
    esac
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
        local hh
        read -r -p "新服务器地址（IP 或域名，留空不变）： " hh || continue
        [ -z "$hh" ] && { echo "没改。"; pause; continue; }
        case "$hh" in *" "*|*"/"*) echo "地址不对：$hh"; pause; continue;; esac
        HOST="$hh"
        apply_config "服务器地址改为 $HOST"
        ;;
      5) traffic_menu ;;
      6)
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
  # Xray 节点：停 xray、拆流量监视、清 Xray 的节点配置（xray.conf、Xray 配置、信息文件、分离配置、流量统计）；
  # xray 二进制保留（下次建 XHTTP/ss2022 节点还能用）。
  if [ "${PROTO:-mmx}" != "mmx" ]; then
    xray_stop || true
    xray_disable || true
    remove_xray_watch
    xray_tc_clear
    rm -f "$XRAY_CONF" "$XRAY_CFG_FILE" "$XRAY_INFO_FILE" "$XRAY_SPLIT_A" "$XRAY_SPLIT_B" "$XRAY_TRAFFIC_FILE"
  fi
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
  # Xray 节点（如果有）：xray 服务、Xray 配置、流量监视、LE 续期 hook；xray 二进制只删自己装的。
  if [ -f "$XRAY_INSTALLED_MARKER" ] || command -v xray >/dev/null 2>&1; then
    echo "  服务 xray（停用并删除服务文件）"
    echo "  Xray 配置 $XRAY_CFG_FILE、Xray 状态 $XRAY_CONF、流量监视（mmx-xray-watch）"
    echo "  续期 hook：$le_dir/renewal-hooks/deploy/restart-xray.sh"
    [ -f "$XRAY_INSTALLED_MARKER" ] && echo "  程序 $BIN_DIR/xray（本次安装的 Xray）"
  fi
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
  # Xray 清理：停服务、拆监视、删服务文件和配置；xray 二进制只删自己装的（有标记才删）。
  xray_stop || true
  xray_disable || true
  remove_xray_watch
  xray_tc_clear
  if [ "$INIT_SYS" = "openrc" ]; then rm -f "$INIT_DIR/xray"; else rm -f "$UNIT_DIR/xray.service"; fi
  # xray 二进制只删自己装的（有标记才删），先判断再删标记。
  if [ -f "$XRAY_INSTALLED_MARKER" ]; then rm -f "$BIN_DIR/xray"; fi
  rm -f "$XRAY_CFG_FILE" "$XRAY_CONF" "$XRAY_INFO_FILE" "$XRAY_SPLIT_A" "$XRAY_SPLIT_B" "$XRAY_TRAFFIC_FILE" "$XRAY_INSTALLED_MARKER"
  rm -f "$le_dir/renewal-hooks/deploy/restart-xray.sh"
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
  # 隐藏用法：部署脚本装完后按配置写服务文件；只打印链接；只打印 TLS 指纹；只打印流量统计；一键设置域名
  if [ "${1:-}" = "--write-service" ]; then load_config; write_service; exit 0; fi
  if [ "${1:-}" = "--show-link" ]; then show_link "${2:-opaque}"; exit 0; fi
  if [ "${1:-}" = "--show-pin" ]; then show_pin; exit 0; fi
  if [ "${1:-}" = "--show-traffic" ]; then show_traffic; exit 0; fi
  if [ "${1:-}" = "--setup-domain" ]; then load_config; setup_domain "${2:-}" || exit 1; exit 0; fi
  # Xray 流量监视（定时任务调）：run 跑一次，clear 清零本周期，status 打印统计。
  if [ "${1:-}" = "--xray-watch" ]; then
    case "${2:-run}" in
      run) xray_watch_run; exit 0 ;;
      clear) xray_watch_clear; exit $? ;;
      status) show_xray_traffic; exit $? ;;
      *) echo "用法：mmx --xray-watch run|clear|status"; exit 1 ;;
    esac
  fi
  if [ "${1:-}" = "--write-xray-config" ]; then load_config; load_xray_config; write_xray_config; exit $?; fi
  # 菜单界面统一绿色；退出（正常 / Ctrl-C）时复位终端颜色。
  # 放在隐藏用法之后：非交互调用（--show-link / --setup-domain 等）
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
    # XHTTP/ss2022 节点：跑的是 xray，显示 xray 的状态和协议。
    if [ "${PROTO:-mmx}" != "mmx" ]; then
      if xray_is_active; then
        echo "服务：正在运行（xray，$(proto_label) 节点）　端口：${PORT:-?}"
      else
        echo "服务：未运行（看第 6 项日志）"
        echo "协议：$(proto_label)　端口：${PORT:-?}"
      fi
    elif svc_is_active; then
      echo "服务：正在运行　端口：${PORT:-?}　限速：${RATE:-?}"
      echo "TLS ：$tls_desc"
    else
      echo "服务：未运行（看第 6 项日志）"
      echo "端口：${PORT:-?}　限速：${RATE:-?}"
    fi
    echo "   1：添加节点"
    if [ "${DOMAIN_WHITELIST:-}" = "google" ]; then
      echo "   2：谷歌服务：开"
    else
      echo "   2：谷歌服务：关"
    fi
    echo "   3：编辑节点"
    echo "   4：删除节点"
    echo "   5：查看节点"
    echo "   6：查看日志"
    echo "   7：更新脚本"
    echo "   8：完全卸载"
    echo "   9：退出脚本"
    local c
    read -r -p "选项：" c || exit 0
    case "$c" in
      1) add_node ;;
      2) toggle_whitelist ;;
      3) edit_params ;;
      4) delete_node ;;
      5) show_nodes ;;
      6) show_logs ;;
      7) update_script ;;
      8) uninstall ;;
      9|"") exit 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

main "$@"
MM_MENU_EOF
chmod +x "$BIN_DIR/mmx"
echo "管理菜单已安装：$BIN_DIR/mmx（输入 mmx 呼出）"

# 8) 服务文件：按配置文件生成（菜单改参数也是同一份逻辑），开机自启、崩溃自动重启
#    systemd 写单元文件，OpenRC 写 /etc/init.d/mmx-server。
#    全新安装不建节点、没配置可写，跳过（服务文件在菜单第 1 项添加节点时生成）。
if [ "$FRESH_NO_NODE" != "1" ]; then
echo "== 写入服务文件 =="
"$BIN_DIR/mmx" --write-service
mkdir -p "$SVC_DIR"
svc_reload
# 节点协议是 XHTTP/ss2022 时跑的是 xray 不是 mmx-server：不碰 mmx-server，
# 只确保 xray 在跑（xray 二进制和配置都没动，不重启它）。
if [ "${PROTO:-mmx}" != "mmx" ]; then
  if command -v xray >/dev/null 2>&1; then
    if [ "$INIT_SYS" = "openrc" ]; then
      rc-service xray status >/dev/null 2>&1 || rc-service xray start 2>/dev/null || true
    else
      systemctl is-active --quiet xray 2>/dev/null || systemctl start xray 2>/dev/null || true
    fi
    if [ "$INIT_SYS" = "openrc" ]; then
      rc-service xray status >/dev/null 2>&1 && echo "服务已启动：xray 正在运行" || echo "xray 没起来，请看日志：mmx 菜单第 6 项，或 tail -n 50 /var/log/messages"
    else
      systemctl is-active --quiet xray 2>/dev/null && echo "服务已启动：xray 正在运行" || echo "xray 没起来，请看日志：mmx 菜单第 6 项，或 journalctl -u xray -n 50"
    fi
  else
    echo "xray 没装（XHTTP/ss2022 节点需要它），请用 mmx 菜单第 1 项重新添加节点。"
  fi
  [ -n "$BIN_BAK" ] && rm -f "$BIN_BAK"
else
# mmx 节点：先停 xray（如果之前是 Xray 节点，它还占着端口），再启 mmx-server。
if command -v xray >/dev/null 2>&1; then
  if [ "$INIT_SYS" = "openrc" ]; then
    rc-service xray stop 2>/dev/null || true
    rc-update del xray default 2>/dev/null || true
  else
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
  fi
fi
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
fi

if [ "$UPDATE_ONLY" = "1" ]; then
echo ""
echo "== 更新完成 =="
echo "程序文件已更新（服务端二进制、管理菜单、服务文件）；节点配置原样保留。"
if [ "${PROTO:-mmx}" != "mmx" ]; then
  echo "协议：$(case "${PROTO:-mmx}" in xhttp) echo "XHTTP" ;; ss2022) echo "ss2022" ;; *) echo "mmx" ;; esac)；端口：$PORT（不变）；节点名：$NAME"
  echo "Xray 配置：$ROOT/usr/local/etc/xray/config.json（未动）；Xray 状态：$CFG_DIR/xray.conf（未动）"
else
  echo "端口：$PORT（不变）；限速：$RATE；TLS：$TLS_MODE_DESC；节点名：$NAME"
  echo "密钥文件：$PSK_FILE（未变）；配置文件：$CFG_FILE（未动）"
fi
echo "想改节点参数用 mmx 菜单；想彻底重装节点请加 --reinstall。"
echo "服务状态：打开菜单最上方直接显示，或 $(svc_status_cmd)；日志：mmx 菜单第 6 项，或 $(svc_log_follow_cmd)"
elif [ "$FRESH_NO_NODE" = "1" ]; then
echo ""
echo "== 安装完成（只装了程序，未创建节点） =="
echo "已安装：服务端二进制 $BIN_DIR/mmx-server、管理菜单 $BIN_DIR/mmx（输入 mmx 呼出）。"
echo "未创建节点：没有密钥、没有配置文件、服务未启动。"
if [ -n "$NODE_FLAGS_GIVEN" ]; then
echo "安装参数（--port/--rate/--traffic-*/--domain 等）已忽略：全新安装不再创建节点，节点参数在菜单里设置。"
fi
echo "请在菜单第 1 项添加节点（会问端口、流量限额、域名还是 IP），节点建好后服务自动启动；"
echo "建好后在菜单第 5 项查看节点（粘贴到 mm-x 客户端就能用，绝不要分享给第二个人）。"
else
echo ""
echo "== 安装完成 =="
echo "监听端口：$PORT"
echo "限速上限：$RATE（0 = 不限速），突发额度：$BURST"
echo "回退模式：$FALLBACK；TLS：$TLS_MODE_DESC"
if [ "$TRAFFIC_QUOTA" = "0" ]; then
  echo "流量统计：不限额（只统计，不限制）；想限制去 mmx 菜单第 3 项 → 流量设置"
else
  echo "流量统计：限额 $TRAFFIC_QUOTA，超限后 $TRAFFIC_LIMIT_MODE；查看用量去 mmx 菜单第 3 项 → 流量设置 → 查看流量"
fi
echo "密钥文件：$PSK_FILE（重装不换密钥；换密钥请直接改此文件，服务端自动识别，24 小时内新旧密钥都能用）"
echo "配置文件：$CFG_FILE（菜单改参数就改这个文件）"
echo "服务状态：打开菜单最上方直接显示，或 $(svc_status_cmd)；日志：mmx 菜单第 6 项，或 $(svc_log_follow_cmd)"
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
  echo "域名设置失败：服务仍用自签 TLS 继续运行（见上面的报错）；之后可删除节点后用第 1 项重新添加（选域名）重试。"
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
