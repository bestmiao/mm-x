#!/bin/bash
# mm-x 服务端一键部署脚本（在 VPS 上用 sudo 运行）。
# 用法：
#   1) 把本脚本和预编译的 mm1-server-linux-amd64 传到 VPS 同一个目录（例如 /tmp/mm1/）；
#   2) sudo ./install-mm-x-server.sh [--port 端口] [--rate 限速] [--burst 突发] [--name 节点名] [--host 公网IP或域名]
#      [--fallback site|silent] [--tls-domain 域名 --tls-cert 证书 --tls-key 私钥]
#      [--tls-auto [--tls-sni 域名]]（没域名时用自签 TLS + SPKI 锁定，和真 TLS 二选一）
# 默认：随机高位端口（10000-60000）、限速 6250K（50 Mbps，约 6.25 MB/s，1080p、4K30、4K60 都能看）、突发 0（严格模式：任何时候都不超过限速；旧默认 15M 会让每条新连接开头先冲 15MB 再限速，实测 30MB 文件平均跑到 96 Mbps、峰值 1300 Mbps，等于没限——YouTube 这种多连接、分段取数据的流量，每段都落在突发里，更是全程不限）。
# 脚本会：装二进制到 /usr/local/bin/mm1-server；生成/保留 /etc/mm1/psk（重装不换密钥，
#   旧密钥靠服务端的 24 小时宽限期继续用）；默认开 BBR（开不了只警告）；放行防火墙端口；
#   写 /etc/mm1/config（全部参数都在这里，菜单改参数就改这个文件）；写 systemd 服务
#   （开机自启、崩溃自动重启）；装管理菜单 /usr/local/bin/mm（输入 mm 呼出）。
# 安装完不打印 mm:// 链接——链接在 mm 菜单第 1 项里看。
# 重装/更新：直接再跑一次本脚本即可，密钥文件不动，服务会自动重启加载新二进制。
set -euo pipefail

# 测试钩子：MM1_TEST_ROOT 设置时，所有路径都改到该目录下（不碰真实系统），
# BBR 步骤跳过；systemctl/journalctl/ss 由测试替身提供。生产环境不要设置这个变量。
ROOT="${MM1_TEST_ROOT:-}"
CFG_DIR="$ROOT/etc/mm1"
CFG_FILE="$CFG_DIR/config"
PSK_FILE="$CFG_DIR/psk"
BIN_DIR="$ROOT/usr/local/bin"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/mm1-server.service"

PORT=""
RATE="6250K"
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
WHITELIST_IPS=()
WHITELIST_FILE=""
ALLOW_IPS=()
ALLOWLIST_FILE=""

usage() {
  echo "用法：sudo $0 [--port 端口] [--rate 限速] [--burst 突发] [--name 节点名] [--host 公网IP或域名] [--bin 服务端二进制路径] [--whitelist-ip 中转机IP] [--whitelist-file 白名单文件] [--fallback site|silent] [--tls-domain 域名 --tls-cert 证书 --tls-key 私钥]"
  echo "  --port   监听端口，默认随机 10000-60000（不要用一眼能猜到的端口）"
  echo "           443 更像正常 HTTPS（配真 TLS 时最像），但 VPS 上 443 常被 nginx/Apache 等 Web 服务占着："
  echo "           被占时本脚本会直接报错停下，先停掉占用的服务（例如 systemctl stop nginx）或换个端口再装"
  echo "  --rate   服务端限速上限，默认 6250K（50 Mbps，约 6.25 MB/s；0 = 不限速）"
  echo "  --burst  服务端突发额度上限，默认 0（严格模式：任何时候都不超过限速；想允许开头冲一把再填，例如 --burst 5M）"
  echo "  --name   节点名，默认 mm-x"
  echo "  --host   mm:// 链接里的服务器地址，默认自动探测公网 IP；可以填域名或 IP，填了域名就按域名生成链接"
  echo "  --bin    服务端二进制路径，默认用脚本同目录下的 mm1-server-linux-amd64"
  echo "  --whitelist-ip   拉黑白名单 IP（可重复写多个）：白名单里的 IP 永远不拉黑；"
  echo "                   用 realm 中转流量时，把 realm 中转机的出口 IP 写进来，否则它一旦握手失败就可能被拉黑断流"
  echo "  --whitelist-file 拉黑白名单文件路径（每行一个 IP）：会复制到 /etc/mm1/whitelist，写进服务启动参数"
  echo "  --allow-ip       连接白名单 IP 或 CIDR 段（可重复写多个，例如 --allow-ip 1.2.3.4 --allow-ip 5.6.7.0/24）："
  echo "                   填了就只允许这些 IP 连接落地机，其他 IP 在握手前直接丢弃；不填 = 谁都能连（仍要过密钥校验）"
  echo "                   填你自己的 VPS 入口 IP、realm 中转机 IP；入口是机场节点时别填单个 IP——机场出口 IP 会变、还可能是多人共用，"
  echo "                   容易把自己挡住，填机场出口 IP 段（CIDR）或入口改用自己的 VPS"
  echo "  --allowlist-file 连接白名单文件路径（每行一个 IP 或 CIDR）：会复制到 /etc/mm1/allowlist，写进服务启动参数"
  echo "  --fallback       非 mm-x 连接的回退方式，默认 site：site = 回一个像网站的页面/400 页（探测看到一台普通 Web 服务器）；"
  echo "                   silent = 0 字节回包、直接断开（老样子，更隐蔽但探测者会觉得端口是死的）"
  echo "  --tls-domain     真 TLS 模式的域名：填了就开启真 TLS 包装，流量看起来就是正常 HTTPS 访问这个网站；"
  echo "                   DNS 必须先指到这台 VPS；要和 --tls-cert/--tls-key 一起给"
  echo "  --tls-cert       真 TLS 模式的证书文件（fullchain.pem）"
  echo "  --tls-key        真 TLS 模式的私钥文件（privkey.pem）"
  echo "                   没有证书时先申请 Let's Encrypt：apt install certbot -y && certbot certonly --standalone -d 你的域名"
  echo "                   （证书一般在 /etc/letsencrypt/live/你的域名/fullchain.pem 和 privkey.pem）"
  echo "  --tls-auto       自签 TLS 模式（没域名时用）：首次启动自动生成自签证书并存到 /etc/mm1/tls-cert.pem 和"
  echo "                   /etc/mm1/tls-key.pem；客户端靠 mm:// 链接里的 pin（SPKI 指纹）锁定验证，不跳过验证。"
  echo "                   和 --tls-domain 二选一；以后有了域名再用菜单第 7 项换成真 TLS"
  echo "  --tls-sni        自签 TLS 的默认 SNI（一个常见域名，例如 www.microsoft.com，默认就是它）；"
  echo "                   链接里写了 sni 参数就以链接为准"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --burst) BURST="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --whitelist-ip) WHITELIST_IPS+=("$2"); shift 2 ;;
    --whitelist-file) WHITELIST_FILE="$2"; shift 2 ;;
    --allow-ip) ALLOW_IPS+=("$2"); shift 2 ;;
    --allowlist-file) ALLOWLIST_FILE="$2"; shift 2 ;;
    --fallback) FALLBACK="$2"; shift 2 ;;
    --tls-domain) TLS_DOMAIN="$2"; shift 2 ;;
    --tls-cert) TLS_CERT="$2"; shift 2 ;;
    --tls-key) TLS_KEY="$2"; shift 2 ;;
    --tls-auto) TLS_AUTO="1"; shift ;;
    --tls-sni) TLS_SNI="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "未知参数：$1"; usage ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 sudo 运行：sudo $0"
  exit 1
fi

# 回退模式与真 TLS 参数校验
if [ "$FALLBACK" != "site" ] && [ "$FALLBACK" != "silent" ]; then
  echo "回退方式不合法：$FALLBACK，应为 site（默认）或 silent"
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

# 随机高位端口：10000-60000
if [ -z "$PORT" ]; then
  PORT=$((10000 + RANDOM % 50000))
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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "$BIN" ]; then
  if [ -f "$SCRIPT_DIR/mm1-server-linux-amd64" ]; then
    BIN="$SCRIPT_DIR/mm1-server-linux-amd64"
  elif [ -f "$SCRIPT_DIR/mm1-server" ]; then
    BIN="$SCRIPT_DIR/mm1-server"
  elif [ -x "$BIN_DIR/mm1-server" ]; then
    BIN="$BIN_DIR/mm1-server"  # 更新模式：只重装服务配置，不换二进制
  else
    echo "找不到服务端二进制：请把 mm1-server-linux-amd64 和本脚本放在同一个目录再运行，"
    echo "或用 --bin 指定二进制路径。"
    exit 1
  fi
fi
if [ ! -f "$BIN" ]; then echo "服务端二进制不存在：$BIN"; exit 1; fi

echo "== 安装 mm-x 服务端 =="
TLS_MODE_DESC="关"
[ -n "$TLS_DOMAIN" ] && TLS_MODE_DESC="真 TLS（$TLS_DOMAIN）"
[ "$TLS_AUTO" = "1" ] && TLS_MODE_DESC="自签 TLS（SNI ${TLS_SNI:-www.microsoft.com}）"
echo "端口：$PORT；限速：$RATE；突发：$BURST；节点名：$NAME；回退：$FALLBACK；TLS：$TLS_MODE_DESC"

# 1) 装二进制（更新模式下 BIN 就是已安装的文件，跳过自复制）
mkdir -p "$BIN_DIR"
if [ "$BIN" != "$BIN_DIR/mm1-server" ]; then
  install -m 755 "$BIN" "$BIN_DIR/mm1-server"
  echo "二进制已安装：$BIN_DIR/mm1-server"
else
  echo "更新模式：二进制已在安装位置，不重复安装"
fi

# 2) 密钥：/etc/mm1/psk 没有就生成（64 位十六进制，32 字节），有了就保留——
#    重装/更新不换密钥，轮换密钥请用 mm 菜单第 4 项（服务端 24 小时宽限期内新旧密钥都能用）
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

# 3) BBR 默认开：开不了只警告，绝不因为开不了就装失败（测试模式跳过）
echo "== 开启 BBR =="
if [ -n "${MM1_TEST_ROOT:-}" ]; then
  echo "测试模式：跳过 BBR"
else
  BBR_OK=0
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
fi

# 4) 防火墙放行端口（有哪个工具用哪个，都没有就只提醒）
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

# 5) 拉黑白名单：--whitelist-ip（可重复）写进启动参数；--whitelist-file 复制到 /etc/mm1/whitelist 再写进启动参数
WHITELIST_FILE_INSTALLED=""
if [ -n "$WHITELIST_FILE" ]; then
  if [ ! -f "$WHITELIST_FILE" ]; then echo "拉黑白名单文件不存在：$WHITELIST_FILE"; exit 1; fi
  install -m 600 "$WHITELIST_FILE" "$CFG_DIR/whitelist"
  WHITELIST_FILE_INSTALLED="$CFG_DIR/whitelist"
  echo "拉黑白名单文件已安装：$CFG_DIR/whitelist（重装脚本时不会被覆盖，除非再传 --whitelist-file）"
fi

# 5b) 连接白名单：--allow-ip（可重复，IP 或 CIDR）写进启动参数；--allowlist-file 复制到 /etc/mm1/allowlist 再写进启动参数
ALLOWLIST_FILE_INSTALLED=""
if [ -n "$ALLOWLIST_FILE" ]; then
  if [ ! -f "$ALLOWLIST_FILE" ]; then echo "连接白名单文件不存在：$ALLOWLIST_FILE"; exit 1; fi
  install -m 600 "$ALLOWLIST_FILE" "$CFG_DIR/allowlist"
  ALLOWLIST_FILE_INSTALLED="$CFG_DIR/allowlist"
  echo "连接白名单文件已安装：$CFG_DIR/allowlist（重装脚本时不会被覆盖，除非再传 --allowlist-file）"
fi

# 6) 探测公网 IP（--host 优先），写进配置文件（菜单拼链接时用）
if [ -z "$HOST" ]; then
  HOST="$(curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true)"
  if [ -z "$HOST" ]; then HOST="$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"; fi
  if [ -z "$HOST" ]; then HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"; fi
fi
# 127.0.0.1/内网 IP 不能当链接地址（hostname -I 有时先返回它）；
# 探到这种地址就当没探到，菜单里用占位地址提醒用户改。
case "$HOST" in
  127.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) HOST="" ;;
esac
if [ -z "$HOST" ]; then
  echo "警告：探测不到公网 IP，菜单里拼链接时会用占位地址，记得在菜单第 8 项里把服务器地址改成你的 VPS 公网 IP 或域名"
  HOST=""
fi

# 7) 写配置文件 /etc/mm1/config：全部参数都在这里，菜单改参数就改这个文件，
#    再由菜单按它重新生成 systemd 服务（改错了重启失败会自动回滚）。
WHITELIST_IPS_STR="${WHITELIST_IPS[*]:-}"
ALLOW_IPS_STR="${ALLOW_IPS[*]:-}"
{
  printf '%s=%q\n' PORT "$PORT" RATE "$RATE" BURST "$BURST" NAME "$NAME" HOST "$HOST" FALLBACK "$FALLBACK" TLS_DOMAIN "$TLS_DOMAIN" TLS_CERT "$TLS_CERT" TLS_KEY "$TLS_KEY" TLS_AUTO "$TLS_AUTO" TLS_SNI "$TLS_SNI" WHITELIST_IPS "$WHITELIST_IPS_STR" WHITELIST_FILE "$WHITELIST_FILE_INSTALLED" ALLOW_IPS "$ALLOW_IPS_STR" ALLOWLIST_FILE "$ALLOWLIST_FILE_INSTALLED"
} > "$CFG_FILE"
chmod 600 "$CFG_FILE"
echo "配置文件已写入：$CFG_FILE"

# 8) 写管理菜单 /usr/local/bin/mm：输入 mm 呼出。
#    菜单是一个独立的 bash 脚本；配置存在 /etc/mm1/config，密钥在 /etc/mm1/psk，
#    systemd 服务由菜单按配置文件生成（改参数后自动重载 + 重启，重启失败自动回滚）。
echo "== 安装管理菜单 =="
cat > "$BIN_DIR/mm" <<'MM_MENU_EOF'
#!/bin/bash
# mm-x 服务端管理菜单：在 VPS 上输入 mm（或改名后的命令）呼出。
# 功能：1 显示协议链接  2 查看服务状态  3 重启服务  4 更换密钥  5 修改限速
#       6 查看最近日志  7 诱饵回退 / TLS 设置（真 TLS、自签 TLS、查指纹）  8 修改服务启动参数
#       9 修改快捷命令  10 卸载  11 退出
# 全部配置存在 /etc/mm1/config，密钥在 /etc/mm1/psk；
# systemd 服务由本脚本按配置文件生成，改参数后自动重载 + 重启，
# 重启失败自动回滚到改之前的配置，不会让服务起不来。
# 隐藏用法（给部署脚本和脚本调用）：mm --write-service（按配置写服务文件）、mm --show-link [plain|opaque]（只打印链接，
# 默认 plain 短格式；opaque 是一串乱码，只有新版客户端能认——默认绝不能先切过去）、
# mm --show-pin（只打印 TLS 证书的 SPKI 指纹）。
set -u

ROOT="${MM1_TEST_ROOT:-}"
CFG_DIR="$ROOT/etc/mm1"
CFG_FILE="$CFG_DIR/config"
PSK_FILE="$CFG_DIR/psk"
BIN_DIR="$ROOT/usr/local/bin"
SERVER_BIN="$BIN_DIR/mm1-server"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/mm1-server.service"
MYNAME="$(basename "$0")"

# 默认值（配置文件缺失时用）
PORT=""; RATE="6250K"; BURST="0"; NAME="mm-x"; HOST=""
FALLBACK="site"; TLS_DOMAIN=""; TLS_CERT=""; TLS_KEY=""
TLS_AUTO="0"; TLS_SNI=""
WHITELIST_IPS=""; WHITELIST_FILE=""; ALLOW_IPS=""; ALLOWLIST_FILE=""

load_config() {
  if [ -f "$CFG_FILE" ]; then
    # 配置文件是本脚本自己写的 key=value（值已转义），直接 source
    . "$CFG_FILE"
  fi
}

save_config() {
  mkdir -p "$CFG_DIR"
  {
    printf '%s=%q\n' PORT "$PORT" RATE "$RATE" BURST "$BURST" NAME "$NAME" HOST "$HOST" FALLBACK "$FALLBACK" TLS_DOMAIN "$TLS_DOMAIN" TLS_CERT "$TLS_CERT" TLS_KEY "$TLS_KEY" TLS_AUTO "$TLS_AUTO" TLS_SNI "$TLS_SNI" WHITELIST_IPS "$WHITELIST_IPS" WHITELIST_FILE "$WHITELIST_FILE" ALLOW_IPS "$ALLOW_IPS" ALLOWLIST_FILE "$ALLOWLIST_FILE"
  } > "$CFG_FILE"
  chmod 600 "$CFG_FILE"
}

# 按当前配置写 systemd 服务文件（不重载、不重启，只写文件）
write_service() {
  local tls_args="" wl_args="" al_args="" ip e
  if [ -n "$TLS_DOMAIN" ]; then
    tls_args=" --tls-domain $TLS_DOMAIN --tls-cert $TLS_CERT --tls-key $TLS_KEY"
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    # 自签模式：证书路径必须写绝对路径——服务端不给路径时默认相对路径 tls-cert.pem，
    # systemd 下工作目录是 /，会写到根目录去，所以这里固定写 /etc/mm1 下。
    tls_args=" --tls-auto --tls-cert $CFG_DIR/tls-cert.pem --tls-key $CFG_DIR/tls-key.pem"
    if [ -n "${TLS_SNI:-}" ]; then tls_args="$tls_args --tls-sni $TLS_SNI"; fi
  fi
  for ip in $WHITELIST_IPS; do wl_args="$wl_args --whitelist $ip"; done
  if [ -n "$WHITELIST_FILE" ]; then wl_args="$wl_args --whitelist-file $WHITELIST_FILE"; fi
  for e in $ALLOW_IPS; do al_args="$al_args --allowlist $e"; done
  if [ -n "$ALLOWLIST_FILE" ]; then al_args="$al_args --allowlist-file $ALLOWLIST_FILE"; fi
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
ExecStart=$SERVER_BIN --psk-file $PSK_FILE --listen 0.0.0.0:$PORT --rate $RATE --burst $BURST --name "$NAME" --fallback $FALLBACK$tls_args$wl_args$al_args
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
  cp -f "$UNIT_FILE" "$UNIT_FILE.bak" 2>/dev/null || true
  save_config
  write_service
  systemctl daemon-reload 2>/dev/null || true
  if systemctl restart mm1-server 2>/dev/null && systemctl is-active --quiet mm1-server 2>/dev/null; then
    rm -f "$CFG_FILE.bak" "$UNIT_FILE.bak"
    echo "已生效：$desc，服务已重启并正常运行"
    return 0
  fi
  echo "重启失败！正在回滚到改之前的配置……"
  cp -f "$CFG_FILE.bak" "$CFG_FILE" 2>/dev/null || true
  cp -f "$UNIT_FILE.bak" "$UNIT_FILE" 2>/dev/null || true
  load_config
  systemctl daemon-reload 2>/dev/null || true
  systemctl restart mm1-server 2>/dev/null || true
  if systemctl is-active --quiet mm1-server 2>/dev/null; then
    echo "已回滚：服务用原配置恢复运行。请检查输入的参数再改。"
  else
    echo "回滚后服务仍未运行！请手动检查：systemctl status mm1-server；日志：journalctl -u mm1-server -n 50"
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

# IPv4 或 IPv4/CIDR（例如 1.2.3.4、5.6.7.0/24）
valid_ip_cidr() {
  printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
}

port_in_use() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -tln 2>/dev/null | grep -q ":$1[[:space:]]"
}

# 1) 显示协议链接：从配置文件读密钥现拼（mm1-server --print-link）；
#    密钥文件没有就先生成一个再拼。安装完不打印链接，就是为了让链接只在这里出现。
#    用法：show_link [plain|opaque]，默认 plain（短格式）；opaque 是一串乱码，
#    只有新版客户端能认——交互菜单里永远打 plain，要 opaque 用 mm --show-link opaque。
show_link() {
  local fmt="${1:-plain}"
  case "$fmt" in
    plain|opaque) ;;
    *) echo "链接格式不对：$fmt，应为 plain（短格式）或 opaque（不透明链接）"; return 1 ;;
  esac
  load_config
  if [ ! -x "$SERVER_BIN" ]; then echo "服务端程序不在：$SERVER_BIN（被删了？请重装）"; return 1; fi
  if [ -z "$PORT" ]; then echo "配置缺失（没有端口），请重装服务端。"; return 1; fi
  if [ ! -s "$PSK_FILE" ]; then
    echo "密钥文件不存在，先生成一个……"
    mkdir -p "$CFG_DIR"
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32 > "$PSK_FILE";
    else od -An -tx1 -N 32 /dev/urandom | tr -d ' \n' > "$PSK_FILE"; fi
    chmod 600 "$PSK_FILE"
    systemctl restart mm1-server 2>/dev/null || true
  fi
  local psk host link
  psk="$(cat "$PSK_FILE")"
  host="$HOST"
  if [ -n "$TLS_DOMAIN" ]; then
    host="$TLS_DOMAIN"
    link="$("$SERVER_BIN" --print-link --link-format "$fmt" --psk "$psk" --host "$host" --listen "0.0.0.0:$PORT" --rate "$RATE" --burst "$BURST" --name "$NAME" --tls-domain "$TLS_DOMAIN" --tls-cert "$TLS_CERT" --tls-key "$TLS_KEY" 2>/dev/null)"
  elif [ "${TLS_AUTO:-0}" = "1" ]; then
    # 自签模式：--print-link 会按路径加载证书（没有就现场生成），
    # 链接是短格式（ver=4 + pin，obfs=tls 和默认 sni 不写进链接）。
    local sni_args=()
    if [ -n "${TLS_SNI:-}" ]; then sni_args=(--tls-sni "$TLS_SNI"); fi
    if [ -z "$host" ]; then host="<你的 VPS 公网 IP>"; fi
    link="$("$SERVER_BIN" --print-link --link-format "$fmt" --psk "$psk" --host "$host" --listen "0.0.0.0:$PORT" --rate "$RATE" --burst "$BURST" --name "$NAME" --tls-auto --tls-cert "$CFG_DIR/tls-cert.pem" --tls-key "$CFG_DIR/tls-key.pem" "${sni_args[@]}" 2>/dev/null)"
  else
    if [ -z "$host" ]; then host="<你的 VPS 公网 IP>"; fi
    link="$("$SERVER_BIN" --print-link --link-format "$fmt" --psk "$psk" --host "$host" --listen "0.0.0.0:$PORT" --rate "$RATE" --burst "$BURST" --name "$NAME" 2>/dev/null)"
  fi
  if [ -z "$link" ]; then echo "拼链接失败（密钥或参数有问题），请看第 6 项日志。"; return 1; fi
  echo ""
  echo "节点链接（粘贴到 MM 客户端就能用，绝不要分享给第二个人）："
  echo "$link"
  echo ""
}

# 1b) 显示 TLS 证书的 SPKI 指纹（pin）：客户端锁定验证就靠它；换了证书指纹会变，
#     链接也要重新生成（第 1 项）。TLS 没开时无指纹。
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
    echo "TLS 没开（真 TLS 和自签 TLS 都关着），没有指纹。想开去第 7 项。"
    return 1
  fi
}

# 2) 查看服务状态
show_status() {
  load_config
  if systemctl is-active --quiet mm1-server 2>/dev/null; then
    echo "服务状态：正在运行"
  else
    echo "服务状态：未运行（用第 3 项重启，或看第 6 项日志找原因）"
  fi
  systemctl status mm1-server --no-pager 2>&1 | head -20 || true
  if command -v ss >/dev/null 2>&1 && [ -n "$PORT" ]; then
    if port_in_use "$PORT"; then echo "端口 $PORT 正在监听"; else echo "端口 $PORT 没在监听"; fi
  fi
}

# 3) 重启服务
restart_svc() {
  if systemctl restart mm1-server 2>/dev/null && systemctl is-active --quiet mm1-server 2>/dev/null; then
    echo "重启成功，服务正在运行"
  else
    echo "重启失败！请看第 6 项日志：journalctl -u mm1-server -n 50"
    return 1
  fi
}

# 4) 更换密钥：写新密钥进 /etc/mm1/psk，服务端按 24 小时宽限期自动识别新密钥，
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
  show_link
}

# 5) 修改限速：显示当前值，rate/burst 一起改；严格 50 Mbps = rate=6250K burst=0
change_rate() {
  load_config
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

# 6) 查看最近日志
show_logs() {
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u mm1-server -n 50 --no-pager 2>&1 || echo "读日志失败"
  else
    echo "没有 journalctl，请直接看：systemctl status mm1-server"
  fi
}

# 7) 诱饵回退 / TLS 设置：真 TLS（有域名）和自签 TLS（没域名）二选一；
#    自签证书首次启动自动生成并存到 /etc/mm1/tls-cert.pem、tls-key.pem，
#    客户端靠链接里的 pin（SPKI 指纹）锁定验证；换证书要重新生成链接（第 1 项）。
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
          echo "  apt install certbot -y && certbot certonly --standalone -d $dom"
          echo "证书一般在 /etc/letsencrypt/live/$dom/fullchain.pem 和 privkey.pem，拿到后再回来填这两个路径。"
          pause; continue
        fi
        if [ ! -f "$key" ]; then echo "私钥文件不存在：$key"; pause; continue; fi
        TLS_DOMAIN="$dom"; TLS_CERT="$cert"; TLS_KEY="$key"
        if [ "$PORT" != "443" ]; then
          echo "提示：真 TLS 开了，但端口不是 443（当前 $PORT）；443 更像正常 HTTPS，想改去第 8 项改端口。"
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
        echo "证书首次启动自动生成，存在 /etc/mm1/tls-cert.pem 和 tls-key.pem；"
        echo "链接里的 pin 就是证书指纹（第 1 项的链接已带上，换了证书要重新生成链接）。"
        ;;
      5)
        show_pin
        ;;
      0|"") return 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

# 8) 修改服务启动参数：先显示当前启动命令，再按项改；改完校验，写回配置，
#    重载 + 重启，重启失败自动回滚。
edit_params() {
  while true; do
    load_config
    echo ""
    echo "--- 修改服务启动参数 ---"
    echo "当前启动命令："
    if [ -f "$UNIT_FILE" ]; then grep '^ExecStart=' "$UNIT_FILE" | sed 's/^ExecStart=//'; else echo "（服务文件不存在，请重装）"; fi
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
          if [ "$np" = "443" ]; then echo "443 常见占用：nginx / Apache / 其他 Web 服务，先停掉它（systemctl stop nginx）再改。"; fi
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
      0|"") return 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

# 9) 修改快捷命令：把 mm 改成新名字；只允许字母数字下划线短横线，
#    不能和系统已有命令重名；新名字生效后旧的删掉。
rename_cmd() {
  echo "当前快捷命令：$MYNAME"
  local new old_path new_path
  read -r -p "新名字（只允许字母、数字、下划线、短横线）： " new || return 0
  case "$new" in
    ""|*[!a-zA-Z0-9_-]*) echo "名字不合法：只能用字母、数字、下划线、短横线"; return 1;;
  esac
  if [ "$new" = "$MYNAME" ]; then echo "新名字和现在一样，没改。"; return 0; fi
  if [ "$new" = "mm1-server" ] || [ "$new" = "mm1-client" ]; then
    echo "这个名字是 mm-x 自己的程序名，不能用"; return 1
  fi
  if command -v "$new" >/dev/null 2>&1 || [ -e "$BIN_DIR/$new" ] || [ -e "/usr/bin/$new" ] || [ -e "/bin/$new" ]; then
    echo "名字冲突：系统里已经有叫 $new 的命令/文件，换一个名字"; return 1
  fi
  old_path="$BIN_DIR/$MYNAME"
  new_path="$BIN_DIR/$new"
  if [ ! -f "$old_path" ]; then echo "找不到当前命令文件：$old_path"; return 1; fi
  cp "$old_path" "$new_path" && chmod +x "$new_path" || { echo "改名失败：复制新命令时出错"; return 1; }
  rm -f "$old_path"
  echo "已改名：以后用 \`$new\` 呼出菜单（旧的 \`$MYNAME\` 已删除）"
  # 用新名字重新执行本脚本（继续显示菜单，证明新命令能用）；
  # 旧文件已删，exec 新文件不会读到一半断掉。
  exec "$new_path" --renamed "$MYNAME" "$new"
}

# 10) 卸载：停服务、删服务文件、删程序、删菜单命令、删配置（含密钥）；BBR 设置保留。
uninstall() {
  load_config
  echo "要卸载 mm-x 服务端，将删除：服务 mm1-server、程序 $SERVER_BIN、菜单命令 $BIN_DIR/$MYNAME、配置 $CFG_DIR（含密钥）。"
  echo "BBR 内核设置会保留（对系统无害）。"
  local yn
  read -r -p "确认卸载吗？输入 y 确认： " yn || return 0
  case "$yn" in y|Y) ;; *) echo "已取消。"; return 0;; esac
  systemctl stop mm1-server 2>/dev/null || true
  systemctl disable mm1-server 2>/dev/null || true
  rm -f "$UNIT_FILE"
  systemctl daemon-reload 2>/dev/null || true
  if command -v ufw >/dev/null 2>&1 && [ -n "$PORT" ]; then ufw delete allow "$PORT/tcp" >/dev/null 2>&1 || true; fi
  rm -f "$SERVER_BIN" "$BIN_DIR/$MYNAME"
  if [ -n "$CFG_DIR" ] && [ "$CFG_DIR" != "/" ] && [ "$CFG_DIR" != "/etc" ]; then rm -rf "$CFG_DIR"; fi
  echo "已卸载。"
  exit 0
}

main() {
  if [ "$(id -u)" -ne 0 ]; then echo "请用 sudo 运行：sudo $MYNAME"; exit 1; fi
  # 隐藏用法：部署脚本装完后按配置写服务文件；只打印链接；只打印 TLS 指纹；改名后重新执行
  if [ "${1:-}" = "--write-service" ]; then load_config; write_service; exit 0; fi
  if [ "${1:-}" = "--show-link" ]; then show_link "${2:-plain}"; exit 0; fi
  if [ "${1:-}" = "--show-pin" ]; then show_pin; exit 0; fi
  if [ "${1:-}" = "--renamed" ]; then echo "（已切换到新命令 ${3:-$MYNAME}）"; fi
  while true; do
    load_config
    echo ""
    echo "== mm-x 服务端管理（输入 $MYNAME 呼出） =="
    local tls_desc="关"
    [ -n "$TLS_DOMAIN" ] && tls_desc="真 TLS（$TLS_DOMAIN）"
    [ "${TLS_AUTO:-0}" = "1" ] && tls_desc="自签 TLS（SNI ${TLS_SNI:-www.microsoft.com}）"
    if systemctl is-active --quiet mm1-server 2>/dev/null; then
      echo "服务：正在运行　端口：${PORT:-?}　限速：${RATE:-?}　突发：${BURST:-?}　回退：${FALLBACK:-?}　TLS：$tls_desc"
    else
      echo "服务：未运行（用第 3 项重启，或看第 6 项日志）　端口：${PORT:-?}　限速：${RATE:-?}"
    fi
    echo "1) 显示协议链接"
    echo "2) 查看服务状态"
    echo "3) 重启服务"
    echo "4) 更换密钥"
    echo "5) 修改限速"
    echo "6) 查看最近日志"
    echo "7) 诱饵回退 / TLS 设置"
    echo "8) 修改服务启动参数"
    echo "9) 修改快捷命令"
    echo "10) 卸载"
    echo "11) 退出"
    local c
    read -r -p "选一项： " c || exit 0
    case "$c" in
      1) show_link ;;
      2) show_status ;;
      3) restart_svc ;;
      4) rotate_key ;;
      5) change_rate ;;
      6) show_logs ;;
      7) tls_menu ;;
      8) edit_params ;;
      9) rename_cmd ;;
      10) uninstall ;;
      11|"") exit 0 ;;
      *) echo "没有这个选项" ;;
    esac
    pause
  done
}

main "$@"
MM_MENU_EOF
chmod +x "$BIN_DIR/mm"
echo "管理菜单已安装：$BIN_DIR/mm（输入 mm 呼出）"

# 9) systemd 服务：按配置文件生成（菜单改参数也是同一份逻辑），开机自启、崩溃自动重启
echo "== 写入 systemd 服务 =="
"$BIN_DIR/mm" --write-service
mkdir -p "$UNIT_DIR"
systemctl daemon-reload
systemctl enable mm1-server >/dev/null 2>&1
systemctl restart mm1-server
sleep 2
if systemctl is-active --quiet mm1-server; then
  echo "服务已启动：mm1-server 正在运行"
else
  echo "服务启动失败，请看日志：journalctl -u mm1-server -n 50"
  exit 1
fi

echo ""
echo "== 安装完成 =="
echo "监听端口：$PORT"
echo "限速上限：$RATE（0 = 不限速），突发额度：$BURST"
echo "回退模式：$FALLBACK；TLS：$TLS_MODE_DESC"
echo "密钥文件：$PSK_FILE（重装不换密钥；轮换密钥：mm 菜单第 4 项，24 小时内新旧密钥都能用）"
echo "配置文件：$CFG_FILE（菜单改参数就改这个文件）"
echo "服务状态：mm 菜单第 2 项，或 systemctl status mm1-server；日志：mm 菜单第 6 项，或 journalctl -u mm1-server -f"
echo ""
echo "输入 mm 打开管理菜单，在菜单第 1 项查看协议链接（粘贴到 MM 客户端就能用，绝不要分享给第二个人）。"
