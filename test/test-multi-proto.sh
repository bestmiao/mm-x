#!/bin/bash
# mm-x 多协议测试（XHTTP / ss2022，Xray）：在沙箱里用替身命令模拟 systemd，
# 验证：选 XHTTP 能建出节点、选 ss2022 能建出节点、链接格式正确、端口不冲突、
# 协议切换时两个服务互斥、谷歌服务能套到新协议上、流量监视能超限限速、删除/卸载清干净。
# 用法：bash test/test-multi-proto.sh
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"

GO=~/workspace/_build/go/bin/go
TEST_ROOT=/tmp/mmx-multi-proto-test
STUB_BIN="$TEST_ROOT/stubs"
SRC_DIR="$TEST_ROOT/src"
MM_BIN="$TEST_ROOT/usr/local/bin/mmx"
CFG="$TEST_ROOT/etc/mmx/config"
XRAY_CONF="$TEST_ROOT/etc/mmx/xray.conf"
XRAY_CFG="$TEST_ROOT/usr/local/etc/xray/config.json"
UNIT="$TEST_ROOT/etc/systemd/system/mmx-server.service"

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
note() { echo "--- $1"; }
has()  { grep -q "$2" "$1"; }   # has 文件 正则

rm -rf "$TEST_ROOT"
mkdir -p "$STUB_BIN" "$SRC_DIR"

# ---- 替身 systemctl：mmx-server 和 xray 各走一个状态文件，互不干扰；
#      mmx-xray-watch.timer 另走一个状态文件；nginx 等其他服务只记日志不改状态 ----
cat > "$STUB_BIN/systemctl" <<'EOF'
#!/bin/bash
# 测试替身：认 mmx-server / xray / mmx-xray-watch.timer；状态分开存
LOG_FILE="${MMX_TEST_ROOT}/systemctl.log"
echo "systemctl $*" >> "$LOG_FILE"
cmd="$1"; shift
svc_name() {
  local s="$1"
  s="${s%.service}"; s="${s%.timer}"
  printf '%s' "$s"
}
state_for() {
  case "$(svc_name "$1")" in
    xray) printf '%s' "${MMX_TEST_ROOT}/xray-state" ;;
    mmx-xray-watch) printf '%s' "${MMX_TEST_ROOT}/watch-state" ;;
    mmx-server) printf '%s' "${MMX_TEST_ROOT}/svc-state" ;;
    *) printf '%s' "" ;;
  esac
}
case "$cmd" in
  daemon-reload) exit 0 ;;
  enable|disable) exit 0 ;;
  start|stop|restart)
    svc="$(svc_name "${1:-}")"
    st="$(state_for "$svc")"
    [ -z "$st" ] && exit 0
    if [ "$cmd" = "stop" ]; then echo "inactive" > "$st"; exit 0; fi
    if [ -f "${MMX_TEST_ROOT}/fail-next-restart" ]; then
      rm -f "${MMX_TEST_ROOT}/fail-next-restart"
      echo "failed" > "$st"
      echo "Job for $svc failed (simulated)" >&2
      exit 1
    fi
    echo "active" > "$st"
    exit 0 ;;
  is-active)
    svc=""
    for a in "$@"; do case "$a" in --quiet) ;; *) svc="$a" ;; esac; done
    st="$(state_for "$svc")"
    [ -z "$st" ] && exit 3
    [ "$(cat "$st" 2>/dev/null)" = "active" ] && exit 0 || exit 3 ;;
  status)
    svc=""
    for a in "$@"; do case "$a" in --no-pager) ;; *) svc="$a" ;; esac; done
    st="$(state_for "$svc")"
    if [ -n "$st" ] && [ "$(cat "$st" 2>/dev/null)" = "active" ]; then
      echo "● $svc - test"
      echo "   Active: active (running)"
    else
      echo "● $svc - test"
      echo "   Active: inactive (dead)"
    fi
    exit 0 ;;
  *) echo "替身 systemctl 不认识：$cmd" >&2; exit 1 ;;
esac
EOF
chmod +x "$STUB_BIN/systemctl"

# ---- 替身 journalctl：固定打印 3 行假日志 ----
cat > "$STUB_BIN/journalctl" <<'EOF'
#!/bin/bash
echo "11月22日 23:00:00 test xray[1]: Xray 25.11.9 started"
echo "11月22日 23:00:01 test xray[1]: inbound listening on 0.0.0.0:18200"
echo "11月22日 23:00:02 test xray[1]: ready"
EOF
chmod +x "$STUB_BIN/journalctl"

# ---- 替身 ss：ss-busy-ports 文件里每行一个端口，算被占用 ----
cat > "$STUB_BIN/ss" <<'EOF'
#!/bin/bash
f="${MMX_TEST_ROOT}/ss-busy-ports"
[ -f "$f" ] || exit 0
while read -r p; do
  [ -n "$p" ] && echo "LISTEN 0 4096 0.0.0.0:$p 0.0.0.0:*"
done < "$f"
exit 0
EOF
chmod +x "$STUB_BIN/ss"

# ---- 替身 sysctl：只记调用，不碰真实内核 ----
cat > "$STUB_BIN/sysctl" <<'EOF'
#!/bin/bash
echo "sysctl $*" >> "${MMX_TEST_ROOT}/sysctl.log"
exit 0
EOF
chmod +x "$STUB_BIN/sysctl"

# ---- 替身 curl：公网 IP 探测永远返回 203.0.113.5 ----
cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
echo "203.0.113.5"
exit 0
EOF
chmod +x "$STUB_BIN/curl"

# ---- 替身 getent / dig / nslookup：域名解析永远查不到（XHTTP TLS 测试不用 DNS） ----
cat > "$STUB_BIN/getent" <<'EOF'
#!/bin/bash
exit 2
EOF
chmod +x "$STUB_BIN/getent"
cat > "$STUB_BIN/dig" <<'EOF'
#!/bin/bash
exit 1
EOF
chmod +x "$STUB_BIN/dig"
cat > "$STUB_BIN/nslookup" <<'EOF'
#!/bin/bash
exit 1
EOF
chmod +x "$STUB_BIN/nslookup"

# ---- 替身 certbot：只认 certonly --standalone；按 -d 的域名生成假证书 ----
cat > "$STUB_BIN/certbot" <<'EOF'
#!/bin/bash
echo "certbot $*" >> "${MMX_TEST_ROOT}/certbot.log"
has_standalone=0; dom=""; prev=""
for a in "$@"; do
  case "$a" in
    --standalone) has_standalone=1 ;;
    -d) prev="-d" ;;
    *) if [ "$prev" = "-d" ]; then dom="$a"; prev=""; fi ;;
  esac
done
[ "$1" = "certonly" ] || { echo "替身 certbot 只认 certonly" >&2; exit 1; }
[ "$has_standalone" = 1 ] || { echo "替身 certbot：需要 --standalone" >&2; exit 1; }
[ -n "$dom" ] || { echo "替身 certbot：需要 -d 域名" >&2; exit 1; }
le="${MMX_TEST_ROOT}/etc/letsencrypt"
mkdir -p "$le/live/$dom" "$le/renewal"
openssl req -x509 -newkey rsa:2048 -keyout "$le/live/$dom/privkey.pem" -out "$le/live/$dom/fullchain.pem" -days 90 -nodes -subj "/CN=$dom" -addext "subjectAltName=DNS:$dom" >/dev/null 2>&1 || exit 1
printf '[renewalparams]\naccount = test\n' > "$le/renewal/$dom.conf"
exit 0
EOF
chmod +x "$STUB_BIN/certbot"

export MMX_TEST_ROOT="$TEST_ROOT"
export PATH="$TEST_ROOT/usr/local/bin:$STUB_BIN:$PATH"

note "编译服务端二进制（当前源码，v5；mmx 切换测试要它拼链接）"
$GO build -o "$SRC_DIR/mmx-server-linux-amd64" ./cmd/mmx-server || { echo "编译失败"; exit 1; }
ok "编译通过"
cp install-mm-x-server.sh "$SRC_DIR/"
cp "$SRC_DIR/mmx-server-linux-amd64" "$SRC_DIR/mmx-server" 2>/dev/null || true

note "测试0：全新安装只装程序，不建节点"
bash "$SRC_DIR/install-mm-x-server.sh" --port 18200 < /dev/null > "$TEST_ROOT/deploy.log" 2>&1
[ "$?" = 0 ] && ok "部署脚本退出码 0" || bad "部署脚本退出码非 0（见 deploy.log）"
[ -x "$MM_BIN" ] && ok "/usr/local/bin/mmx 存在且可执行" || bad "/usr/local/bin/mmx 不存在或不可执行"
[ ! -e "$CFG" ] && ok "全新安装不写配置文件" || bad "全新安装写了配置文件（应该不建节点）"

# 菜单调用辅助：喂给 mm 的输入（先落文件再 cat，避免 SIGPIPE 竞态）。
run_mm() { printf '%b' "$1" | "$MM_BIN" > "$TEST_ROOT/mm-out.txt" 2>&1; cat "$TEST_ROOT/mm-out.txt"; }

note "测试1：选 XHTTP（Reality）建出节点"
# 菜单1 → 协议2(XHTTP) → 模式1(Reality) → 地区4(美国) → 端口18200 → 分流默认开 → 流量全默认 → 退出
run_mm '1\n2\n1\n4\n18200\n\n\n1\n\n\n10\n' | grep -q "XHTTP 节点已添加" && ok "XHTTP 节点添加成功" || bad "XHTTP 节点添加失败（见 mm-out.txt）"
has "$CFG" "^PROTO=xhttp$" && ok "主配置 PROTO=xhttp" || bad "主配置 PROTO 不是 xhttp"
has "$CFG" "^PORT=18200$" && ok "主配置端口 18200" || bad "主配置端口不对"
( . "$CFG"; [ "$NAME" = "$HOST" ] ) && ok "主配置节点名自动取服务器地址" || bad "主配置节点名不对"
[ -f "$XRAY_CONF" ] && ok "Xray 状态文件已生成：/etc/mmx/xray.conf" || bad "Xray 状态文件没生成"
has "$XRAY_CONF" "^XHTTP_MODE=reality$" && ok "xray.conf 模式 Reality" || bad "xray.conf 模式不对"
has "$XRAY_CONF" "^XHTTP_REGION=us$" && ok "xray.conf 地区 us" || bad "xray.conf 地区不对"
( . "$XRAY_CONF"; [ -n "$XHTTP_UUID" ] && [ -n "$XHTTP_PUBKEY" ] && [ -n "$XHTTP_PRIVKEY" ] && [ -n "$XHTTP_SHORTID" ] && [ -n "$XHTTP_SNI" ] ) && ok "xray.conf 有 UUID/公私钥/短 ID/SNI" || bad "xray.conf 缺 UUID 或密钥"
( . "$XRAY_CONF"; case "$XHTTP_SNI" in www.whitney.org|www.okstate.edu|www.oregonstate.edu|www.ufl.edu) exit 0;; *) exit 1;; esac ) && ok "SNI 来自美国 SNI 池" || bad "SNI 不是美国池的域名"
[ -f "$XRAY_CFG" ] && ok "Xray 配置已生成：/usr/local/etc/xray/config.json" || bad "Xray 配置没生成"
jq -e . "$XRAY_CFG" >/dev/null 2>&1 && ok "Xray 配置是合法 JSON" || bad "Xray 配置不是合法 JSON"
jq -e '.inbounds[0].protocol == "vless" and .inbounds[0].port == 18200 and .inbounds[0].streamSettings.network == "xhttp" and .inbounds[0].streamSettings.security == "reality"' "$XRAY_CFG" >/dev/null 2>&1 && ok "Xray 配置是 VLESS + XHTTP + Reality" || bad "Xray 配置内容不对"
[ -x "$TEST_ROOT/usr/local/bin/xray" ] && ok "替身 xray 已安装" || bad "替身 xray 没装上"
[ -f "$TEST_ROOT/etc/mmx/xray-installed" ] && ok "xray 安装标记已生成" || bad "xray 安装标记没生成"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "建节点后 xray 在运行" || bad "建节点后 xray 没运行"
[ ! -f "$TEST_ROOT/svc-state" ] || [ "$(cat "$TEST_ROOT/svc-state" 2>/dev/null)" != "active" ] && ok "XHTTP 节点时 mmx-server 没在运行（两个服务不同时跑）" || bad "XHTTP 节点时 mmx-server 还在运行"
[ -f "$TEST_ROOT/etc/mmx/xhttp-split-a.json" ] && ok "分离配置 A 已生成" || bad "分离配置 A 没生成"
[ -f "$TEST_ROOT/etc/mmx/xhttp-split-b.json" ] && ok "分离配置 B 已生成" || bad "分离配置 B 没生成"
jq -e '.outbounds[0].streamSettings.xhttpSettings.mode == "stream-up"' "$TEST_ROOT/etc/mmx/xhttp-split-a.json" >/dev/null 2>&1 && ok "分离配置 A 是 stream-up" || bad "分离配置 A 内容不对"
jq -e '.transport.mode == "stream-up"' "$TEST_ROOT/etc/mmx/xhttp-split-b.json" >/dev/null 2>&1 && ok "分离配置 B 是 stream-up" || bad "分离配置 B 内容不对"
[ -f "$TEST_ROOT/etc/mmx/xray-info.txt" ] && ok "Xray 节点信息文件已生成" || bad "Xray 节点信息文件没生成"
grep -q "mmx-xray-watch.timer" "$TEST_ROOT/systemctl.log" && ok "建 XHTTP 节点时装了流量监视定时任务" || bad "建 XHTTP 节点时没装流量监视"

note "测试2：XHTTP 节点链接格式"
XHTTP_OUT="$(run_mm '5\n10\n')"
printf '%s' "$XHTTP_OUT" | grep -q "vless://" && ok "第 5 项显示 vless:// 链接" || bad "第 5 项没显示 vless:// 链接"
XHTTP_LINK="$(printf '%s' "$XHTTP_OUT" | grep -o 'vless://[^ ]*' | head -1)"
printf '%s' "$XHTTP_LINK" | grep -q "security=reality" && ok "链接是 Reality" || bad "链接不是 Reality"
printf '%s' "$XHTTP_LINK" | grep -q "type=xhttp" && ok "链接 type=xhttp" || bad "链接没 type=xhttp"
printf '%s' "$XHTTP_LINK" | grep -q "mode=stream-up" && ok "链接 mode=stream-up（分流开）" || bad "链接没 mode=stream-up"
printf '%s' "$XHTTP_LINK" | grep -q "path=%2Fapi" && ok "链接 path=%2Fapi" || bad "链接 path 不对"
printf '%s' "$XHTTP_LINK" | grep -q "sni=" && ok "链接带 sni" || bad "链接没 sni"
printf '%s' "$XHTTP_LINK" | grep -q "pbk=" && ok "链接带 pbk（公钥）" || bad "链接没 pbk"
printf '%s' "$XHTTP_LINK" | grep -q "sid=" && ok "链接带 sid（短 ID）" || bad "链接没 sid"
printf '%s' "$XHTTP_LINK" | grep -q ":18200" && ok "链接端口 18200" || bad "链接端口不对"
LINK2="$("$MM_BIN" --show-link 2>/dev/null | grep -o 'vless://[^ ]*' | head -1)"
[ "$LINK2" = "$XHTTP_LINK" ] && ok "--show-link 和第 5 项链接一致" || bad "--show-link 链接不一致"
STATUS_OUT="$(run_mm '6\n10\n')"
printf '%s' "$STATUS_OUT" | grep -q "xray" && ok "第 6 项状态显示 xray" || bad "第 6 项状态没提 xray"
printf '%s' "$STATUS_OUT" | grep -q "正在运行" && ok "第 6 项状态正在运行" || bad "第 6 项状态不对"
run_mm '7\n10\n' | grep -q "重启成功" && ok "第 7 项重启 xray 成功" || bad "第 7 项重启失败"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "重启后 xray 仍在运行" || bad "重启后 xray 停了"

note "测试3：端口冲突——被别的服务占的端口拒绝重问，本服务的端口允许"
echo "18299" > "$TEST_ROOT/ss-busy-ports"
# 菜单1 → y(覆盖) → 协议3(ss2022) → 端口18299(被占) → 端口18201 → 流量默认
run_mm '1\ny\n3\n18299\n18201\n\n1\n\n\n10\n' | grep -q "端口 18299 已被占用" && ok "被占端口 18299 被拒绝并提示" || bad "被占端口没被拒绝"
has "$CFG" "^PROTO=ss2022$" && ok "切到 ss2022 后 PROTO=ss2022" || bad "切到 ss2022 后 PROTO 不对"
has "$CFG" "^PORT=18201$" && ok "ss2022 节点端口 18201（重问后）" || bad "ss2022 节点端口不对"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "ss2022 节点 xray 在运行" || bad "ss2022 节点 xray 没运行"
rm -f "$TEST_ROOT/ss-busy-ports"

note "测试4：ss2022 节点链接格式"
SS_OUT="$(run_mm '5\n10\n')"
printf '%s' "$SS_OUT" | grep -q "ss://" && ok "第 5 项显示 ss:// 链接" || bad "第 5 项没显示 ss:// 链接"
SS_LINK="$(printf '%s' "$SS_OUT" | grep -o 'ss://[^ ]*' | head -1)"
printf '%s' "$SS_LINK" | grep -q ":18201#" && ok "ss 链接端口 18201" || bad "ss 链接端口不对"
# ss:// 的 userinfo 是 base64url(方法:密码)，解出来应是 2022-blake3-aes-256-gcm:xxx
SS_USER="$(printf '%s' "$SS_LINK" | sed -n 's|^ss://\([^@]*\)@.*|\1|p')"
SS_DEC="$(printf '%s' "$SS_USER" | tr '_-' '/+' | awk '{printf "%s%s", $0, substr("====", 1, (4 - length($0) % 4) % 4)}' | base64 -d 2>/dev/null)"
printf '%s' "$SS_DEC" | grep -q "^2022-blake3-aes-256-gcm:" && ok "ss 链接方法是 2022-blake3-aes-256-gcm" || bad "ss 链接方法不对：$SS_DEC"
( . "$XRAY_CONF"; [ "$SS_PASSWORD" = "${SS_DEC#2022-blake3-aes-256-gcm:}" ] ) && ok "ss 链接密码和 xray.conf 一致" || bad "ss 链接密码和配置不一致"
jq -e '.inbounds[0].protocol == "shadowsocks" and .inbounds[0].port == 18201 and .inbounds[0].settings.method == "2022-blake3-aes-256-gcm"' "$XRAY_CFG" >/dev/null 2>&1 && ok "Xray 配置是 Shadowsocks 2022" || bad "Xray 配置不是 ss2022"
[ ! -e "$TEST_ROOT/etc/mmx/xhttp-split-a.json" ] && ok "切到 ss2022 后分离配置 A 已删" || bad "切到 ss2022 后分离配置 A 还在"
[ ! -e "$TEST_ROOT/etc/mmx/xhttp-split-b.json" ] && ok "切到 ss2022 后分离配置 B 已删" || bad "切到 ss2022 后分离配置 B 还在"

note "测试5：切回 mmx——xray 停，mmx-server 起，链接是 mmx://"
# 菜单1 → y(覆盖) → 协议1(mmx) → 端口18202 → 流量默认 → 域名/IP 2 → 退出
run_mm '1\ny\n1\n18202\n\n1\n\n\n2\n10\n' | grep -q "添加节点" && ok "切回 mmx 添加成功" || bad "切回 mmx 添加失败"
has "$CFG" "^PROTO=mmx$" && ok "切回 mmx 后 PROTO=mmx" || bad "切回 mmx 后 PROTO 不对"
has "$CFG" "^PORT=18202$" && ok "mmx 节点端口 18202" || bad "mmx 节点端口不对"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" != "active" ] && ok "切回 mmx 后 xray 已停" || bad "切回 mmx 后 xray 还在运行"
[ "$(cat "$TEST_ROOT/svc-state" 2>/dev/null)" = "active" ] && ok "切回 mmx 后 mmx-server 在运行" || bad "切回 mmx 后 mmx-server 没运行"
MMX_OUT="$(run_mm '5\n10\n')"
printf '%s' "$MMX_OUT" | grep -q "mmx://" && ok "mmx 节点第 5 项显示 mmx:// 链接" || bad "mmx 节点第 5 项没显示 mmx:// 链接"
! printf '%s' "$MMX_OUT" | grep -q "vless://\|ss://" && ok "mmx 节点不显示 vless/ss 链接" || bad "mmx 节点混进了 Xray 链接"

note "测试6：再切回 XHTTP——mmx-server 停，xray 起"
run_mm '1\ny\n2\n1\n1\n18203\n\n\n1\n\n\n10\n' | grep -q "XHTTP 节点已添加" && ok "再切回 XHTTP 添加成功" || bad "再切回 XHTTP 添加失败"
has "$CFG" "^PROTO=xhttp$" && ok "再切回 XHTTP 后 PROTO=xhttp" || bad "再切回 XHTTP 后 PROTO 不对"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "再切回 XHTTP 后 xray 在运行" || bad "再切回 XHTTP 后 xray 没运行"
[ "$(cat "$TEST_ROOT/svc-state" 2>/dev/null)" != "active" ] && ok "再切回 XHTTP 后 mmx-server 已停" || bad "再切回 XHTTP 后 mmx-server 还在运行"

note "测试7：谷歌服务开关（XHTTP 节点）——开→关→开，配置和 Xray 路由跟着翻"
# 先删节点（复用旧测试7的删除校验），再用菜单 1 正常建一个 XHTTP 节点（不限额、不限速、无白名单）
run_mm '4\ny\n10\n' | grep -q "节点已删除" && ok "先删除节点" || bad "删除节点失败"
[ ! -e "$CFG" ] && ok "删除后主配置已删" || bad "删除后主配置还在"
[ ! -e "$XRAY_CONF" ] && ok "删除后 xray.conf 已删" || bad "删除后 xray.conf 还在"
[ ! -e "$XRAY_CFG" ] && ok "删除后 Xray 配置已删" || bad "删除后 Xray 配置还在"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" != "active" ] && ok "删除后 xray 已停" || bad "删除后 xray 还在运行"
# 菜单1 → 协议2(XHTTP) → 模式1(Reality) → 地区4(美国) → 端口18204 → 分流默认 → 流量默认 → 退出
run_mm '1\n2\n1\n4\n18204\n\n\n1\n\n\n10\n' | grep -q "XHTTP 节点已添加" && ok "菜单 1 建出 XHTTP 节点" || bad "菜单 1 建 XHTTP 节点失败"
has "$CFG" "^PROTO=xhttp$" && ok "新建节点 PROTO=xhttp" || bad "新建节点 PROTO 不对"
has "$CFG" "^DOMAIN_WHITELIST=''$" && ok "新建节点白名单默认关" || bad "新建节点白名单默认不对"
! jq -e '.routing' "$XRAY_CFG" >/dev/null 2>&1 && ok "白名单关时 Xray 配置里没 routing" || bad "白名单关时 Xray 配置里有 routing"
# 点第 2 项：关 → 开（记下重启次数，验证切换时重启了 xray）
RC0=$(grep -c "restart xray" "$TEST_ROOT/systemctl.log" 2>/dev/null || true); RC0=${RC0:-0}
OUT="$(run_mm '2\n10\n')"
printf '%s' "$OUT" | grep -q "谷歌服务：关" && ok "菜单第 2 项显示白名单关" || bad "菜单第 2 项没显示白名单关"
printf '%s' "$OUT" | grep -q "谷歌服务已开" && ok "点第 2 项提示白名单已开" || bad "点第 2 项没提示白名单已开"
printf '%s' "$OUT" | grep -q "谷歌服务：开" && ok "切换后菜单第 2 项显示白名单开" || bad "切换后菜单第 2 项没显示白名单开"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "开白名单后配置是 google" || bad "开白名单后配置不对"
jq -e '.routing.rules[0].domain[0] == "geosite:google"' "$XRAY_CFG" >/dev/null 2>&1 && ok "Xray 配置里有 geosite:google 路由（白名单只对 XHTTP 生效）" || bad "Xray 配置里没 geosite:google 路由"
jq -e '.routing.rules[1].outboundTag == "blocked" and .routing.rules[1].network == "tcp,udp"' "$XRAY_CFG" >/dev/null 2>&1 && ok "XHTTP 白名单兜底规则带 network（真 xray 才认得出这条规则）" || bad "XHTTP 白名单兜底规则不对"
RC1=$(grep -c "restart xray" "$TEST_ROOT/systemctl.log" 2>/dev/null || true); RC1=${RC1:-0}
[ "$RC1" -gt "$RC0" ] && ok "开白名单时重启了 xray" || bad "开白名单时没重启 xray"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "开白名单后 xray 仍在运行" || bad "开白名单后 xray 停了"
# 再点第 2 项：开 → 关
OUT="$(run_mm '2\n10\n')"
printf '%s' "$OUT" | grep -q "谷歌服务：开" && ok "菜单第 2 项显示白名单开" || bad "菜单第 2 项没显示白名单开"
printf '%s' "$OUT" | grep -q "谷歌服务已关" && ok "再点第 2 项提示白名单已关" || bad "再点第 2 项没提示白名单已关"
has "$CFG" "^DOMAIN_WHITELIST=''$" && ok "关白名单后配置已清空" || bad "关白名单后配置没清空"
! jq -e '.routing' "$XRAY_CFG" >/dev/null 2>&1 && ok "白名单关后 Xray 配置里没了 routing" || bad "白名单关后 Xray 配置里还有 routing"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "关白名单后 xray 仍在运行" || bad "关白名单后 xray 停了"
# 第三次点第 2 项：关 → 开
run_mm '2\n10\n' | grep -q "谷歌服务已开" && ok "第三次点第 2 项又打开" || bad "第三次点第 2 项没打开"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "再开后配置又是 google" || bad "再开后配置不对"

note "测试8：谷歌服务开关（ss2022 节点）——白名单对 ss2022 也生效"
# 当前是 XHTTP 节点，白名单开着；切到 ss2022（菜单 1），白名单跟着配置走
run_mm '1\ny\n3\n18205\n\n1\n\n\n10\n' | grep -q "ss2022 节点已添加" && ok "菜单 1 切到 ss2022 成功" || bad "菜单 1 切 ss2022 失败"
has "$CFG" "^PROTO=ss2022$" && ok "切到 ss2022 后 PROTO=ss2022" || bad "切到 ss2022 后 PROTO 不对"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "切协议后白名单仍开着（配置跟着走）" || bad "切协议后白名单被关了"
jq -e '.inbounds[0].protocol == "shadowsocks"' "$XRAY_CFG" >/dev/null 2>&1 && ok "ss2022 节点 Xray 配置是 Shadowsocks" || bad "ss2022 节点 Xray 配置不对"
jq -e '.routing.rules[0].domain[0] == "geosite:google" and .routing.rules[0].outboundTag == "direct"' "$XRAY_CFG" >/dev/null 2>&1 && ok "ss2022 白名单：geosite:google → direct" || bad "ss2022 白名单路由不对"
jq -e '.routing.rules[1].outboundTag == "blocked" and .routing.rules[1].network == "tcp,udp"' "$XRAY_CFG" >/dev/null 2>&1 && ok "ss2022 白名单：其余流量 → blocked（兜底规则带 network 才认得出）" || bad "ss2022 白名单兜底规则不对"
jq -e '.outbounds[] | select(.tag == "blocked") | .protocol == "blackhole"' "$XRAY_CFG" >/dev/null 2>&1 && ok "ss2022 白名单：blocked 出站是 blackhole" || bad "ss2022 白名单缺 blocked 出站"
jq -e '.inbounds[0].sniffing.enabled == true' "$XRAY_CFG" >/dev/null 2>&1 && ok "ss2022 入站开了 sniffing（域名路由才认得出）" || bad "ss2022 入站没开 sniffing"
# 点第 2 项：开 → 关
OUT="$(run_mm '2\n10\n')"
printf '%s' "$OUT" | grep -q "谷歌服务已关" && ok "ss2022 下点第 2 项提示白名单已关" || bad "ss2022 下点第 2 项没提示白名单已关"
has "$CFG" "^DOMAIN_WHITELIST=''$" && ok "关白名单后配置已清空" || bad "关白名单后配置没清空"
! jq -e '.routing' "$XRAY_CFG" >/dev/null 2>&1 && ok "白名单关后 ss2022 配置里没了 routing" || bad "白名单关后 ss2022 配置里还有 routing"
jq -e '.inbounds[0].protocol == "shadowsocks"' "$XRAY_CFG" >/dev/null 2>&1 && ok "关白名单后节点仍是 ss2022" || bad "关白名单后节点变了"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "关白名单后 xray 仍在运行" || bad "关白名单后 xray 停了"
# 再点第 2 项：关 → 开
run_mm '2\n10\n' | grep -q "谷歌服务已开" && ok "ss2022 下再点第 2 项又打开" || bad "ss2022 下再点第 2 项没打开"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "再开后配置又是 google" || bad "再开后配置不对"
jq -e '.routing.rules[0].domain[0] == "geosite:google"' "$XRAY_CFG" >/dev/null 2>&1 && ok "再开后 ss2022 路由回来了" || bad "再开后 ss2022 路由没回来"

note "测试10：Xray 流量监视——假网卡计数，超限后 TC 限速"
# 先把限额改成 1K（第3项→第6项→第6子项），方便超限
run_mm '3\n6\n6\n1K\n0\n0\n10\n' | grep -q "限额改为 1K" && ok "限额改为 1K" || bad "改限额失败"
has "$CFG" "^TRAFFIC_QUOTA=1K$" && ok "配置限额已是 1K" || bad "配置限额不对"
# 假网卡：test0，初始收/发各 1000 字节
export XRAY_IFACE="test0"
export MMX_XRAY_SYSFS_ROOT="$TEST_ROOT/sys/class/net"
mkdir -p "$TEST_ROOT/sys/class/net/test0/statistics"
printf '1000' > "$TEST_ROOT/sys/class/net/test0/statistics/rx_bytes"
printf '1000' > "$TEST_ROOT/sys/class/net/test0/statistics/tx_bytes"
# 菜单流量页每次打开都会先跑一次监视（show_traffic），上面改限额时已用真实网卡
# 写过一次 xray-traffic.json；先删掉，保证首次跑从 0 开始计数。
rm -f "$TEST_ROOT/etc/mmx/xray-traffic.json"
"$MM_BIN" --xray-watch run
[ -f "$TEST_ROOT/etc/mmx/xray-traffic.json" ] && ok "流量监视跑完写出 xray-traffic.json" || bad "流量监视没写 xray-traffic.json"
jq -e '.in == 0 and .out == 0 and .enforced == ""' "$TEST_ROOT/etc/mmx/xray-traffic.json" >/dev/null 2>&1 && ok "首次跑计数从 0 开始，未超限" || bad "首次跑计数不对"
# 网卡计数涨到各 5000（本周期新增 4000+4000=8000，总计模式，超 1K 限额）
printf '5000' > "$TEST_ROOT/sys/class/net/test0/statistics/rx_bytes"
printf '5000' > "$TEST_ROOT/sys/class/net/test0/statistics/tx_bytes"
"$MM_BIN" --xray-watch run
jq -e '.in == 4000 and .out == 4000 and .enforced == "throttle"' "$TEST_ROOT/etc/mmx/xray-traffic.json" >/dev/null 2>&1 && ok "超限后 enforced=throttle（TC 限速）" || bad "超限后 enforced 不对"
TRAFFIC_OUT="$("$MM_BIN" --show-traffic 2>/dev/null)"
printf '%s' "$TRAFFIC_OUT" | grep -q "流量统计（本周期）" && ok "--show-traffic 显示流量统计" || bad "--show-traffic 没显示统计"
printf '%s' "$TRAFFIC_OUT" | grep -q "已超限" && ok "--show-traffic 显示已超限" || bad "--show-traffic 没显示已超限"
printf '%s' "$TRAFFIC_OUT" | grep -q "TC 限速" && ok "--show-traffic 显示 TC 限速模式" || bad "--show-traffic 没显示 TC 限速"
printf '%s' "$TRAFFIC_OUT" | grep -q "限额：1.00 KB" && ok "--show-traffic 限额显示 1.00 KB" || bad "--show-traffic 限额显示不对"
# 清零：流量文件删掉，xray 重启后仍在运行
"$MM_BIN" --xray-watch clear | grep -q "已清零" && ok "--xray-watch clear 提示已清零" || bad "--xray-watch clear 提示不对"
[ ! -e "$TEST_ROOT/etc/mmx/xray-traffic.json" ] && ok "清零后流量文件已删" || bad "清零后流量文件还在"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" = "active" ] && ok "清零后 xray 仍在运行" || bad "清零后 xray 停了"
# 清零后再跑一次：计数重新从 0 开始
"$MM_BIN" --xray-watch run
jq -e '.in == 0 and .out == 0 and .enforced == ""' "$TEST_ROOT/etc/mmx/xray-traffic.json" >/dev/null 2>&1 && ok "清零后再跑计数从 0 开始" || bad "清零后再跑计数不对"

note "测试11：编辑节点里 mmx 专属项对 Xray 节点有守卫"
run_mm '3\n2\n0\n10\n' | grep -q "mmx 节点专属" && ok "第 2 项 rate 对 ss2022 节点被守卫" || bad "第 2 项 rate 没被守卫"
run_mm '3\n5\n0\n10\n' | grep -q "mmx 节点专属" && ok "第 5 项 TLS 对 ss2022 节点被守卫" || bad "第 10 项 TLS 没被守卫"
run_mm '3\n8\noff\n0\n10\n' | grep -q "域名白名单改为 关闭" && ok "第 8 项域名白名单对 ss2022 节点能改（不再守卫）" || bad "第 8 项域名白名单对 ss2022 节点改不了"
has "$CFG" "^DOMAIN_WHITELIST=''$" && ok "改完白名单已关" || bad "改完白名单没关"
! jq -e '.routing' "$XRAY_CFG" >/dev/null 2>&1 && ok "白名单关后 ss2022 配置里没了 routing" || bad "白名单关后 ss2022 配置里还有 routing"
has "$CFG" "^TRAFFIC_QUOTA=1K$" && ok "守卫没改配置（限额仍是 1K）" || bad "守卫后配置被改了"

note "测试12：XHTTP TLS 模式（域名 + certbot 假证书）"
# 菜单1 → y(覆盖) → 协议2(XHTTP) → 模式2(TLS) → 端口18206 → 域名 tls.example → 分流默认 → 流量默认 → 退出
run_mm '1\ny\n2\n2\n18206\ntls.example\n\n\n1\n\n\n10\n' | grep -q "XHTTP 节点已添加" && ok "XHTTP TLS 节点添加成功" || bad "XHTTP TLS 节点添加失败"
has "$XRAY_CONF" "^XHTTP_MODE=tls$" && ok "xray.conf 模式 TLS" || bad "xray.conf 模式不对"
( . "$XRAY_CONF"; [ "$XHTTP_SNI" = "tls.example" ] && [ -n "$XHTTP_CERT" ] && [ -n "$XHTTP_KEY" ] ) && ok "xray.conf 有 SNI 和证书路径" || bad "xray.conf 缺 SNI 或证书"
[ -f "$TEST_ROOT/etc/letsencrypt/live/tls.example/fullchain.pem" ] && ok "假证书已生成" || bad "假证书没生成"
jq -e '.inbounds[0].streamSettings.security == "tls" and .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile != null' "$XRAY_CFG" >/dev/null 2>&1 && ok "Xray 配置是 TLS 模式带证书" || bad "Xray 配置 TLS 内容不对"
TLS_OUT="$(run_mm '5\n10\n')"
TLS_LINK="$(printf '%s' "$TLS_OUT" | grep -o 'vless://[^ ]*' | head -1)"
printf '%s' "$TLS_LINK" | grep -q "security=tls" && ok "TLS 链接 security=tls" || bad "TLS 链接不是 security=tls"
printf '%s' "$TLS_LINK" | grep -q "sni=tls.example" && ok "TLS 链接 sni=tls.example" || bad "TLS 链接 sni 不对"
! printf '%s' "$TLS_LINK" | grep -q "pbk=" && ok "TLS 链接没有 pbk（Reality 才有）" || bad "TLS 链接不应有 pbk"
[ -f "$TEST_ROOT/etc/letsencrypt/renewal-hooks/deploy/restart-xray.sh" ] && ok "Xray 续期 hook 已生成" || bad "Xray 续期 hook 没生成"

note "测试13：删除节点清干净 Xray"
run_mm '4\ny\n10\n' | grep -q "节点已删除" && ok "删除节点提示正常" || bad "删除节点提示不对"
[ ! -e "$CFG" ] && ok "删除后主配置已删" || bad "删除后主配置还在"
[ ! -e "$XRAY_CONF" ] && ok "删除后 xray.conf 已删" || bad "删除后 xray.conf 还在"
[ ! -e "$XRAY_CFG" ] && ok "删除后 Xray 配置已删" || bad "删除后 Xray 配置还在"
[ ! -e "$TEST_ROOT/etc/mmx/xray-info.txt" ] && ok "删除后信息文件已删" || bad "删除后信息文件还在"
[ ! -e "$TEST_ROOT/etc/mmx/xray-traffic.json" ] && ok "删除后流量统计已删" || bad "删除后流量统计还在"
[ "$(cat "$TEST_ROOT/xray-state" 2>/dev/null)" != "active" ] && ok "删除后 xray 已停" || bad "删除后 xray 还在运行"
[ -x "$TEST_ROOT/usr/local/bin/xray" ] && ok "删除节点后 xray 二进制保留（下次建节点还能用）" || bad "删除节点后 xray 二进制被删了"
[ -x "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "删除节点后 mmx-server 保留" || bad "删除节点后 mmx-server 被删了"
[ -x "$MM_BIN" ] && ok "删除节点后菜单命令保留" || bad "删除节点后菜单命令被删了"

note "测试14：完全卸载清干净（含 Xray）"
# 先建一个 ss2022 节点再卸载（验证卸载删自己装的 xray）
run_mm '1\n3\n18207\n\n1\n\n\n10\n' | grep -q "ss2022 节点已添加" && ok "卸载前建好 ss2022 节点" || bad "卸载前建节点失败"
run_mm '9\ny\n' | grep -q "已卸载" && ok "卸载提示正常" || bad "卸载提示不对"
[ ! -e "$TEST_ROOT/etc/mmx" ] && ok "卸载后配置目录已删除" || bad "卸载后配置目录还在"
[ ! -e "$XRAY_CFG" ] && ok "卸载后 Xray 配置已删除" || bad "卸载后 Xray 配置还在"
[ ! -x "$TEST_ROOT/usr/local/bin/xray" ] && ok "卸载后自己装的 xray 二进制已删除" || bad "卸载后 xray 二进制还在"
[ ! -e "$TEST_ROOT/etc/systemd/system/xray.service" ] && ok "卸载后 xray 服务文件已删除" || bad "卸载后 xray 服务文件还在"
[ ! -e "$TEST_ROOT/etc/letsencrypt/renewal-hooks/deploy/restart-xray.sh" ] && ok "卸载后 Xray 续期 hook 已删除" || bad "卸载后 Xray 续期 hook 还在"
[ ! -e "$TEST_ROOT/etc/systemd/system/mmx-xray-watch.service" ] && ok "卸载后流量监视 service 已删除" || bad "卸载后流量监视 service 还在"
[ ! -e "$TEST_ROOT/etc/systemd/system/mmx-xray-watch.timer" ] && ok "卸载后流量监视 timer 已删除" || bad "卸载后流量监视 timer 还在"
[ ! -x "$MM_BIN" ] && ok "卸载后菜单命令已删除" || bad "卸载后菜单命令还在"
[ ! -x "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "卸载后 mmx-server 已删除" || bad "卸载后 mmx-server 还在"

note "测试15：OpenRC 下建 XHTTP 节点，/etc/init.d/xray 已生成"
OROOT=/tmp/mmx-multi-proto-openrc
OSTUB="$OROOT/stubs"
OCLEAN="$OROOT/cleanbin"
OSRC="$OROOT/src"
OMM="$OROOT/usr/local/bin/mmx"
OCFG="$OROOT/etc/mmx/config"
OXRAY_INIT="$OROOT/etc/init.d/xray"
rm -rf "$OROOT"
mkdir -p "$OSTUB" "$OCLEAN" "$OSRC"
# 替身 rc-service：mmx-server 和 xray 各走一个状态文件
cat > "$OSTUB/rc-service" <<'EOF'
#!/bin/bash
LOG_FILE="${MMX_TEST_ROOT}/rc-service.log"
echo "rc-service $*" >> "$LOG_FILE"
svc="$1"; shift
case "$svc" in
  mmx-server) STATE_FILE="${MMX_TEST_ROOT}/svc-state" ;;
  xray) STATE_FILE="${MMX_TEST_ROOT}/xray-state" ;;
  *) echo "替身 rc-service 只认 mmx-server/xray" >&2; exit 1 ;;
esac
cmd="$1"; shift
case "$cmd" in
  start) echo "active" > "$STATE_FILE"; exit 0 ;;
  stop) echo "inactive" > "$STATE_FILE"; exit 0 ;;
  restart) echo "active" > "$STATE_FILE"; exit 0 ;;
  status)
    if [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ]; then echo " * status: started"; exit 0; else echo " * status: stopped"; exit 3; fi ;;
  *) echo "替身 rc-service 不认识：$cmd" >&2; exit 1 ;;
esac
EOF
chmod +x "$OSTUB/rc-service"
cat > "$OSTUB/rc-update" <<'EOF'
#!/bin/bash
echo "rc-update $*" >> "${MMX_TEST_ROOT}/rc-update.log"
exit 0
EOF
chmod +x "$OSTUB/rc-update"
# 替身 crond：只记调用
cat > "$OSTUB/crond" <<'EOF'
#!/bin/bash
echo "crond $*" >> "${MMX_TEST_ROOT}/crond.log"
exit 0
EOF
chmod +x "$OSTUB/crond"
# 其他替身复用主 harness 的（curl/getent/dig/nslookup/ss/sysctl）
for t in curl getent dig nslookup ss sysctl; do cp "$STUB_BIN/$t" "$OSTUB/$t"; done
# 干净 PATH：系统命令软链接，排除 systemctl/journalctl/apt 等（像真 Alpine）
for d in /usr/bin /bin /usr/sbin /sbin; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    b="$(basename "$f")"
    case "$b" in
      systemctl|journalctl|apt-get|apt|rc-service|rc-update|curl|getent|dig|nslookup|certbot|apk|ss|sysctl|ufw|firewall-cmd|crond) ;;
      *) [ -e "$OCLEAN/$b" ] || ln -s "$f" "$OCLEAN/$b" ;;
    esac
  done
done
export MMX_TEST_ROOT="$OROOT"
ORC_PATH="$OROOT/usr/local/bin:$OSTUB:$OCLEAN"
# 复用已编译的二进制和脚本
cp install-mm-x-server.sh "$OSRC/"
cp "$SRC_DIR/mmx-server-linux-amd64" "$OSRC/mmx-server" 2>/dev/null || true
# 注意：部署脚本也要用 ORC_PATH 跑（里面没 systemctl 才认 OpenRC），不能用主测试的 PATH。
PATH="$ORC_PATH" bash "$OSRC/install-mm-x-server.sh" --port 18210 < /dev/null > "$OROOT/deploy.log" 2>&1
[ "$?" = 0 ] && ok "OpenRC 全新安装退出码 0" || bad "OpenRC 全新安装退出码非 0（见 $OROOT/deploy.log）"
[ ! -e "$OROOT/etc/systemd/system/mmx-server.service" ] && ok "OpenRC 全新安装没写 systemd 单元" || bad "OpenRC 全新安装写了 systemd 单元"
run_omm() { printf '%b' "$1" | PATH="$ORC_PATH" "$OMM" > "$OROOT/mm-out.txt" 2>&1; cat "$OROOT/mm-out.txt"; }
# 菜单1 → 协议2(XHTTP) → 模式1(Reality) → 地区1(香港) → 端口18210 → 分流默认 → 流量默认 → 退出
run_omm '1\n2\n1\n1\n18210\n\n\n1\n\n\n10\n' | grep -q "XHTTP 节点已添加" && ok "OpenRC 下 XHTTP 节点添加成功" || bad "OpenRC 下 XHTTP 节点添加失败"
[ -f "$OXRAY_INIT" ] && ok "OpenRC 下 /etc/init.d/xray 已生成" || bad "OpenRC 下 /etc/init.d/xray 没生成"
[ -x "$OXRAY_INIT" ] && ok "OpenRC 下 /etc/init.d/xray 可执行" || bad "OpenRC 下 /etc/init.d/xray 不可执行"
head -1 "$OXRAY_INIT" | grep -q "#!/sbin/openrc-run" && ok "xray init 脚本第一行是 #!/sbin/openrc-run" || bad "xray init 脚本第一行不对"
grep -Fq "command=\"/usr/local/bin/xray\"" "$OXRAY_INIT" && ok "xray init 脚本 command 是 xray 二进制" || bad "xray init 脚本 command 不对"
grep -q "need net" "$OXRAY_INIT" && ok "xray init 脚本 depend() 里 need net" || bad "xray init 脚本 depend() 里没有 need net"
[ "$(cat "$OROOT/xray-state" 2>/dev/null)" = "active" ] && ok "OpenRC 下 xray 在运行" || bad "OpenRC 下 xray 没运行"
grep -q "xray" "$OROOT/rc-service.log" && ok "OpenRC 下服务操作走了 rc-service" || bad "OpenRC 下服务操作没走 rc-service"
[ -f "$OROOT/etc/crontabs/root" ] && grep -q "mmx --xray-watch run" "$OROOT/etc/crontabs/root" && ok "OpenRC 下流量监视写了 cron" || bad "OpenRC 下流量监视没写 cron"

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail"
if [ "$fail" -eq 0 ]; then
  echo "多协议测试全部通过"
  exit 0
else
  echo "有 $fail 项失败，见上文"
  exit 1
fi
