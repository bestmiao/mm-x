#!/bin/bash
# mm-x 部署脚本 + mm 菜单测试：在沙箱里用替身命令模拟 systemd，
# 验证：装完不打印链接、mm 菜单每项能跑通、改参数重启失败会回滚、流量设置能跑通。
# 用法：bash test/test-deploy.sh
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"

GO=~/workspace/_build/go/bin/go
TEST_ROOT=/tmp/mmx-deploy-test
STUB_BIN="$TEST_ROOT/stubs"
SRC_DIR="$TEST_ROOT/src"
MM_BIN="$TEST_ROOT/usr/local/bin/mm"
CFG="$TEST_ROOT/etc/mmx/config"
UNIT="$TEST_ROOT/etc/systemd/system/mmx-server.service"

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
note() { echo "--- $1"; }
has()  { grep -q "$2" "$1"; }   # has 文件 正则

rm -rf "$TEST_ROOT"
mkdir -p "$STUB_BIN" "$SRC_DIR"

# ---- 替身 systemctl：状态文件驱动，restart 可被标记为失败一次 ----
cat > "$STUB_BIN/systemctl" <<'EOF'
#!/bin/bash
# 测试替身：只认 mmx-server 这一个服务；状态存在 $MMX_TEST_ROOT/svc-state
STATE_FILE="${MMX_TEST_ROOT}/svc-state"
LOG_FILE="${MMX_TEST_ROOT}/systemctl.log"
echo "systemctl $*" >> "$LOG_FILE"
cmd="$1"; shift
case "$cmd" in
  daemon-reload) exit 0 ;;
  enable|disable) exit 0 ;;
  restart)
    if [ -f "${MMX_TEST_ROOT}/fail-next-restart" ]; then
      rm -f "${MMX_TEST_ROOT}/fail-next-restart"
      echo "failed" > "$STATE_FILE"
      echo "Job for mmx-server.service failed (simulated)" >&2
      exit 1
    fi
    echo "active" > "$STATE_FILE"
    exit 0 ;;
  stop) echo "inactive" > "$STATE_FILE"; exit 0 ;;
  is-active)
    [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ] && exit 0 || exit 3 ;;
  status)
    if [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ]; then
      echo "● mmx-server.service - mm-x private proxy server"
      echo "   Active: active (running)"
    else
      echo "● mmx-server.service - mm-x private proxy server"
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
echo "11月22日 23:00:00 test mmx-server[1]: mm-x 服务端启动，监听 0.0.0.0:18130"
echo "11月22日 23:00:01 test mmx-server[1]: BBR：已开启"
echo "11月22日 23:00:02 test mmx-server[1]: 节点链接：mmx://fake"
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

# ---- 替身 sysctl：只记调用（卸载时 BBR 还原用）；不碰真实内核 ----
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

# ---- 替身 getent：只认 hosts 查询；按 $MMX_TEST_ROOT/dns-map 回答域名解析
# （每行 "域名 IP"），没命中就空输出、exit 2（像查不到 A 记录） ----
cat > "$STUB_BIN/getent" <<'EOF'
#!/bin/bash
[ "$1" = "hosts" ] || exit 2
map="${MMX_TEST_ROOT}/dns-map"
[ -f "$map" ] || exit 2
while read -r d ip; do
  if [ "$d" = "$2" ]; then echo "$ip $d"; exit 0; fi
done < "$map"
exit 2
EOF
chmod +x "$STUB_BIN/getent"

# ---- 替身 dig / nslookup：永远查不到（域名解析只由上面的 getent + dns-map 控制，
# 否则沙箱的假 DNS 会把所有域名都解析到 198.18.x.x，测不了“没解析”的分支） ----
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

# ---- 替身 certbot：只认 certonly --standalone；没 --reuse-key 就报错退出
# （证明脚本传了 --reuse-key）；按 -d 的域名在 $MMX_TEST_ROOT/etc/letsencrypt
# 下生成假证书 + 带 reuse_key = True 的续期配置 ----
cat > "$STUB_BIN/certbot" <<'EOF'
#!/bin/bash
echo "certbot $*" >> "${MMX_TEST_ROOT}/certbot.log"
has_reuse=0; has_standalone=0; dom=""
prev=""
for a in "$@"; do
  case "$a" in
    --reuse-key) has_reuse=1 ;;
    --standalone) has_standalone=1 ;;
    -d) prev="-d" ;;
    *) if [ "$prev" = "-d" ]; then dom="$a"; prev=""; fi ;;
  esac
done
[ "$1" = "certonly" ] || { echo "替身 certbot 只认 certonly" >&2; exit 1; }
[ "$has_standalone" = 1 ] || { echo "替身 certbot：需要 --standalone" >&2; exit 1; }
[ "$has_reuse" = 1 ] || { echo "替身 certbot：需要 --reuse-key（续期密钥不变，pin 才不变）" >&2; exit 1; }
[ -n "$dom" ] || { echo "替身 certbot：需要 -d 域名" >&2; exit 1; }
le="${MMX_TEST_ROOT}/etc/letsencrypt"
mkdir -p "$le/live/$dom" "$le/renewal"
openssl req -x509 -newkey rsa:2048 -keyout "$le/live/$dom/privkey.pem" -out "$le/live/$dom/fullchain.pem" -days 90 -nodes -subj "/CN=$dom" -addext "subjectAltName=DNS:$dom" >/dev/null 2>&1 || exit 1
printf '[renewalparams]\naccount = test\nreuse_key = True\n' > "$le/renewal/$dom.conf"
exit 0
EOF
chmod +x "$STUB_BIN/certbot"

export MMX_TEST_ROOT="$TEST_ROOT"
export PATH="$TEST_ROOT/usr/local/bin:$STUB_BIN:$PATH"

note "编译服务端二进制（当前源码，v5）"
$GO build -o "$SRC_DIR/mmx-server-linux-amd64" ./cmd/mmx-server || { echo "编译失败"; exit 1; }
ok "编译通过"
cp install-mm-x-server.sh "$SRC_DIR/"
cp "$SRC_DIR/mmx-server-linux-amd64" "$SRC_DIR/mmx-server" 2>/dev/null || true

note "部署脚本 --help 里有 443 说明"
bash "$SRC_DIR/install-mm-x-server.sh" --help 2>&1 | grep -q "443" && ok "--help 提到 443（更像 HTTPS、被占怎么办）" || bad "--help 没提 443"

note "测试1：跑部署脚本（--port 18130）"
bash "$SRC_DIR/install-mm-x-server.sh" --port 18130 --name 测试节点 < /dev/null > "$TEST_ROOT/deploy.log" 2>&1
DEPLOY_CODE=$?
[ "$DEPLOY_CODE" = 0 ] && ok "部署脚本退出码 0" || bad "部署脚本退出码 $DEPLOY_CODE（见 deploy.log）"
if grep -q "mmx://" "$TEST_ROOT/deploy.log"; then bad "部署输出里打印了 mmx:// 链接（应该只在菜单里看）"; else ok "部署输出里没有 mmx:// 链接"; fi
grep -q "输入 mm 打开管理菜单" "$TEST_ROOT/deploy.log" && ok "部署完成提示让用户输入 mm 打开菜单" || bad "部署完成提示没提 mm 菜单"
[ -x "$MM_BIN" ] && ok "/usr/local/bin/mm 存在且可执行" || bad "/usr/local/bin/mm 不存在或不可执行"
grep -Fq "printf '\033[32m'" "$MM_BIN" && ok "菜单脚本含绿色 printf（交互菜单统一绿色）" || bad "菜单脚本没有绿色 printf"
grep -Fq "trap 'printf \"\033[0m\"' EXIT" "$MM_BIN" && ok "菜单脚本含 EXIT 复位 trap（退出时恢复终端颜色）" || bad "菜单脚本没有 EXIT 复位 trap"
"$MM_BIN" --show-link plain 2>/dev/null | grep -q $'\033' && bad "非交互 --show-link 输出带了 ANSI 颜色码（绿色只该在交互菜单里）" || ok "非交互 --show-link 输出干净（无颜色码）"
[ -x "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "mmx-server 二进制已安装" || bad "mmx-server 二进制没装上"
has "$CFG" "^PORT=18130$" && ok "配置文件端口 18130" || bad "配置文件端口不对"
has "$CFG" "^RATE=0$" && ok "配置文件默认不限速（RATE=0）" || bad "配置文件限速不对"
has "$CFG" "^BURST=0$" && ok "配置文件默认突发 0（严格）" || bad "配置文件突发不对"
has "$CFG" "^FALLBACK=site$" && ok "配置文件默认回退 site" || bad "配置文件回退不对"
( . "$CFG"; [ "$NAME" = "测试节点" ] ) && ok "配置文件节点名是传进来的 测试节点" || bad "配置文件节点名不对"
PSK="$(cat "$TEST_ROOT/etc/mmx/psk" 2>/dev/null)"
printf '%s' "$PSK" | grep -Eq '^[0-9a-f]{64}$' && ok "密钥文件是 64 位十六进制" || bad "密钥文件格式不对"
has "$UNIT" "ExecStart=" && ok "服务文件已生成" || bad "服务文件没生成"
has "$UNIT" "0.0.0.0:18130" && has "$UNIT" "\-\-rate 0 --burst 0" && has "$UNIT" "\-\-fallback site" && ok "ExecStart 含端口/限速/回退参数" || bad "ExecStart 参数不对"
grep -q "restart" "$TEST_ROOT/systemctl.log" && ok "部署时调用了 systemctl restart" || bad "部署时没调用 restart"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "部署后服务状态 active" || bad "部署后服务状态不是 active"

# 菜单调用辅助：喂给 mm 的输入。
# 注意：mm 的输出先落文件再 cat——不能直接 | grep -q：菜单文本里
# 本身就印着要找的字（例如第 2 项"开启真 TLS"），grep -q 一匹配就
# 退出关管道，mm 还没读输入就被 SIGPIPE 杀掉，配置来不及保存
#（老竞态：基线 68/2 的两处失败就是这么来的）。
run_mm() { printf '%b' "$1" | "$MM_BIN" > "$TEST_ROOT/mm-out.txt" 2>&1; cat "$TEST_ROOT/mm-out.txt"; }

note "测试2：菜单第 5 项显示链接"
LINK_OUT="$(run_mm '5\n11\n')"
printf '%s' "$LINK_OUT" | grep -q "mmx://" && ok "菜单显示出 mmx:// 链接" || bad "菜单没显示链接"
printf '%s' "$LINK_OUT" | grep -q "ver=5" && ok "链接是 ver=5（v5 默认）" || bad "链接版本不对"
printf '%s' "$LINK_OUT" | grep -q "203.0.113.5" && ok "链接里的地址是探测到的公网 IP" || bad "链接地址不对"
! printf '%s' "$LINK_OUT" | grep -q "rate=" && ok "短格式链接不带 rate（限速由服务端配置）" || bad "短格式链接不应带 rate"

note "测试3：菜单第 6 项状态 / 第 7 项重启 / 第 9 项日志"
run_mm '6\n11\n' | grep -q "正在运行" && ok "状态显示正在运行" || bad "状态显示不对"
run_mm '7\n11\n' | grep -q "重启成功" && ok "重启成功" || bad "重启没成功"
run_mm '9\n11\n' | grep -q "mm-x 服务端启动" && ok "日志显示最近记录" || bad "日志显示不对"

note "测试4：更换密钥已从主菜单移除（函数保留在脚本内，不可从菜单调用）"
grep -q "^rotate_key()" "$MM_BIN" && ok "菜单脚本里仍有 rotate_key 函数定义" || bad "菜单脚本里 rotate_key 函数没了"
run_mm '6\n11\n' | grep -q "正在运行" && ok "主菜单第 6 项已是服务状态（不再是换密钥）" || bad "主菜单第 6 项不对"

note "测试5：菜单第 8 项修改限速（rate=3000K burst=0）"
run_mm '8\n3000K\n0\n11\n' | grep -q "限速改为 rate=3000K burst=0" && ok "改限速提示正常" || bad "改限速提示不对"
has "$CFG" "^RATE=3000K$" && ok "配置文件 rate 已改为 3000K" || bad "配置文件 rate 没改"
has "$UNIT" "\-\-rate 3000K" && ok "服务文件 ExecStart 已用新限速" || bad "服务文件限速没更新"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改限速后服务仍在运行" || bad "改限速后服务停了"

note "测试6：菜单第 3 项 → 第 10 子项切换回退模式（site→silent→site）"
run_mm '3\n10\n1\n0\n0\n11\n' | grep -q "回退模式改为 silent" && ok "回退切换到 silent" || bad "回退切换提示不对"
has "$CFG" "^FALLBACK=silent$" && has "$UNIT" "\-\-fallback silent" && ok "配置+服务文件都已是 silent" || bad "回退 silent 没写进配置/服务"
run_mm '3\n10\n1\n0\n0\n11\n' | grep -q "回退模式改为 site" && ok "回退切换回 site" || bad "回退切换回 site 失败"

note "测试7：菜单第 3 项 → 第 10 子项开启真 TLS（自签名证书）再关闭"
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_ROOT/key.pem" -out "$TEST_ROOT/cert.pem" -days 1 -nodes -subj "/CN=test.example" -addext "subjectAltName=DNS:test.example" >/dev/null 2>&1
run_mm "3\n10\n2\ntest.example\n$TEST_ROOT/cert.pem\n$TEST_ROOT/key.pem\n0\n0\n10\n" | grep -q "开启真 TLS" && ok "开启真 TLS 提示正常" || bad "开启真 TLS 提示不对"
has "$CFG" "^TLS_DOMAIN=test.example$" && has "$UNIT" "\-\-tls-domain test.example" && ok "配置+服务文件都有 TLS 域名" || bad "TLS 域名没写进配置/服务"
run_mm '5\n11\n' | grep -q "pin=" && ok "TLS 模式下链接带 pin（短格式，obfs=tls 为 ver=5 默认）" || bad "TLS 模式下链接没有 pin"
run_mm '5\n11\n' | grep -q "test.example" && ok "TLS 模式下链接地址是域名" || bad "TLS 模式下链接地址不是域名"
run_mm '3\n10\n3\n0\n0\n11\n' | grep -q "关闭真 TLS" && ok "关闭真 TLS 提示正常" || bad "关闭真 TLS 提示不对"
grep -q "^TLS_DOMAIN=''$" "$CFG" && ! grep -q "tls-domain" "$UNIT" && ok "关闭后配置+服务文件里没了 TLS" || bad "关闭 TLS 后还有残留"

note "测试7b：菜单第 3 项 → 第 10 子项开启自签 TLS（无域名）再查指纹、关闭"
run_mm "3\n10\n4\n\n0\n0\n10\n" | grep -q "开启自签 TLS" && ok "开启自签 TLS 提示正常" || bad "开启自签 TLS 提示不对"
has "$CFG" "^TLS_AUTO=1$" && has "$UNIT" "\\-\\-tls-auto" && ok "配置+服务文件都有 --tls-auto" || bad "自签 TLS 没写进配置/服务"
has "$UNIT" "tls-cert.pem" && has "$UNIT" "tls-key.pem" && ok "服务文件里自签证书是绝对路径" || bad "自签证书路径不对"
! run_mm '5\n11\n' | grep -q "obfs=tls-fake" && ok "自签模式下链接不是明文（短格式，obfs=tls 为 ver=5 默认）" || bad "自签模式下链接不对"
run_mm '5\n11\n' | grep -q "pin=" && ok "自签模式下链接带 pin" || bad "自签模式下链接没有 pin"
run_mm '3\n10\n5\n0\n0\n11\n' | grep -Eq "[A-Za-z0-9_-]{43}" && ok "第 3 项 → 第 10 子项 → 第 5 子项能查到 43 位指纹" || bad "查指纹没拿到 pin"
run_mm '3\n10\n3\n0\n0\n11\n' | grep -q "关闭自签 TLS" && ok "关闭自签 TLS 提示正常" || bad "关闭自签 TLS 提示不对"
grep -q "^TLS_AUTO=0$" "$CFG" && ! grep -q "tls-auto" "$UNIT" && ok "关闭后配置+服务文件里没了自签 TLS" || bad "关闭自签 TLS 后还有残留"

note "测试8：菜单第 3 项改端口（18130→18131）"
run_mm '3\n1\n18131\n0\n11\n' | grep -q "端口改为 18131" && ok "改端口提示正常" || bad "改端口提示不对"
has "$CFG" "^PORT=18131$" && has "$UNIT" "0.0.0.0:18131" && ok "配置+服务文件端口已是 18131" || bad "端口没写进配置/服务"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改端口后服务仍在运行" || bad "改端口后服务停了"

note "测试9：端口占用冲突（18132 被占）：拒绝改、确认后才改"
echo "18132" > "$TEST_ROOT/ss-busy-ports"
run_mm '3\n1\n18132\nn\n0\n11\n' | grep -q "已被别的服务占用" && ok "占用端口有警告" || bad "占用端口没警告"
has "$CFG" "^PORT=18131$" && ok "拒绝后端口保持 18131" || bad "拒绝后端口被改了"
run_mm '3\n1\n18132\ny\n0\n11\n' | grep -q "端口改为 18132" && ok "确认后改成占用端口（测试替身下能起来）" || bad "确认后改端口失败"
has "$CFG" "^PORT=18132$" && ok "确认后配置端口已是 18132" || bad "确认后配置端口不对"
rm -f "$TEST_ROOT/ss-busy-ports"

note "测试10：非法输入被拒绝（端口 99999、rate abc）"
run_mm '3\n1\n99999\n0\n11\n' | grep -q "端口不合法" && ok "99999 端口被拒绝" || bad "99999 端口没被拒绝"
has "$CFG" "^PORT=18132$" && ok "非法端口后配置没变" || bad "非法端口后配置被改了"
run_mm '3\n2\nabc\n0\n11\n' | grep -q "rate 格式不对" && ok "abc 限速被拒绝" || bad "abc 限速没被拒绝"
has "$CFG" "^RATE=3000K$" && ok "非法限速后配置没变" || bad "非法限速后配置被改了"

note "测试11：改端口后重启失败 → 回滚到原配置"
touch "$TEST_ROOT/fail-next-restart"
ROLLBACK_OUT="$(run_mm '3\n1\n18133\n0\n11\n')"
printf '%s' "$ROLLBACK_OUT" | grep -q "回滚" && ok "重启失败时提示回滚" || bad "重启失败时没提示回滚"
has "$CFG" "^PORT=18132$" && ok "回滚后配置端口恢复 18132" || bad "回滚后配置端口不对"
has "$UNIT" "0.0.0.0:18132" && ! grep -q "0.0.0.0:18133" "$UNIT" && ok "回滚后服务文件恢复 18132" || bad "回滚后服务文件不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "回滚后服务用原配置恢复运行" || bad "回滚后服务没起来"

note "测试12：部署时端口被占直接失败（--port 18140，需 --reinstall 才重装）"
echo "18140" > "$TEST_ROOT/ss-busy-ports"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 18140 < /dev/null > "$TEST_ROOT/deploy-busy.log" 2>&1
[ "$?" != 0 ] && grep -q "已被别的服务占用" "$TEST_ROOT/deploy-busy.log" && ok "部署时占用端口报错退出" || bad "部署时占用端口没报错"
rm -f "$TEST_ROOT/ss-busy-ports"

note "测试13：部署脚本带流量参数（--traffic-*）写进配置和服务文件"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 18132 --rate 3000K --name 测试节点 --traffic-mode outbound --traffic-period quarterly --traffic-start-day 15 --traffic-limit-mode throttle --traffic-quota 500G --traffic-throttle-rate 1M < /dev/null > "$TEST_ROOT/deploy-traffic.log" 2>&1
[ "$?" = 0 ] && ok "带流量参数的部署脚本退出码 0" || bad "带流量参数的部署脚本退出码非 0（见 deploy-traffic.log）"
has "$CFG" "^TRAFFIC_MODE=outbound$" && has "$CFG" "^TRAFFIC_PERIOD=quarterly$" && has "$CFG" "^TRAFFIC_START_DAY=15$" && ok "配置文件里流量模式/周期/起始日正确" || bad "配置文件里流量模式/周期/起始日不对"
has "$CFG" "^TRAFFIC_LIMIT_MODE=throttle$" && has "$CFG" "^TRAFFIC_QUOTA=500G$" && has "$CFG" "^TRAFFIC_THROTTLE_RATE=1M$" && ok "配置文件里限制模式/限额/TC 限速值正确" || bad "配置文件里限制模式/限额/TC 限速值不对"
has "$UNIT" "\-\-traffic-mode outbound" && has "$UNIT" "\-\-traffic-period quarterly" && has "$UNIT" "\-\-traffic-start-day 15" && ok "服务文件 ExecStart 里有流量模式/周期/起始日" || bad "服务文件 ExecStart 里流量模式/周期/起始日不对"
has "$UNIT" "\-\-traffic-limit-mode throttle" && has "$UNIT" "\-\-traffic-quota 500G" && has "$UNIT" "\-\-traffic-throttle-rate 1M" && has "$UNIT" "\-\-traffic-file $TEST_ROOT/etc/mmx/traffic.json" && ok "服务文件 ExecStart 里有限制模式/限额/TC 限速值/计数文件" || bad "服务文件 ExecStart 里流量限额参数不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "带流量参数部署后服务仍在运行" || bad "带流量参数部署后服务停了"
# 部署脚本非法流量参数应直接报错退出。
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 18132 --traffic-start-day 32 < /dev/null > "$TEST_ROOT/deploy-traffic-bad.log" 2>&1
[ "$?" != 0 ] && grep -q "周期起始日不合法" "$TEST_ROOT/deploy-traffic-bad.log" && ok "部署时起始日 32 报错退出" || bad "部署时起始日 32 没报错"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 18132 --traffic-quota 1X < /dev/null > "$TEST_ROOT/deploy-traffic-bad2.log" 2>&1
[ "$?" != 0 ] && grep -q "流量限额格式不对" "$TEST_ROOT/deploy-traffic-bad2.log" && ok "部署时限额 1X 报错退出" || bad "部署时限额 1X 没报错"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 18132 --rate 3000K --traffic-mode outbound --traffic-period quarterly --traffic-start-day 15 --traffic-limit-mode throttle --traffic-quota 500G --traffic-throttle-rate 1M < /dev/null > "$TEST_ROOT/deploy-noname.log" 2>&1
[ "$?" = 0 ] && has "$CFG" "^NAME=mm-x$" && ok "不传 --name 且非交互时节点名用默认 mm-x（不卡住等输入）" || bad "不传 --name 时节点名不对（见 deploy-noname.log）"
# v5 掩护流量：默认 low 应写进配置和服务文件；显式 high 生效；非法值报错退出。
# 注意：重装（--reinstall）会按传入参数全量重写配置，所以下面每次部署都要带上已有的
# 流量参数（和测试 13 开头那次一样），否则限额/起始日会被重置回默认值，
# 后面的测试 14（流量菜单）会跟着失败。
COVER_DEPLOY_FLAGS="--reinstall --port 18132 --rate 3000K --name 测试节点 --traffic-mode outbound --traffic-period quarterly --traffic-start-day 15 --traffic-limit-mode throttle --traffic-quota 500G --traffic-throttle-rate 1M"
has "$CFG" "^COVER_TRAFFIC=low$" && has "$UNIT" "\-\-cover-traffic low" && ok "默认掩护流量 low 已写进配置和服务文件" || bad "默认掩护流量 low 没写进配置/服务"
bash "$SRC_DIR/install-mm-x-server.sh" $COVER_DEPLOY_FLAGS --cover-traffic high < /dev/null > "$TEST_ROOT/deploy-cover-high.log" 2>&1
[ "$?" = 0 ] && has "$CFG" "^COVER_TRAFFIC=high$" && has "$UNIT" "\-\-cover-traffic high" && ok "--cover-traffic high 写进配置和服务文件" || bad "--cover-traffic high 没生效（见 deploy-cover-high.log）"
bash "$SRC_DIR/install-mm-x-server.sh" $COVER_DEPLOY_FLAGS --cover-traffic foo < /dev/null > "$TEST_ROOT/deploy-cover-bad.log" 2>&1
[ "$?" != 0 ] && grep -q "掩护流量档位不合法" "$TEST_ROOT/deploy-cover-bad.log" && ok "部署时掩护档位 foo 报错退出" || bad "部署时掩护档位 foo 没报错"
bash "$SRC_DIR/install-mm-x-server.sh" $COVER_DEPLOY_FLAGS --cover-traffic low < /dev/null > "$TEST_ROOT/deploy-cover-low.log" 2>&1
[ "$?" = 0 ] && has "$CFG" "^COVER_TRAFFIC=low$" && ok "掩护档位恢复 low" || bad "掩护档位恢复 low 失败"
# 恢复 low 后流量参数必须还在（重装没把它们重置掉）。
has "$CFG" "^TRAFFIC_QUOTA=500G$" && has "$CFG" "^TRAFFIC_START_DAY=15$" && ok "掩护部署后流量限额/起始日还在" || bad "掩护部署后流量参数被重置了"

note "测试14：菜单第 3 项 → 第 11 项流量设置（查看/改限额/非法输入/清零）"
run_mm '3\n11\n1\n0\n0\n11\n' | grep -q "流量统计（本周期）" && ok "流量设置里查看流量显示统计" || bad "流量设置里查看流量显示不对"
run_mm '3\n11\n1\n0\n0\n11\n' | grep -q "限额：500.00 GB" && ok "查看流量显示限额 500.00 GB" || bad "查看流量限额显示不对"
run_mm '3\n11\n6\n1T\n0\n0\n11\n' | grep -q "流量限额改为 1T" && ok "改限额提示正常" || bad "改限额提示不对"
has "$CFG" "^TRAFFIC_QUOTA=1T$" && has "$UNIT" "\-\-traffic-quota 1T" && ok "配置+服务文件限额已是 1T" || bad "限额 1T 没写进配置/服务"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改限额后服务仍在运行" || bad "改限额后服务停了"
run_mm '3\n11\n4\n32\n0\n0\n11\n' | grep -q "起始日不对" && ok "起始日 32 被拒绝" || bad "起始日 32 没被拒绝"
has "$CFG" "^TRAFFIC_START_DAY=15$" && ok "非法起始日后配置没变" || bad "非法起始日后配置被改了"
run_mm '3\n11\n2\nfoo\n0\n0\n11\n' | grep -q "统计模式不对" && ok "统计模式 foo 被拒绝" || bad "统计模式 foo 没被拒绝"
run_mm '3\n11\n8\ny\n0\n0\n11\n' | grep -q "已清零" && ok "清零本周期流量提示正常" || bad "清零提示不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "清零后服务仍在运行" || bad "清零后服务停了"
"$MM_BIN" --show-traffic 2>/dev/null | grep -q "流量统计（本周期）" && ok "隐藏用法 mm --show-traffic 能显示流量统计" || bad "mm --show-traffic 显示不对"

note "测试14b：菜单第 3 项 → 第 12 项掩护流量（改档位/非法输入/恢复）"
run_mm '3\n12\nhigh\n0\n11\n' | grep -q "掩护流量改为 high" && ok "改掩护档位提示正常" || bad "改掩护档位提示不对"
has "$CFG" "^COVER_TRAFFIC=high$" && has "$UNIT" "\-\-cover-traffic high" && ok "配置+服务文件掩护档位已是 high" || bad "掩护档位 high 没写进配置/服务"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改掩护档位后服务仍在运行" || bad "改掩护档位后服务停了"
run_mm '3\n12\nfoo\n0\n11\n' | grep -q "档位不对" && ok "掩护档位 foo 被拒绝" || bad "掩护档位 foo 没被拒绝"
has "$CFG" "^COVER_TRAFFIC=high$" && ok "非法档位后配置没变" || bad "非法档位后配置被改了"
run_mm '3\n12\noff\n0\n11\n' | grep -q "掩护流量改为 off" && ok "掩护档位改回 off 提示正常" || bad "掩护档位改回 off 提示不对"
run_mm '3\n12\nlow\n0\n11\n' | grep -q "掩护流量改为 low" && ok "掩护档位恢复 low" || bad "掩护档位恢复 low 失败"
has "$CFG" "^COVER_TRAFFIC=low$" && ok "恢复后配置掩护档位是 low" || bad "恢复后配置掩护档位不对"

note "测试15：菜单第 2 项载入预设（GCP / 阿里云CDT）"
run_mm '2\n0\n11\n' | grep -q "阿里云CDT" && ok "预设菜单显示 GCP/阿里云CDT" || bad "预设菜单显示不对"
run_mm '2\n1\n\ny\n0\n11\n' | grep -q "载入预设" && ok "载入 GCP 提示正常" || bad "载入 GCP 提示不对"
has "$CFG" "^TRAFFIC_MODE=total$" && has "$CFG" "^TRAFFIC_QUOTA=180G$" && has "$CFG" "^TRAFFIC_PERIOD=monthly$" && has "$CFG" "^TRAFFIC_START_DAY=1$" && ok "GCP 配置：total/180G/月/1日" || bad "GCP 配置值不对"
has "$CFG" "^TRAFFIC_LIMIT_MODE=throttle$" && has "$CFG" "^TRAFFIC_THROTTLE_RATE=125K$" && has "$CFG" "^RATE=0$" && ok "GCP 配置：throttle/125K/不限速" || bad "GCP 配置限制值不对"
has "$UNIT" "\-\-traffic-mode total" && has "$UNIT" "\-\-traffic-quota 180G" && ok "GCP 服务文件已更新" || bad "GCP 服务文件没更新"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "GCP 配置：域名白名单 google" || bad "GCP 配置白名单不对"
has "$UNIT" "\-\-domain-whitelist google" && ok "GCP 服务文件有白名单参数" || bad "GCP 服务文件缺白名单参数"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "载入 GCP 后服务仍在运行" || bad "载入 GCP 后服务停了"
run_mm '2\n2\n\nn\n0\n11\n' | grep -q "已取消" && ok "取消载入提示正常" || bad "取消载入提示不对"
has "$CFG" "^TRAFFIC_MODE=total$" && ok "取消后配置保持 GCP" || bad "取消后配置被改了"
run_mm '2\n2\n\ny\n0\n11\n' | grep -q "载入预设" && ok "载入 CDT 提示正常" || bad "载入 CDT 提示不对"
has "$CFG" "^TRAFFIC_MODE=max$" && has "$CFG" "^TRAFFIC_QUOTA=180G$" && ok "CDT 配置：max/180G" || bad "CDT 配置值不对"
has "$UNIT" "\-\-traffic-mode max" && ok "CDT 服务文件已更新" || bad "CDT 服务文件没更新"
has "$CFG" "^DOMAIN_WHITELIST=''$" && ok "CDT 配置：域名白名单关闭" || bad "CDT 配置白名单没关"
! has "$UNIT" "domain-whitelist" && ok "CDT 服务文件无白名单参数" || bad "CDT 服务文件还有白名单参数"
note "测试15a：菜单第 3 项第 13 项手动改域名白名单"
run_mm '3\n13\ngoogle\n0\n11\n' | grep -q "域名白名单改为" && ok "手动开白名单提示正常" || bad "手动开白名单提示不对"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "手动开白名单后配置是 google" || bad "手动开白名单后配置不对"
has "$UNIT" "\-\-domain-whitelist google" && ok "手动开白名单后服务文件已更新" || bad "手动开白名单后服务文件没更新"
run_mm '3\n13\nfoo\n0\n11\n' | grep -q "白名单不对" && ok "非法白名单值被拒绝" || bad "非法白名单值没被拒绝"
has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "非法值后配置保持 google" || bad "非法值后配置被改了"
run_mm '3\n13\noff\n0\n11\n' | grep -q "域名白名单改为" && ok "手动关白名单提示正常" || bad "手动关白名单提示不对"
has "$CFG" "^DOMAIN_WHITELIST=''$" && ok "手动关白名单后配置已清空" || bad "手动关白名单后配置没清空"
"$MM_BIN" --preset gcp > "$TEST_ROOT/mm-out.txt" 2>&1
has "$CFG" "^TRAFFIC_MODE=total$" && ok "--preset gcp 非交互生效" || bad "--preset gcp 没生效"
"$MM_BIN" --preset foo > "$TEST_ROOT/mm-out.txt" 2>&1; [ "$?" != 0 ] && grep -q "没有这个预设" "$TEST_ROOT/mm-out.txt" && ok "--preset foo 报错退出" || bad "--preset foo 没报错"
has "$CFG" "^TRAFFIC_MODE=total$" && ok "非法预设后配置没变" || bad "非法预设后配置被改了"

note "测试15b：再跑部署脚本（不加 --reinstall）不改节点配置；加 --reinstall 才重装"
RERUN_PSK_BEFORE="$(cat "$TEST_ROOT/etc/mmx/psk")"
RERUN_CFG_BEFORE="$(cat "$CFG")"
bash "$SRC_DIR/install-mm-x-server.sh" --port 19999 --rate 100K --traffic-quota 1T < /dev/null > "$TEST_ROOT/deploy-rerun.log" 2>&1
[ "$?" = 0 ] && ok "不加 --reinstall 再跑部署脚本退出码 0" || bad "不加 --reinstall 再跑部署脚本退出码非 0（见 deploy-rerun.log）"
grep -q "只更新程序文件" "$TEST_ROOT/deploy-rerun.log" && grep -q "不改节点配置" "$TEST_ROOT/deploy-rerun.log" && ok "不加 --reinstall 时提示只更新程序、不改节点配置" || bad "不加 --reinstall 时没提示只更新程序"
[ "$(cat "$CFG")" = "$RERUN_CFG_BEFORE" ] && ok "不加 --reinstall 时配置文件一字未动" || bad "不加 --reinstall 时配置文件被改了"
[ "$(cat "$TEST_ROOT/etc/mmx/psk")" = "$RERUN_PSK_BEFORE" ] && ok "不加 --reinstall 时密钥未变" || bad "不加 --reinstall 时密钥被换了"
has "$CFG" "^PORT=18132$" && has "$UNIT" "0.0.0.0:18132" && ! grep -q "19999" "$UNIT" && ok "不加 --reinstall 时端口仍是 18132（19999 没生效）" || bad "不加 --reinstall 时端口被改了"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "不加 --reinstall 再跑后服务仍在运行" || bad "不加 --reinstall 再跑后服务停了"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --rate 100K --name 测试节点 < /dev/null > "$TEST_ROOT/deploy-reinstall.log" 2>&1
[ "$?" = 0 ] && ok "加 --reinstall 再跑部署脚本退出码 0" || bad "加 --reinstall 再跑部署脚本退出码非 0（见 deploy-reinstall.log）"
has "$CFG" "^PORT=19999$" && has "$CFG" "^RATE=100K$" && has "$UNIT" "0.0.0.0:19999" && ok "--reinstall 后端口/限速已按新参数重写" || bad "--reinstall 后配置没按新参数重写"
[ "$(cat "$TEST_ROOT/etc/mmx/psk")" = "$RERUN_PSK_BEFORE" ] && ok "--reinstall 后密钥仍保留（重装不换密钥）" || bad "--reinstall 后密钥被换了"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "--reinstall 后服务仍在运行" || bad "--reinstall 后服务停了"

note "测试15c：--domain 一键设置域名（格式错/冲突/DNS 不对/80 被占/成功/菜单路径）"
# 15c-1：域名格式不对，部署直接报错，服务仍在跑（配置没动）
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --rate 100K --name 测试节点 --domain 'not a domain' < /dev/null > "$TEST_ROOT/deploy-domain-bad.log" 2>&1
[ "$?" != 0 ] && grep -q "域名不对" "$TEST_ROOT/deploy-domain-bad.log" && ok "--domain 格式不对时报错退出" || bad "--domain 格式不对时没报错"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "格式错被拒后服务仍在运行" || bad "格式错被拒后服务停了"
# 15c-2：--domain 和 --tls-domain 不能同时用
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --tls-domain x.example --tls-cert "$TEST_ROOT/cert.pem" --tls-key "$TEST_ROOT/key.pem" --domain good.example < /dev/null > "$TEST_ROOT/deploy-domain-conflict.log" 2>&1
[ "$?" != 0 ] && grep -q "不能同时用" "$TEST_ROOT/deploy-domain-conflict.log" && ok "--domain 和 --tls-domain 冲突时报错退出" || bad "--domain 和 --tls-domain 冲突时没报错"
# 15c-3：DNS 没解析到本机（dns-map 为空），报错，服务仍用自签 TLS 跑，不留半切配置
printf '' > "$TEST_ROOT/dns-map"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --rate 100K --name 测试节点 --domain good.example < /dev/null > "$TEST_ROOT/deploy-domain-nodns.log" 2>&1
[ "$?" != 0 ] && grep -q "还没解析" "$TEST_ROOT/deploy-domain-nodns.log" && ok "DNS 没解析时报错退出" || bad "DNS 没解析时没报错"
has "$CFG" "^TLS_AUTO=1$" && grep -q "^TLS_DOMAIN=''$" "$CFG" && ok "DNS 失败后仍是自签 TLS（没留半切配置）" || bad "DNS 失败后 TLS 配置不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "DNS 失败后服务仍在运行" || bad "DNS 失败后服务停了"
# 15c-4：DNS 指到别人（不是本机 IP），报错
printf 'good.example 198.51.100.1\n' > "$TEST_ROOT/dns-map"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --rate 100K --name 测试节点 --domain good.example < /dev/null > "$TEST_ROOT/deploy-domain-wrongip.log" 2>&1
[ "$?" != 0 ] && grep -q "不是本机公网 IP" "$TEST_ROOT/deploy-domain-wrongip.log" && ok "DNS 指到别人时报错退出" || bad "DNS 指到别人时没报错"
has "$CFG" "^TLS_AUTO=1$" && ok "DNS 错 IP 后仍是自签 TLS" || bad "DNS 错 IP 后 TLS 配置不对"
# 15c-5：80 端口被占，报错
printf 'good.example 203.0.113.5\nmenu.example 203.0.113.5\n' > "$TEST_ROOT/dns-map"
echo "80" > "$TEST_ROOT/ss-busy-ports"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --rate 100K --name 测试节点 --domain good.example < /dev/null > "$TEST_ROOT/deploy-domain-busy80.log" 2>&1
[ "$?" != 0 ] && grep -q "80 端口" "$TEST_ROOT/deploy-domain-busy80.log" && ok "80 端口被占时报错退出" || bad "80 端口被占时没报错"
has "$CFG" "^TLS_AUTO=1$" && ok "80 被占后仍是自签 TLS" || bad "80 被占后 TLS 配置不对"
rm -f "$TEST_ROOT/ss-busy-ports"
# 15c-6：DNS 对了、80 空着，一键成功
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 19999 --rate 100K --name 测试节点 --domain good.example < /dev/null > "$TEST_ROOT/deploy-domain-ok.log" 2>&1
[ "$?" = 0 ] && ok "--domain 一键部署退出码 0" || bad "--domain 一键部署退出码非 0（见 deploy-domain-ok.log）"
has "$CFG" "^TLS_DOMAIN=good.example$" && has "$CFG" "^TLS_AUTO=0$" && ok "一键成功后配置是真 TLS（good.example，自签已关）" || bad "一键成功后配置不是真 TLS"
has "$CFG" "^TLS_CERT=$TEST_ROOT/etc/letsencrypt/live/good.example/fullchain.pem$" && has "$CFG" "^TLS_KEY=$TEST_ROOT/etc/letsencrypt/live/good.example/privkey.pem$" && ok "一键成功后配置里证书路径是 LE 的" || bad "一键成功后证书路径不对"
has "$UNIT" "\-\-tls-domain good.example" && ok "一键成功后服务文件有真 TLS 参数" || bad "一键成功后服务文件没真 TLS"
grep -q "reuse_key = True" "$TEST_ROOT/etc/letsencrypt/renewal/good.example.conf" && ok "续期配置里有 reuse_key = True（续期不换密钥，pin 不变）" || bad "续期配置里没有 reuse_key"
grep -q "\-\-reuse-key" "$TEST_ROOT/certbot.log" && grep -q "\-\-standalone" "$TEST_ROOT/certbot.log" && ok "certbot 是 standalone + --reuse-key 调用的" || bad "certbot 调用参数不对（见 certbot.log）"
[ -x "$TEST_ROOT/etc/letsencrypt/renewal-hooks/deploy/restart-mmx-server.sh" ] && ok "续期 deploy-hook 已安装且可执行" || bad "续期 deploy-hook 没装上"
grep -q "mmx://" "$TEST_ROOT/deploy-domain-ok.log" && ok "一键成功后部署输出打印了新链接" || bad "一键成功后部署输出没打印新链接"
"$MM_BIN" --show-link plain 2>/dev/null | grep -q "good.example" && ok "新链接（plain）地址是域名 good.example" || bad "新链接地址不是域名"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "一键成功后服务仍在运行" || bad "一键成功后服务停了"
# 15c-7：已开真 TLS 时菜单第 3 项 → 第 10 子项域名一键拒绝（换别的域名：先关再开；同域名则幂等）
run_mm '3\n10\n6\nother.example\n0\n0\n11\n' | grep -q "已经开了" && ok "已开真 TLS 时换域名被拒绝并提示先关闭" || bad "已开真 TLS 时换域名没被拒绝"
has "$CFG" "^TLS_DOMAIN=good.example$" && ok "拒绝后域名配置没变" || bad "拒绝后域名配置被改了"
run_mm '3\n10\n6\ngood.example\n0\n0\n11\n' | grep -q "已经是这个域名" && ok "同域名重复设置时提示已是该域名（幂等）" || bad "同域名重复设置时提示不对"
has "$CFG" "^TLS_DOMAIN=good.example$" && ok "幂等后域名配置没变" || bad "幂等后域名配置被改了"
# 15c-8：菜单第 3 项 → 第 10 子项先关 TLS，再用第 6 子项一键设另一个域名
run_mm '3\n10\n3\n0\n0\n11\n' | grep -q "关闭真 TLS" && ok "菜单关闭真 TLS" || bad "菜单关闭真 TLS 失败"
run_mm '3\n10\n6\nmenu.example\n0\n0\n11\n' | grep -q "域名设置完成" && ok "菜单域名一键提示完成" || bad "菜单域名一键提示不对"
has "$CFG" "^TLS_DOMAIN=menu.example$" && has "$CFG" "^TLS_AUTO=0$" && ok "菜单一键后配置是真 TLS（menu.example）" || bad "菜单一键后配置不是真 TLS"
grep -q "reuse_key = True" "$TEST_ROOT/etc/letsencrypt/renewal/menu.example.conf" && ok "菜单一键后续期配置也有 reuse_key = True" || bad "菜单一键后续期配置没有 reuse_key"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "菜单一键后服务仍在运行" || bad "菜单一键后服务停了"

note "测试15d：菜单第 1 项添加节点（向导：非法输入重问 + 全填值 + 覆盖确认）"
run_mm '1\ny\n99999\n18140\n\n180G\n1\n\n\n\n11\n' | grep -q "端口不合法" && ok "向导里非法端口 99999 被拒绝并重问" || bad "向导里非法端口没被拒绝"
has "$CFG" "^PORT=18140$" && ok "向导建节点后端口是 18140" || bad "向导建节点后端口不对"
has "$CFG" "^TRAFFIC_QUOTA=180G$" && has "$CFG" "^TRAFFIC_START_DAY=1$" && has "$CFG" "^TRAFFIC_LIMIT_MODE=throttle$" && has "$CFG" "^TRAFFIC_THROTTLE_RATE=125K$" && ok "向导建节点后流量设置正确（180G/1日/限速/125K）" || bad "向导建节点后流量设置不对"
has "$CFG" "^NAME=mm-x$" && ok "向导里节点名空输入用默认 mm-x" || bad "向导里节点名默认值不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "向导建节点后服务仍在运行" || bad "向导建节点后服务停了"
run_mm '1\nn\n11\n' | grep -q "已有节点" && ok "已有节点时向导先提示覆盖，选 n 取消" || bad "已有节点时向导没提示覆盖"
[ "$(cat "$CFG" | grep -c "^PORT=18140$")" = "1" ] && ok "取消覆盖后配置没变" || bad "取消覆盖后配置被改了"
run_mm '1\ny\n18141\n测试节点2\n500G\n15\nblock\n1M\nother.example\n11\n' | grep -q "添加节点" && ok "确认覆盖后向导能重建节点" || bad "确认覆盖后向导重建失败"
run_mm '1\ny\n18141\n测试节点2\n500G\n15\nblock\n1M\nother.example\n11\n' | grep -q "已经开了" && ok "向导里域名已被占用时提示先关闭（节点照常建成）" || bad "向导域名失败提示不对"
has "$CFG" "^TLS_DOMAIN=menu.example$" && ok "向导域名失败后真 TLS 配置没变（仍是 menu.example）" || bad "向导域名失败后 TLS 配置被改了"
has "$CFG" "^PORT=18141$" && has "$CFG" "^TRAFFIC_QUOTA=500G$" && has "$CFG" "^TRAFFIC_START_DAY=15$" && has "$CFG" "^TRAFFIC_LIMIT_MODE=block$" && has "$CFG" "^TRAFFIC_THROTTLE_RATE=1M$" && ok "重建后配置正确（18141/500G/15日/阻断/1M）" || bad "重建后配置不对"
( . "$CFG"; [ "$NAME" = "测试节点2" ] ) && ok "重建后节点名是 测试节点2" || bad "重建后节点名不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "重建节点后服务仍在运行" || bad "重建节点后服务停了"

note "测试15e：菜单第 4 项删除节点（取消 / 确认删除 / 程序菜单保留 / 重建）"
run_mm '4\nn\n11\n' | grep -q "已取消" && ok "删除节点时选 n 取消" || bad "删除节点取消提示不对"
[ -f "$CFG" ] && ok "取消删除后配置还在" || bad "取消删除后配置没了"
run_mm '4\ny\n11\n' | grep -q "节点已删除" && ok "确认删除后提示节点已删除" || bad "确认删除提示不对"
[ ! -f "$CFG" ] && ok "删除后配置文件已删除" || bad "删除后配置文件还在"
[ ! -f "$TEST_ROOT/etc/mmx/psk" ] && ok "删除后密钥文件已删除" || bad "删除后密钥文件还在"
[ ! -f "$TEST_ROOT/etc/mmx/traffic.json" ] && ok "删除后流量统计已删除" || bad "删除后流量统计还在"
[ "$(cat "$TEST_ROOT/svc-state")" = "inactive" ] && ok "删除后服务已停止" || bad "删除后服务还在运行"
[ -x "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "删除后程序还在" || bad "删除后程序没了"
[ -x "$MM_BIN" ] && ok "删除后菜单命令还在" || bad "删除后菜单命令没了"
[ -f "$UNIT" ] && ok "删除后服务文件还在" || bad "删除后服务文件没了"
run_mm '4\n11\n' | grep -q "没有节点配置" && ok "没节点时删除提示不用删除" || bad "没节点时删除提示不对"
run_mm '1\n\n\n\n\n\n\n\n11\n' | grep -q "添加节点" && ok "删除后可用添加节点重建（全默认）" || bad "删除后添加节点重建失败"
[ -f "$CFG" ] && has "$CFG" "^PORT=443$" && ok "重建后节点是默认端口 443" || bad "重建后节点端口不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "重建后服务仍在运行" || bad "重建后服务停了"


note "测试15f：菜单第 2 项载入预设时顺手设域名（成功 / 失败也不影响预设）"
run_mm '2\n2\ngood.example\ny\n0\n11\n' | grep -q "域名设置完成" && ok "预设 CDT + 域名 good.example 时提示域名设置完成" || bad "预设 + 域名成功提示不对"
has "$CFG" "^TLS_DOMAIN=good.example$" && has "$CFG" "^TRAFFIC_MODE=max$" && has "$CFG" "^TRAFFIC_QUOTA=180G$" && ok "预设 + 域名成功后配置是真 TLS + CDT（max/180G）" || bad "预设 + 域名成功后配置不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "预设 + 域名成功后服务仍在运行" || bad "预设 + 域名成功后服务停了"
run_mm '2\n1\nother.example\ny\n0\n11\n' | grep -q "已经开了" && ok "预设 GCP + 已占用域名时提示先关闭（域名失败）" || bad "预设 + 占用域名时提示不对"
has "$CFG" "^TRAFFIC_MODE=total$" && has "$CFG" "^DOMAIN_WHITELIST=google$" && ok "域名失败后预设 GCP 照常载入（total/谷歌白名单）" || bad "域名失败后预设没载入"
has "$CFG" "^TLS_DOMAIN=good.example$" && ok "域名失败后真 TLS 配置没变（仍是 good.example）" || bad "域名失败后 TLS 配置被改了"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "域名失败、预设照常载入后服务仍在运行" || bad "域名失败后服务停了"

note "测试15g：菜单第 1 项添加节点时顺手设域名（成功）"
run_mm '3\n10\n3\n0\n0\n11\n' | grep -q "关闭真 TLS" && ok "先关真 TLS（为向导域名成功腾地方）" || bad "关真 TLS 失败"
run_mm '1\ny\n18150\n向导域名\n100G\n5\nthrottle\n200K\nmenu.example\n11\n' | grep -q "域名设置完成" && ok "向导 + 域名 menu.example 时提示域名设置完成" || bad "向导 + 域名成功提示不对"
has "$CFG" "^PORT=18150$" && has "$CFG" "^TLS_DOMAIN=menu.example$" && has "$CFG" "^TRAFFIC_QUOTA=100G$" && ok "向导 + 域名成功后配置正确（18150/真 TLS menu.example/100G）" || bad "向导 + 域名成功后配置不对"
( . "$CFG"; [ "$NAME" = "向导域名" ] ) && ok "向导 + 域名成功后节点名是 向导域名" || bad "向导 + 域名成功后节点名不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "向导 + 域名成功后服务仍在运行" || bad "向导 + 域名成功后服务停了"
note "测试16：菜单第 10 项卸载（最后执行）"
# 卸载前先摆好各种残留：菜单备份、LE 证书、hook、BBR 配置、服务备份、/tmp 备份。
# 注意：此时节点域名是 menu.example（测试 15g），卸载只应删 menu.example 的证书，
# good.example（测试 15c 留下的另一域名）必须原样保留。
touch "$TEST_ROOT/usr/local/bin/mmx.bak-preset" "$TEST_ROOT/usr/local/bin/mmx-server.bak" "$TEST_ROOT/usr/local/bin/mm.bak"
mkdir -p "$TEST_ROOT/etc/letsencrypt/archive/menu.example"
touch "$TEST_ROOT/etc/letsencrypt/archive/menu.example/fullchain1.pem"
mkdir -p "$TEST_ROOT/etc/sysctl.d"
printf 'net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\n' > "$TEST_ROOT/etc/sysctl.d/99-mmx-bbr.conf"
touch "$UNIT.bak"
touch /tmp/mmx-server.bak-board /tmp/mmx-server.bak-domain
UNINSTALL_OUT="$(printf '10\ny\n' | "$MM_BIN" 2>&1)"
printf '%s' "$UNINSTALL_OUT" | grep -q "已卸载" && ok "卸载提示正常" || bad "卸载提示不对"
printf '%s' "$UNINSTALL_OUT" | grep -q "无残留" && ok "卸载提示说无残留" || bad "卸载提示没说无残留"
printf '%s' "$UNINSTALL_OUT" | grep -q "Let's Encrypt" && ok "卸载确认里列出了本域名证书" || bad "卸载确认里没列证书"
[ ! -e "$UNIT" ] && ok "卸载后服务文件已删除" || bad "卸载后服务文件还在"
[ ! -e "$UNIT.bak" ] && ok "卸载后服务文件备份已删除" || bad "卸载后服务文件备份还在"
[ ! -e "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "卸载后程序已删除" || bad "卸载后程序还在"
[ ! -e "$MM_BIN" ] && ok "卸载后菜单命令 mm 已删除" || bad "卸载后菜单命令 mm 还在"
[ ! -e "$TEST_ROOT/usr/local/bin/mmx" ] && ok "卸载后菜单命令 mmx 已删除" || bad "卸载后菜单命令 mmx 还在"
[ ! -e "$TEST_ROOT/usr/local/bin/mmx.bak-preset" ] && [ ! -e "$TEST_ROOT/usr/local/bin/mmx-server.bak" ] && [ ! -e "$TEST_ROOT/usr/local/bin/mm.bak" ] && ok "卸载后菜单备份文件已删除" || bad "卸载后菜单备份文件还在"
[ ! -d "$TEST_ROOT/etc/mmx" ] && ok "卸载后配置目录已删除" || bad "卸载后配置目录还在"
[ ! -d "$TEST_ROOT/etc/letsencrypt/live/menu.example" ] && [ ! -d "$TEST_ROOT/etc/letsencrypt/archive/menu.example" ] && [ ! -f "$TEST_ROOT/etc/letsencrypt/renewal/menu.example.conf" ] && ok "卸载后本域名（menu.example）的 LE 证书已删除" || bad "卸载后本域名 LE 证书还在"
[ ! -e "$TEST_ROOT/etc/letsencrypt/renewal-hooks/deploy/restart-mmx-server.sh" ] && ok "卸载后续期 hook 已删除" || bad "卸载后续期 hook 还在"
[ -d "$TEST_ROOT/etc/letsencrypt/live/good.example" ] && ok "卸载后另一域名（good.example）的证书原样保留" || bad "卸载误删了另一域名的证书"
[ ! -e "$TEST_ROOT/etc/sysctl.d/99-mmx-bbr.conf" ] && ok "卸载后 BBR 配置文件已删除" || bad "卸载后 BBR 配置文件还在"
grep -q "net.ipv4.tcp_congestion_control=cubic" "$TEST_ROOT/sysctl.log" && grep -q "net.core.default_qdisc=pfifo_fast" "$TEST_ROOT/sysctl.log" && ok "卸载时把内核拥塞算法还原为 cubic、队列还原为 pfifo_fast" || bad "卸载时没还原内核设置"
[ ! -e /tmp/mmx-server.bak-board ] && [ ! -e /tmp/mmx-server.bak-domain ] && ok "卸载后 /tmp 里的 mmx 备份已删除" || bad "卸载后 /tmp 里的 mmx 备份还在"
rm -f /tmp/mmx-server.bak-*
grep -q "stop" "$TEST_ROOT/systemctl.log" && grep -q "disable" "$TEST_ROOT/systemctl.log" && ok "卸载时停用并禁用了服务" || bad "卸载时没停用服务"

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" = 0 ] && echo "部署+菜单测试全部通过" || echo "有 $fail 项失败，见上文"
exit "$([ "$fail" = 0 ] && echo 0 || echo 1)"
