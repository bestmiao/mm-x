#!/bin/bash
# mm-x 部署脚本 OpenRC/Alpine 测试：在沙箱里用替身命令模拟 OpenRC，
# 且 PATH 里 deliberately 没有 systemctl/journalctl（像真 Alpine 一样），
# 验证：检测到 OpenRC、写 /etc/init.d/mmx-server（不是 systemd 单元）、
# 服务操作走 rc-service/rc-update、certbot 走 apk 装、菜单各项能跑通、
# 改参数重启失败会回滚、卸载清干净。
# 用法：bash test/test-openrc.sh
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"

GO=~/workspace/_build/go/bin/go
TEST_ROOT=/tmp/mmx-openrc-test
STUB_BIN="$TEST_ROOT/stubs"
CLEANBIN="$TEST_ROOT/cleanbin"
SRC_DIR="$TEST_ROOT/src"
MM_BIN="$TEST_ROOT/usr/local/bin/mmx"
CFG="$TEST_ROOT/etc/mmx/config"
INIT_FILE="$TEST_ROOT/etc/init.d/mmx-server"
UNIT="$TEST_ROOT/etc/systemd/system/mmx-server.service"

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
note() { echo "--- $1"; }
has()  { grep -q "$2" "$1"; }   # has 文件 正则

# 解码不透明 mmx:// 链接，输出 "ver=<n> pin=<0|1>"（和 test-deploy.sh 同一份逻辑）
opaque_info() {
  python3 - "$1" <<'PYEOF'
import base64, binascii, sys
link = sys.argv[1].strip()
rest = link[6:] if link.startswith("mmx://") else link
blob = base64.urlsafe_b64decode(rest + "=" * (-len(rest) % 4))
body, want = blob[:-4], int.from_bytes(blob[-4:], "big")
assert (binascii.crc32(body) & 0xffffffff) == want, "crc mismatch"
off = 5 + 32  # magic(4)+blob 版本(1)+PSK(32)
ht = blob[off]; off += 1
if ht == 0x01: off += 4
elif ht == 0x02: off += 16
elif ht == 0x03:
    ln = blob[off]; off += 1 + ln
else: raise SystemExit("bad host type")
off += 2  # 端口
ver = blob[off]; off += 1
off += 1  # obfs
sf = blob[off]; off += 1
if sf == 1:
    ln = blob[off]; off += 1 + ln
pf = blob[off]; off += 1
print(f"ver={ver} pin={1 if pf == 1 else 0}")
PYEOF
}

rm -rf "$TEST_ROOT"
mkdir -p "$STUB_BIN" "$SRC_DIR" "$CLEANBIN"

# ---- 替身 rc-service：状态文件驱动，restart 可被标记为失败一次 ----
cat > "$STUB_BIN/rc-service" <<'EOF'
#!/bin/bash
# OpenRC 替身：只认 mmx-server；状态存在 $MMX_TEST_ROOT/svc-state
STATE_FILE="${MMX_TEST_ROOT}/svc-state"
LOG_FILE="${MMX_TEST_ROOT}/rc-service.log"
echo "rc-service $*" >> "$LOG_FILE"
svc="$1"; shift
[ "$svc" = "mmx-server" ] || { echo "替身 rc-service 只认 mmx-server" >&2; exit 1; }
cmd="$1"; shift
case "$cmd" in
  start)
    echo "active" > "$STATE_FILE"
    echo " * Starting mmx-server ..."
    echo " [ ok ]"
    exit 0 ;;
  stop)
    echo "inactive" > "$STATE_FILE"
    echo " * Stopping mmx-server ..."
    echo " [ ok ]"
    exit 0 ;;
  restart)
    if [ -f "${MMX_TEST_ROOT}/fail-next-restart" ]; then
      rm -f "${MMX_TEST_ROOT}/fail-next-restart"
      echo "failed" > "$STATE_FILE"
      echo " * Starting mmx-server ..."
      echo " * start-stop-daemon: failed to start mmx-server (simulated)" >&2
      exit 1
    fi
    echo "active" > "$STATE_FILE"
    echo " * Stopping mmx-server ..."
    echo " [ ok ]"
    echo " * Starting mmx-server ..."
    echo " [ ok ]"
    exit 0 ;;
  status)
    if [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ]; then
      echo " * status: started"
      exit 0
    else
      echo " * status: stopped"
      exit 3
    fi ;;
  *) echo "替身 rc-service 不认识：$cmd" >&2; exit 1 ;;
esac
EOF
chmod +x "$STUB_BIN/rc-service"

# ---- 替身 rc-update：只记调用（开机自启用） ----
cat > "$STUB_BIN/rc-update" <<'EOF'
#!/bin/bash
echo "rc-update $*" >> "${MMX_TEST_ROOT}/rc-update.log"
exit 0
EOF
chmod +x "$STUB_BIN/rc-update"

# ---- 替身 apk：只认 add --no-cache certbot；"安装"时把预置的 certbot 替身放进 stub 目录 ----
cat > "$STUB_BIN/apk" <<'EOF'
#!/bin/bash
echo "apk $*" >> "${MMX_TEST_ROOT}/apk.log"
[ "$1" = "add" ] || { echo "替身 apk 只认 add" >&2; exit 1; }
shift
[ "$1" = "--no-cache" ] && shift
[ "$1" = "certbot" ] || { echo "替身 apk 只认 certbot" >&2; exit 1; }
cp "${MMX_TEST_ROOT}/certbot-stub-template" "${MMX_TEST_ROOT}/stubs/certbot"
chmod +x "${MMX_TEST_ROOT}/stubs/certbot"
echo "OK: certbot installed (stub)"
exit 0
EOF
chmod +x "$STUB_BIN/apk"

# ---- certbot 替身模板（apk "装上" certbot 后才出现；和 test-deploy.sh 的 certbot 替身同一份逻辑） ----
cat > "$TEST_ROOT/certbot-stub-template" <<'EOF'
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
chmod +x "$TEST_ROOT/certbot-stub-template"

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

# ---- 替身 sysctl：只记调用；不碰真实内核 ----
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

# ---- 替身 getent：只认 hosts 查询；按 $MMX_TEST_ROOT/dns-map 回答域名解析 ----
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

# ---- 替身 dig / nslookup：永远查不到（域名解析只由上面的 getent + dns-map 控制） ----
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

# ---- 干净 PATH：系统命令的软链接，但 deliberately 排除 systemctl/journalctl
# （真 Alpine 没有它们）、apt-get/apt（真 Alpine 没有，脚本应走 apk 分支）
# 和所有替身命令（替身优先）以及 ufw/firewall-cmd
# （真 Alpine 默认没有，脚本应走"手动放行"警告分支） ----
for d in /usr/bin /bin /usr/sbin /sbin; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    b="$(basename "$f")"
    case "$b" in
      systemctl|journalctl|apt-get|apt|rc-service|rc-update|curl|getent|dig|nslookup|certbot|apk|ss|sysctl|ufw|firewall-cmd) ;;
      *) [ -e "$CLEANBIN/$b" ] || ln -s "$f" "$CLEANBIN/$b" ;;
    esac
  done
done

export MMX_TEST_ROOT="$TEST_ROOT"
# 注意：这里 PATH 故意不含系统 /usr/bin（里面有真 systemctl），
# 只含 mmx 安装目录 + 替身 + 干净软链接目录。
OPENRC_PATH="$TEST_ROOT/usr/local/bin:$STUB_BIN:$CLEANBIN"

note "编译服务端二进制（当前源码，v5）"
$GO build -o "$SRC_DIR/mmx-server-linux-amd64" ./cmd/mmx-server || { echo "编译失败"; exit 1; }
ok "编译通过"
cp install-mm-x-server.sh "$SRC_DIR/"
cp "$SRC_DIR/mmx-server-linux-amd64" "$SRC_DIR/mmx-server" 2>/dev/null || true

note "测试0：干净 PATH 里确实没有 systemctl/journalctl/apt-get，但有 rc-service/apk"
[ -z "$(PATH="$OPENRC_PATH" command -v systemctl 2>/dev/null)" ] && ok "干净 PATH 里找不到 systemctl（像 Alpine）" || bad "干净 PATH 里居然有 systemctl"
[ -z "$(PATH="$OPENRC_PATH" command -v journalctl 2>/dev/null)" ] && ok "干净 PATH 里找不到 journalctl（像 Alpine）" || bad "干净 PATH 里居然有 journalctl"
[ -z "$(PATH="$OPENRC_PATH" command -v apt-get 2>/dev/null)" ] && ok "干净 PATH 里找不到 apt-get（像 Alpine）" || bad "干净 PATH 里居然有 apt-get"
[ -n "$(PATH="$OPENRC_PATH" command -v rc-service 2>/dev/null)" ] && ok "干净 PATH 里能找到 rc-service 替身" || bad "干净 PATH 里找不到 rc-service"
[ -n "$(PATH="$OPENRC_PATH" command -v apk 2>/dev/null)" ] && ok "干净 PATH 里能找到 apk 替身" || bad "干净 PATH 里找不到 apk"

note "测试1：跑部署脚本（--port 18130），应检测到 OpenRC；全新安装只装程序，不建节点"
PATH="$OPENRC_PATH" bash "$SRC_DIR/install-mm-x-server.sh" --port 18130 < /dev/null > "$TEST_ROOT/deploy.log" 2>&1
DEPLOY_CODE=$?
[ "$DEPLOY_CODE" = 0 ] && ok "部署脚本退出码 0" || bad "部署脚本退出码 $DEPLOY_CODE（见 deploy.log）"
! grep -q "systemctl" "$TEST_ROOT/deploy.log" && ok "部署输出里没提 systemctl（全是 OpenRC 命令）" || bad "部署输出里还提 systemctl"
grep -q "只装程序，不建节点" "$TEST_ROOT/deploy.log" && ok "部署输出说明只装程序、不建节点" || bad "部署输出没说只装程序"
grep -q "已忽略" "$TEST_ROOT/deploy.log" && ok "部署输出说明安装参数已忽略" || bad "部署输出没说安装参数已忽略"
grep -q "输入 mmx 打开菜单添加节点" "$TEST_ROOT/deploy.log" && ok "部署完成提示让用户输入 mmx 打开菜单添加节点" || bad "部署完成提示不对"
[ -x "$MM_BIN" ] && ok "/usr/local/bin/mmx 存在且可执行" || bad "/usr/local/bin/mmx 不存在或不可执行"
[ -x "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "mmx-server 二进制已安装" || bad "mmx-server 二进制没装上"
[ ! -e "$CFG" ] && ok "全新安装不写配置文件" || bad "全新安装写了配置文件（应该不建节点）"
[ ! -e "$TEST_ROOT/etc/mmx/psk" ] && ok "全新安装不生成密钥" || bad "全新安装生成了密钥（应该不建节点）"
[ ! -e "$INIT_FILE" ] && ok "全新安装不写 init 脚本" || bad "全新安装写了 init 脚本（应该不建节点）"
[ ! -e "$UNIT" ] && ok "全新安装不写 systemd 单元文件" || bad "全新安装写了 systemd 单元文件"
[ ! -e "$TEST_ROOT/svc-state" ] && ok "全新安装后服务未启动" || bad "全新安装后服务被启动了"
[ ! -e "$TEST_ROOT/rc-service.log" ] && ok "全新安装时没调用 rc-service" || bad "全新安装时调用了 rc-service"
[ ! -e "$TEST_ROOT/rc-update.log" ] && ok "全新安装时没调用 rc-update" || bad "全新安装时调用了 rc-update"

# 菜单调用辅助：喂给 mm 的输入（用干净 PATH 跑菜单）。
run_mm() { printf '%b' "$1" | PATH="$OPENRC_PATH" "$MM_BIN" > "$TEST_ROOT/mm-out.txt" 2>&1; cat "$TEST_ROOT/mm-out.txt"; }

note "测试1b：菜单第 1 项添加节点（端口 18130、选 IP）建好节点"
run_mm '1\n1\n18130\n\n1\n\n\n2\n9\n' | grep -q "用域名还是 IP" && ok "向导里问域名还是 IP（明确选，不是可选收尾）" || bad "向导里没问域名还是 IP"
has "$CFG" "^PORT=18130$" && ok "配置文件端口 18130" || bad "配置文件端口不对"
grep -q "add mmx-server default" "$TEST_ROOT/rc-update.log" && ok "加节点时 rc-update add mmx-server default（开机自启）" || bad "加节点时没调 rc-update add"
grep -q "restart" "$TEST_ROOT/rc-service.log" && ok "加节点时调用了 rc-service restart" || bad "加节点时没调用 rc-service restart"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "加节点后服务状态 active" || bad "加节点后服务状态不是 active"

note "测试2：OpenRC init 脚本已生成（不是 systemd 单元）"
[ -f "$INIT_FILE" ] && ok "init 脚本已生成：/etc/init.d/mmx-server" || bad "init 脚本没生成"
[ ! -e "$UNIT" ] && ok "没有生成 systemd 单元文件" || bad "还生成了 systemd 单元文件"
[ -x "$INIT_FILE" ] && ok "init 脚本可执行" || bad "init 脚本不可执行"
head -1 "$INIT_FILE" | grep -q "#!/sbin/openrc-run" && ok "init 脚本第一行是 #!/sbin/openrc-run" || bad "init 脚本第一行不对"
grep -Fq "command=\"$TEST_ROOT/usr/local/bin/mmx-server\"" "$INIT_FILE" && ok "init 脚本 command 是 mmx-server 二进制" || bad "init 脚本 command 不对"
grep -q "need net" "$INIT_FILE" && ok "init 脚本 depend() 里 need net" || bad "init 脚本 depend() 里没有 need net"
grep -Fq 'pidfile="/run/mmx-server.pid"' "$INIT_FILE" && ok "init 脚本有 pidfile" || bad "init 脚本没有 pidfile"
grep -q "command_background=true" "$INIT_FILE" && ok "init 脚本 command_background=true" || bad "init 脚本没有 command_background"
# command_args 必须和 systemd 的 ExecStart 参数字节一致（只差二进制路径）：
# 部署配置是端口 18130、不限速、回退 site、默认流量（total/月/1日/限速/0/125K）、掩护 low。
EXPECTED_ARGS="--psk-file $TEST_ROOT/etc/mmx/psk --listen 0.0.0.0:18130 --rate 0 --burst 0 --name \"203.0.113.5\" --fallback site --traffic-mode total --traffic-period monthly --traffic-start-day 1 --traffic-limit-mode throttle --traffic-quota 0 --traffic-throttle-rate 125K --traffic-file $TEST_ROOT/etc/mmx/traffic.json --cover-traffic low"
INIT_ARGS="$(grep '^command_args=' "$INIT_FILE" | sed 's/^command_args="//; s/"$//; s/\\"/"/g')"
[ "$INIT_ARGS" = "$EXPECTED_ARGS" ] && ok "init 脚本 command_args 和 systemd ExecStart 参数字节一致" || bad "init 脚本 command_args 和预期参数不一致（见 $INIT_FILE）"

note "测试3：菜单第 5 项查看节点"
LINK_OUT="$(run_mm '5\n9\n')"
printf '%s' "$LINK_OUT" | grep -q "查看节点" && ok "第 5 项标题是查看节点" || bad "第 5 项标题不对"
printf '%s' "$LINK_OUT" | grep -Fq "1. 203.0.113.5" && ok "第 1 条地址是探测到的公网 IP" || bad "第 1 条地址不对"
LINK1="$(printf '%s' "$LINK_OUT" | grep -o 'mmx://[A-Za-z0-9_-]*' | head -1)"
printf '%s' "$(opaque_info "$LINK1")" | grep -q "ver=5" && ok "链接是 ver=5（v5 默认）" || bad "链接版本不对"

note "测试4：服务状态在菜单最上方默认显示 / 第 6 项日志（走 rc-service，没有 journalctl；重启菜单已删除）"
run_mm '9\n' | grep -q "正在运行" && ok "菜单最上方显示服务正在运行" || bad "菜单最上方没显示服务状态"
grep -q "status" "$TEST_ROOT/rc-service.log" && ok "状态查询走了 rc-service status" || bad "状态查询没走 rc-service"
run_mm '9\n' | grep -q "重启服务" && bad "菜单里还有重启服务这一项（已删除）" || ok "菜单里没有重启服务这一项"
run_mm '6\n9\n' | grep -q "rc-service mmx-server status" && ok "没 journalctl 时日志页提示用 rc-service 看状态" || bad "日志页没提示 rc-service"

note "测试5：菜单第 3 项 → 第 2/3 子项改限速（rate=3000K），init 脚本跟着更新"
OUT5="$(run_mm '3\n2\n3000K\n3\n0\n0\n9\n')"
printf '%s' "$OUT5" | grep -q "限速 rate 改为 3000K" && ok "改 rate 提示正常" || bad "改 rate 提示不对"
printf '%s' "$OUT5" | grep -q "突发 burst 改为 0" && ok "改 burst 提示正常" || bad "改 burst 提示不对"
has "$CFG" "^RATE=3000K$" && ok "配置文件 rate 已改为 3000K" || bad "配置文件 rate 没改"
has "$CFG" "^BURST=0$" && ok "配置文件 burst 已改为 0" || bad "配置文件 burst 没改"
grep -Fq -- "--rate 3000K" "$INIT_FILE" && ok "init 脚本 command_args 已用新限速" || bad "init 脚本限速没更新"
[ ! -e "$UNIT" ] && ok "改限速后仍没有 systemd 单元文件" || bad "改限速后冒出了 systemd 单元文件"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改限速后服务仍在运行" || bad "改限速后服务停了"

note "测试6：改端口后重启失败 → 回滚到原配置（走 rc-service）"
touch "$TEST_ROOT/fail-next-restart"
ROLLBACK_OUT="$(run_mm '3\n1\n18133\n0\n9\n')"
printf '%s' "$ROLLBACK_OUT" | grep -q "回滚" && ok "重启失败时提示回滚" || bad "重启失败时没提示回滚"
has "$CFG" "^PORT=18130$" && ok "回滚后配置端口恢复 18130" || bad "回滚后配置端口不对"
grep -Fq "0.0.0.0:18130" "$INIT_FILE" && ! grep -q "0.0.0.0:18133" "$INIT_FILE" && ok "回滚后 init 脚本恢复 18130" || bad "回滚后 init 脚本不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "回滚后服务用原配置恢复运行" || bad "回滚后服务没起来"

note "测试7：certbot 走 apk 装（没有 certbot 替身时），再一键设域名（TLS 菜单已移除，改走隐藏用法 mmx --setup-domain）"
printf 'good.example 203.0.113.5\n' > "$TEST_ROOT/dns-map"
PATH="$OPENRC_PATH" "$MM_BIN" --setup-domain good.example > "$TEST_ROOT/mm-out.txt" 2>&1
grep -q "域名设置完成" "$TEST_ROOT/mm-out.txt" && ok "域名一键提示完成" || bad "域名一键提示不对（见 mm-out.txt）"
grep -q "add.*certbot" "$TEST_ROOT/apk.log" && ok "certbot 是经 apk add 装的" || bad "certbot 没走 apk 装"
has "$CFG" "^TLS_DOMAIN=good.example$" && has "$CFG" "^TLS_AUTO=0$" && ok "一键成功后配置是真 TLS（good.example）" || bad "一键成功后配置不是真 TLS"
grep -Fq -- "--tls-domain good.example" "$INIT_FILE" && ok "一键成功后 init 脚本有真 TLS 参数" || bad "一键成功后 init 脚本没真 TLS"
grep -q "reuse_key = True" "$TEST_ROOT/etc/letsencrypt/renewal/good.example.conf" && ok "续期配置里有 reuse_key = True" || bad "续期配置里没有 reuse_key"
grep -q "rc-service mmx-server restart" "$TEST_ROOT/etc/letsencrypt/renewal-hooks/deploy/restart-mmx-server.sh" && ok "续期 hook 里重启命令是 rc-service（不是 systemctl）" || bad "续期 hook 里重启命令不对"
! grep -q "systemctl" "$TEST_ROOT/etc/letsencrypt/renewal-hooks/deploy/restart-mmx-server.sh" && ok "续期 hook 里没有 systemctl" || bad "续期 hook 里还有 systemctl"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "一键成功后服务仍在运行" || bad "一键成功后服务停了"

note "测试8：菜单第 8 项完全卸载（走 rc-service/rc-update，清干净）"
touch "$TEST_ROOT/usr/local/bin/mmx.bak-preset"
touch "$INIT_FILE.bak"
UNINSTALL_OUT="$(printf '8\ny\n' | PATH="$OPENRC_PATH" "$MM_BIN" 2>&1)"
printf '%s' "$UNINSTALL_OUT" | grep -q "已卸载" && ok "卸载提示正常" || bad "卸载提示不对"
[ ! -e "$INIT_FILE" ] && ok "卸载后 init 脚本已删除" || bad "卸载后 init 脚本还在"
[ ! -e "$INIT_FILE.bak" ] && ok "卸载后 init 脚本备份已删除" || bad "卸载后 init 脚本备份还在"
[ ! -e "$UNIT" ] && ok "卸载后也没有 systemd 单元文件" || bad "卸载后冒出了 systemd 单元文件"
[ ! -e "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "卸载后程序已删除" || bad "卸载后程序还在"
[ ! -e "$MM_BIN" ] && ok "卸载后菜单命令 mmx 已删除" || bad "卸载后菜单命令 mm 还在"
[ ! -e "$TEST_ROOT/usr/local/bin/mmx" ] && ok "卸载后菜单命令 mmx 已删除" || bad "卸载后菜单命令 mmx 还在"
[ ! -d "$TEST_ROOT/etc/mmx" ] && ok "卸载后配置目录已删除" || bad "卸载后配置目录还在"
grep -q "stop" "$TEST_ROOT/rc-service.log" && ok "卸载时 rc-service stop 了服务" || bad "卸载时没停服务"
grep -q "del mmx-server default" "$TEST_ROOT/rc-update.log" && ok "卸载时 rc-update del 取消了开机自启" || bad "卸载时没取消开机自启"

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" = 0 ] && echo "OpenRC/Alpine 测试全部通过" || echo "有 $fail 项失败，见上文"
exit "$([ "$fail" = 0 ] && echo 0 || echo 1)"
