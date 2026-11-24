#!/bin/bash
# MM-1 部署脚本 + mm 菜单测试：在沙箱里用替身命令模拟 systemd，
# 验证：装完不打印链接、mm 菜单每项能跑通、改参数重启失败会回滚、改名生效。
# 用法：bash test/test-deploy.sh
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"

GO=~/workspace/_build/go/bin/go
TEST_ROOT=/tmp/mm1-deploy-test
STUB_BIN="$TEST_ROOT/stubs"
SRC_DIR="$TEST_ROOT/src"
MM_BIN="$TEST_ROOT/usr/local/bin/mm"
CFG="$TEST_ROOT/etc/mm1/config"
UNIT="$TEST_ROOT/etc/systemd/system/mm1-server.service"

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
# 测试替身：只认 mm1-server 这一个服务；状态存在 $MM1_TEST_ROOT/svc-state
STATE_FILE="${MM1_TEST_ROOT}/svc-state"
LOG_FILE="${MM1_TEST_ROOT}/systemctl.log"
echo "systemctl $*" >> "$LOG_FILE"
cmd="$1"; shift
case "$cmd" in
  daemon-reload) exit 0 ;;
  enable|disable) exit 0 ;;
  restart)
    if [ -f "${MM1_TEST_ROOT}/fail-next-restart" ]; then
      rm -f "${MM1_TEST_ROOT}/fail-next-restart"
      echo "failed" > "$STATE_FILE"
      echo "Job for mm1-server.service failed (simulated)" >&2
      exit 1
    fi
    echo "active" > "$STATE_FILE"
    exit 0 ;;
  stop) echo "inactive" > "$STATE_FILE"; exit 0 ;;
  is-active)
    [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ] && exit 0 || exit 3 ;;
  status)
    if [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ]; then
      echo "● mm1-server.service - MM-1 private proxy server"
      echo "   Active: active (running)"
    else
      echo "● mm1-server.service - MM-1 private proxy server"
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
echo "11月22日 23:00:00 test mm1-server[1]: MM-1 服务端启动，监听 0.0.0.0:18130"
echo "11月22日 23:00:01 test mm1-server[1]: BBR：已开启"
echo "11月22日 23:00:02 test mm1-server[1]: 节点链接：mm://fake"
EOF
chmod +x "$STUB_BIN/journalctl"

# ---- 替身 ss：ss-busy-ports 文件里每行一个端口，算被占用 ----
cat > "$STUB_BIN/ss" <<'EOF'
#!/bin/bash
f="${MM1_TEST_ROOT}/ss-busy-ports"
[ -f "$f" ] || exit 0
while read -r p; do
  [ -n "$p" ] && echo "LISTEN 0 4096 0.0.0.0:$p 0.0.0.0:*"
done < "$f"
exit 0
EOF
chmod +x "$STUB_BIN/ss"

# ---- 替身 curl：公网 IP 探测永远返回 203.0.113.5 ----
cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
echo "203.0.113.5"
exit 0
EOF
chmod +x "$STUB_BIN/curl"

export MM1_TEST_ROOT="$TEST_ROOT"
export PATH="$TEST_ROOT/usr/local/bin:$STUB_BIN:$PATH"

note "编译服务端二进制（当前源码，v3）"
$GO build -o "$SRC_DIR/mm1-server-linux-amd64" ./cmd/mm1-server || { echo "编译失败"; exit 1; }
ok "编译通过"
cp install-mm1-server.sh "$SRC_DIR/"
cp "$SRC_DIR/mm1-server-linux-amd64" "$SRC_DIR/mm1-server" 2>/dev/null || true

note "部署脚本 --help 里有 443 说明"
bash "$SRC_DIR/install-mm1-server.sh" --help 2>&1 | grep -q "443" && ok "--help 提到 443（更像 HTTPS、被占怎么办）" || bad "--help 没提 443"

note "测试1：跑部署脚本（--port 18130）"
bash "$SRC_DIR/install-mm1-server.sh" --port 18130 --name 测试节点 > "$TEST_ROOT/deploy.log" 2>&1
DEPLOY_CODE=$?
[ "$DEPLOY_CODE" = 0 ] && ok "部署脚本退出码 0" || bad "部署脚本退出码 $DEPLOY_CODE（见 deploy.log）"
if grep -q "mm://" "$TEST_ROOT/deploy.log"; then bad "部署输出里打印了 mm:// 链接（应该只在菜单里看）"; else ok "部署输出里没有 mm:// 链接"; fi
grep -q "输入 mm 打开管理菜单" "$TEST_ROOT/deploy.log" && ok "部署完成提示让用户输入 mm 打开菜单" || bad "部署完成提示没提 mm 菜单"
[ -x "$MM_BIN" ] && ok "/usr/local/bin/mm 存在且可执行" || bad "/usr/local/bin/mm 不存在或不可执行"
[ -x "$TEST_ROOT/usr/local/bin/mm1-server" ] && ok "mm1-server 二进制已安装" || bad "mm1-server 二进制没装上"
has "$CFG" "^PORT=18130$" && ok "配置文件端口 18130" || bad "配置文件端口不对"
has "$CFG" "^RATE=6250K$" && ok "配置文件默认限速 6250K" || bad "配置文件限速不对"
has "$CFG" "^BURST=0$" && ok "配置文件默认突发 0（严格）" || bad "配置文件突发不对"
has "$CFG" "^FALLBACK=site$" && ok "配置文件默认回退 site" || bad "配置文件回退不对"
PSK="$(cat "$TEST_ROOT/etc/mm1/psk" 2>/dev/null)"
printf '%s' "$PSK" | grep -Eq '^[0-9a-f]{64}$' && ok "密钥文件是 64 位十六进制" || bad "密钥文件格式不对"
has "$UNIT" "ExecStart=" && ok "服务文件已生成" || bad "服务文件没生成"
has "$UNIT" "0.0.0.0:18130" && has "$UNIT" "\-\-rate 6250K --burst 0" && has "$UNIT" "\-\-fallback site" && ok "ExecStart 含端口/限速/回退参数" || bad "ExecStart 参数不对"
grep -q "restart" "$TEST_ROOT/systemctl.log" && ok "部署时调用了 systemctl restart" || bad "部署时没调用 restart"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "部署后服务状态 active" || bad "部署后服务状态不是 active"

# 菜单调用辅助：喂给 mm 的输入。
# 注意：mm 的输出先落文件再 cat——不能直接 | grep -q：菜单文本里
# 本身就印着要找的字（例如第 2 项"开启真 TLS"），grep -q 一匹配就
# 退出关管道，mm 还没读输入就被 SIGPIPE 杀掉，配置来不及保存
#（老竞态：基线 68/2 的两处失败就是这么来的）。
run_mm() { printf '%b' "$1" | "$MM_BIN" > "$TEST_ROOT/mm-out.txt" 2>&1; cat "$TEST_ROOT/mm-out.txt"; }

note "测试2：菜单第 1 项显示链接"
LINK_OUT="$(run_mm '1\n11\n')"
printf '%s' "$LINK_OUT" | grep -q "mm://" && ok "菜单显示出 mm:// 链接" || bad "菜单没显示链接"
printf '%s' "$LINK_OUT" | grep -q "ver=4" && ok "链接是 ver=4（v4 默认）" || bad "链接版本不对"
printf '%s' "$LINK_OUT" | grep -q "203.0.113.5" && ok "链接里的地址是探测到的公网 IP" || bad "链接地址不对"
! printf '%s' "$LINK_OUT" | grep -q "rate=" && ok "短格式链接不带 rate（限速由服务端配置）" || bad "短格式链接不应带 rate"

note "测试3：菜单第 2 项状态 / 第 3 项重启 / 第 6 项日志"
run_mm '2\n11\n' | grep -q "正在运行" && ok "状态显示正在运行" || bad "状态显示不对"
run_mm '3\n11\n' | grep -q "重启成功" && ok "重启成功" || bad "重启没成功"
run_mm '6\n11\n' | grep -q "MM-1 服务端启动" && ok "日志显示最近记录" || bad "日志显示不对"

note "测试4：菜单第 4 项更换密钥"
OLD_PSK="$(cat "$TEST_ROOT/etc/mm1/psk")"
run_mm '4\n11\n' | grep -q "密钥已更换" && ok "换密钥提示正常" || bad "换密钥提示不对"
NEW_PSK="$(cat "$TEST_ROOT/etc/mm1/psk")"
[ "$OLD_PSK" != "$NEW_PSK" ] && [ -n "$NEW_PSK" ] && ok "密钥文件已换成新密钥" || bad "密钥文件没换"
run_mm '1\n11\n' | grep -q "mm://" && ok "换密钥后仍能显示新链接" || bad "换密钥后链接显示异常"

note "测试5：菜单第 5 项修改限速（rate=3000K burst=0）"
run_mm '5\n3000K\n0\n11\n' | grep -q "限速改为 rate=3000K burst=0" && ok "改限速提示正常" || bad "改限速提示不对"
has "$CFG" "^RATE=3000K$" && ok "配置文件 rate 已改为 3000K" || bad "配置文件 rate 没改"
has "$UNIT" "\-\-rate 3000K" && ok "服务文件 ExecStart 已用新限速" || bad "服务文件限速没更新"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改限速后服务仍在运行" || bad "改限速后服务停了"

note "测试6：菜单第 7 项切换回退模式（site→silent→site）"
run_mm '7\n1\n0\n11\n' | grep -q "回退模式改为 silent" && ok "回退切换到 silent" || bad "回退切换提示不对"
has "$CFG" "^FALLBACK=silent$" && has "$UNIT" "\-\-fallback silent" && ok "配置+服务文件都已是 silent" || bad "回退 silent 没写进配置/服务"
run_mm '7\n1\n0\n11\n' | grep -q "回退模式改为 site" && ok "回退切换回 site" || bad "回退切换回 site 失败"

note "测试7：菜单第 7 项开启真 TLS（自签名证书）再关闭"
openssl req -x509 -newkey rsa:2048 -keyout "$TEST_ROOT/key.pem" -out "$TEST_ROOT/cert.pem" -days 1 -nodes -subj "/CN=test.example" -addext "subjectAltName=DNS:test.example" >/dev/null 2>&1
run_mm "7\n2\ntest.example\n$TEST_ROOT/cert.pem\n$TEST_ROOT/key.pem\n0\n11\n" | grep -q "开启真 TLS" && ok "开启真 TLS 提示正常" || bad "开启真 TLS 提示不对"
has "$CFG" "^TLS_DOMAIN=test.example$" && has "$UNIT" "\-\-tls-domain test.example" && ok "配置+服务文件都有 TLS 域名" || bad "TLS 域名没写进配置/服务"
run_mm '1\n11\n' | grep -q "pin=" && ok "TLS 模式下链接带 pin（短格式，obfs=tls 为 ver=4 默认）" || bad "TLS 模式下链接没有 pin"
run_mm '1\n11\n' | grep -q "test.example" && ok "TLS 模式下链接地址是域名" || bad "TLS 模式下链接地址不是域名"
run_mm '7\n3\n0\n11\n' | grep -q "关闭真 TLS" && ok "关闭真 TLS 提示正常" || bad "关闭真 TLS 提示不对"
grep -q "^TLS_DOMAIN=''$" "$CFG" && ! grep -q "tls-domain" "$UNIT" && ok "关闭后配置+服务文件里没了 TLS" || bad "关闭 TLS 后还有残留"

note "测试7b：菜单第 7 项开启自签 TLS（无域名）再查指纹、关闭"
run_mm "7\n4\n\n0\n11\n" | grep -q "开启自签 TLS" && ok "开启自签 TLS 提示正常" || bad "开启自签 TLS 提示不对"
has "$CFG" "^TLS_AUTO=1$" && has "$UNIT" "\\-\\-tls-auto" && ok "配置+服务文件都有 --tls-auto" || bad "自签 TLS 没写进配置/服务"
has "$UNIT" "tls-cert.pem" && has "$UNIT" "tls-key.pem" && ok "服务文件里自签证书是绝对路径" || bad "自签证书路径不对"
! run_mm '1\n11\n' | grep -q "obfs=tls-fake" && ok "自签模式下链接不是明文（短格式，obfs=tls 为 ver=4 默认）" || bad "自签模式下链接不对"
run_mm '1\n11\n' | grep -q "pin=" && ok "自签模式下链接带 pin" || bad "自签模式下链接没有 pin"
run_mm '7\n5\n0\n11\n' | grep -Eq "[A-Za-z0-9_-]{43}" && ok "第 7 项第 5 子项能查到 43 位指纹" || bad "查指纹没拿到 pin"
run_mm '7\n3\n0\n11\n' | grep -q "关闭自签 TLS" && ok "关闭自签 TLS 提示正常" || bad "关闭自签 TLS 提示不对"
grep -q "^TLS_AUTO=0$" "$CFG" && ! grep -q "tls-auto" "$UNIT" && ok "关闭后配置+服务文件里没了自签 TLS" || bad "关闭自签 TLS 后还有残留"

note "测试8：菜单第 8 项改端口（18130→18131）"
run_mm '8\n1\n18131\n0\n11\n' | grep -q "端口改为 18131" && ok "改端口提示正常" || bad "改端口提示不对"
has "$CFG" "^PORT=18131$" && has "$UNIT" "0.0.0.0:18131" && ok "配置+服务文件端口已是 18131" || bad "端口没写进配置/服务"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "改端口后服务仍在运行" || bad "改端口后服务停了"

note "测试9：端口占用冲突（18132 被占）：拒绝改、确认后才改"
echo "18132" > "$TEST_ROOT/ss-busy-ports"
run_mm '8\n1\n18132\nn\n0\n11\n' | grep -q "已被别的服务占用" && ok "占用端口有警告" || bad "占用端口没警告"
has "$CFG" "^PORT=18131$" && ok "拒绝后端口保持 18131" || bad "拒绝后端口被改了"
run_mm '8\n1\n18132\ny\n0\n11\n' | grep -q "端口改为 18132" && ok "确认后改成占用端口（测试替身下能起来）" || bad "确认后改端口失败"
has "$CFG" "^PORT=18132$" && ok "确认后配置端口已是 18132" || bad "确认后配置端口不对"
rm -f "$TEST_ROOT/ss-busy-ports"

note "测试10：非法输入被拒绝（端口 99999、rate abc）"
run_mm '8\n1\n99999\n0\n11\n' | grep -q "端口不合法" && ok "99999 端口被拒绝" || bad "99999 端口没被拒绝"
has "$CFG" "^PORT=18132$" && ok "非法端口后配置没变" || bad "非法端口后配置被改了"
run_mm '8\n2\nabc\n0\n11\n' | grep -q "rate 格式不对" && ok "abc 限速被拒绝" || bad "abc 限速没被拒绝"
has "$CFG" "^RATE=3000K$" && ok "非法限速后配置没变" || bad "非法限速后配置被改了"

note "测试11：改端口后重启失败 → 回滚到原配置"
touch "$TEST_ROOT/fail-next-restart"
ROLLBACK_OUT="$(run_mm '8\n1\n18133\n0\n11\n')"
printf '%s' "$ROLLBACK_OUT" | grep -q "回滚" && ok "重启失败时提示回滚" || bad "重启失败时没提示回滚"
has "$CFG" "^PORT=18132$" && ok "回滚后配置端口恢复 18132" || bad "回滚后配置端口不对"
has "$UNIT" "0.0.0.0:18132" && ! grep -q "0.0.0.0:18133" "$UNIT" && ok "回滚后服务文件恢复 18132" || bad "回滚后服务文件不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "回滚后服务用原配置恢复运行" || bad "回滚后服务没起来"

note "测试12：部署时端口被占直接失败（--port 18140）"
echo "18140" > "$TEST_ROOT/ss-busy-ports"
bash "$SRC_DIR/install-mm1-server.sh" --port 18140 > "$TEST_ROOT/deploy-busy.log" 2>&1
[ "$?" != 0 ] && grep -q "已被别的服务占用" "$TEST_ROOT/deploy-busy.log" && ok "部署时占用端口报错退出" || bad "部署时占用端口没报错"
rm -f "$TEST_ROOT/ss-busy-ports"

note "测试13：菜单第 9 项改快捷命令名（mm→mmx）"
run_mm '9\nmmx\n11\n' | grep -q "已改名" && ok "改名提示正常" || bad "改名提示不对"
[ -x "$TEST_ROOT/usr/local/bin/mmx" ] && ok "新命令 mmx 存在且可执行" || bad "新命令 mmx 不存在"
[ ! -e "$MM_BIN" ] && ok "旧命令 mm 已删除" || bad "旧命令 mm 还在"
command -v mmx >/dev/null 2>&1 && ok "mmx 能在 PATH 里找到" || bad "mmx 在 PATH 里找不到"
mmx --show-link 2>/dev/null | grep -q "mm://" && ok "新命令 mmx --show-link 能显示链接" || bad "新命令 mmx 不能用"
command -v mm >/dev/null 2>&1 && bad "旧命令 mm 还能找到（应该失效）" || ok "旧命令 mm 已失效"

note "测试14：改名冲突（改成 ls）与非法名"
printf '9\nls\n11\n' | "$TEST_ROOT/usr/local/bin/mmx" | grep -q "名字冲突" && ok "改成已有命令名被拒绝" || bad "改成已有命令名没被拒绝"
[ -x "$TEST_ROOT/usr/local/bin/mmx" ] && ok "冲突后 mmx 还在" || bad "冲突后 mmx 没了"
printf '9\nbad name!\n11\n' | "$TEST_ROOT/usr/local/bin/mmx" | grep -q "名字不合法" && ok "非法名字被拒绝" || bad "非法名字没被拒绝"

note "测试15：菜单第 10 项卸载（最后执行）"
printf '10\ny\n' | "$TEST_ROOT/usr/local/bin/mmx" | grep -q "已卸载" && ok "卸载提示正常" || bad "卸载提示不对"
[ ! -e "$UNIT" ] && ok "卸载后服务文件已删除" || bad "卸载后服务文件还在"
[ ! -e "$TEST_ROOT/usr/local/bin/mm1-server" ] && ok "卸载后程序已删除" || bad "卸载后程序还在"
[ ! -e "$TEST_ROOT/usr/local/bin/mmx" ] && ok "卸载后菜单命令已删除" || bad "卸载后菜单命令还在"
[ ! -d "$TEST_ROOT/etc/mm1" ] && ok "卸载后配置目录已删除" || bad "卸载后配置目录还在"
grep -q "stop" "$TEST_ROOT/systemctl.log" && grep -q "disable" "$TEST_ROOT/systemctl.log" && ok "卸载时停用并禁用了服务" || bad "卸载时没停用服务"

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" = 0 ] && echo "部署+菜单测试全部通过" || echo "有 $fail 项失败，见上文"
exit "$([ "$fail" = 0 ] && echo 0 || echo 1)"
