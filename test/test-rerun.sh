#!/bin/bash
# mm-x 安装脚本“再跑不重置”测试：全新安装默认端口 443；已安装时再跑
# 脚本（不加 --reinstall）只更新程序文件，不改节点配置；加 --reinstall 才重装。
# 用法：bash test/test-rerun.sh（在沙箱里用替身命令模拟 systemd，不碰真实系统）
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"

GO=~/workspace/_build/go/bin/go
TEST_ROOT=/tmp/mmx-rerun-test
STUB_BIN="$TEST_ROOT/stubs"
SRC_DIR="$TEST_ROOT/src"
CFG="$TEST_ROOT/etc/mmx/config"
UNIT="$TEST_ROOT/etc/systemd/system/mmx-server.service"

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
note() { echo "--- $1"; }
has()  { grep -q "$2" "$1"; }

rm -rf "$TEST_ROOT"
mkdir -p "$STUB_BIN" "$SRC_DIR"

cat > "$STUB_BIN/systemctl" <<'EOF'
#!/bin/bash
STATE_FILE="${MMX_TEST_ROOT}/svc-state"
cmd="$1"; shift
case "$cmd" in
  daemon-reload) exit 0 ;;
  enable|disable) exit 0 ;;
  restart) echo "active" > "$STATE_FILE"; exit 0 ;;
  stop) echo "inactive" > "$STATE_FILE"; exit 0 ;;
  is-active) [ "$(cat "$STATE_FILE" 2>/dev/null)" = "active" ] && exit 0 || exit 3 ;;
  status) exit 0 ;;
  *) echo "替身 systemctl 不认识：$cmd" >&2; exit 1 ;;
esac
EOF
chmod +x "$STUB_BIN/systemctl"

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

cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
echo "203.0.113.5"
exit 0
EOF
chmod +x "$STUB_BIN/curl"

export MMX_TEST_ROOT="$TEST_ROOT"
export PATH="$TEST_ROOT/usr/local/bin:$STUB_BIN:$PATH"

note "编译服务端二进制（当前源码，v5）"
$GO build -o "$SRC_DIR/mmx-server-linux-amd64" ./cmd/mmx-server || { echo "编译失败"; exit 1; }
ok "编译通过"
cp install-mm-x-server.sh "$SRC_DIR/"

note "测试1：全新安装（--name 测试节点）只装程序，不建节点"
bash "$SRC_DIR/install-mm-x-server.sh" --name 测试节点 < /dev/null > "$TEST_ROOT/deploy-fresh.log" 2>&1
[ "$?" = 0 ] && ok "全新安装退出码 0" || bad "全新安装退出码非 0（见 deploy-fresh.log）"
grep -q "只装程序，不建节点" "$TEST_ROOT/deploy-fresh.log" && ok "全新安装输出说明只装程序、不建节点" || bad "全新安装输出没说只装程序"
grep -q "已忽略" "$TEST_ROOT/deploy-fresh.log" && ok "全新安装输出说明 --name 已忽略" || bad "全新安装输出没说参数已忽略"
grep -q "输入 mmx 打开菜单添加节点" "$TEST_ROOT/deploy-fresh.log" && ok "全新安装提示进菜单加节点" || bad "全新安装提示不对"
! grep -q "mmx://" "$TEST_ROOT/deploy-fresh.log" && ok "全新安装输出里没有链接" || bad "全新安装输出里有链接"
[ -x "$TEST_ROOT/usr/local/bin/mmx-server" ] && ok "全新安装后二进制已装" || bad "全新安装后二进制没装"
[ -x "$TEST_ROOT/usr/local/bin/mmx" ] && ok "全新安装后菜单已装" || bad "全新安装后菜单没装"
[ ! -e "$CFG" ] && ok "全新安装不写配置文件" || bad "全新安装写了配置文件（应该不建节点）"
[ ! -e "$TEST_ROOT/etc/mmx/psk" ] && ok "全新安装不生成密钥" || bad "全新安装生成了密钥（应该不建节点）"
[ ! -e "$UNIT" ] && ok "全新安装不写服务文件" || bad "全新安装写了服务文件（应该不建节点）"
[ ! -e "$TEST_ROOT/svc-state" ] && ok "全新安装后服务未启动" || bad "全新安装后服务被启动了"

note "测试1b：用 --reinstall 建节点（默认端口 443），为后面的再跑测试准备状态"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --name 测试节点 < /dev/null > "$TEST_ROOT/deploy-create.log" 2>&1
[ "$?" = 0 ] && ok "--reinstall 建节点退出码 0" || bad "--reinstall 建节点退出码非 0（见 deploy-create.log）"
has "$CFG" "^PORT=443$" && ok "--reinstall 建节点默认端口是 443" || bad "--reinstall 建节点默认端口不是 443"
has "$UNIT" "0.0.0.0:443" && ok "服务文件监听 443" || bad "服务文件端口不对"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "--reinstall 建节点后服务 active" || bad "--reinstall 建节点后服务不是 active"
PSK1="$(cat "$TEST_ROOT/etc/mmx/psk")"
printf '%s' "$PSK1" | grep -Eq '^[0-9a-f]{64}$' && ok "密钥文件是 64 位十六进制" || bad "密钥文件格式不对"
CFG1="$(cat "$CFG")"

note "测试2：已安装时再跑脚本（不传 --port，不加 --reinstall），配置原样保留"
bash "$SRC_DIR/install-mm-x-server.sh" < /dev/null > "$TEST_ROOT/deploy-rerun.log" 2>&1
[ "$?" = 0 ] && ok "再跑脚本退出码 0" || bad "再跑脚本退出码非 0（见 deploy-rerun.log）"
grep -q "只更新程序文件" "$TEST_ROOT/deploy-rerun.log" && ok "再跑时提示只更新程序文件" || bad "再跑时没提示只更新程序"
grep -q "更新完成" "$TEST_ROOT/deploy-rerun.log" && ok "再跑完成提示是“更新完成”（不是“安装完成”）" || bad "再跑完成提示不对"
[ "$(cat "$CFG")" = "$CFG1" ] && ok "再跑后配置文件一字未动" || bad "再跑后配置文件被改了"
[ "$(cat "$TEST_ROOT/etc/mmx/psk")" = "$PSK1" ] && ok "再跑后密钥未变" || bad "再跑后密钥被换了"
has "$UNIT" "0.0.0.0:443" && ok "再跑后服务文件仍监听 443" || bad "再跑后服务文件端口变了"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "再跑后服务仍 active" || bad "再跑后服务停了"

note "测试3：已安装时再跑脚本，传 --port 19999 也不改端口（安装参数被忽略）"
bash "$SRC_DIR/install-mm-x-server.sh" --port 19999 --rate 100K --traffic-quota 1T < /dev/null > "$TEST_ROOT/deploy-rerun2.log" 2>&1
[ "$?" = 0 ] && ok "带参数再跑退出码 0" || bad "带参数再跑退出码非 0（见 deploy-rerun2.log）"
[ "$(cat "$CFG")" = "$CFG1" ] && ok "带参数再跑后配置文件仍一字未动" || bad "带参数再跑后配置文件被改了"
has "$CFG" "^PORT=443$" && has "$CFG" "^RATE=0$" && ok "带参数再跑后端口仍是 443、限速仍是 0" || bad "带参数再跑后端口/限速被改了"
[ "$(cat "$TEST_ROOT/etc/mmx/psk")" = "$PSK1" ] && ok "带参数再跑后密钥未变" || bad "带参数再跑后密钥被换了"

note "测试3b：已安装时再跑脚本传 --domain 也不改 TLS（安装参数被忽略）"
bash "$SRC_DIR/install-mm-x-server.sh" --domain good.example < /dev/null > "$TEST_ROOT/deploy-rerun3.log" 2>&1
[ "$?" = 0 ] && ok "带 --domain 再跑退出码 0" || bad "带 --domain 再跑退出码非 0（见 deploy-rerun3.log）"
grep -q "已忽略 --domain" "$TEST_ROOT/deploy-rerun3.log" && ok "带 --domain 再跑时提示已忽略 --domain" || bad "带 --domain 再跑时没提示忽略"
[ "$(cat "$CFG")" = "$CFG1" ] && ok "带 --domain 再跑后配置文件仍一字未动" || bad "带 --domain 再跑后配置文件被改了"
has "$CFG" "^TLS_AUTO=0$" && ! grep -q "tls-domain" "$UNIT" && ok "带 --domain 再跑后 TLS 仍是关的" || bad "带 --domain 再跑后 TLS 被改了"

note "测试4：加 --reinstall 再跑，才按新参数重写配置（密钥仍保留）"
bash "$SRC_DIR/install-mm-x-server.sh" --reinstall --port 8443 --rate 100K --name 测试节点 < /dev/null > "$TEST_ROOT/deploy-reinstall.log" 2>&1
[ "$?" = 0 ] && ok "--reinstall 退出码 0" || bad "--reinstall 退出码非 0（见 deploy-reinstall.log）"
has "$CFG" "^PORT=8443$" && has "$CFG" "^RATE=100K$" && has "$UNIT" "0.0.0.0:8443" && ok "--reinstall 后端口/限速已按新参数重写" || bad "--reinstall 后配置没按新参数重写"
[ "$(cat "$TEST_ROOT/etc/mmx/psk")" = "$PSK1" ] && ok "--reinstall 后密钥仍保留" || bad "--reinstall 后密钥被换了"
[ "$(cat "$TEST_ROOT/svc-state")" = "active" ] && ok "--reinstall 后服务仍 active" || bad "--reinstall 后服务停了"

note "测试5：--help 提到默认 443 和 --reinstall"
bash "$SRC_DIR/install-mm-x-server.sh" --help 2>&1 | grep -q "默认 443" && ok "--help 说默认 443" || bad "--help 没说默认 443"
bash "$SRC_DIR/install-mm-x-server.sh" --help 2>&1 | grep -q "reinstall" && ok "--help 有 --reinstall 说明" || bad "--help 没提 --reinstall"

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" = 0 ] && echo "再跑不重置测试全部通过" || echo "有 $fail 项失败，见上文"
exit "$([ "$fail" = 0 ] && echo 0 || echo 1)"
