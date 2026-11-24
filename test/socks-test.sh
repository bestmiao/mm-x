#!/bin/bash
# MM-1 客户端 SOCKS5 模式验证（MM 0.1.13 集成用）：
# mm1-server + mm1-client --socks-listen，curl 经 SOCKS5 访问本地 HTTP 目标。
# 用法：bash test/socks-test.sh
# 不动 run-tests.sh 的固定目标模式；只测新增的 SOCKS5 模式。
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
LOG="$ROOT/test/socks-results.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

GO=~/workspace/_build/go/bin/go
PSK_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
HTTP_PORT=18182
SRV_PORT=18181
SOCKS_PORT=18180

pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
note() { echo "--- $1"; }

cleanup() { kill $HTTP_PID $SRV_PID $CLI_PID 2>/dev/null; }
trap cleanup EXIT

note "编译"
$GO build -o mm1-server ./cmd/mm1-server && $GO build -o mm1-client ./cmd/mm1-client || { echo "编译失败"; exit 1; }
ok "编译通过"

note "启动本地 HTTP 目标服务（$HTTP_PORT，双栈监听：curl 会把 localhost 解析成 ::1）"
cd "$ROOT/test/www" || exit 1
python3 -c "from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler; ThreadingHTTPServer.address_family=__import__('socket').AF_INET6; ThreadingHTTPServer(('::', $HTTP_PORT), SimpleHTTPRequestHandler).serve_forever()" >/dev/null 2>&1 &
HTTP_PID=$!
cd "$ROOT" || exit 1
sleep 1
if curl -s --max-time 3 "http://127.0.0.1:$HTTP_PORT/" | grep -q "Hello MM-1"; then ok "本地 HTTP 服务正常"; else bad "本地 HTTP 服务不正常"; fi

note "启动 mm1-server（固定 psk）"
./mm1-server --listen 127.0.0.1:$SRV_PORT --psk "$PSK_HEX" --block-fails 100 --name "测试节点" --allow-private > test/server-socks.log 2>&1 &
SRV_PID=$!
sleep 1
LINK=$(./mm1-server --print-link --psk "$PSK_HEX" --host 127.0.0.1 --listen 127.0.0.1:$SRV_PORT --name "测试节点" 2>/dev/null)
if [ -n "$LINK" ]; then ok "用 --print-link 拿到 mm:// 链接"; else bad "--print-link 没拿到链接"; fi
if grep -q "mm://" test/server-socks.log; then bad "启动日志里不应出现 mm:// 链接"; else ok "启动日志里没有 mm:// 链接"; fi

note "启动 mm1-client（SOCKS5 模式）"
./mm1-client --link "$LINK" --socks-listen 127.0.0.1:$SOCKS_PORT > test/client-socks.log 2>&1 &
CLI_PID=$!
sleep 1
if grep -q "SOCKS5 模式" test/client-socks.log; then ok "客户端以 SOCKS5 模式启动"; else bad "客户端没进 SOCKS5 模式"; fi

note "测试1：curl 经 SOCKS5（IP 目标）拿本地页面"
if env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:$SOCKS_PORT "http://127.0.0.1:$HTTP_PORT/" | grep -q "Hello MM-1"; then
  ok "经 SOCKS5 + MM-1 拿到正确内容（IP 目标）"
else
  bad "经 SOCKS5 + MM-1 拿不到内容（IP 目标）"
fi
# 防绕过断言：客户端日志里必须有这条连接的接通记录，否则 curl 可能直连了目标、根本没走代理
if grep -q "已接通 127.0.0.1:$HTTP_PORT" test/client-socks.log; then
  ok "客户端日志有接通记录（流量确实走了 MM-1，不是直连）"
else
  bad "客户端日志里没有接通记录（curl 可能绕过了代理直连）"
fi

note "测试2：curl 经 SOCKS5（域名目标 localhost）拿本地页面"
if env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:$SOCKS_PORT "http://localhost:$HTTP_PORT/" | grep -q "Hello MM-1"; then
  ok "经 SOCKS5 + MM-1 拿到正确内容（域名目标）"
else
  bad "经 SOCKS5 + MM-1 拿不到内容（域名目标）"
fi

note "测试3：目标拒绝连接时，SOCKS5 应回错误、不卡死（10MB 不存在的端口）"
if env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:$SOCKS_PORT "http://127.0.0.1:19999/" >/dev/null 2>&1; then
  bad "目标不存在时 curl 居然成功了"
else
  ok "目标不存在时 curl 失败、客户端没卡死（退出码非 0）"
fi
# 失败后客户端仍能服务好请求
if env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:$SOCKS_PORT "http://127.0.0.1:$HTTP_PORT/" | grep -q "Hello MM-1"; then
  ok "一次失败后 SOCKS5 仍正常服务"
else
  bad "一次失败后 SOCKS5 不能服务了"
fi

note "测试4：错误密钥的链接，SOCKS5 应拒绝、不卡死"
./mm1-client --link "mm://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:$SRV_PORT?enc=aes-256-gcm&obfs=tls-fake&ver=1#错密钥" --socks-listen 127.0.0.1:18189 > test/client-socks-badkey.log 2>&1 &
BAD_PID=$!
sleep 1
if env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:18189 "http://127.0.0.1:$HTTP_PORT/" >/dev/null 2>&1; then
  bad "错误密钥居然连通了"
else
  ok "错误密钥被拒绝"
fi
kill $BAD_PID 2>/dev/null

note "测试5：域名链接（服务端地址是 localhost 域名，不是 IP）也能连通"
./mm1-server --listen 127.0.0.1:18191 --psk "$PSK_HEX" --block-fails 100 --host localhost --name "域名节点" --allow-private > test/server-socks-domain.log 2>&1 &
DSRV_PID=$!
sleep 1
DLINK=$(./mm1-server --print-link --psk "$PSK_HEX" --host localhost --listen 127.0.0.1:18191 --name "域名节点" 2>/dev/null)
if echo "$DLINK" | grep -q "@localhost:"; then ok "--print-link 拿到域名 mm:// 链接"; else bad "--print-link 没拿到域名链接"; fi
./mm1-client --link "$DLINK" --socks-listen 127.0.0.1:18192 > test/client-socks-domain.log 2>&1 &
DCLI_PID=$!
sleep 1
if env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:18192 "http://127.0.0.1:$HTTP_PORT/" | grep -q "Hello MM-1"; then
  ok "域名链接经 SOCKS5 + MM-1 拿到正确内容"
else
  bad "域名链接经 SOCKS5 + MM-1 拿不到内容"
fi
kill $DCLI_PID $DSRV_PID 2>/dev/null

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" -eq 0 ] && echo "全部通过" || echo "有失败项，见上文"
exit "$fail"
