#!/bin/bash
# MM-1 v3 VPS 部署验证：UDP 数据面真测（沙箱里 UDP 不通，只能在 VPS 上跑）。
# 在 VPS 上用（/tmp/mm1-v3/ 里放好新版 mm1-client-linux-amd64 和本脚本）：
#   MM1_V3_LINK="$(mm --show-link)" bash test/udp-test.sh
# 或直接把链接存在文件里：
#   MM1_V3_LINK_FILE=/tmp/mm1-v3/v3-link.txt bash test/udp-test.sh
# 链接只从环境/文件读，绝不打印。
# 验证：① UDP 回显经隧道往返；② 真 DNS 查询 8.8.8.8:53 经隧道拿到应答；
#      ③ 20 条并行 TCP 流只用 1 次 v3 握手（复用）。
# 退出码 0 = 全过，1 = 有失败。
set -u
cd "$(dirname "$0")/.." || exit 1

# UDP 测试工具：优先用预编译的 socks-udp-test（VPS 上一般没装 Go），
# 没有才现场 go run 编译。
UDP_TEST="${UDP_TEST_BIN:-./dist/socks-udp-test}"
if [ ! -x "$UDP_TEST" ]; then
  GO="${GO:-go}"
  command -v "$GO" >/dev/null 2>&1 || GO=/usr/local/go/bin/go
  if command -v "$GO" >/dev/null 2>&1; then
    UDP_TEST="$GO run ./test/socks-udp-test"
  else
    echo "找不到 socks-udp-test（预编译的在 dist/ 里）也没装 Go，跑不了 UDP 测试"
    exit 1
  fi
fi

CLIENT="${MM1_CLIENT:-./mm1-client-linux-amd64}"
[ -x "$CLIENT" ] || CLIENT="./mm1-client"
[ -x "$CLIENT" ] || { echo "找不到 mm1-client 二进制（放个新版 mm1-client-linux-amd64 在仓库根目录）"; exit 1; }

LINK="${MM1_V3_LINK:-}"
if [ -z "$LINK" ] && [ -n "${MM1_V3_LINK_FILE:-}" ]; then LINK="$(cat "$MM1_V3_LINK_FILE")"; fi
[ -n "$LINK" ] || { echo "没给链接：MM1_V3_LINK=... 或 MM1_V3_LINK_FILE=... 再跑"; exit 1; }

SOCKS_PORT="${SOCKS_PORT:-18135}"
HTTP_PORT="${HTTP_PORT:-18182}"
pass=0; fail=0
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
cleanup() {
  kill $CLI_PID $HTTP_PID 2>/dev/null || true
  wait $CLI_PID $HTTP_PID 2>/dev/null || true
}
trap cleanup EXIT

# 本地 HTTP 目标（复用测试用）
mkdir -p test/www
[ -f test/www/index.html ] || printf 'Hello MM-1! 这是通过 MM-1 协议拿到的数据。\n' > test/www/index.html
python3 -m http.server "$HTTP_PORT" --directory test/www >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

"$CLIENT" --link "$LINK" --socks-listen "127.0.0.1:$SOCKS_PORT" > /tmp/mm1-v3-udp-client.log 2>&1 &
CLI_PID=$!
sleep 2
kill -0 $CLI_PID 2>/dev/null || { echo "mm1-client 启动失败，见 /tmp/mm1-v3-udp-client.log"; exit 1; }

echo "--- ①② UDP：回显 + 真 DNS（8.8.8.8:53）经隧道 ---"
if $UDP_TEST --socks "127.0.0.1:$SOCKS_PORT" --real-dns; then
  ok "UDP 回显 + 真 DNS 查询经隧道通过"
else
  bad "UDP 回显/真 DNS 查询失败"
fi

echo "--- ③ 复用：20 条并行 TCP 流 ---"
rm -f /tmp/mm1-v3-mux.ok
PIDS=""
for i in $(seq 20); do
  env -u no_proxy -u NO_PROXY curl -s --max-time 15 --socks5 "127.0.0.1:$SOCKS_PORT" "http://127.0.0.1:$HTTP_PORT/index.html" | grep -q "Hello MM-1" && echo ok >> /tmp/mm1-v3-mux.ok &
  PIDS="$PIDS $!"
done
for p in $PIDS; do wait $p 2>/dev/null; done
OKN=$(wc -l < /tmp/mm1-v3-mux.ok 2>/dev/null || echo 0)
[ "$OKN" = 20 ] && ok "20 条并行流全通（$OKN/20）" || bad "并行流只通 $OKN/20"

echo "================ 结果 ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" = 0 ]
