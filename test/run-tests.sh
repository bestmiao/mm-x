#!/bin/bash
# mm-x 原型验证脚本：本地跑通加密传输 + 延迟对比 + 大文件校验 + 错误情况 + mmx:// 链接测试
# 用法：bash test/run-tests.sh
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
LOG="$ROOT/test/results.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

GO=~/workspace/_build/go/bin/go
PSK_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
HTTP_PORT=18082
SRV_PORT=18081
CLI_PORT=18080

pass=0; fail=0; skip=0
RSRV_PID=; RCLI_PID=; RCLI2_PID=; BSRV_PID=; BCLI_PID=
BSRV2_PID=; BCLI2_PID=; RSRV2_PID=; RCLI3_PID=; RCLI4_PID=
B14_SRV=; B14_CLI=; B14_SRV0=; B14_CLI0=; B14_SRV3=; B14_CLI3=
SSRF_SRV_PID=
S9_SRV=; S15_SRV=; S15_CLI=; T17_SRV=; T17_CLI=; T19_CLI=; T20_CLI=; T20B_CLI=; T21_SRV=; T21_CLI=; T21_SOCKS=; T22_CLI=; T23_SRV=; T23_CLI=; T24_CLI=
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
skipped() { echo "[SKIP] $1"; skip=$((skip+1)); }
note() { echo "--- $1"; }

cleanup() {
  kill $HTTP_PID $SRV_PID $CLI_PID $CLI2_PID $RSRV_PID $RCLI_PID $RCLI2_PID $BSRV_PID $BCLI_PID $BSRV2_PID $BCLI2_PID $RSRV2_PID $RCLI3_PID $RCLI4_PID $B14_SRV $B14_CLI $B14_SRV0 $B14_CLI0 $B14_SRV3 $B14_CLI3 $S9_SRV $S15_SRV $S15_CLI $T17_SRV $T17_CLI $T19_CLI $T20_CLI $T20B_CLI $T21_SRV $T21_CLI $T21_SOCKS $T22_CLI $T23_SRV $T23_CLI $T24_CLI $SSRF_SRV_PID 2>/dev/null
  # 注意：不要在这里 wait——本脚本的输出经过 tee，wait 会等 tee，
  # 而 tee 在等脚本退出，造成死锁。
}
trap cleanup EXIT

note "编译"
$GO build -o mmx-server ./cmd/mmx-server && $GO build -o mmx-client ./cmd/mmx-client || { echo "编译失败"; exit 1; }
ok "编译通过"

note "准备本地 HTTP 目标服务（$HTTP_PORT）"
mkdir -p test/www
printf 'Hello mm-x! 这是通过 mm-x 协议拿到的数据。\n' > test/www/index.html
python3 -c "import random; random.seed(42); open('test/www/big10m.bin','wb').write(bytes(random.getrandbits(8) for _ in range(10*1024*1024)))"
SHA_DIRECT=$(sha256sum test/www/big10m.bin | awk '{print $1}')
echo "10MB 文件直连 SHA256: $SHA_DIRECT"
python3 -c "import random; random.seed(43); open('test/www/one1m.bin','wb').write(bytes(random.getrandbits(8) for _ in range(1024*1024)))"
SHA_1M=$(sha256sum test/www/one1m.bin | awk '{print $1}')
echo "1MB 文件直连 SHA256: $SHA_1M"
cd test/www && python3 -m http.server $HTTP_PORT --bind 127.0.0.1 >/dev/null 2>&1 &
HTTP_PID=$!
cd "$ROOT"
sleep 1
curl -s --max-time 5 "http://127.0.0.1:$HTTP_PORT/index.html" | grep -q "Hello mm-x" && ok "本地 HTTP 服务正常" || bad "本地 HTTP 服务不正常"

note "启动 mmx-server（固定 psk），抓取它打印的 mmx:// 链接"
# 注意：主服务端用 --block-fails 100（宽松阈值），因为测试 5/8/9 会故意
# 从 127.0.0.1 制造多次握手失败来验证错误处理；默认的严格规则
#（1 分钟 5 次失败拉黑 10 分钟）在专用的测试 12 里验证。
# 测试服务都加 --allow-private：测试目标全是本机地址（127.0.0.1），
# 默认的目标过滤（只许公网）会把它们全拦掉；目标过滤本身由
# 专用的 SSRF 测试（测试5补2）和 target_test.go 单独验证。
./mmx-server --listen 127.0.0.1:$SRV_PORT --psk "$PSK_HEX" --block-fails 100 --allow-private --name "测试节点" > test/server.log 2>&1 &
SRV_PID=$!
sleep 1
# 链接不再从启动日志里抓：启动时不打印链接了（P2-11，密钥不进日志），
# 用 --print-link 单独取（短格式链接，顺带验证短格式解析）。
LINK=$(./mmx-server --print-link --psk "$PSK_HEX" --host 127.0.0.1 --listen 127.0.0.1:$SRV_PORT --name "测试节点" 2>/dev/null)
[ -n "$LINK" ] && ok "用 --print-link 拿到 mmx:// 链接" || bad "--print-link 没拿到链接"
if grep -q "mmx://" test/server.log; then bad "启动日志里不应出现 mmx:// 链接（P2-11：密钥不进日志）"; else ok "启动日志里没有 mmx:// 链接"; fi

note "测试11：BBR 默认开启（开不了也只记警告，不影响启动）"
grep "BBR" test/server.log | head -2
if grep -q "BBR 已开启" test/server.log; then ok "服务端启动日志有 BBR 已开启的记录";
elif grep -q "BBR" test/server.log; then skipped "BBR 开启路径未验证：沙箱内核不支持 BBR（可用算法只有 reno/cubic），只验证了开不了也不影响启动（服务端已正常启动并服务）";
else bad "服务端启动日志里没有 BBR 相关记录"; fi

note "启动 mmx-client，用链接连接，目标为本地 HTTP 服务"
./mmx-client --link "$LINK" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:$CLI_PORT > test/client.log 2>&1 &
CLI_PID=$!
sleep 1

note "测试1：经 mm-x curl 本地页面，内容正确"
BODY_VIA=$(curl -s --max-time 10 "http://127.0.0.1:$CLI_PORT/index.html")
BODY_DIRECT=$(curl -s --max-time 5 "http://127.0.0.1:$HTTP_PORT/index.html")
if [ "$BODY_VIA" = "$BODY_DIRECT" ] && [ -n "$BODY_VIA" ]; then ok "经 mm-x 拿到正确内容：$BODY_VIA"; else bad "内容不一致或为空（via=[$BODY_VIA] direct=[$BODY_DIRECT]）"; fi

note "测试2：延迟对比，各测 10 次（直连 vs 走 mm-x）"
measure() { # $1=url $2=n -> 平均秒
  local url=$1 n=$2 sum=0 ok_n=0
  for _ in $(seq 1 "$n"); do
    t=$(curl -s -o /dev/null --max-time 10 -w "%{time_total}" "$url") || t=""
    if [ -n "$t" ]; then sum=$(awk "BEGIN{print $sum+$t}"); ok_n=$((ok_n+1)); fi
  done
  echo "$ok_n $sum"
}
read -r DN DSUM <<< "$(measure "http://127.0.0.1:$HTTP_PORT/index.html" 10)"
read -r VN VSUM <<< "$(measure "http://127.0.0.1:$CLI_PORT/index.html" 10)"
AVG_D=$(awk "BEGIN{printf \"%.4f\", $DSUM/$DN}")
AVG_V=$(awk "BEGIN{printf \"%.4f\", $VSUM/$VN}")
echo "直连：成功 $DN/10，平均 ${AVG_D}s；走 mm-x：成功 $VN/10，平均 ${AVG_V}s；额外开销约 $(awk "BEGIN{printf \"%.4f\", $AVG_V-$AVG_D}")s"
[ "$DN" = 10 ] && [ "$VN" = 10 ] && ok "延迟测试 10/10 成功" || bad "延迟测试有失败（直连 $DN/10，mm-x $VN/10）"

note "测试3：经 mm-x 传 10MB，哈希校验"
curl -s --max-time 60 -o test/big10m-via.bin "http://127.0.0.1:$CLI_PORT/big10m.bin"
SHA_VIA=$(sha256sum test/big10m-via.bin | awk '{print $1}')
echo "经 mm-x 的 SHA256: $SHA_VIA"
[ "$SHA_VIA" = "$SHA_DIRECT" ] && ok "10MB 哈希一致，不断流" || bad "10MB 哈希不一致"

note "测试4：真实外网目标（经 mm-x 访问 example.com）"
# 说明：沙箱会拦截直连外网的 TCP，所以这里让 mm-x 转发到沙箱出口代理
# 198.19.0.1:3128，用绝对地址的 HTTP 请求拿到真实外网内容。
# 在真实 VPS 上没有这层拦截，直接 --target example.com:80 即可。
# 如果这项失败，先看直连出口代理通不通：直连也不通 = 沙箱外网受限，
# 记为 SKIP（未验证），不算 FAIL；直连通但走 mm-x 不通 = 真 FAIL。
./mmx-client --link "$LINK" --target 198.19.0.1:3128 --listen 127.0.0.1:18083 > test/client2.log 2>&1 &
CLI2_PID=$!
sleep 1
if python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 18083), timeout=15)
s.sendall(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
s.settimeout(15)
data = b''
try:
    while True:
        c = s.recv(65536)
        if not c: break
        data += c
except socket.timeout:
    pass
raise SystemExit(0 if b'Example Domain' in data else 1)
"; then ok "经 mm-x 访问到真实外网 example.com（经出口代理）";
elif curl -s --max-time 10 -x http://198.19.0.1:3128 -o /dev/null http://example.com/; then bad "经 mm-x 访问 example.com 失败（直连出口代理正常，见 client2.log）";
else skipped "经 mm-x 访问 example.com 未验证：沙箱外网受限（直连出口代理也不通）"; fi

note "测试5：错误情况——魔数不对 / 版本不对 / 密钥不对，服务端应拒绝"
err_case() { # $1=名字 $2=客户端参数 $3=期望日志关键字 $4=监听端口 $5=服务端日志关键字 $6=链接（默认 $LINK）
  local link="${6:-$LINK}"
  ./mmx-client --link "$link" --target 127.0.0.1:$HTTP_PORT --listen "127.0.0.1:$4" "$2" > "test/err-$1.log" 2>&1 &
  local pid=$!
  sleep 1
  curl -s --max-time 5 "http://127.0.0.1:$4/index.html" >/dev/null 2>&1
  local code=$?
  sleep 1
  kill $pid 2>/dev/null
  if [ "$code" != 0 ] && grep -q "$3" "test/err-$1.log"; then ok "$1：连接失败且客户端报错含[$3]（curl 退出码 $code）";
  else bad "$1：未按预期失败（curl 退出码 $code，日志见 test/err-$1.log）"; fi
  grep -q "$5" test/server.log && ok "$1：服务端日志有[$5]记录" || bad "$1：服务端日志无[$5]记录"
}
err_case bad-magic --bad-magic 握手失败 18084 握手失败
err_case bad-version --bad-version 握手失败 18085 握手失败
# bad-key 用 v2 链接：v2 是 CONNECT+ACK 路径，篡改密钥后服务端解密失败；
# v4 是 yamux 会话，篡改密钥后整个会话直接死掉（见下面的 v4 检查），不是 ACK 失败。
LINK_V2_ERR=$(echo "$LINK" | sed 's/ver=4/ver=2/')
err_case bad-key --bad-key "等待服务端 ACK 失败" 18086 "解密失败" "$LINK_V2_ERR"
# v4 bad-key：篡改密钥后 yamux 会话建不起来，服务端会话直接结束。
BEFORE_BKV3=$(grep -c "v3/v4 会话结束" test/server.log || true)
./mmx-client --link "$LINK" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18087 --bad-key > test/err-bad-key-v4.log 2>&1 &
BADKEY_V3_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18087/index.html" >/dev/null 2>&1
V3BK_CODE=$?
sleep 1
kill $BADKEY_V3_PID 2>/dev/null
AFTER_BKV3=$(grep -c "v3/v4 会话结束" test/server.log || true)
if [ "$V3BK_CODE" != 0 ] && [ "$AFTER_BKV3" -gt "$BEFORE_BKV3" ]; then ok "v4 bad-key：连接失败且服务端 v3/v4 会话结束（篡改密钥后会话建不起来）";
else bad "v4 bad-key 未按预期失败（curl 退出码 $V3BK_CODE，服务端 v3/v4 会话结束 $BEFORE_BKV3 → $AFTER_BKV3）"; fi

note "测试5补：错误测试后服务端仍可用（好客户端再连一次）"
curl -s --max-time 10 "http://127.0.0.1:$CLI_PORT/index.html" | grep -q "Hello mm-x" && ok "错误测试后服务端仍正常服务" || bad "错误测试后服务端异常"

note "测试5补2：目标过滤——内网目标应被拒绝（SSRF 防护，P0-2）"
# 这个服务端故意不加 --allow-private（默认只许公网目标）：
# 客户端要去的目标是本机 HTTP 服务（127.0.0.1），应被拒绝。
# v4 和 v2 两条拨号路径都测（v2 链接把 ver=4 改成 ver=2）。
./mmx-server --listen 127.0.0.1:18140 --psk "$PSK_HEX" --block-fails 100 --name "SSRF测试" > test/server-ssrf.log 2>&1 &
SSRF_SRV_PID=$!
sleep 1
SSRF_LINK=$(./mmx-server --print-link --psk "$PSK_HEX" --host 127.0.0.1 --listen 127.0.0.1:18140 --name "SSRF测试" 2>/dev/null)
ssrf_case() { # $1=名字 $2=链接 $3=监听端口 $4=客户端日志
  ./mmx-client --link "$2" --target 127.0.0.1:$HTTP_PORT --listen "127.0.0.1:$3" > "$4" 2>&1 &
  local pid=$!
  sleep 1
  curl -s --max-time 5 "http://127.0.0.1:$3/index.html" >/dev/null 2>&1
  local code=$?
  sleep 1
  kill $pid 2>/dev/null
  if [ "$code" != 0 ] && grep -q "目标不允许" "$4"; then ok "$1：内网目标被拒绝，客户端报错含[目标不允许]"; else bad "$1：内网目标未被拒绝（curl 退出码 $code，日志见 $4）"; fi
}
ssrf_case "SSRF-v4" "$SSRF_LINK" 18141 test/client-ssrf-v4.log
SSRF_LINK_V2=$(echo "$SSRF_LINK" | sed 's/ver=4/ver=2/')
ssrf_case "SSRF-v2" "$SSRF_LINK_V2" 18142 test/client-ssrf-v2.log
grep -q "目标不允许" test/server-ssrf.log && ok "SSRF：服务端日志有[目标不允许]记录" || bad "SSRF：服务端日志无[目标不允许]记录"
kill $SSRF_SRV_PID 2>/dev/null; SSRF_SRV_PID=""

note "测试6：中途断开服务端，客户端不卡死"
curl -s --max-time 3 --limit-rate 100k "http://127.0.0.1:$CLI_PORT/big10m.bin" -o /dev/null &
CURL_PID=$!
sleep 1
kill $SRV_PID 2>/dev/null; SRV_PID=""
sleep 1
START=$(date +%s)
wait $CURL_PID 2>/dev/null; CURL_CODE=$?
ELAPSED=$(( $(date +%s) - START ))
echo "服务端断开后 curl 退出码 $CURL_CODE，等待耗时约 ${ELAPSED}s"
[ "$CURL_CODE" != 0 ] && [ "$ELAPSED" -lt 15 ] && ok "服务端断开后客户端报错、不卡死" || bad "服务端断开后表现异常（退出码 $CURL_CODE，耗时 ${ELAPSED}s）"
# 重启服务端，供后续测试使用（同样用宽松拉黑阈值，原因见上）
./mmx-server --listen 127.0.0.1:$SRV_PORT --psk "$PSK_HEX" --block-fails 100 --name "测试节点" --allow-private > test/server2.log 2>&1 &
SRV_PID=$!
sleep 1

note "测试7：非法 mmx:// 链接报错"
bad_link() { # $1=名字 $2=链接 $3=期望关键字
  if ./mmx-client --link "$2" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18087 >test/badlink-$1.log 2>&1; then
    bad "$1：非法链接竟然启动成功"
  elif grep -q "$3" test/badlink-$1.log; then ok "$1：明确报错含[$3]";
  else bad "$1：报错信息不对（见 test/badlink-$1.log）"; fi
}
bad_link no-prefix "vless://abc@127.0.0.1:18081" "mmx://"
bad_link no-key "mmx://@127.0.0.1:18081" "缺少密钥"
bad_link bad-port "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:99999" "端口不合法"
bad_link no-port "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1" "缺少端口"
bad_link short-key "mmx://aGVsbG8@127.0.0.1:18081" "密钥长度不对"
bad_link bad-enc "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:18081?enc=aes-128-gcm" "不支持的加密方式"
bad_link bad-ver "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:18081?ver=9" "版本号不受支持"
bad_link old-ver "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:18081?ver=1" "版本号不受支持"
bad_link bad-obfs "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:18081?obfs=foo" "不支持的混淆方式"
bad_link no-host "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@:18081" "缺少服务器地址"
bad_link bad-burst "mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@127.0.0.1:18081?burst=xyz" "突发参数不合法"

note "测试8：UUID 形式的密钥也能用"
UUID_LINK="mmx://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:18081?enc=aes-256-gcm&obfs=tls-fake&ver=2#UUID节点"
./mmx-client --link "$UUID_LINK" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18088 > test/client-uuid.log 2>&1 &
UUID_PID=$!
sleep 1
# 该 UUID 派生的密钥与服务端 psk 不同，应握手失败（说明解析走了 UUID 分支且鉴权生效）
curl -s --max-time 5 "http://127.0.0.1:18088/index.html" >/dev/null 2>&1
[ "$?" != 0 ] && grep -q "握手失败" test/client-uuid.log && ok "UUID 链接被解析、密钥不同则握手失败（鉴权生效）" || bad "UUID 链接测试异常"
kill $UUID_PID 2>/dev/null

note "测试9：防主动探测——诱饵回退（默认 site）：HTTP 拿到像网站的页面，TLS 握手/随机字节拿到 400 页"
# 预期：三种探测都收不到任何能暴露 mm-x 的内容（页面里没有 mm-x/mmx:// 字样），
# 且探测后服务端仍能正常服务好客户端；silent 模式则 0 字节回包。
python3 - <<'PYEOF'
import os, socket, sys
def probe(payload):
    s = socket.create_connection(('127.0.0.1', 18081), timeout=5)
    s.sendall(payload)
    s.settimeout(3)
    data = b''
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    s.close()
    return data
results = {}
results['明文HTTP'] = probe(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
results['随机字节'] = probe(os.urandom(64))
# 手工拼一个 TLS ClientHello 记录（0x16 0x03 0x01 + 长度 + 32 字节体）：
# 服务端读到记录头后验魔数失败，按诱饵规则回 400 页。
results['TLS握手'] = probe(b'\x16\x03\x01\x00\x20' + os.urandom(32))
ok = True
http_resp = results['明文HTTP']
print(f"探测[明文HTTP]：服务端回包 {len(http_resp)} 字节")
if b'200 OK' not in http_resp or '我的小站'.encode() not in http_resp:
    print('探测[明文HTTP]异常：应回 200 + 诱饵页')
    ok = False
if b'mm-x' in http_resp or b'mmx://' in http_resp:
    print('探测[明文HTTP]泄露了 mm-x 信息')
    ok = False
for label in ('随机字节', 'TLS握手'):
    d = results[label]
    print(f'探测[{label}]：服务端回包 {len(d)} 字节')
    if b'400 Bad Request' not in d:
        print(f'探测[{label}]异常：应回 400 页')
        ok = False
    if b'mm-x' in d or b'mmx://' in d:
        print(f'探测[{label}]泄露了 mm-x 信息')
        ok = False
sys.exit(0 if ok else 1)
PYEOF
if [ "$?" = 0 ]; then ok "三种探测均只拿到像网站的内容（HTTP 200 诱饵页 / 其余 400 页），不暴露 mm-x"; else bad "探测时服务端回包异常（见上文）"; fi
grep -c "握手失败" test/server2.log | awk '{print "服务端日志握手失败记录数：" $1}'
[ "$(grep -c "握手失败" test/server2.log)" -ge 3 ] && ok "服务端日志记下 3 次探测拒绝" || bad "服务端日志里探测拒绝记录不足 3 条"
curl -s --max-time 10 "http://127.0.0.1:$CLI_PORT/index.html" | grep -q "Hello mm-x" && ok "探测后服务端仍正常服务" || bad "探测后服务端异常"
# silent 模式：同样的三种探测都应 0 字节回包
./mmx-server --listen 127.0.0.1:18114 --psk "$PSK_HEX" --block-fails 100 --fallback silent --name "静默测试" --allow-private > test/server-silent.log 2>&1 &
S9_SRV=$!
sleep 1
python3 - <<'PYEOF'
import os, socket, sys
def probe(payload):
    s = socket.create_connection(('127.0.0.1', 18114), timeout=5)
    s.sendall(payload)
    s.settimeout(3)
    data = b''
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    s.close()
    return data
leak = False
for label, p in (('明文HTTP', b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'),
                 ('随机字节', os.urandom(64)),
                 ('TLS握手', b'\x16\x03\x01\x00\x20' + os.urandom(32))):
    d = probe(p)
    print(f'silent 探测[{label}]：服务端回包 {len(d)} 字节')
    if len(d) > 0:
        leak = True
sys.exit(1 if leak else 0)
PYEOF
[ "$?" = 0 ] && ok "silent 模式下三种探测均 0 字节回包" || bad "silent 模式下探测有回包"
kill $S9_SRV 2>/dev/null; S9_SRV=

note "测试10：限速（令牌桶，双向，服务端取 min 后执行）"
# 注意：限速服务端都显式加 --burst 0（不许突发），因为默认突发 5MB
# 会让 1MB 直接走突发通道、测不出平均限速；严格限速的预期
#（1MB 约 10 秒）只在 burst=0 时成立。突发行为单独在测试 14 验证。
# 10a：服务端 --rate 100K --burst 0，链接也带 rate=100K&burst=0
#（服务端打印的链接自带），传 1MB 应约 10 秒（>5s），数据完整不断流
./mmx-server --listen 127.0.0.1:18091 --psk "$PSK_HEX" --rate 100K --burst 0 --name "限速节点" --allow-private > test/server-rate.log 2>&1 &
RSRV_PID=$!
sleep 1
LINK91=$(./mmx-server --print-link --listen 127.0.0.1:18091 --psk "$PSK_HEX" --rate 100K --burst 0 --name "限速节点" 2>/dev/null)
echo "限速服务端链接：$LINK91"
./mmx-client --link "$LINK91" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18090 > test/client-rate.log 2>&1 &
RCLI_PID=$!
sleep 1
T10A=$(curl -s --max-time 60 -o test/one1m-via-rate.bin -w "%{time_total}" "http://127.0.0.1:18090/one1m.bin")
SHA_10A=$(sha256sum test/one1m-via-rate.bin | awk '{print $1}')
echo "限速 100K 传 1MB 耗时 ${T10A}s，SHA256: $SHA_10A"
if [ "$SHA_10A" = "$SHA_1M" ] && awk "BEGIN{exit !($T10A > 5)}"; then ok "限速 100K：1MB 耗时 ${T10A}s（>5s），数据完整不断流"; else bad "限速 100K 表现异常（耗时 ${T10A}s，SHA 对得上：$([ "$SHA_10A" = "$SHA_1M" ] && echo 是 || echo 否)）"; fi
# 10b：链接要求 1M，但服务端上限 100K——服务端说了算，仍应约 10 秒（>5s）
LINK1M=$(echo "$LINK91" | sed 's/rate=100K/rate=1M/')
./mmx-client --link "$LINK1M" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18094 > test/client-rate1m.log 2>&1 &
RCLI2_PID=$!
sleep 1
T10B=$(curl -s --max-time 60 -o test/one1m-via-rate1m.bin -w "%{time_total}" "http://127.0.0.1:18094/one1m.bin")
SHA_10B=$(sha256sum test/one1m-via-rate1m.bin | awk '{print $1}')
echo "服务端 100K + 链接 1M 传 1MB 耗时 ${T10B}s"
if [ "$SHA_10B" = "$SHA_1M" ] && awk "BEGIN{exit !($T10B > 5)}"; then ok "服务端上限获胜：链接要 1M 仍被压到 100K（${T10B}s），数据完整"; else bad "服务端上限未生效（耗时 ${T10B}s，SHA 对得上：$([ "$SHA_10B" = "$SHA_1M" ] && echo 是 || echo 否)）"; fi
kill $RCLI2_PID 2>/dev/null; RCLI2_PID=
# 10c：不限速（服务端 --rate 0 + 链接无 rate），1MB 应很快（<3s），数据完整
./mmx-server --listen 127.0.0.1:18093 --psk "$PSK_HEX" --rate 0 --name "不限速节点" --allow-private > test/server-norate.log 2>&1 &
BSRV_PID=$!
sleep 1
LINK93=$(./mmx-server --print-link --listen 127.0.0.1:18093 --psk "$PSK_HEX" --rate 0 --name "不限速节点" 2>/dev/null)
./mmx-client --link "$LINK93" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18092 > test/client-norate.log 2>&1 &
BCLI_PID=$!
sleep 1
T10C=$(curl -s --max-time 60 -o test/one1m-via-norate.bin -w "%{time_total}" "http://127.0.0.1:18092/one1m.bin")
SHA_10C=$(sha256sum test/one1m-via-norate.bin | awk '{print $1}')
echo "不限速传 1MB 耗时 ${T10C}s"
if [ "$SHA_10C" = "$SHA_1M" ] && awk "BEGIN{exit !($T10C < 3)}"; then ok "不限速：1MB 耗时 ${T10C}s（<3s），速度正常，数据完整"; else bad "不限速表现异常（耗时 ${T10C}s）"; fi
kill $RSRV_PID $RCLI_PID $BSRV_PID $BCLI_PID 2>/dev/null; RSRV_PID=; RCLI_PID=; BSRV_PID=; BCLI_PID=

note "测试12：失败握手拉黑（专用服务端，短时间参数验证默认逻辑）"
# 规则：30 秒内握手失败 5 次就拉黑 8 秒（生产默认是 1 分钟 5 次拉黑 10 分钟，
# 这里用短时间参数验证同一套逻辑）
./mmx-server --listen 127.0.0.1:18095 --psk "$PSK_HEX" --block-fails 5 --block-window 30s --block-duration 8s --name "拉黑测试" --allow-private > test/server-block.log 2>&1 &
BSRV2_PID=$!
sleep 1
LINK95=$(./mmx-server --print-link --listen 127.0.0.1:18095 --psk "$PSK_HEX" --block-fails 5 --block-window 30s --block-duration 8s --name "拉黑测试" 2>/dev/null)
echo "拉黑测试服务端链接：$LINK95"
python3 - <<'PYEOF'
import socket
for _ in range(5):
    s = socket.create_connection(('127.0.0.1', 18095), timeout=5)
    s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
    try:
        s.recv(1024)
    except Exception:
        pass
    s.close()
print('5 次垃圾探测发完（每次都是一次握手失败）')
PYEOF
sleep 1
grep -q "拉黑 IP 127.0.0.1" test/server-block.log && ok "5 次失败后服务端日志有拉黑记录" || bad "5 次失败后服务端无拉黑记录"
./mmx-client --link "$LINK95" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18096 > test/client-block.log 2>&1 &
BCLI2_PID=$!
sleep 1
if curl -s --max-time 5 "http://127.0.0.1:18096/index.html" | grep -q "Hello mm-x"; then bad "拉黑期间好客户端竟然连通了"; else ok "拉黑期间第 6 次连接被直接丢弃（好客户端也连不上）"; fi
kill $BCLI2_PID 2>/dev/null; BCLI2_PID=
sleep 9
./mmx-client --link "$LINK95" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18096 > test/client-block2.log 2>&1 &
BCLI2_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18096/index.html" | grep -q "Hello mm-x" && ok "拉黑到期后自动解除，好客户端恢复连通" || bad "拉黑到期后仍连不上"
kill $BCLI2_PID 2>/dev/null; BCLI2_PID=
kill $BSRV2_PID 2>/dev/null; BSRV2_PID=

note "测试12b：白名单 + 成功即信任（白名单 IP 失败 10 次不拉黑；成功过一次的 IP 之后失败不拉黑）"
# 白名单服务端：127.0.0.1 在白名单里，10 次垃圾探测后好客户端仍能连
./mmx-server --listen 127.0.0.1:18098 --psk "$PSK_HEX" --block-fails 5 --block-window 30s --block-duration 8s --whitelist 127.0.0.1 --name "白名单测试" --allow-private > test/server-wl.log 2>&1 &
WSRV_PID=$!
sleep 1
LINK98=$(./mmx-server --print-link --listen 127.0.0.1:18098 --psk "$PSK_HEX" --block-fails 5 --block-window 30s --block-duration 8s --whitelist 127.0.0.1 --name "白名单测试" 2>/dev/null)
grep -q "白名单（永不拉黑）：127.0.0.1" test/server-wl.log && ok "白名单服务端启动日志里有白名单" || bad "白名单服务端启动日志里没有白名单"
python3 - <<'PYEOF'
import socket
for _ in range(10):
    s = socket.create_connection(('127.0.0.1', 18098), timeout=5)
    s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
    try:
        s.recv(1024)
    except Exception:
        pass
    s.close()
print('10 次垃圾探测发完（白名单 IP）')
PYEOF
sleep 1
grep -q "拉黑 IP 127.0.0.1" test/server-wl.log && bad "白名单 IP 失败 10 次后被拉黑了" || ok "白名单 IP 失败 10 次也没有拉黑记录"
./mmx-client --link "$LINK98" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18099 > test/client-wl.log 2>&1 &
WCLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18099/index.html" | grep -q "Hello mm-x" && ok "白名单 IP 失败 10 次后好客户端仍能连通" || bad "白名单 IP 失败 10 次后好客户端连不上了"
kill $WCLI_PID 2>/dev/null; WCLI_PID=
kill $WSRV_PID 2>/dev/null; WSRV_PID=
# 信任服务端：不设白名单，好客户端先成功连一次，再发 5 次垃圾探测，之后好客户端仍能连
./mmx-server --listen 127.0.0.1:18100 --psk "$PSK_HEX" --block-fails 5 --block-window 30s --block-duration 8s --name "信任测试" --allow-private > test/server-trust.log 2>&1 &
TSRV_PID=$!
sleep 1
LINK100=$(./mmx-server --print-link --listen 127.0.0.1:18100 --psk "$PSK_HEX" --block-fails 5 --block-window 30s --block-duration 8s --name "信任测试" 2>/dev/null)
./mmx-client --link "$LINK100" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18101 > test/client-trust.log 2>&1 &
TCLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18101/index.html" | grep -q "Hello mm-x" && ok "信任测试：首次成功握手连通" || bad "信任测试：首次成功握手没连通"
kill $TCLI_PID 2>/dev/null; TCLI_PID=
python3 - <<'PYEOF'
import socket
for _ in range(5):
    s = socket.create_connection(('127.0.0.1', 18100), timeout=5)
    s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
    try:
        s.recv(1024)
    except Exception:
        pass
    s.close()
print('5 次垃圾探测发完（已成功过的 IP）')
PYEOF
sleep 1
grep -q "拉黑 IP 127.0.0.1" test/server-trust.log && bad "已成功过的 IP 失败 5 次后被拉黑了" || ok "已成功过的 IP 失败 5 次也没有拉黑记录"
./mmx-client --link "$LINK100" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18101 > test/client-trust2.log 2>&1 &
TCLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18101/index.html" | grep -q "Hello mm-x" && ok "已成功过的 IP 失败 5 次后好客户端仍能连通" || bad "已成功过的 IP 失败 5 次后好客户端连不上了"
kill $TCLI_PID 2>/dev/null; TCLI_PID=
kill $TSRV_PID 2>/dev/null; TSRV_PID=

note "测试12c：连接白名单（开了之后白名单外丢弃、白名单内正常连、密钥不对仍拒绝、CIDR 生效）"
# 白名单只放 127.0.0.1：好客户端正常连；错密钥的客户端仍被拒绝（白名单不是代替密钥）
./mmx-server --listen 127.0.0.1:18106 --psk "$PSK_HEX" --allowlist 127.0.0.1 --name "连接白名单测试" --allow-private > test/server-allow.log 2>&1 &
ASRV_PID=$!
sleep 1
LINK106=$(./mmx-server --print-link --listen 127.0.0.1:18106 --psk "$PSK_HEX" --allowlist 127.0.0.1 --name "连接白名单测试" 2>/dev/null)
grep -q "连接白名单（只允许这些 IP 连接）：127.0.0.1" test/server-allow.log && ok "连接白名单服务端启动日志里有白名单" || bad "连接白名单服务端启动日志里没有白名单"
./mmx-client --link "$LINK106" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18107 > test/client-allow.log 2>&1 &
ACLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18107/index.html" | grep -q "Hello mm-x" && ok "白名单内 IP 正常连通" || bad "白名单内 IP 连不上了"
kill $ACLI_PID 2>/dev/null; ACLI_PID=
BADLINK106=$(echo "$LINK106" | sed 's|mmx://[^@]*@|mmx://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@|')
./mmx-client --link "$BADLINK106" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18107 > test/client-allow-badkey.log 2>&1 &
ACLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18107/index.html" | grep -q "Hello mm-x" && bad "白名单内 IP 密钥不对居然连通了" || ok "白名单内 IP 密钥不对仍被拒绝"
grep -q "握手失败" test/server-allow.log && ok "错密钥的握手失败记进了服务端日志" || bad "错密钥的握手失败没记进日志"
kill $ACLI_PID 2>/dev/null; ACLI_PID=
kill $ASRV_PID 2>/dev/null; ASRV_PID=
# 白名单只放 203.0.113.99（不是本机 IP）：本机连上来直接丢弃，0 字节回包
./mmx-server --listen 127.0.0.1:18108 --psk "$PSK_HEX" --allowlist 203.0.113.99 --name "连接白名单拒绝测试" --allow-private > test/server-allow-deny.log 2>&1 &
DSRV_PID=$!
sleep 1
LINK108=$(./mmx-server --print-link --listen 127.0.0.1:18108 --psk "$PSK_HEX" --allowlist 203.0.113.99 --name "连接白名单拒绝测试" 2>/dev/null)
python3 - <<'PYEOF'
import socket
s = socket.create_connection(('127.0.0.1', 18108), timeout=5)
s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
s.settimeout(5)
try:
    data = s.recv(1024)
    n = len(data)
except ConnectionResetError:
    # 服务端没读客户端发来的数据就关连接，内核会发 RST（不是应用层回包）；
    # 收到 RST 也算丢弃：应用层一个字节都没回。
    n = 0
    print('白名单外连接被 RST 丢弃（应用层 0 字节回包）')
print('白名单外连接收到的字节数：', n)
assert n == 0, '白名单外应 0 字节回包'
s.close()
PYEOF
[ $? -eq 0 ] && ok "白名单外 IP 连接被丢弃（0 字节回包）" || bad "白名单外 IP 连接居然有回包"
./mmx-client --link "$LINK108" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18109 > test/client-allow-deny.log 2>&1 &
DCLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18109/index.html" | grep -q "Hello mm-x" && bad "白名单外 IP 的好客户端居然连通了" || ok "白名单外 IP 的好客户端连不上"
kill $DCLI_PID 2>/dev/null; DCLI_PID=
kill $DSRV_PID 2>/dev/null; DSRV_PID=
# CIDR 段 127.0.0.0/8：本机 127.0.0.1 在段内，正常连通
./mmx-server --listen 127.0.0.1:18110 --psk "$PSK_HEX" --allowlist 127.0.0.0/8 --name "连接白名单CIDR测试" --allow-private > test/server-allow-cidr.log 2>&1 &
CSRV_PID=$!
sleep 1
LINK110=$(./mmx-server --print-link --listen 127.0.0.1:18110 --psk "$PSK_HEX" --allowlist 127.0.0.0/8 --name "连接白名单CIDR测试" 2>/dev/null)
./mmx-client --link "$LINK110" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18111 > test/client-allow-cidr.log 2>&1 &
CCLI_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18111/index.html" | grep -q "Hello mm-x" && ok "CIDR 段 127.0.0.0/8 内的 IP 正常连通" || bad "CIDR 段内的 IP 连不上了"
kill $CCLI_PID 2>/dev/null; CCLI_PID=
kill $CSRV_PID 2>/dev/null; CSRV_PID=

note "测试13：密钥轮换（不重启，旧密钥宽限期内能用，过期后拒绝）"
PSK1="$PSK_HEX"
PSK2="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
echo "$PSK1" > test/rotate.psk
./mmx-server --listen 127.0.0.1:18097 --psk-file test/rotate.psk --grace 10s --name "轮换测试" --allow-private > test/server-rotate.log 2>&1 &
RSRV2_PID=$!
sleep 1
LINK97_OLD=$(./mmx-server --print-link --listen 127.0.0.1:18097 --psk-file test/rotate.psk --grace 10s --name "轮换测试" 2>/dev/null)
./mmx-client --link "$LINK97_OLD" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18096 > test/client-rot-old.log 2>&1 &
RCLI3_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18096/index.html" | grep -q "Hello mm-x" && ok "轮换前旧密钥客户端正常" || bad "轮换前旧密钥客户端异常"
echo "$PSK2" > test/rotate.psk
sleep 1
LINK97_NEW=$(./mmx-server --print-link --psk "$PSK2" --host 127.0.0.1 --listen 127.0.0.1:18097 --name "轮换测试")
echo "轮换后新链接：$LINK97_NEW"
curl -s --max-time 5 "http://127.0.0.1:18096/index.html" | grep -q "Hello mm-x" && ok "宽限期内旧密钥仍能用" || bad "宽限期内旧密钥被拒绝"
grep -q "密钥已轮换" test/server-rotate.log && ok "服务端日志有密钥已轮换记录" || bad "服务端日志无轮换记录"
./mmx-client --link "$LINK97_NEW" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18098 > test/client-rot-new.log 2>&1 &
RCLI4_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18098/index.html" | grep -q "Hello mm-x" && ok "新密钥客户端正常" || bad "新密钥客户端异常"
sleep 11
curl -s --max-time 5 "http://127.0.0.1:18096/index.html" | grep -q "Hello mm-x" && bad "宽限期过后旧密钥竟然还能用" || ok "宽限期过后旧密钥被拒绝"
curl -s --max-time 5 "http://127.0.0.1:18098/index.html" | grep -q "Hello mm-x" && ok "宽限期过后新密钥仍正常" || bad "宽限期过后新密钥异常"
kill $RCLI3_PID $RCLI4_PID $RSRV2_PID 2>/dev/null; RCLI3_PID=; RCLI4_PID=; RSRV2_PID=

note "测试14：突发（burst）——平均限速不变，短时间允许冲一把填缓冲"
# 14a：rate=1250K burst=5M 传 10MB：前 5MB 走突发（本地回环几乎不花时间），
# 后 5MB 按 1250K/s（约 1.25MB/s）走约 4 秒，总计应在 3–6.5 秒之间；
# 对照组 burst=0 时 10MB 全程按平均限速走，约 8.2 秒。
# 预期：突发让同样 10MB 快约一半，数据完整。
./mmx-server --listen 127.0.0.1:18101 --psk "$PSK_HEX" --rate 1250K --burst 5M --name "突发测试" --allow-private > test/server-burst.log 2>&1 &
B14_SRV=$!
sleep 1
LINK_BURST=$(./mmx-server --print-link --listen 127.0.0.1:18101 --psk "$PSK_HEX" --rate 1250K --burst 5M --name "突发测试" 2>/dev/null)
echo "突发服务端链接：$LINK_BURST"
echo "$LINK_BURST" | grep -qv "burst=" && ok "短格式链接不带 burst（突发由服务端配置）" || bad "短格式链接不应带 burst：$LINK_BURST"
./mmx-client --link "$LINK_BURST" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18100 > test/client-burst.log 2>&1 &
B14_CLI=$!
sleep 1
T14A=$(curl -s --max-time 60 -o test/big10m-via-burst.bin -w "%{time_total}" "http://127.0.0.1:18100/big10m.bin")
SHA_14A=$(sha256sum test/big10m-via-burst.bin | awk '{print $1}')
echo "burst=5M 传 10MB 耗时 ${T14A}s"
if [ "$SHA_14A" = "$SHA_DIRECT" ] && awk "BEGIN{exit !(($T14A > 3) && ($T14A < 6.5))}"; then ok "突发 5M：10MB 耗时 ${T14A}s（3–6.5s 之间，前 5MB 走突发、后 5MB 回平均限速），数据完整"; else bad "突发 5M 表现异常（耗时 ${T14A}s，SHA 对得上：$([ "$SHA_14A" = "$SHA_DIRECT" ] && echo 是 || echo 否)）"; fi
kill $B14_CLI $B14_SRV 2>/dev/null; B14_CLI=; B14_SRV=
sleep 1
# 14b：burst=0（不许突发），同样 rate=1250K 传 10MB，应全程按平均限速，>7 秒
./mmx-server --listen 127.0.0.1:18103 --psk "$PSK_HEX" --rate 1250K --burst 0 --name "突发测试" --allow-private > test/server-burst0.log 2>&1 &
B14_SRV0=$!
sleep 1
LINK_BURST0=$(./mmx-server --print-link --listen 127.0.0.1:18103 --psk "$PSK_HEX" --rate 1250K --burst 0 --name "突发测试" 2>/dev/null)
./mmx-client --link "$LINK_BURST0" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18102 > test/client-burst0.log 2>&1 &
B14_CLI0=$!
sleep 1
T14B=$(curl -s --max-time 60 -o test/big10m-via-burst0.bin -w "%{time_total}" "http://127.0.0.1:18102/big10m.bin")
SHA_14B=$(sha256sum test/big10m-via-burst0.bin | awk '{print $1}')
echo "burst=0 传 10MB 耗时 ${T14B}s"
if [ "$SHA_14B" = "$SHA_DIRECT" ] && awk "BEGIN{exit !($T14B > 7)}"; then ok "突发 0：10MB 耗时 ${T14B}s（>7s，全程按平均限速），数据完整"; else bad "突发 0 表现异常（耗时 ${T14B}s，SHA 对得上：$([ "$SHA_14B" = "$SHA_DIRECT" ] && echo 是 || echo 否)）"; fi
kill $B14_CLI0 $B14_SRV0 2>/dev/null; B14_CLI0=; B14_SRV0=
sleep 1
# 14c：服务端 --burst 3M，链接要求 burst=8M——取最小，生效 3M：
# 10MB = 前 3MB 走突发 + 后 7MB 按 1250K/s 约 5.6 秒，总计 4.5–7.5 秒
./mmx-server --listen 127.0.0.1:18105 --psk "$PSK_HEX" --rate 1250K --burst 3M --name "突发测试" --allow-private > test/server-burst3.log 2>&1 &
B14_SRV3=$!
sleep 1
LINK_BURST3=$(./mmx-server --print-link --listen 127.0.0.1:18105 --psk "$PSK_HEX" --rate 1250K --burst 3M --name "突发测试" 2>/dev/null)
# 短链接不带 burst：客户端默认 5M，服务端仍压到 3M，测的还是“取最小”
#（原来是链接里写 burst=8M 再让服务端压到 3M，效果一样）。
echo "服务端 3M + 链接默认 5M 的测试链接：$LINK_BURST3"
./mmx-client --link "$LINK_BURST3" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18104 > test/client-burst3.log 2>&1 &
B14_CLI3=$!
sleep 1
T14C=$(curl -s --max-time 60 -o test/big10m-via-burst3.bin -w "%{time_total}" "http://127.0.0.1:18104/big10m.bin")
SHA_14C=$(sha256sum test/big10m-via-burst3.bin | awk '{print $1}')
echo "服务端 3M + 链接 8M 传 10MB 耗时 ${T14C}s"
if [ "$SHA_14C" = "$SHA_DIRECT" ] && awk "BEGIN{exit !(($T14C > 4.5) && ($T14C < 7.5))}"; then ok "突发取最小生效：服务端 3M 胜过链接默认 5M，10MB 耗时 ${T14C}s（4.5–7.5s），数据完整"; else bad "突发取最小未生效（耗时 ${T14C}s，SHA 对得上：$([ "$SHA_14C" = "$SHA_DIRECT" ] && echo 是 || echo 否)）"; fi
kill $B14_CLI3 $B14_SRV3 2>/dev/null; B14_CLI3=; B14_SRV3=

note "测试15：严格限速（rate=6250K burst=0，传 30MB 全程测速，峰值 ≤ 50 Mbps）"
# 背景：旧默认 burst=15M 时 30MB 平均跑到 96 Mbps、峰值 1300 Mbps，等于没限；
# 严格模式要求任何 100ms 窗口都不超过 50 Mbps（6.25 MB/s）。
python3 -c "import random; random.seed(44); open('test/www/big30m.bin','wb').write(bytes(random.getrandbits(8) for _ in range(30*1024*1024)))"
SHA_30M=$(sha256sum test/www/big30m.bin | awk '{print $1}')
./mmx-server --listen 127.0.0.1:18113 --psk "$PSK_HEX" --rate 6250K --burst 0 --name "严格限速测试" --allow-private > test/server-strict.log 2>&1 &
S15_SRV=$!
sleep 1
LINK_STRICT=$(./mmx-server --print-link --listen 127.0.0.1:18113 --psk "$PSK_HEX" --rate 6250K --burst 0 --name "严格限速测试" 2>/dev/null)
echo "严格限速服务端链接：$LINK_STRICT"
./mmx-client --link "$LINK_STRICT" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18112 > test/client-strict.log 2>&1 &
S15_CLI=$!
sleep 1
STRICT_OUT=$(python3 - <<'PYEOF'
import hashlib, time, urllib.request
t0 = time.time()
samples = []  # (时间, 累计字节)
total = 0
h = hashlib.sha256()
with urllib.request.urlopen('http://127.0.0.1:18112/big30m.bin', timeout=60) as r:
    while True:
        chunk = r.read(65536)
        if not chunk:
            break
        h.update(chunk)
        total += len(chunk)
        samples.append((time.time() - t0, total))
elapsed = time.time() - t0
# 任意 100ms 滑动窗口内的峰值速率
peak = 0.0
j = 0
for i, (ti, bi) in enumerate(samples):
    while samples[j][0] < ti - 0.1:
        j += 1
    window_bytes = bi - (samples[j-1][1] if j > 0 else 0)
    rate = window_bytes / 0.1
    if rate > peak:
        peak = rate
avg = total / elapsed
print(f'30MB 传完耗时 {elapsed:.2f}s，平均 {avg/1024/1024:.2f} MB/s（{avg*8/1024/1024:.1f} Mbps），'
      f'峰值 100ms 窗口 {peak/1024/1024:.2f} MB/s（{peak*8/1024/1024:.1f} Mbps）')
print(f'PEAK_MBPS={peak*8/1024/1024:.1f}')
print(f'ELAPSED={elapsed:.2f}')
print(f'SHA30={h.hexdigest()}')
PYEOF
)
echo "$STRICT_OUT"
PEAK_MBPS=$(printf '%s' "$STRICT_OUT" | grep -o 'PEAK_MBPS=[0-9.]*' | cut -d= -f2)
ELAPSED_S=$(printf '%s' "$STRICT_OUT" | grep -o 'ELAPSED=[0-9.]*' | cut -d= -f2)
SHA_30M_VIA=$(printf '%s' "$STRICT_OUT" | grep -o 'SHA30=[0-9a-f]*' | cut -d= -f2)
echo "严格限速实测：峰值 ${PEAK_MBPS} Mbps，耗时 ${ELAPSED_S}s"
if [ "$SHA_30M_VIA" = "$SHA_30M" ] && awk "BEGIN{exit !(($PEAK_MBPS <= 52) && ($ELAPSED_S > 4))}"; then
  ok "严格限速：30MB 峰值 ${PEAK_MBPS} Mbps（≤52），耗时 ${ELAPSED_S}s（>4s），数据完整"
else
  bad "严格限速未达标（峰值 ${PEAK_MBPS} Mbps，耗时 ${ELAPSED_S}s，SHA 对得上：$([ "$SHA_30M_VIA" = "$SHA_30M" ] && echo 是 || echo 否)）"
fi
kill $S15_CLI $S15_SRV 2>/dev/null; S15_CLI=; S15_SRV=

note "测试16：v2 握手——旧版 v1 的固定魔数握手被拒绝"
# 手工拼 v1 握手记录：魔数 "MM1" + 版本 0x01 + 32 字节公钥 + 16 随机数 + 16 标签 + 填充长度 0。
# v2 服务端的魔数是 PSK+随机盐派生的，"MMX" 对不上，应拒绝并回 400 页。
python3 - <<'PYEOF'
import socket, sys
payload = b'MM1' + b'\x01' + bytes(32) + bytes(16) + bytes(16) + b'\x00'
rec = b'\x16\x03\x01' + len(payload).to_bytes(2, 'big') + payload
s = socket.create_connection(('127.0.0.1', 18081), timeout=5)
s.sendall(rec)
s.settimeout(3)
data = b''
try:
    while True:
        c = s.recv(4096)
        if not c:
            break
        data += c
except (socket.timeout, ConnectionResetError, BrokenPipeError):
    pass
s.close()
print(f'v1 握手探测回包 {len(data)} 字节：{data[:60]!r}')
sys.exit(0 if b'400 Bad Request' in data else 1)
PYEOF
[ "$?" = 0 ] && ok "v1 固定魔数握手被拒绝（回 400 页，旧版客户端/服务端作废）" || bad "v1 握手没被拒绝"
grep -q "魔数不对" test/server2.log && ok "服务端日志记下魔数不对" || bad "服务端日志无魔数不对记录"
curl -s --max-time 10 "http://127.0.0.1:$CLI_PORT/index.html" | grep -q "Hello mm-x" && ok "v1 探测后好客户端仍正常" || bad "v1 探测后服务端异常"

note "测试17：真 TLS 模式（自签名证书，仅测试用）"
openssl req -x509 -newkey rsa:2048 -keyout test/tls-key.pem -out test/tls-cert.pem -days 1 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
./mmx-server --listen 127.0.0.1:18115 --psk "$PSK_HEX" --host localhost --tls-domain localhost --tls-cert test/tls-cert.pem --tls-key test/tls-key.pem --name "TLS测试" --allow-private > test/server-tls.log 2>&1 &
T17_SRV=$!
sleep 1
LINK_TLS=$(./mmx-server --print-link --listen 127.0.0.1:18115 --psk "$PSK_HEX" --host localhost --tls-domain localhost --tls-cert test/tls-cert.pem --tls-key test/tls-key.pem --name "TLS测试" 2>/dev/null)
echo "TLS 模式服务端链接：$LINK_TLS"
echo "$LINK_TLS" | grep -q "pin=" && echo "$LINK_TLS" | grep -q "ver=4" && ok "TLS 模式打印的链接是短格式（ver=4 + pin，obfs=tls 为默认）" || bad "TLS 模式链接不对：$LINK_TLS"
grep -q "真 TLS 模式：域名 localhost" test/server-tls.log && ok "服务端日志确认真 TLS 模式（域名 localhost）" || bad "服务端日志无真 TLS 记录"
./mmx-client --link "$LINK_TLS" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18116 --tls-insecure > test/client-tls.log 2>&1 &
T17_CLI=$!
sleep 1
curl -s --max-time 10 "http://127.0.0.1:18116/index.html" | grep -q "Hello mm-x" && ok "真 TLS 模式下客户端连通（SNI localhost，自签名证书测试开关）" || bad "真 TLS 模式下客户端连不上（见 client-tls.log）"

note "测试18：TLS 端口对路人就是一台正常 HTTPS 网站"
# v3/v4 起单端口双模式：同一个端口同时接受明文 mm-x 和真实 TLS，
# 所以明文 HTTP 打过去也会拿到诱饵站首页（和明文端口一样），
# 不再是旧的 TLS 专属端口行为（0 字节或 TLS alert）。
# curl -k 直接访问 TLS 端口应拿到诱饵站首页。
curl -sk --max-time 5 "https://127.0.0.1:18115/" | grep -q "我的小站" && ok "curl -k 访问 TLS 端口拿到诱饵站首页（200 + 我的小站）" || bad "curl -k 访问 TLS 端口没拿到诱饵站"
curl -s --max-time 5 "http://127.0.0.1:18115/" | grep -q "我的小站" && ok "明文 HTTP 打 TLS 端口也拿到诱饵站首页（双模式端口）" || bad "明文 HTTP 打 TLS 端口没拿到诱饵站"
curl -s --max-time 10 "http://127.0.0.1:18116/index.html" | grep -q "Hello mm-x" && ok "TLS 探测后 mm-x 客户端仍正常" || bad "TLS 探测后客户端异常"
kill $T17_CLI $T17_SRV 2>/dev/null; T17_CLI=; T17_SRV=

note "测试19：v4 复用——20 条并行流只用一条会话（1 次握手），数据完整"
# 关键断言：20 个并发请求只产生 1 次新的 v4 握手（会话池单飞），
# 而不是每个请求各拨一条连接；curl 必须用 env -u no_proxy（沙箱的
# no_proxy 含 127.0.0.1，会让 curl 绕过 --socks5 直连目标）。
./mmx-client --link "$LINK" --socks-listen 127.0.0.1:18133 > test/client-t19.log 2>&1 &
T19_CLI=$!
sleep 1
BEFORE19=$(grep -c "握手成功（ver=4）" test/server2.log || true)
rm -f test/t19.ok
# 注意：不能用裸 wait——本脚本输出经过 tee，裸 wait 会等 tee，
# 而 tee 在等脚本退出，造成死锁（见脚本开头 trap 注释）。
# 只等这 20 个 curl 的 PID。
PIDS19=""
for i in $(seq 20); do
  env -u no_proxy -u NO_PROXY curl -s --max-time 15 --socks5 127.0.0.1:18133 "http://127.0.0.1:$HTTP_PORT/index.html" | grep -q "Hello mm-x" && echo ok >> test/t19.ok &
  PIDS19="$PIDS19 $!"
done
for p in $PIDS19; do wait $p 2>/dev/null; done
OK19=$(wc -l < test/t19.ok 2>/dev/null || echo 0)
AFTER19=$(grep -c "握手成功（ver=4）" test/server2.log || true)
NEW19=$((AFTER19 - BEFORE19))
echo "20 并行流：成功 $OK19/20，新增 v4 握手 $NEW19 次"
if [ "$OK19" = 20 ] && [ "$NEW19" = 1 ]; then ok "20 条并行流全通，且只用 1 次握手（复用生效）";
elif [ "$OK19" = 20 ]; then bad "20 条并行流全通，但新增握手 $NEW19 次（应为 1 次，会话池没复用）";
else bad "20 条并行流只成功 $OK19/20"; fi
kill $T19_CLI 2>/dev/null; T19_CLI=

note "测试20：v2 回归——显式 ver=2 链接在新服务端上仍能用"
LINK2=$(echo "$LINK" | sed 's/ver=4/ver=2/')
./mmx-client --link "$LINK2" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18134 > test/client-t20.log 2>&1 &
T20_CLI=$!
sleep 1
curl -s --max-time 10 "http://127.0.0.1:18134/index.html" | grep -q "Hello mm-x" && ok "ver=2 链接经新服务端拿到正确内容" || bad "ver=2 链接在新服务端上不通"
grep -q "握手成功（ver=2）" test/server2.log && ok "服务端日志确认这次是 v2 握手（双版本共存）" || bad "服务端日志里没有 v2 握手记录"
kill $T20_CLI 2>/dev/null; T20_CLI=

note "测试20补：v3 回归——显式 ver=3 链接在新服务端上仍能用（v4 服务端向下兼容）"
LINK3=$(echo "$LINK" | sed 's/ver=4/ver=3/')
./mmx-client --link "$LINK3" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18135 > test/client-t20b.log 2>&1 &
T20B_CLI=$!
sleep 1
curl -s --max-time 10 "http://127.0.0.1:18135/index.html" | grep -q "Hello mm-x" && ok "ver=3 链接经新服务端拿到正确内容" || bad "ver=3 链接在新服务端上不通"
grep -q "握手成功（ver=3）" test/server2.log && ok "服务端日志确认这次是 v3 握手（三版本共存）" || bad "服务端日志里没有 v3 握手记录"
kill $T20B_CLI 2>/dev/null; T20B_CLI=

note "测试21：v4 自签 TLS + SPKI 锁定（--tls-auto，无域名）"
mkdir -p test/tls-auto
./mmx-server --listen 127.0.0.1:18120 --psk "$PSK_HEX" --block-fails 100 --host localhost --tls-auto --tls-cert test/tls-auto/cert.pem --tls-key test/tls-auto/key.pem --name "TLS自签" --allow-private > test/server-tlsauto.log 2>&1 &
T21_SRV=$!
sleep 1
LINK_AUTO=$(./mmx-server --print-link --listen 127.0.0.1:18120 --psk "$PSK_HEX" --block-fails 100 --host localhost --tls-auto --tls-cert test/tls-auto/cert.pem --tls-key test/tls-auto/key.pem --name "TLS自签" 2>/dev/null)
echo "自签 TLS 链接：$LINK_AUTO"
echo "$LINK_AUTO" | grep -q "ver=4" && echo "$LINK_AUTO" | grep -q "pin=" && ! echo "$LINK_AUTO" | grep -q "sni=" && ok "自签 TLS 链接是短格式（ver=4 + pin，sni 默认省略）" || bad "自签 TLS 链接不对：$LINK_AUTO"
grep -q "自签 TLS 模式" test/server-tlsauto.log && ok "服务端日志确认自签 TLS 模式" || bad "服务端日志无自签 TLS 记录"
ls -l test/tls-auto/cert.pem test/tls-auto/key.pem >/dev/null 2>&1 && ok "自签证书已生成并存到文件" || bad "自签证书文件没生成"
# 带正确 pin 的客户端（不用 --tls-insecure）应连通——pin 锁定生效。
./mmx-client --link "$LINK_AUTO" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18121 > test/client-tlsauto.log 2>&1 &
T21_CLI=$!
sleep 1
curl -s --max-time 10 "http://127.0.0.1:18121/index.html" | grep -q "Hello mm-x" && ok "正确 pin 的客户端连通（SPKI 锁定验证通过）" || bad "正确 pin 的客户端连不上（见 client-tlsauto.log）"
# 指纹不对的链接应被拒绝（中间人换证书就对不上 pin）。
LINK_BADPIN=$(echo "$LINK_AUTO" | sed 's/pin=[^&]*/pin=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/')
./mmx-client --link "$LINK_BADPIN" --target 127.0.0.1:$HTTP_PORT --listen 127.0.0.1:18123 > test/client-tlsbadpin.log 2>&1 &
BADPIN_PID=$!
sleep 1
curl -s --max-time 5 "http://127.0.0.1:18123/index.html" >/dev/null 2>&1
if [ "$?" != 0 ] && grep -q "指纹" test/client-tlsbadpin.log; then ok "错误 pin 的客户端被拒绝（报错提到指纹）";
else bad "错误 pin 的客户端没被拒绝（见 client-tlsbadpin.log）"; fi
kill $BADPIN_PID 2>/dev/null
# TLS 里的诱饵站：curl -k + http/1.1 应拿到首页。
curl -sk --http1.1 --max-time 5 "https://127.0.0.1:18120/" | grep -q "我的小站" && ok "TLS 里的诱饵站正常（curl -k 拿到首页）" || bad "TLS 里的诱饵站没拿到首页"
# 复用跑在 TLS 会话里：SOCKS5 + 5 并行。
./mmx-client --link "$LINK_AUTO" --socks-listen 127.0.0.1:18122 > test/client-tlsauto-socks.log 2>&1 &
T21_SOCKS=$!
sleep 1
rm -f test/t21.ok
PIDS21=""
for i in $(seq 5); do
  env -u no_proxy -u NO_PROXY curl -s --max-time 10 --socks5 127.0.0.1:18122 "http://127.0.0.1:$HTTP_PORT/index.html" | grep -q "Hello mm-x" && echo ok >> test/t21.ok &
  PIDS21="$PIDS21 $!"
done
for p in $PIDS21; do wait $p 2>/dev/null; done
OK21=$(wc -l < test/t21.ok 2>/dev/null || echo 0)
[ "$OK21" = 5 ] && ok "复用 + UDP 承载在 TLS 会话里：5 并行全通" || bad "TLS 会话里复用只通 $OK21/5"
kill $T21_CLI $T21_SOCKS $T21_SRV 2>/dev/null; T21_CLI=; T21_SOCKS=; T21_SRV=

note "测试22：v4 UDP——SOCKS5 UDP ASSOCIATE 经隧道回显 + DNS 查询"
# 沙箱会静默丢弃 UDP 包（包到不了对端），先探测本机 UDP 通不通；
# 不通就 SKIP（VPS 部署验证时真测，见 test/udp-test.sh），不断言失败。
if $GO run ./test/udp-probe 2>&1 | tee /tmp/udp-probe.log | grep -q "收发正常"; then
  ./mmx-client --link "$LINK" --socks-listen 127.0.0.1:18135 > test/client-t22.log 2>&1 &
  T22_CLI=$!
  sleep 1
  if $GO run ./test/socks-udp-test --socks 127.0.0.1:18135 2>&1 | tee test/udp-t22.log | grep -q "UDP DNS 查询：PASS"; then
    ok "UDP 经隧道回显 + DNS 查询全通（SOCKS5 UDP ASSOCIATE）"
  else
    bad "UDP 测试失败（见 test/udp-t22.log）"
  fi
  kill $T22_CLI 2>/dev/null; T22_CLI=
else
  skipped "本机 UDP 不通（沙箱静默丢弃 UDP 包），UDP 数据面留到 VPS 部署验证真测"
fi

note "测试23：v4 会话级限速——两条并行流共用一个桶"
# 服务端限速 100K + burst 0；同一个 SOCKS5 客户端（同一会话）上
# 两条并行流各下 1MB：总量 2MB / 100K ≈ 20s。若每条流各拿一个桶
# （v2 的老口子），只要 ~10s；>15s 才算会话级限速生效。
./mmx-server --listen 127.0.0.1:18130 --psk "$PSK_HEX" --block-fails 100 --rate 100K --burst 0 --name "限速" --allow-private > test/server-t23.log 2>&1 &
T23_SRV=$!
sleep 1
LINK23=$(./mmx-server --print-link --listen 127.0.0.1:18130 --psk "$PSK_HEX" --block-fails 100 --rate 100K --burst 0 --name "限速" 2>/dev/null)
./mmx-client --link "$LINK23" --socks-listen 127.0.0.1:18131 > test/client-t23.log 2>&1 &
T23_CLI=$!
sleep 1
START23=$(date +%s)
env -u no_proxy -u NO_PROXY curl -s --max-time 60 --socks5 127.0.0.1:18131 "http://127.0.0.1:$HTTP_PORT/one1m.bin" -o test/t23-a.bin &
PID23A=$!
env -u no_proxy -u NO_PROXY curl -s --max-time 60 --socks5 127.0.0.1:18131 "http://127.0.0.1:$HTTP_PORT/one1m.bin" -o test/t23-b.bin &
PID23B=$!
wait $PID23A 2>/dev/null; wait $PID23B 2>/dev/null
ELAPSED23=$(( $(date +%s) - START23 ))
SHA23A=$(sha256sum test/t23-a.bin | awk '{print $1}')
SHA23B=$(sha256sum test/t23-b.bin | awk '{print $1}')
echo "两条并行流 2MB 耗时 ${ELAPSED23}s（会话级限速 100K 时应 ≈20s）"
if [ "$SHA23A" = "$SHA_1M" ] && [ "$SHA23B" = "$SHA_1M" ] && [ "$ELAPSED23" -gt 15 ]; then
  ok "会话级限速生效：2MB 耗时 ${ELAPSED23}s（>15s），数据完整"
else
  bad "会话级限速异常（耗时 ${ELAPSED23}s，SHA 对得上：A=$([ "$SHA23A" = "$SHA_1M" ] && echo 是 || echo 否) B=$([ "$SHA23B" = "$SHA_1M" ] && echo 是 || echo 否)）"
fi
kill $T23_CLI $T23_SRV 2>/dev/null; T23_CLI=; T23_SRV=

note "测试24：v4 错误码——目标拒绝时客户端日志带 [目标拒绝]"
./mmx-client --link "$LINK" --socks-listen 127.0.0.1:18137 > test/client-t24.log 2>&1 &
T24_CLI=$!
sleep 1
env -u no_proxy -u NO_PROXY curl -s --max-time 8 --socks5 127.0.0.1:18137 "http://127.0.0.1:19999/" >/dev/null 2>&1
if [ "$?" != 0 ] && grep -q "\[目标拒绝\]" test/client-t24.log; then ok "v4 目标拒绝时客户端日志带 [目标拒绝]（错误码仍生效）";
else bad "v4 错误码异常（见 client-t24.log）"; fi
kill $T24_CLI 2>/dev/null; T24_CLI=

echo ""
echo "================ 结果汇总 ================"
echo "PASS: $pass  FAIL: $fail  SKIP: $skip"
[ "$fail" = 0 ] && echo "全部已执行项通过（SKIP 项为沙箱环境受限，未验证）" || echo "有 $fail 项失败，见上文"
