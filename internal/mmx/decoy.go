// 诱饵站：非 mm-x 连接看到的东西。
//
// 目标：让一次主动探测看到一台普通 Web 服务器，而不是一个代理端口。
//   - 发来 HTTP 请求 → 回 200 + 一个极简静态页面（内嵌，无外部资源，
//     不会再向外发任何请求）；
//   - 发来 TLS 握手或乱字节 → 回一个像网站的 400 错误页；
//   - --fallback silent 时以上两种情况都改成 0 字节回包、直接断开。
//
// 响应头要像真服务器：带 Date（当前 GMT 时间）和 Server（nginx）。
// 以前没有这两个头——真实服务器每次响应都带 Date，没有它本身就很可疑。
// 首页正文里还有一行“最后更新：当天日期”，每天变一次，
// 多次探测看到的响应体不再是字节完全相同的同一份。
//
// 注意取舍：诱饵站让单次探测看到“网站”，但多次探测仍会计入拉黑
// （5 次失败就拉黑该 IP 10 分钟），拉黑后连诱饵站也不回了——
// 私人单用户服务器上这是可以接受的：正常访客不会反复来敲这个端口。
package mmx

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// decoyHTML 是诱饵站的唯一页面：家庭影音登录页。
// %s 处填当天日期（最后更新），每天变一次。
// 纯静态页面，不引用任何外部资源，和代理/VPN 没有任何关系。
// 密码是假的：表单提交后由 JS 拦截（不发任何请求），永远只显示
// “密码错误，请重试”，没有任何密码能通过——页面背后没有任何内容，
// 登录页本身就是整个站。代码里不存在任何“正确密码”，
// 诱饵站不接受也不会处理 POST——就是个摆设。
const decoyHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>家庭影音</title>
<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; background: #14161a; color: #e8e8e8; line-height: 1.6; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.card { width: 100%; max-width: 380px; margin: 0 auto; padding: 32px 24px; text-align: center; }
.logo { width: 64px; height: 64px; margin: 0 auto 16px; border-radius: 16px; background: #2e7fff; color: #fff; font-size: 30px; line-height: 64px; }
h1 { font-size: 24px; margin: 0 0 4px; }
.sub { color: #999; font-size: 14px; margin: 0 0 28px; }
input { width: 100%; padding: 12px; font-size: 16px; color: #e8e8e8; background: #1e2126; border: 1px solid #333; border-radius: 8px; font-family: inherit; text-align: center; }
input:focus { outline: none; border-color: #2e7fff; }
button { margin-top: 14px; width: 100%; padding: 12px; font-size: 16px; color: #fff; background: #2e7fff; border: none; border-radius: 8px; cursor: pointer; }
button:active { background: #1c60d8; }
.err { display: none; color: #ff6b6b; font-size: 14px; margin-top: 14px; }
.foot { color: #666; font-size: 12px; margin-top: 32px; }
@media (max-width: 600px) {
  .card { padding: 24px 20px; }
  h1 { font-size: 21px; }
  input { font-size: 16px; }
}
</style>
</head>
<body>
<div class="card">
<div class="logo">▶</div>
<h1>家庭影音</h1>
<p class="sub">私人影音服务器 · 请输入访问密码</p>
<form id="form">
<input id="pwd" type="password" placeholder="访问密码" autocomplete="off">
<button type="submit">登录</button>
</form>
<p class="err" id="err">密码错误，请重试</p>
<p class="foot">最后更新：%s</p>
</div>
<script>
document.getElementById("form").addEventListener("submit", function (ev) {
  ev.preventDefault();
  document.getElementById("pwd").value = "";
  document.getElementById("err").style.display = "block";
});
</script>
</body>
</html>
`

// decoy400HTML 是诱饵站的 400 错误页：发来 TLS 握手或乱字节时回这个。
// 按真 nginx 默认错误页的格式写（英文 + 底部 nginx 署名），中文自制页
// 一眼就能认出来（2026-11-26 评审指出）。
const decoy400HTML = `<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
`

// decoy404HTML 是诱饵站的 404 错误页：不存在的路径回这个，不再什么都回 200。
// 真站对不存在的路径回 404，任意路径都回 200 本身就是特征（2026-11-26 评审指出）。
const decoy404HTML = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
`

var httpMethods = []string{
	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ",
	"TRACE ", "CONNECT ",
}

// LooksLikeHTTP 判断首字节是不是 HTTP 请求（方法 + 空格）。
func LooksLikeHTTP(head []byte) bool {
	for _, m := range httpMethods {
		if len(head) >= len(m) && string(head[:len(m)]) == m {
			return true
		}
	}
	return false
}

// LooksLikeTLSRecord 判断首字节是不是 TLS 记录头：
// 0x16 0x03 0x01（TLS 1.0 记录：v2/v3 的 mm-x 握手和真实 ClientHello）
// 或 0x16 0x03 0x03（TLS 1.2 记录：v4 的 mm-x 握手）。
// mm-x 握手和真实 TLS ClientHello 都长这样，靠后面魔数/鉴权再区分。
func LooksLikeTLSRecord(head []byte) bool {
	return len(head) >= 3 && head[0] == 0x16 && head[1] == 0x03 && (head[2] == 0x01 || head[2] == 0x03)
}

// decoyServer 是诱饵站响应里冒充的服务器软件：一个常见的 nginx 版本。
// 真实服务器的响应头里总有 Server 和 Date，缺了反而可疑。
const decoyServer = "nginx/1.18.0"

// decoyHeaders 返回诱饵站响应的通用头：Date（当前 GMT 时间）+ Server。
func decoyHeaders() string {
	return fmt.Sprintf("Date: %s\r\nServer: %s\r\n", time.Now().UTC().Format(http.TimeFormat), decoyServer)
}

// ServeDecoySite 读完一个 HTTP 请求（最多 8KB 请求头），回诱饵页面。
// 单页站：只有 / 和 /index.html 回 200 + 家庭影音登录页，
// 其余一切路径（/about.html、/blog/*、不存在的路径）都回 404——
// 真站就是这样，任意路径都回 200 本身就是特征（2026-11-26 评审指出）。
// r 是已 peek 过的缓冲读端，w 是同一条连接的写端。
func ServeDecoySite(r *bufio.Reader, w io.Writer) error {
	total := 0
	requestLine := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if requestLine == "" {
			requestLine = strings.TrimRight(line, "\r\n")
		}
		total += len(line)
		if total > 8192 {
			return fmt.Errorf("请求头太大")
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}
	// 请求行：METHOD /path HTTP/x.y，取中间那段当路径；去掉 ? 后面的查询串。
	path := ""
	if fields := strings.Fields(requestLine); len(fields) >= 2 {
		path = fields[1]
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if path == "/" || path == "/index.html" || path == "/index.htm" {
		// 注意：页面含 CSS 的 100%，不能用 Sprintf（% 会被当成格式符），
		// 用 strings.Replace 只换 %s 这一处。
		body := strings.Replace(decoyHTML, "%s", time.Now().Format("2006-01-02"), 1)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			decoyHeaders(), len(body), body)
		_, err := io.WriteString(w, resp)
		return err
	}
	resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n%sContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		decoyHeaders(), len(decoy404HTML), decoy404HTML)
	_, err := io.WriteString(w, resp)
	return err
}

// ServeDecoy400 回一个像网站的 400 错误页。
func ServeDecoy400(w io.Writer) error {
	resp := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\n%sContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		decoyHeaders(), len(decoy400HTML), decoy400HTML)
	_, err := io.WriteString(w, resp)
	return err
}
