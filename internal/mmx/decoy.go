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

// decoyHTML 是诱饵站的首页：极简静态页面，不引用任何外部资源。
// %s 处填当天日期（最后更新），每天变一次。
const decoyHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>我的小站</title></head>
<body>
<h1>你好，这里是我的小站</h1>
<p>这里什么也没有，只是一个放在云上的小页面。</p>
<p>如果你是误入的访客，不用管它；如果你是站长，请记得回来更新内容。</p>
<p>最后更新：%s</p>
</body>
</html>
`

// decoy400HTML 是诱饵站的 400 错误页：发来 TLS 握手或乱字节时回这个。
const decoy400HTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>400 Bad Request</title></head>
<body><h1>400 Bad Request</h1><p>请求有误，服务器无法理解。</p></body></html>
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

// ServeDecoySite 读完一个 HTTP 请求（最多 8KB 请求头），回 200 + 诱饵页面。
// r 是已 peek 过的缓冲读端，w 是同一条连接的写端。
func ServeDecoySite(r *bufio.Reader, w io.Writer) error {
	total := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		total += len(line)
		if total > 8192 {
			return fmt.Errorf("请求头太大")
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}
	body := fmt.Sprintf(decoyHTML, time.Now().Format("2006-01-02"))
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		decoyHeaders(), len(body), body)
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
