// 密钥轮换：服务端不重启换密钥。
//
// 用法：启动时用 --psk-file <文件> 指定密钥文件（文件里写 64 位十六进制密钥），
// 再用 --grace <时长> 设旧密钥宽限期（默认 24h，0 = 换了就立即失效）。
// 换密钥时直接改文件内容（echo <新密钥> > 文件），服务端在下一次握手前
// 发现文件变了就自动轮换：新密钥成为当前密钥，旧密钥在宽限期内仍能用，
// 过了宽限期就失效。轮换不用重启服务端，正在跑的 v2 连接不受影响
// （握手时已经协商好的会话密钥继续用，只影响新连接）；
// 但 v3 会话是长连接，建好后不再握手——不处理的话，旧密钥能借着
// 已建好的会话一直用下去，轮换失效。服务端发现轮换后按旧密钥的
// 宽限期排一个定时器：宽限期内旧会话照常用，宽限期一到只断开用旧密钥
// 建的会话（见 cmd/mm1-server 的轮换监视）。
package mm1

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// KeyManager 管当前密钥和宽限期内的旧密钥。
type KeyManager struct {
	mu          sync.Mutex
	file        string // 密钥文件路径（空 = 不从文件轮换）
	grace       time.Duration
	current     []byte
	prev        []byte
	prevExpires time.Time
	lastMod     time.Time
	rotations   int // 累计轮换次数（服务端监视轮换用）
}

// NewKeyManager 新建密钥管理器。initial 是启动时的密钥；
// file 为空表示不轮换；grace 是旧密钥轮换后的宽限期。
func NewKeyManager(initial []byte, file string, grace time.Duration) *KeyManager {
	km := &KeyManager{file: file, grace: grace, current: initial}
	if file != "" {
		if fi, err := os.Stat(file); err == nil {
			km.lastMod = fi.ModTime()
		}
	}
	return km
}

// ReadKeyFile 从文件读一个 64 位十六进制密钥。
func ReadKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if len(s) != 64 {
		return nil, fmt.Errorf("密钥文件 %s 内容不合法：应为 64 位十六进制字符（32 字节），实际 %d 位", path, len(s))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var v int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
			return nil, fmt.Errorf("密钥文件 %s 第 %d 字节不是十六进制：%v", path, i, err)
		}
		out[i] = byte(v)
	}
	return out, nil
}

// checkRotationLocked 看一眼密钥文件，变了就轮换（调用方必须已持锁）。
func (km *KeyManager) checkRotationLocked() {
	if km.file == "" {
		return
	}
	if fi, err := os.Stat(km.file); err == nil && fi.ModTime().After(km.lastMod) {
		if b, err := ReadKeyFile(km.file); err != nil {
			log.Printf("密钥文件 %s 读失败（%v），继续用旧密钥", km.file, err)
		} else if !bytes.Equal(b, km.current) {
			km.prev = km.current
			km.prevExpires = time.Now().Add(km.grace)
			km.current = b
			km.rotations++
			log.Printf("密钥已轮换：旧密钥宽限到 %s，之后失效", km.prevExpires.Format("2006-01-02 15:04:05"))
		}
		km.lastMod = fi.ModTime()
	}
}

// Keys 返回握手可用的密钥列表：当前密钥在前，宽限期内的旧密钥在后。
// 每次调用都会看一眼密钥文件，文件变了就自动轮换。
func (km *KeyManager) Keys() [][]byte {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.checkRotationLocked()
	keys := [][]byte{km.current}
	if len(km.prev) > 0 && time.Now().Before(km.prevExpires) {
		keys = append(keys, km.prev)
	}
	return keys
}

// Rotations 返回累计轮换次数（调用时也会检查一次密钥文件，
// 所以服务端轮换监视可以只调它就发现轮换）。
func (km *KeyManager) Rotations() int {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.checkRotationLocked()
	return km.rotations
}

// PrevKey 返回正在宽限期内的旧密钥和它的过期时间；
// 没有旧密钥（没轮换过，或宽限期已过）时返回 nil 和零值。
// 服务端轮换监视用它安排“宽限期一到就断开用旧密钥建的 v3 会话”。
func (km *KeyManager) PrevKey() ([]byte, time.Time) {
	km.mu.Lock()
	defer km.mu.Unlock()
	if len(km.prev) == 0 || !time.Now().Before(km.prevExpires) {
		return nil, time.Time{}
	}
	return append([]byte(nil), km.prev...), km.prevExpires
}

// CurrentHex 返回当前密钥的十六进制（用于 --print-link 生成新链接）。
func (km *KeyManager) CurrentHex() string {
	km.mu.Lock()
	defer km.mu.Unlock()
	return fmt.Sprintf("%x", km.current)
}
