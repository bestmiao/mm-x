package mm1

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 白名单 IP 连续失败 10 次也不拉黑（失败不计数）。
func TestBlocklistWhitelistNeverBlocked(t *testing.T) {
	bl := NewBlocklist(5, time.Minute, 10*time.Minute)
	bl.AddWhitelist("203.0.113.10")
	for i := 0; i < 10; i++ {
		if bl.RecordFailure("203.0.113.10") {
			t.Fatalf("白名单 IP 第 %d 次失败就触发了拉黑", i+1)
		}
	}
	if bl.IsBlocked("203.0.113.10") {
		t.Fatal("白名单 IP 失败 10 次后被拉黑了")
	}
	if n := bl.FailCount("203.0.113.10"); n != 0 {
		t.Fatalf("白名单 IP 的失败计数应为 0，实际 %d", n)
	}
}

// 成功过一次的 IP，之后失败不再拉黑。
func TestBlocklistSuccessTrustsIP(t *testing.T) {
	bl := NewBlocklist(5, time.Minute, 10*time.Minute)
	// 先攒 4 次失败（差 1 次就触发），再成功一次
	for i := 0; i < 4; i++ {
		bl.RecordFailure("198.51.100.7")
	}
	if n := bl.FailCount("198.51.100.7"); n != 4 {
		t.Fatalf("成功前失败计数应为 4，实际 %d", n)
	}
	bl.RecordSuccess("198.51.100.7")
	if !bl.IsTrusted("198.51.100.7") {
		t.Fatal("成功握手后 IP 应进入信任状态")
	}
	// 成功后失败计数清零
	if n := bl.FailCount("198.51.100.7"); n != 0 {
		t.Fatalf("成功后失败计数应清零，实际 %d", n)
	}
	// 之后再失败 10 次也不拉黑
	for i := 0; i < 10; i++ {
		if bl.RecordFailure("198.51.100.7") {
			t.Fatalf("已信任 IP 第 %d 次失败就触发了拉黑", i+1)
		}
	}
	if bl.IsBlocked("198.51.100.7") {
		t.Fatal("已信任 IP 失败 10 次后被拉黑了")
	}
}

// 从未成功过的 IP，连续 5 次失败照常拉黑（默认规则不变）。
func TestBlocklistUntrustedBlockedAfter5(t *testing.T) {
	bl := NewBlocklist(5, time.Minute, 10*time.Minute)
	for i := 0; i < 4; i++ {
		if bl.RecordFailure("192.0.2.99") {
			t.Fatalf("第 %d 次失败就触发了拉黑（应为第 5 次）", i+1)
		}
	}
	if bl.IsBlocked("192.0.2.99") {
		t.Fatal("4 次失败后不应被拉黑")
	}
	if !bl.RecordFailure("192.0.2.99") {
		t.Fatal("第 5 次失败应触发拉黑")
	}
	if !bl.IsBlocked("192.0.2.99") {
		t.Fatal("5 次失败后应被拉黑")
	}
}

// 白名单文件：空行和 # 注释跳过，合法 IP 正常读入。
func TestLoadWhitelistFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist")
	if err := os.WriteFile(path, []byte("# realm 中转机\n203.0.113.10\n\n198.51.100.7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ips, err := LoadWhitelistFile(path)
	if err != nil {
		t.Fatalf("干净的白名单文件应读入成功：%v", err)
	}
	if len(ips) != 2 || ips[0] != "203.0.113.10" || ips[1] != "198.51.100.7" {
		t.Fatalf("读入的白名单不对：%v", ips)
	}
}

// 白名单文件里有一行不是 IP：报错并指明行号。
func TestLoadWhitelistFileBadLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist")
	if err := os.WriteFile(path, []byte("203.0.113.10\nnot-an-ip\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWhitelistFile(path)
	if err == nil {
		t.Fatal("第 2 行不是 IP，应报错")
	}
	t.Logf("报错内容（应指明行号）：%v", err)
}
