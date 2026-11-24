package mm1

import (
	"os"
	"path/filepath"
	"testing"
)

// 白名单关闭（空的）时，任何 IP 都允许连接。
func TestAllowlistDisabledAllowsAll(t *testing.T) {
	a := NewAllowlist()
	if a.Enabled() {
		t.Fatal("空的白名单应是关闭状态")
	}
	if !a.Contains("127.0.0.1") || !a.Contains("203.0.113.99") {
		t.Fatal("白名单关闭时任何 IP 都应允许连接")
	}
}

// 白名单开了之后：里面的 IP 允许，外面的拒绝。
func TestAllowlistExactIP(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if !a.Enabled() {
		t.Fatal("填了一条后白名单应是开启状态")
	}
	if !a.Contains("203.0.113.10") {
		t.Fatal("白名单里的 IP 应允许连接")
	}
	if a.Contains("203.0.113.11") {
		t.Fatal("白名单外的 IP 应拒绝连接")
	}
	if a.Contains("not-an-ip") {
		t.Fatal("不是 IP 的输入应拒绝连接")
	}
}

// CIDR 段匹配：段内允许，段外拒绝。
func TestAllowlistCIDR(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("1.2.3.0/24"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"1.2.3.1", "1.2.3.254", "1.2.3.0"} {
		if !a.Contains(ip) {
			t.Fatalf("CIDR 段内的 %s 应允许连接", ip)
		}
	}
	for _, ip := range []string{"1.2.4.1", "1.2.2.255", "2.3.4.5"} {
		if a.Contains(ip) {
			t.Fatalf("CIDR 段外的 %s 应拒绝连接", ip)
		}
	}
	// IPv6 段也支持
	if err := a.Add("2001:db8::/32"); err != nil {
		t.Fatal(err)
	}
	if !a.Contains("2001:db8::1") || a.Contains("2001:db9::1") {
		t.Fatal("IPv6 CIDR 段匹配不对")
	}
}

// 写错的条目要报错，不静默吞掉。
func TestAllowlistBadEntry(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("1.2.3.999"); err == nil {
		t.Fatal("不合法的 IP 应报错")
	}
	if err := a.Add("1.2.3.0/33"); err == nil {
		t.Fatal("不合法的 CIDR 应报错")
	}
	if a.Enabled() {
		t.Fatal("写错的条目不应让白名单变成开启状态")
	}
}

// 白名单文件：IP 和 CIDR 混写、空行和 # 注释跳过。
func TestLoadAllowlistFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist")
	if err := os.WriteFile(path, []byte("# realm 中转机\n203.0.113.10\n1.2.3.0/24\n\n198.51.100.7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadAllowlistFile(path)
	if err != nil {
		t.Fatalf("干净的白名单文件应读入成功：%v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("应读入 3 条，实际 %v", entries)
	}
	a := NewAllowlist()
	for _, e := range entries {
		if err := a.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if !a.Contains("203.0.113.10") || !a.Contains("1.2.3.200") || !a.Contains("198.51.100.7") {
		t.Fatal("文件里的 IP/CIDR 都应生效")
	}
	if a.Contains("203.0.113.11") {
		t.Fatal("文件里没有的 IP 应拒绝")
	}
}

// 白名单文件里有一行写错：报错并指明行号。
func TestLoadAllowlistFileBadLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist")
	if err := os.WriteFile(path, []byte("203.0.113.10\nnot-an-ip-or-cidr\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAllowlistFile(path)
	if err == nil {
		t.Fatal("第 2 行不合法，应报错")
	}
	t.Logf("报错内容（应指明行号）：%v", err)
}
