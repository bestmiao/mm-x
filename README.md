# mm-x

## 一键部署（在 VPS 上）

```bash
mkdir -p /tmp/mm1 && cd /tmp/mm1 && curl -fsSL -O https://raw.githubusercontent.com/bestmiao/mm-x/main/install-mm1-server.sh && curl -fsSL -O https://raw.githubusercontent.com/bestmiao/mm-x/main/mm1-server-linux-amd64 && chmod +x mm1-server-linux-amd64 && sudo bash install-mm1-server.sh
```

默认随机高位端口、限速 50 Mbps。装完在 `mm` 菜单第 1 项里看 mm:// 链接。
