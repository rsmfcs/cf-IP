# Cloudflare-IP-Auto V3.1（IPv4 高覆盖率版）

仅扫描 Cloudflare 官方 IPv4 网段，**只测试 TCP 443**。由 GitHub Actions 每 6 小时自动运行并提交结果。

## V3.1 改进

- 候选地址上限 1024，按官方 IPv4 网段均匀采样。
- 两阶段检测：1 轮快速初筛，再对通过者进行 3 轮稳定性复测。
- 并发 40，连接超时 4 秒；最多对 50 个候选进行 2 次下载测速。
- 综合延迟、下载速度、成功率和抖动评分。
- 保留 TOP20/50/100/200/400 订阅文件名和旧目录输出。
- 新增 `all.txt`、`fast.txt`、`stable.txt`，以及 `output/summary.json`。
- `fast.txt`：测速中位数不低于 25 Mbps；`stable.txt`：复测成功率 100% 且抖动不高于 50 ms。
- 订阅每行格式为 `IPv4:443`。实际数量不足时不填充虚假 IP。

## 根目录订阅链接

将 `OWNER/REPO` 替换为你的仓库路径，分支为 `main`：

- `https://raw.githubusercontent.com/OWNER/REPO/main/best-cf-ip-scanned-top20.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/best-cf-ip-scanned-top50.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/best-cf-ip-scanned-top100.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/best-cf-ip-scanned-top200.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/best-cf-ip-scanned-top400.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/all.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/fast.txt`
- `https://raw.githubusercontent.com/OWNER/REPO/main/stable.txt`

另保留 `cf-ipv4-top20.txt` 至 `cf-ipv4-top400.txt` 别名文件。

## 部署

1. 解压完整 ZIP。
2. 将 `Cloudflare-IP-Auto-V3.1` 内全部文件复制到仓库根目录并覆盖同名文件。
3. 用 GitHub Desktop 提交并推送到 `main`。
4. 打开 Actions，手动运行 `Update Cloudflare IPv4 IPs`。
5. 查看运行日志和 `output/summary.json`。

## 注意

增加候选数量不保证可用 IP 数量按比例增加；Cloudflare 边缘路由和 GitHub Runner 网络会影响结果。扫描只判断指定 HTTPS/SNI/Host 探测是否成功，不保证这些 IP 在所有代理协议或客户端网络中都可用。请遵守 Cloudflare 服务条款及适用规则。
