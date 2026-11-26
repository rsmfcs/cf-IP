# Cloudflare-IP-Auto V3.6（IPv4 扫描 + IPv6 同步更新）

IPv4 继续扫描 Cloudflare 官方 IPv4 网段并检测 TCP 443；IPv6 从 HostMonit 获取候选地址，进行格式校验、去重和地区标注后独立发布。GitHub Actions 每 6 小时自动更新两类数据。

## 自动更新

- 定时任务：UTC 每天 00:17、06:17、12:17、18:17（每 6 小时一次）。
- 也可以在仓库 **Actions → Update Cloudflare IPs (IPv4 + IPv6 sync) → Run workflow** 手动运行。
- 运行结果写入仓库根目录订阅文件及 `output/ipv4/`。
- 工作流会先运行测试，测试通过后再扫描。
- GitHub 定时任务只在默认分支运行；请确保工作流文件保留在 `main` 分支。

## 检测规则

- Cloudflare 官方 IPv4 网段均匀采样，候选上限 1024。
- 两阶段检测：1 轮初筛，再对通过者进行 3 轮稳定性复测。
- 并发 40，连接超时 4 秒；最多对 50 个候选进行 2 次下载测速。
- 综合延迟、下载速度、成功率和抖动评分。
- IPv4 使用 TCP 443 进行连通性、TLS、HTTP、稳定性和速度检测。\n- IPv6 每 6 小时从 HostMonit API 同步，校验 IPv6 格式、过滤非全球单播地址并去重；当前 GitHub Runner 不具备可用 IPv6 出站网络，因此 IPv6 数据标记为来源候选，**未经本项目连通性和速度实测**。
- 国家/地区代码通过 GeoIP 查询补充，订阅行显示为 `IP:443#US 🇺🇸`。
- GeoIP 仅用于显示参考；Cloudflare Anycast 地址的归属地不代表每位用户实际连接到的边缘机房。GeoIP 查询失败时仍会保留节点，地区显示为 `ZZ 🌐`。

## 订阅地址（Raw）

以下链接可直接复制到支持 URL 订阅的客户端：

| 订阅 | Raw 地址 |
|---|---|
| TOP 20 | [best-cf-ip-scanned-top20.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top20.txt) |
| TOP 50 | [best-cf-ip-scanned-top50.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top50.txt) |
| TOP 100 | [best-cf-ip-scanned-top100.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top100.txt) |
| TOP 200 | [best-cf-ip-scanned-top200.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top200.txt) |
| TOP 400 | [best-cf-ip-scanned-top400.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top400.txt) |
| 全部 IPv4 节点 | [all.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/all.txt) |\n| HostMonit IPv6 候选 | [ipv6.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/ipv6.txt) |
| 高速节点（≥25 Mbps） | [fast.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/fast.txt) |
| 稳定节点（成功率 100%、抖动 ≤50 ms） | [stable.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/stable.txt) |

备用别名：`cf-ipv4-top20.txt`、`cf-ipv4-top50.txt`、`cf-ipv4-top100.txt`、`cf-ipv4-top200.txt`、`cf-ipv4-top400.txt`。

## 数据文件

- `output/summary.json`：最近一次扫描时间、候选数量、可用数量及失败原因。
- `output/ipv4/all.json` / `all.csv`：完整 IPv4 检测数据。\n- `output/ipv6/source.json`：HostMonit IPv6 来源信息、更新时间及候选地址。\n- `output/ipv6/source.txt` / `all.txt`：IPv6 独立订阅。
- `output/ipv4/topN.json` / `topN.txt`：各排名的详细数据。
- 根目录 `*.txt`：适合客户端直接订阅的节点列表。

## 使用方法

1. 复制上方所需 Raw 地址。
2. 在支持自定义 URL 订阅的客户端中添加订阅。
3. 更新间隔由客户端自行设置；仓库端每 6 小时生成新文件。
4. 如果刚部署后尚未出现定时记录，可在 Actions 页面手动运行一次验证。

## 空结果保护

如果 IPv4 扫描没有找到可用 IP，或 HostMonit 返回空数据/接口异常，程序都会保留对应家族上一次有效订阅文件。IPv6 同步失败不会阻断 IPv4 更新。下一次定时任务仍会继续扫描。

## 注意

可用数量取决于 Cloudflare 边缘路由及 GitHub Actions Runner 的网络环境；TOP 400 表示最多输出 400 条，不会用虚假 IP 补齐。扫描结果不保证在所有地区、运营商或代理客户端中都可用。
