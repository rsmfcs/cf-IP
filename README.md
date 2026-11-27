# Cloudflare-IP-Auto V3.9（中国三网准入验证 + IPv4/IPv6 双栈优选）

IPv4 扫描 Cloudflare 官方网段，IPv6 汇总 HostMonit、WeTest、CMLiu 等候选源；两种地址都必须通过中国大陆电信、联通、移动三网 HTTPS 实测后才进入正式订阅。GitHub Actions 每 6 小时自动更新。

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
- IPv4 使用 TCP 443 进行连通性、TLS、HTTP、稳定性和速度检测。
- IPv6 候选每 6 小时汇总 HostMonit、WeTest、CMLiu 等公开来源，并通过 Cloudflare 官方 IPv6 CIDR 清单校验；候选来源不代表可用，必须再经过 Globalping 国内三网 IPv6 HTTPS 实测。
- 国家/地区代码通过 GeoIP 查询补充，订阅行显示为 `IP:443#US 🇺🇸`。
- GeoIP 仅用于显示参考；Cloudflare Anycast 地址的归属地不代表每位用户实际连接到的边缘机房。GeoIP 查询失败时仍会保留节点，地区显示为 `ZZ 🌐`。

## 中国大陆三网准入验证

> V3.9 起，国内三网验证是 IPv4 订阅的强制准入门槛。

- 国内可用性是正式 IPv4 订阅的准入条件，不再是排序加分项。海外扫描通过但未完成国内验证的 IP，只保留在 `output/ipv4/all.json` 和 `all.csv` 诊断数据中，不进入 `all.txt`、`fast.txt`、`stable.txt` 或 TOP 订阅。
- 电信（AS4134）、联通（AS4837）、移动（AS9808）每个运营商最多请求 3 个中国大陆 eyeball-network 探针；每个运营商至少 2 个不同探针 HTTPS 验证成功，且该运营商 TCP 延迟中位数不超过 300 ms，才算该运营商合格。
- 通用 IPv4 订阅要求三家运营商全部合格；`china-ct.txt`、`china-cu.txt`、`china-cm.txt` 则分别要求对应运营商合格。探针不足、数据过期或测试失败的 IP 一律不进入正式订阅；若一轮扫描没有任何 IP 达标，订阅文件将保持为空，不沿用旧的未验证地址。
- 每 6 小时轮转最多 24 个候选，优先测试从未测试或最久未测试的 IP；验证记录保留最近 7 天，以便覆盖整个候选池。Globalping 探针数量属于尽力而为，无法保证每次都能分配到请求数量，因此不满足探针门槛时宁可不发布该 IP。
- 可选 GitHub Actions Secret：`GLOBALPING_TOKEN`。未配置时使用 Globalping 公共额度；可选变量 `CHINA_PROBE_BUDGET` 用于调整每轮候选数（默认 24，最大 30）。
- IPv6 与 IPv4 使用独立探测历史。电信、联通、移动各至少 2 个不同国内探针成功，且各自 TCP 延迟中位数不超过 300 ms，才进入 `ipv6.txt`；通用 IPv6 订阅必须三网全部合格。

## 订阅地址（Raw）

以下链接可直接复制到支持 URL 订阅的客户端：

| 订阅 | Raw 地址 |
|---|---|
| TOP 20 | [best-cf-ip-scanned-top20.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top20.txt) |
| TOP 50 | [best-cf-ip-scanned-top50.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top50.txt) |
| TOP 100 | [best-cf-ip-scanned-top100.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top100.txt) |
| TOP 200 | [best-cf-ip-scanned-top200.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top200.txt) |
| TOP 400 | [best-cf-ip-scanned-top400.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/best-cf-ip-scanned-top400.txt) |
| IPv4 + IPv6 综合订阅 | [all.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/all.txt) |
| 国内三网合格 IPv6 独立订阅 | [ipv6.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/ipv6.txt) |\n| 电信 IPv6 | [china-ct-ipv6.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-ct-ipv6.txt) |\n| 联通 IPv6 | [china-cu-ipv6.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cu-ipv6.txt) |\n| 移动 IPv6 | [china-cm-ipv6.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cm-ipv6.txt) |
| 高速节点（≥25 Mbps） | [fast.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/fast.txt) |
| 稳定节点（成功率 100%、抖动 ≤50 ms） | [stable.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/stable.txt) |
| 中国电信实测优选 | [china-ct.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-ct.txt) |
| 中国联通实测优选 | [china-cu.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cu.txt) |
| 中国移动实测优选 | [china-cm.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cm.txt) |

备用别名：`cf-ipv4-top20.txt`、`cf-ipv4-top50.txt`、`cf-ipv4-top100.txt`、`cf-ipv4-top200.txt`、`cf-ipv4-top400.txt`。

## 数据文件

- `output/summary.json`：最近一次扫描时间、候选数量、可用数量及失败原因。
- `output/ipv4/all.json` / `all.csv`：完整 IPv4 检测数据。
- 根目录 `all.txt` 合并三网全部合格的 IPv4 与 IPv6；`fast.txt`、`stable.txt` 和 TOP 系列保留 IPv4 扫描结果。任何未通过国内三网 IPv6 实测的地址都不会进入正式订阅。
- `output/ipv6/source.json`：HostMonit IPv6 来源信息、更新时间及候选地址。
- `output/ipv6/source.txt` / `all.txt`：IPv6 独立订阅。
- `output/ipv4/topN.json` / `topN.txt`：各排名的详细数据。
- 根目录 `*.txt`：适合客户端直接订阅的节点列表。

## 使用方法

1. 复制上方所需 Raw 地址。
2. 在支持自定义 URL 订阅的客户端中添加订阅。
3. 更新间隔由客户端自行设置；仓库端每 6 小时生成新文件。
4. 如果刚部署后尚未出现定时记录，可在 Actions 页面手动运行一次验证。

## 空结果保护

如果 IPv4 或 IPv6 本轮没有任何地址通过对应的国内准入门槛，该家族的正式订阅会清空，不沿用未经本轮有效验证的旧地址。IPv6 候选源异常不会阻断 IPv4 更新。

## 注意

可用数量取决于 Cloudflare 边缘路由及 GitHub Actions Runner 的网络环境；TOP 400 表示最多输出 400 条，不会用虚假 IP 补齐。扫描结果不保证在所有地区、运营商或代理客户端中都可用。
