# Cloudflare-IP-Auto V4.0（中国大陆运营商分组双栈订阅）

项目面向中国大陆用户。IPv4 与 IPv6 分别检测、分别验证，最终按运营商合并为四份双栈订阅。GitHub Actions 每 12 小时自动更新。

## 自动更新

- 定时任务：UTC 每天 00:17、12:17（北京时间每天 08:17、20:17）。
- 可在仓库 **Actions → Update Cloudflare IPs (IPv4 + IPv6 China verified) → Run workflow** 手动运行。
- 工作流先运行测试，测试通过后执行扫描并更新订阅。
- 定时任务在默认分支 `main` 上运行；GitHub Actions 可能因排队略有延迟。

## 国内运营商验证规则

- 电信（CT）、联通（CU）、移动（CM）分别独立判断是否合格。
- 某运营商至少需要 2 个不同的中国大陆探针 HTTPS 验证成功，且该运营商 TCP RTT 中位数不超过 300 ms。
- IPv4 和 IPv6 分别进行国内探测，不能用 IPv4 的测试结果替代 IPv6，反之亦然。
- 某个运营商的订阅只收录通过该运营商验证的地址；联通+移动综合订阅只收录同时通过 CU 和 CM 的地址，不要求电信也通过。
- 同一 IP 可以同时出现在多份订阅中。订阅不按固定 20/50/100/200 数量截断，实际有多少合格地址就发布多少。
- 探针不足、数据过期或测试失败的 IP 不进入相应订阅。某轮没有合格地址时，对应订阅清空，不沿用未经本轮有效验证的旧地址。

## 四份正式订阅（IPv4 + IPv6）

| 订阅 | 准入条件 | Raw 地址 |
|---|---|---|
| 中国电信 | CT 单网合格 | [china-ct.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-ct.txt) |
| 中国联通 | CU 单网合格 | [china-cu.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cu.txt) |
| 中国移动 | CM 单网合格 | [china-cm.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cm.txt) |
| 联通 + 移动 | CU、CM 同时合格 | [china-cu-cm.txt](https://raw.githubusercontent.com/rsmfcs/cf-IP/main/china-cu-cm.txt) |

四份文件均同时包含通过对应门槛的 IPv4 和 IPv6。IPv6 节点使用标准方括号格式，例如 `[2606:4700::1]:443#美国`。

## 检测与数据说明

- IPv4：从 Cloudflare 官方 IPv4 网段采样，执行 TCP 443、TLS、HTTP、稳定性和速度检测，再进行中国大陆运营商验证。
- IPv6：汇总 HostMonit、WeTest、CMLiu 等候选源，并通过 Cloudflare 官方 IPv6 CIDR 清单校验；候选源本身不代表可用，必须再通过 Globalping 国内 IPv6 实测。
- GeoIP 仅用于订阅中的地区文字标注，不代表每位用户实际连接到的 Cloudflare 边缘机房。
- Globalping 每轮探针分配受公共额度、Token 额度和探针在线情况影响；不满足验证门槛时宁可不发布。

## 其他文件

- `all.txt`：联通+移动双网订阅的兼容别名，与 `china-cu-cm.txt` 内容相同。
- `fast.txt`、`stable.txt`：仅 IPv4 的辅助测速列表，不属于四份正式双栈订阅。
- `output/summary.json`：最近一次扫描时间、候选数量、各运营商合格数量和运行状态。
- `output/ipv4/all.json`、`all.csv`：完整 IPv4 检测数据。
- `output/ipv6/source.json`、`source.txt`：IPv6 候选来源诊断数据，未经验证，不是订阅。
- `output/ipv6/all.json`：完整 IPv6 国内探测结果。
- `output/china-probe/history.json`、`ipv6-history.json`：IPv4、IPv6 独立的国内探测历史。

## 使用方法

1. 选择上方与你的运营商对应的 Raw 订阅地址。
2. 在支持 URL 订阅的客户端中添加。
3. 客户端更新间隔自行设置；仓库每 12 小时生成新数据。

## 注意

Cloudflare Anycast 的路由会随时间和地区变化。测试结果是本轮探针环境下的实测结果，不保证所有省份、地区和网络线路的体验完全一致。