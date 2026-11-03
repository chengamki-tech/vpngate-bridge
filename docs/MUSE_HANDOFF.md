# Muse 接手：VPNGate Bridge

用户已明确要求 Muse 接手剩余项目，并指定通过 Muse MCP 派发。Codex 停止功能修改，避免双写；本目标尚未完成。

## 仓库与当前状态

- 本机：`/Users/amki/Documents/ChatGPT/Google/vpngate-bridge`
- 公共仓库：https://github.com/chengamki-tech/vpngate-bridge
- 分支：`main`；交接时实现基线：`99e9a47f0b0ea3f6ee29c5b412417ba54773d16c`。
- 独立嵌套 Git 仓库。不要修改父目录其他项目，也不要改相邻 `3x-ui` 参考源码。
- 用户已授权创建开源项目及推送 GitHub。不要发布状态目录、订阅密钥、证书私钥、面板密码或 cookies。
- 本机是 macOS、没有 Docker；真实 Docker/VPN 验收在 GitHub Actions Linux runner 执行。

## 不可改变的原始要求

`fetcher -> prober -> gateway -> bridge -> sub-gen`，另有 healer。

1. VPNGate OpenVPN 不能直接塞进 3x-ui/Xray。转换必须经过独立 OpenVPN 网关的内部 SOCKS5，由 sing-box 提供 VLESS+WS+TLS 和 Hysteria2；3x-ui 只做 client、流量及到期管理。
2. 从 API 动态发现所有国家；只启用合格节点的国家，不写死名单。
3. 淘汰连接失败、超时 >10 秒、出口国家不符、hosting=true、重复出口。按延迟 30%、速度 30%、三次稳定性测量 25%、在线时长 15% 评分；每国保留最佳合格出口。持久化失败网段，避免换端口重新入选。
4. 每国一个活动 OpenVPN Docker 网关，SOCKS5 只对内；自动分配端口并记录清单；有 CPU、内存、活动国家数上限。
5. healer 每十分钟检查，连续两次失败后重扫同国并替换网关，入站参数和订阅链接不变。
6. 交付可订阅的开源项目到 GitHub。目标是住宅出口候选；非 hosting 分类并不能证明住宅所有权，不要宣称保证住宅或 SLA。

## 已实现及证据

- 动态 fetch、严格 OpenVPN 配置白名单、隔离探测、评分/网段黑名单、端口持久化、活动网关池、固定私有 TCP SOCKS 转送器。
- sing-box 双协议/TLS 配置及订阅生成、HMAC 订阅 HTTP、3x-ui 登录/CSRF/流量绝对值同步、SQLite 累计计数、gRPC 收集、短租约守护与失效停机。
- Linux 服务入口 `python3 -m vpngate_bridge.service` 已接入扫描、激活、router、bridge、订阅及 healer；有 systemd/Nginx 模板。
- [41444855011](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41444855011)：两个不同 JP 节点真实替换，两协议可继续使用，sing-box 未重启、订阅未改变。
- [41486745887](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41486745887)：真实服务、Nginx HTTPS 订阅、两个 TLS 客户端、VPNGate 出口、3x-ui 计量和退出清理全部通过。
- 最新本机：72 项 Python 测试通过；3 项 Go final-stats 测试通过 `-race`。
- 最新一般 CI [41564221222](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41564221222) 通过，含 Docker 镜像及 sing-box 配置检查。

## 正在完成的正常重启结算

提交 `99e9a47` 加入最终流量快照，尚未完成真实跨重启验收：

- `bridge/final_stats.go`：在被计量的 TCP/packet I/O 外加 RWMutex 门，关闭后冻结，等待在途计量结束，再输出原子、私有、带 run UUID 的快照。隐藏 Upstream/可替换快路径以防计量绕过；不支持的 TUN flow 不生成可靠快照。
- `bridge/patch_singbox.py`：只允许精确上游提交 `c005f35300ce76427dc285481ec5695f5b179cd2`，验证原始文件及精确插入位置；在网络/连接关闭之后的 v2ray cleanup 写最终计数。
- `bridge/Dockerfile`：构建时注入扩充及运行 Go 测试；镜像保留上游 GPL 许可证。控制器代码为 MIT，构建的 sing-box 仍受其上游许可约束。
- `final_stats.py` 严格核对大小、JSON 重复字段、run UUID、完整用户名单及整数范围。
- `runtime.py`：撤销租约、停止容器，验证已停止且代次未变、非 OOM/强杀，再读取最终快照、关闭账本并同步最终流量。无可靠快照则保留未确认状态；不要删除账本或伪造 `quiesced=True` 绕过。
- `sync.py` 同步前先验证固定客户身份，防止向已改变的 UUID/subId 推送旧流量。
- `gateway/service_live_check.py` 已扩成同一状态连续启动两次，要求累计流量递增、最终流量同步、订阅参数不变及完整清理。

最新真实验收 [41564240258](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41564240258) 已终止为失败，**不是运行中**。两镜像构建成功，Go 扩充测试成功；但八个临时候选在初始扫描没有留下合格节点，因此尚未进入重启验收。不要误称重启已通过，也不要为通过而放宽节点淘汰条件。先查看失败日志，再在有合格志愿节点时重跑或改善样本选择。

## 接下来优先做

1. 真实验证最终快照及两次服务启动。修复实际出现的问题，不能只凭单元测试宣布可恢复。更新 README、accounting/deployment 文档中落后的“正常停机不可重启”描述，注明已证实及未证实边界。
2. 基于已结算的正常代次实现 client 变更、启停、到期/额度耗尽后的配置重建；不要因为一个用户到期而永久停止其他用户。保留国家端口与现有合法用户订阅。
3. 面板续期/流量重置的可审计代次与对账、客户身份持久化绑定、会话重新登录；当前只支持固定 roster 和 bridge-only 面板，所有 Xray 入站必须禁用。并发管理变更还没有 CAS 保证。
4. 按部署实例归属恢复/清理孤儿网关；当前只有按容器名匹配的拥有标签，禁止粗暴删除同主机上其他实例的所有 vgb 容器。硬崩溃没有最终快照时不得默认为零流量。
5. 实现目的端 UDP：现在仅支持 SOCKS TCP CONNECT；Hysteria2 的 QUIC 传输成功不等于 UDP 目的端已实现。保持 DNS/IPv6/隧道断开时 fail-closed。
6. 证书轮换、长时间负载/资源上限、真实 10 分钟 ×2 healer 失效替换验收。当前 bind-mount 证书文件不能据此声称原子替换/ACME 轮换已通过。
7. 按原始要求逐项审计后再发布完成声明；目前仍为 WIP，不是生产就绪。没有指定真实 VPS/域名，不能把本地 CA/loopback 验收当成公共 DNS/证书部署完成。

## 常用命令

```sh
python3 -m unittest discover -s tests -q
git status --short
gh workflow run live-service.yml
gh workflow run live-stack.yml
gh run view RUN_ID --json status,conclusion,jobs
gh run view RUN_ID --log-failed
```

本机临时参考源码 `/tmp/vgb-singbox-final` 已应用扩充；可运行 `go test -race ./experimental/v2rayapi -run '^TestFinal' -count=1`。若目录不存在，按 Dockerfile 的固定提交重新克隆并运行 patcher。原始 `3x-ui` 参考目录只读；不要把 OpenVPN 配置写进其 Xray。

Muse 请先确认能访问仓库及具备实际执行/推送能力，再继续第一项；若缺少权限或本机访问能力，明确说明边界，不要索要聊天明文密码或 cookies。沿用已授权的 GitHub 发布范围。请回复接手确认，以便用户区分“已派发”和“已开始执行”。
