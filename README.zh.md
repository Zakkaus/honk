<div align="center">

# honk

**用 Rust 编写的实验性 Linux 透明代理引擎。**

**[文档](doc/README.md)** / **[网页界面示范](https://demo.daeuniverse.org/)** / **[下载](https://github.com/daeuniverse/honk/releases)**

[English](README.md) / 简体中文

[功能概览](#功能概览) / [安装](#安装) / [网页界面](#网页界面) / [报告问题](#报告问题)

</div>

> **早期 alpha，不建议用于生产。** 可能发生破坏性变更，部分功能尚未完成，真实环境验证仍然有限。

honk 的 eBPF 数据面和配置语法参考 dae 的设计，出站组与 Clash API 参考 sing-box 的设计。它是独立实现，并非任一项目的移植。

## 功能概览

- 透明 TCP/UDP：通过 TC eBPF、`dae0`/`daens` 和编译路由处理 LAN 转发及本机发起的流量。
- 出站：SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess、VLESS、`direct` 和 `block`。Trojan/VMess/VLESS 支持 H2 XHTTP（`packet-up`、`stream-up`、`stream-one`）；VMess 仅支持 TCP。详见[协议限制](doc/zh/reference/nodes.md)。
- 组策略：Selector（默认）、URLTest、LoadBalance、Fallback 和 Score。Score 使用业务观测与有界验证，详见[组策略参考](doc/zh/reference/groups.md#score-策略)。
- DNS：支持 UDP、TCP、DoT、DoH、DoQ、DoH3 上游，可经节点或组出站，并提供路由和缓存。
- 配置与控制：dae 语法、订阅、重载、Clash 兼容 REST/WebSocket API，以及 `honk-tool` CLI 工具箱。

不提供 FakeIP 引擎、完整 mihomo 兼容性或 Windows/macOS 数据面。

## 安装

从 [Releases](https://github.com/daeuniverse/honk/releases) 下载适合目标平台的归档。提供 x86_64 与 aarch64 Linux 版本；不确定时选 `full`。

| 构建 | 原生 API | Clash API | 内嵌 doona 与 doona lite |
| --- | --- | --- | --- |
| `full` | 是 | 是 | 是 |
| `native-api` | 是 | 否 | 否 |
| `clash-api` | 否 | 是 | 否 |

每种构建都有静态链接的 musl 版本，`full` 另有链接 glibc 的 `gnu` 版本。名称含 `stock` 的归档使用系统分配器而非 mimalloc。每个版本的 Downloads 一节列出校验和及构建来源证明。

OpenWrt 用户可使用 [daeuniverse 软件源](https://openwrt.daeuniverse.org/zh-cn/)。

自行编译请按[从源码构建](doc/zh/how-to-start.md#从源码构建)准备。发布二进制内嵌 eBPF；仅执行 `cargo build --release` 不会启用真实数据面。

按[启动指南](doc/zh/how-to-start.md)检查内核、安装程序并验证连通性。首次部署会修改网络 hook、命名空间和 sysctl，须保留带外管理通道。

## 网页界面

honk 支持两类网页界面：

- [doona](https://github.com/Zakkaus/doona) 使用原生 API，可查看观测数据、诊断并编辑配置。doona lite 是较轻量的预览版。可先体验[演示版](https://demo.daeuniverse.org/)或 [lite 演示版](https://demo.daeuniverse.org/lite/)。
- [zashboard](https://github.com/Zephyruso/zashboard) 等 Clash 面板使用 Clash 兼容 API。

![doona 活动页的流量图表与状态卡片](https://doona.daeuniverse.org/screenshots/zh-CN/activity-light.webp)

![doona lite 节点页](https://doona.daeuniverse.org/images/lite-nodes-light.webp)

使用 `full` 构建时，启用 `experimental.native_api` 并设置 `ui: 'embedded'`；使用 doona lite 时设置 `ui: 'embedded-lite'`，步骤见 [doona 快速入门](https://doona.daeuniverse.org/zh-CN/quick-start.html)。使用 Clash 面板时设置 `experimental.clash_api`，honk 首次启动时会下载 zashboard。两者的设置项见 [experimental 设置](doc/zh/reference/experimental.md)。

## 文档

[文档索引](doc/README.md)汇总中英文配置指南、原生与 Clash API 参考、子系统设计及运维指南。

## 版本与兼容性

- 自 `v0.1.0` 起，发布遵循 [SemVer](https://semver.org/lang/zh-CN/)；带 `-alpha.N`、`-beta.N` 或 `-rc.N` 后缀的标签为预发布。`1.0` 之前，次版本可能改变配置或行为，升级前应阅读发布说明。
- 透明代理需要 root 权限、Linux 6.12+、所需内核选项和 bpffs。发布目标为 `x86_64` 与 `aarch64`，支持 gnu 或 musl，详见上方链接的启动指南。
- 配置使用 [dae 语法](doc/zh/configuration.md)。修改已有部署前，请查阅 [NFQUEUE 运行说明](doc/zh/design/nfqueue.md)和 [VLESS 迁移指南](doc/zh/reference/nodes.md#从-vless_mode-迁移)。
- 原生 API 使用 `/api/v1`，其契约在 `1.0` 之前可能随次版本变化。`GET /api/v1/version` 返回契约标识。

## 开发

工作区包含配置、共享 eBPF 类型、NFQUEUE、出站、核心和工具 crate；`crates/honk-ebpf` 单独构建。详见 [Justfile](Justfile) 与[贡献政策](CONTRIBUTING.md)。

无 root 的用户态开发可使用 [mock 模式](doc/zh/how-to-start.md#无-root-开发)。`--mock-ebpf` 不会拦截流量，不能代替数据面测试。

滚动的 [Debug 预发布](https://github.com/daeuniverse/honk/releases/tag/debug)提供来自 `main` 的最新 `debug.*` 测试构建。它们使用 release profile，并非 Cargo debug profile；保留期限与发布流程见[发布规则](.agents/rules/release.md)。

## 报告问题

代理、路由和 DNS 问题请到 [honk issues](https://github.com/daeuniverse/honk/issues) 提交；网页界面问题请到 [doona issues](https://github.com/Zakkaus/doona/issues) 提交。

安全漏洞请按 [SECURITY.md](.github/SECURITY.md) 报告。

## 致谢

- [dae](https://github.com/daeuniverse/dae) / daed-rs：eBPF 透明代理谱系
- [sing-box](https://github.com/SagerNet/sing-box)：出站组与 Clash API 模式
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound)：协议参考
- [juicity-rs](https://github.com/juicity/juicity-rs)（Markson Pigeonzilla Plus）：Juicity 协议参考、wire 格式对齐及真实互通测试
- [aya-rs](https://github.com/aya-rs/aya)：Rust eBPF

## 许可证

[GPL-3.0-only](LICENSE)。

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```

仅用于开发的 [dae 解析器 oracle](tools/dae-parse/README.md)链接了 dae（AGPL-3.0-only）。它不随发布物分发，也不链接进 `honk-core`。

## TODO

- [ ] 评估 AF_XDP 与 XDP 路径以进一步提升性能
- [ ] 在 Clash 兼容 API 之外添加 honk 专用 REST API
- [ ] 添加入站支持
- [ ] 探索 macOS 与 Windows 支持；数据面基于 Linux eBPF，这两个平台需要另一种接管流量的方式
