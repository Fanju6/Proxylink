# Proxylink 开发文档

本文档介绍了 `Proxylink` 项目的代码目录结构及其各模块的功能，方便开发者理解与维护。

## 目录结构

```text
Proxylink/
├── main.go             # 命令行工具入口，处理参数解析与流程调优
├── go.mod              # 项目 Go Module 定义
└── pkg/                # 核心功能包
    ├── model/          # 基础数据模型
    │   ├── config_type.go   # 协议类型定义 (VMess, VLESS, SS 等)
    │   ├── network_type.go  # 传输网络类型定义 (TCP, WS, GRPC 等)
    │   └── profile.go       # ProfileItem 核心结构，统一存储节点配置
    ├── parser/          # 协议解析器
    │   ├── parser.go        # 统一解析入口 (Parse / ParseBatch)
    │   ├── base.go          # 解析通用辅助工具
    │   └── vless.go...      # 针对各协议 (VLESS, VMess, SS, Trojan, Socks, WG, HY2) 的具体实现
    ├── encoder/         # 协议生成器
    │   └── encoder.go       # 将 ProfileItem 编码回 URI 格式
    ├── generator/       # 配置生成器
    │   └── xray.go          # 生成 Xray 出站 (Outbound) 配置
    ├── subscription/    # 订阅处理
    │   ├── fetcher.go       # 处理订阅链接的 HTTP 获取
    │   ├── decoder.go       # 处理订阅内容的 Base64 解码
    │   └── converter.go     # 订阅转换逻辑 (获取 -> 解码 -> 解析)
    └── util/            # 通用工具
        ├── base64.go        # Base64 编解码增强版
        ├── http.go          # HTTP 客户端封装 (支持自定义 User-Agent, DNS)
        └── url.go           # URL 参数处理工具
```

## 模块说明

### 1. `pkg/model`
作为项目的基础，定义了统一的 `ProfileItem` 结构。无论输入是何种协议，解析后都会转换为 `ProfileItem`，配置生成时也以此为准。这样实现了协议解析与配置生成的解耦。

### 2. `pkg/parser`
解析模块。采用工厂模式思想：
- 各协议解析器（如 `vless.go`）负责处理特定前缀的链接。
- `parser.go` 作为主入口，自动识别协议头并分发给对应的子解析器。

### 3. `pkg/generator`
生成模块。目前主要负责 `xray` 格式的生成：
- `xray.go`：将 `ProfileItem` 转换为 Xray-core 可以直接识别的 JSON 对象结构，对标 `v2rayNG` 的生成逻辑。

### 4. `pkg/subscription`
处理批量节点获取的任务：
- 支持 Base64 编码的传统订阅格式。
- `fetcher` 支持自定义 DNS 解析（应对 Android 端的 DNS 兼容性问题）和自定义 User-Agent。

### 5. `pkg/util`
存放不包含具体业务逻辑的底层函数，如特殊的 Base64 补齐填充、针对特定平台的 HTTP 处理等。

---