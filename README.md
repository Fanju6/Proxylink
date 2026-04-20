# Proxylink

Proxylink 是一个用 Go 编写的代理链接解析和配置转换工具。它可以解析常见代理 URI、订阅内容、Clash YAML 和 Xray JSON，并输出标准化的 ProfileItem、Xray 配置、sing-box 配置或代理链接。

## 功能

- 解析 VLESS、VMess、Shadowsocks、Trojan、Socks、HTTP、WireGuard、Hysteria2、AnyTLS、TUIC 节点
- 支持从订阅 URL、文件、stdin、Clash YAML 和 Xray JSON 读取节点
- 支持输出 ProfileItem JSON、Xray 配置、sing-box 配置和 URI 链接
- 支持多节点批量转换，以及按节点拆分为多个文件
- 支持订阅请求跳过 TLS 证书验证和使用公共 DNS
- 支持 Xray JSON 反向解析为 ProfileItem 或 URI

## 构建

Go module 位于 `Proxylink/` 目录，构建前先进入该目录。

```bash
cd Proxylink

# Windows
go build -o proxylink.exe .

# Linux/macOS
go build -o proxylink .

# Linux ARM64
go env -w GOOS=linux GOARCH=arm64
go build -o proxylink-arm64 .
```

## 命令行

```bash
proxylink [选项] [链接]
```

常用输入方式：

```bash
# 解析单条链接
proxylink -parse "vless://uuid@example.com:443?type=ws#节点"

# 链接也可以直接作为位置参数传入
proxylink "vless://uuid@example.com:443#节点" -format xray

# 从文件批量解析，每行一条链接
proxylink -file nodes.txt -format singbox -o config.json

# 从 stdin 读取
cat nodes.txt | proxylink -format xray

# 拉取订阅并转换
proxylink -sub "https://example.com/sub" -format singbox -o config.json

# 从 Xray JSON 反向解析
proxylink -xray config.json -format uri
```

## 输出格式

| 参数 | 说明 |
| --- | --- |
| `-format json` | 输出内部 ProfileItem JSON，默认格式 |
| `-format xray` | 输出 Xray 配置，包含 `outbounds` |
| `-format singbox` | 输出 sing-box 配置，包含 `outbounds` |
| `-format uri` | 输出代理 URI 链接 |

## 选项

| 参数 | 说明 |
| --- | --- |
| `-parse <uri>` | 解析单条代理链接 |
| `-file <file>` | 从文件批量解析链接 |
| `-xray <file>` | 从 Xray JSON 配置文件反向解析节点 |
| `-sub <url>` | 从订阅 URL 拉取并解析节点 |
| `-o <file>` | 输出到单个文件 |
| `-dir <path>` | 将每个节点单独输出到指定目录 |
| `-auto` | 单节点输出时使用节点名作为文件名 |
| `-pretty` | 美化 JSON 输出，默认为 true |
| `-insecure` | 订阅请求跳过 TLS 证书验证 |
| `-dns` | 订阅请求使用内置公共 DNS |
| `-ua <value>` | 指定订阅请求 User-Agent；留空时会自动处理客户端版本提示 |
| `-h` | 显示帮助 |

`-insecure` 和 `-dns` 只影响 `-sub` 订阅拉取过程，不改变本地链接解析结果。

## 多文件输出

使用 `-dir` 时，每个节点会单独写入一个文件。文件名来自节点名，并会清理不允许的字符。

```bash
proxylink -file nodes.txt -format singbox -dir ./nodes
```

同名节点会自动追加序号，避免覆盖：

```text
./nodes/HK.json
./nodes/HK_2.json
./nodes/HK_3.json
```

当输出格式为 `singbox` 时，多文件输出里的 `tag` 会跟随同名节点逻辑：

```text
HK.json    -> "tag": "HK"
HK_2.json  -> "tag": "HK_2"
```

## sing-box 输出说明

`-format singbox` 会输出完整 sing-box 配置对象，而不是裸 outbound：

```json
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "节点名",
      "server": "example.com",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000"
    }
  ]
}
```

批量输出时，sing-box outbound 的 `tag` 使用节点名，并对同名节点追加 `_2`、`_3`：

```text
HK
HK_2
HK_3
```

普通 TCP 传输不会生成 sing-box 顶层 `network` 字段，也不会生成 TCP `transport`。这是为了保留 sing-box 默认的 TCP 和 UDP 支持，避免把 VLESS 分享链接里的 `type=tcp` 错误映射为 sing-box 的 `network: tcp`。

当前 sing-box 生成器支持以下协议：

- VLESS
- VMess
- Shadowsocks
- Trojan
- Hysteria2
- AnyTLS
- TUIC

当前 sing-box transport 支持：

- WebSocket: `type=ws`
- gRPC: `type=grpc`
- HTTP/HTTP2: `type=http` 或 `type=h2`
- HTTPUpgrade: `type=httpupgrade`

## Xray 输出说明

`-format xray` 会输出包含 `outbounds` 的 Xray 配置对象。

```bash
proxylink -parse "vless://uuid@example.com:443?type=ws#节点" -format xray
```

Xray 输出的 outbound tag 当前使用固定的 `proxy`。

## 代码调用

解析单条链接：

```go
package main

import (
    "fmt"
    "log"

    "proxylink/pkg/parser"
)

func main() {
    profile, err := parser.Parse("vless://uuid@example.com:443?type=ws#节点")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(profile.Server)
    fmt.Println(profile.ServerPort)
    fmt.Println(profile.ConfigType)
}
```

生成 sing-box 配置：

```go
import "proxylink/pkg/generator"

config, err := generator.GenerateSingboxOutbound(profile)
if err != nil {
    log.Fatal(err)
}
fmt.Println(config)
```

批量生成 sing-box 配置：

```go
config, err := generator.GenerateSingboxOutbounds(profiles)
if err != nil {
    log.Fatal(err)
}
fmt.Println(config)
```

订阅转换：

```go
import "proxylink/pkg/subscription"

converter := subscription.NewConverterFull(false, false)
result, err := converter.Convert("https://example.com/sub")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("成功: %d, 失败: %d\n", result.Success, result.Failed)
```

## 项目结构

```text
Proxylink/
├── README.md
├── Proxylink/
│   ├── go.mod
│   ├── main.go
│   └── pkg/
│       ├── encoder/        # URI 生成
│       ├── generator/      # Xray 和 sing-box 配置生成
│       ├── model/          # ProfileItem 和枚举定义
│       ├── parser/         # URI、Clash、Xray、WireGuard 解析
│       ├── subscription/   # 订阅拉取、解码和转换
│       └── util/           # 通用工具
└── DEVELOPMENT.md
```

## 支持的协议

| 协议 | Scheme 示例 |
| --- | --- |
| VLESS | `vless://uuid@server:443?type=ws#name` |
| VMess | `vmess://base64...` 或 `vmess://uuid@server:443?...` |
| Shadowsocks | `ss://method:password@server:8388#name` |
| Trojan | `trojan://password@server:443#name` |
| Socks | `socks://user:pass@server:1080#name` |
| HTTP | `http://user:pass@server:8080#name` |
| WireGuard | `wireguard://key@server:51820?...` 或 WireGuard `.conf` |
| Hysteria2 | `hysteria2://auth@server:443?sni=example.com#name` |
| AnyTLS | `anytls://password@server:443?sni=example.com#name` |
| TUIC | `tuic://uuid:password@server:443?sni=example.com#name` |
