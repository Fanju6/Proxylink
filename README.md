# Proxylink - 代理链接解析器

将 Xray 的节点链接解析用 Go 语言实现。

## 功能特性

- **链接解析**: 支持 8 种协议 (VMess/VLESS/SS/Trojan/Socks/HTTP/WireGuard/Hysteria2)
- **配置文件**: 支持解析 WireGuard 配置文件 (.conf)
- **链接生成**: ProfileItem → URI
- **配置生成**: ProfileItem → Xray JSON / Hysteria2 JSON
- **订阅转换**: 订阅 URL → 批量解析
- **命令行工具**: 支持管道、文件、订阅等多种输入方式

---

## 编译

```bash
# Windows
go build -o proxylink.exe .

# Linux/macOS
go build -o proxylink .

# 交叉编译 Linux ARM64 (适合 Android)
GOOS=linux GOARCH=arm64 go build -o proxylink-arm64 .
```

---

## 命令行使用

### 帮助信息

```bash
proxylink -h
```

### 解析单条链接

```bash
# 输出 ProfileItem JSON
proxylink -parse "vless://uuid@example.com:443?type=ws#节点"

# 输出 Xray 配置
proxylink -parse "vless://uuid@example.com:443?type=ws#节点" -format xray

# 输出 Hysteria2 配置
proxylink -parse "hysteria2://auth@hk.example.com:443?sni=bing.com#HK" -format hy2

# 直接传入链接作为参数
proxylink "vless://uuid@example.com:443#节点" -format xray
```

### 从文件批量解析

```bash
# 解析文件中的所有链接，输出 Xray 配置
proxylink -file nodes.txt -format xray -o outbounds.json

# 输出链接列表
proxylink -file nodes.txt -format uri
```

### 订阅转换

```bash
# 获取订阅并转换为 Xray 配置
proxylink -sub "https://example.com/sub" -format xray -o config.json

# 订阅转 Hysteria2 配置
proxylink -sub "https://example.com/sub" -format hy2
```

### 管道输入

```bash
# 从 stdin 读取
echo "vless://uuid@example.com:443?type=ws#节点" | proxylink -format xray

# 配合其他命令
cat nodes.txt | proxylink -format xray
```

### 输出格式

| 参数 | 说明 |
|------|------|
| `-format json` | ProfileItem JSON (默认) |
| `-format xray` | Xray 出站配置 |
| `-format hy2` | Hysteria2 原生配置 |
| `-format uri` | 生成链接 |

### 其他参数

| 参数 | 说明 |
|------|------|
| `-o <file>` | 输出到单个文件 |
| `-dir <path>` | 输出目录 (每个节点单独一个文件) |
| `-auto` | 自动使用 remarks 作为文件名 |
| `-port <port>` | Hysteria2 SOCKS 端口 (默认 1234) |
| `-pretty` | 美化 JSON 输出 (默认 true) |
| `-insecure` | 跳过 TLS 证书验证 |

### 多文件输出模式

```bash
# 解析单条，自动使用 remarks 作为文件名
proxylink -parse "vless://...#香港节点" -format xray -auto
# 输出: 香港节点.json

# 订阅转换，每个节点单独输出到指定目录
proxylink -sub "https://example.com/sub" -format xray -dir ./nodes
# 输出:
#   ./nodes/香港节点.json
#   ./nodes/日本节点.json
#   ./nodes/美国节点.json

# 从文件批量解析，每个节点单独输出
proxylink -file nodes.txt -format hy2 -dir ./configs
```

---

## 代码调用

### 解析单条链接

```go
import "proxylink/pkg/parser"

uri := "vless://uuid@example.com:443?type=ws&security=tls&sni=example.com#节点名"
profile, err := parser.Parse(uri)
if err != nil {
    log.Fatal(err)
}

fmt.Println(profile.Server)      // example.com
fmt.Println(profile.ServerPort)  // 443
fmt.Println(profile.ConfigType)  // vless
```

### 批量解析

```go
content := `vless://uuid@server1.com:443#节点1
trojan://pass@server2.com:443#节点2
ss://base64@server3.com:8388#节点3`

profiles, errs := parser.ParseBatch(content)
for _, p := range profiles {
    fmt.Printf("[%s] %s\n", p.ConfigType, p.Remarks)
}
```

### 生成 Xray 配置

```go
import "proxylink/pkg/generator"
import "encoding/json"

outbound := generator.GenerateXrayOutbound(profile)
jsonBytes, _ := json.MarshalIndent(outbound, "", "  ")
fmt.Println(string(jsonBytes))
```

### 生成 Hysteria2 配置

```go
// socksPort 是 Hysteria2 监听的本地端口
config := generator.GenerateHysteria2Config(profile, 1234)
jsonBytes, _ := json.MarshalIndent(config, "", "  ")
fmt.Println(string(jsonBytes))
```

### 生成链接

```go
import "proxylink/pkg/encoder"

uri := encoder.ToURI(profile)
fmt.Println(uri) // vless://uuid@example.com:443?...#节点名
```

### 订阅转换

```go
import "proxylink/pkg/subscription"

converter := subscription.NewConverter()
result, err := converter.Convert("https://example.com/sub")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("成功: %d, 失败: %d\n", result.Success, result.Failed)

for _, profile := range result.Profiles {
    outbound := generator.GenerateXrayOutbound(profile)
    // ...
}
```

---

## 项目结构

```
xray2json/
├── go.mod                     # module proxylink
├── main.go                    # CLI 入口
├── pkg/
│   ├── model/                 # 数据结构
│   │   ├── config_type.go     # 协议类型枚举
│   │   ├── network_type.go    # 传输类型枚举
│   │   └── profile.go         # ProfileItem 结构
│   │
│   ├── parser/                # 协议解析器
│   │   ├── parser.go          # 解析入口
│   │   ├── base.go            # 基础方法
│   │   ├── vless.go           # VLESS/VMess
│   │   ├── shadowsocks.go     # Shadowsocks
│   │   ├── trojan.go          # Trojan
│   │   ├── socks.go           # Socks
│   │   ├── http.go            # HTTP
│   │   ├── wireguard.go       # WireGuard
│   │   └── hysteria2.go       # Hysteria2
│   │
│   ├── encoder/               # 链接生成
│   │   └── encoder.go
│   │
│   ├── generator/             # 配置生成
│   │   ├── xray.go            # Xray 出站配置
│   │   └── hysteria2.go       # Hysteria2 原生配置
│   │
│   ├── subscription/          # 订阅处理
│   │   ├── fetcher.go         # HTTP 获取
│   │   ├── decoder.go         # Base64 解码
│   │   └── converter.go       # 转换器
│   │
│   └── util/                  # 工具函数
│       ├── base64.go
│       └── url.go
```

---

## 支持的协议

| 协议 | Scheme | 示例 |
|------|--------|------|
| VLESS | `vless://` | `vless://uuid@server:443?type=ws#name` |
| VMess | `vmess://` | `vmess://base64...` |
| Shadowsocks | `ss://` | `ss://base64@server:8388#name` |
| Trojan | `trojan://` | `trojan://pass@server:443#name` |
| Socks | `socks://` | `socks://user:pass@server:1080#name` |
| HTTP | `http://` | `http://user:pass@server:8080#name` |
| WireGuard | `wireguard://` | `wireguard://key@server:51820?...` |
| Hysteria2 | `hysteria2://` `hy2://` | `hysteria2://auth@server:443?sni=...#name` |
