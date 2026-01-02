package parser

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseVLess 解析 VLESS 链接
// 格式: vless://uuid@server:port?type=ws&security=tls&sni=xxx#remarks
func ParseVLess(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.VLESS)

	// 基础信息
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.Password = u.User.Username() // UUID

	// 加密方式
	query := u.Query()
	config.Method = query.Get("encryption")
	if config.Method == "" {
		config.Method = "none"
	}

	// 解析通用参数
	parseQueryParams(config, query)

	return config, nil
}

// ToVLessURI 生成 VLESS 链接
func ToVLessURI(config *model.ProfileItem) string {
	query := buildQueryParams(config)
	query.Set("encryption", config.Method)
	if query.Get("encryption") == "" {
		query.Set("encryption", "none")
	}

	return buildURI("vless://", config.Password, config, query)
}

// VmessQRCode VMess JSON 格式
type VmessQRCode struct {
	V        string `json:"v"`
	Ps       string `json:"ps"`
	Add      string `json:"add"`
	Port     string `json:"port"`
	ID       string `json:"id"`
	Aid      string `json:"aid"`
	Scy      string `json:"scy"`
	Net      string `json:"net"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	TLS      string `json:"tls"`
	SNI      string `json:"sni"`
	Alpn     string `json:"alpn"`
	Fp       string `json:"fp"`
	Insecure string `json:"insecure"`
}

// ParseVMess 解析 VMess 链接
// 支持两种格式:
// 1. vmess://base64(json) - 标准格式
// 2. vmess://uuid@server:port?... - 类似 VLESS 的格式
func ParseVMess(uri string) (*model.ProfileItem, error) {
	// 移除 scheme
	content := strings.TrimPrefix(uri, "vmess://")

	// 尝试 Base64 解码 (标准 vmess 格式)
	decoded, err := util.Base64Decode(content)
	if err == nil && strings.Contains(decoded, "\"") {
		return parseVMessJSON(decoded)
	}

	// 尝试类似 VLESS 的格式
	return parseVMessStd(uri)
}

// parseVMessJSON 解析 JSON 格式的 VMess
func parseVMessJSON(jsonStr string) (*model.ProfileItem, error) {
	config := model.NewProfileItem(model.VMESS)

	var qr VmessQRCode
	if err := json.Unmarshal([]byte(jsonStr), &qr); err != nil {
		// 回退到手动解析
		return parseVMessJSONManual(jsonStr)
	}

	config.Server = qr.Add
	config.ServerPort = qr.Port
	config.Password = qr.ID
	config.Remarks = util.URLDecode(qr.Ps)
	if config.Remarks == "" {
		config.Remarks = "none"
	}

	// 安全类型
	config.Method = qr.Scy
	if config.Method == "" {
		config.Method = "auto"
	}

	// AlterId
	if qr.Aid != "" {
		if aid, err := strconv.Atoi(qr.Aid); err == nil {
			config.AlterId = aid
		}
	}

	// 网络类型
	config.Network = qr.Net
	if config.Network == "" {
		config.Network = "tcp"
	}
	config.HeaderType = qr.Type
	config.Host = qr.Host
	config.Path = qr.Path

	// 特殊网络类型处理
	switch config.Network {
	case "kcp":
		config.Seed = qr.Path
	case "grpc":
		config.Mode = qr.Type
		config.ServiceName = qr.Path
		config.Authority = qr.Host
	}

	// TLS
	if qr.TLS == "tls" {
		config.Security = "tls"
	}
	config.SNI = qr.SNI
	config.Fingerprint = qr.Fp
	config.ALPN = qr.Alpn
	config.Insecure = qr.Insecure == "1"

	return config, nil
}

// parseVMessJSONManual 手动解析 VMess JSON (兼容格式)
func parseVMessJSONManual(jsonStr string) (*model.ProfileItem, error) {
	config := model.NewProfileItem(model.VMESS)

	config.Server = extractJSONField(jsonStr, "add")
	config.ServerPort = extractJSONField(jsonStr, "port")
	config.Password = extractJSONField(jsonStr, "id")
	config.Remarks = util.URLDecode(extractJSONField(jsonStr, "ps"))
	if config.Remarks == "" {
		config.Remarks = "none"
	}

	config.Method = extractJSONField(jsonStr, "scy")
	if config.Method == "" {
		config.Method = "auto"
	}

	config.Network = extractJSONField(jsonStr, "net")
	if config.Network == "" {
		config.Network = "tcp"
	}
	config.HeaderType = extractJSONField(jsonStr, "type")
	config.Host = extractJSONField(jsonStr, "host")
	config.Path = extractJSONField(jsonStr, "path")

	// TLS
	if extractJSONField(jsonStr, "tls") == "tls" {
		config.Security = "tls"
	}
	config.SNI = extractJSONField(jsonStr, "sni")
	config.Fingerprint = extractJSONField(jsonStr, "fp")
	config.ALPN = extractJSONField(jsonStr, "alpn")

	return config, nil
}

// parseVMessStd 解析类似 VLESS 格式的 VMess
func parseVMessStd(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.VMESS)

	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.Password = u.User.Username()
	config.Method = "auto"

	query := u.Query()
	parseQueryParams(config, query)

	return config, nil
}

// extractJSONField 从 JSON 字符串中提取字段值 (简单实现)
func extractJSONField(jsonData, field string) string {
	patterns := []string{
		`"` + field + `":"`,
		`"` + field + `": "`,
		`"` + field + `":`,
	}

	for _, pattern := range patterns {
		idx := strings.Index(jsonData, pattern)
		if idx == -1 {
			continue
		}

		start := idx + len(pattern)
		if start >= len(jsonData) {
			continue
		}

		if jsonData[start] == '"' {
			start++
			end := strings.Index(jsonData[start:], `"`)
			if end != -1 {
				return jsonData[start : start+end]
			}
		} else {
			end := strings.IndexAny(jsonData[start:], ",}")
			if end != -1 {
				value := strings.TrimSpace(jsonData[start : start+end])
				return strings.Trim(value, `"`)
			}
		}
	}

	return ""
}

// ToVMessURI 生成 VMess 链接 (JSON Base64 格式)
func ToVMessURI(config *model.ProfileItem) string {
	qr := VmessQRCode{
		V:    "2",
		Ps:   config.Remarks,
		Add:  config.Server,
		Port: config.ServerPort,
		ID:   config.Password,
		Aid:  strconv.Itoa(config.AlterId),
		Scy:  config.Method,
		Net:  config.Network,
		Type: config.HeaderType,
		Host: config.Host,
		Path: config.Path,
		SNI:  config.SNI,
		Fp:   config.Fingerprint,
		Alpn: config.ALPN,
	}

	if config.Security == "tls" {
		qr.TLS = "tls"
	}
	if config.Insecure {
		qr.Insecure = "1"
	}

	// 特殊网络处理
	switch config.Network {
	case "kcp":
		qr.Path = config.Seed
	case "grpc":
		qr.Type = config.Mode
		qr.Path = config.ServiceName
		qr.Host = config.Authority
	}

	jsonBytes, _ := json.Marshal(qr)
	return "vmess://" + util.Base64Encode(string(jsonBytes))
}
