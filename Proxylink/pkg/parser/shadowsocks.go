package parser

import (
	"net/url"
	"strings"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseShadowsocks 解析 Shadowsocks 链接
// 支持两种格式:
// 1. ss://base64(method:password)@server:port#remarks (SIP002)
// 2. ss://base64(method:password@server:port)#remarks (Legacy)
func ParseShadowsocks(uri string) (*model.ProfileItem, error) {
	// 尝试 SIP002 格式
	config, err := parseShadowsocksSIP002(uri)
	if err == nil {
		return config, nil
	}

	// 尝试 Legacy 格式
	return parseShadowsocksLegacy(uri)
}

// parseShadowsocksSIP002 解析 SIP002 格式
// ss://base64(method:password)@server:port?plugin=...#remarks
func parseShadowsocksSIP002(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.SHADOWSOCKS)
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()

	// 解码 userinfo
	userInfo := u.User.Username()
	if u.User != nil {
		if pwd, ok := u.User.Password(); ok {
			// 已经是 method:password 格式
			config.Method = userInfo
			config.Password = pwd
		} else {
			// Base64 编码的 method:password
			decoded, err := util.Base64Decode(userInfo)
			if err != nil {
				return nil, err
			}
			parts := strings.SplitN(decoded, ":", 2)
			if len(parts) == 2 {
				config.Method = parts[0]
				config.Password = parts[1]
			}
		}
	}

	// 解析插件参数
	if u.RawQuery != "" {
		query := u.Query()
		plugin := query.Get("plugin")
		if plugin != "" {
			parseSSPlugin(config, plugin)
		}
	}

	return config, nil
}

// parseSSPlugin 解析 Shadowsocks 插件参数
func parseSSPlugin(config *model.ProfileItem, plugin string) {
	if strings.Contains(plugin, "obfs=http") || strings.Contains(plugin, "obfs-local") {
		// 解析 obfs-http 插件
		config.Network = "tcp"
		config.HeaderType = "http"

		params := make(map[string]string)
		for _, pair := range strings.Split(plugin, ";") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}

		if host, ok := params["obfs-host"]; ok {
			config.Host = host
		}
		if path, ok := params["path"]; ok {
			config.Path = path
		}
	}
}

// parseShadowsocksLegacy 解析 Legacy 格式
// ss://base64(method:password@server:port)#remarks
func parseShadowsocksLegacy(uri string) (*model.ProfileItem, error) {
	content := strings.TrimPrefix(uri, "ss://")

	// 提取 remarks
	remarks := ""
	if idx := strings.Index(content, "#"); idx != -1 {
		remarks = util.URLDecode(content[idx+1:])
		content = content[:idx]
	}

	// Base64 解码
	decoded, err := util.Base64Decode(content)
	if err != nil {
		return nil, err
	}

	// 解析 method:password@server:port
	atIdx := strings.LastIndex(decoded, "@")
	if atIdx == -1 {
		return nil, err
	}

	methodPwd := decoded[:atIdx]
	serverPort := decoded[atIdx+1:]

	// 解析 method:password
	colonIdx := strings.Index(methodPwd, ":")
	if colonIdx == -1 {
		return nil, err
	}

	method := methodPwd[:colonIdx]
	password := methodPwd[colonIdx+1:]

	// 解析 server:port
	lastColonIdx := strings.LastIndex(serverPort, ":")
	if lastColonIdx == -1 {
		return nil, err
	}

	server := serverPort[:lastColonIdx]
	port := serverPort[lastColonIdx+1:]

	// 处理 IPv6
	server = strings.Trim(server, "[]")

	config := model.NewProfileItem(model.SHADOWSOCKS)
	config.Remarks = remarks
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = server
	config.ServerPort = port
	config.Method = method
	config.Password = password

	return config, nil
}

// ToShadowsocksURI 生成 Shadowsocks 链接 (SIP002 格式)
func ToShadowsocksURI(config *model.ProfileItem) string {
	userInfo := util.Base64EncodeURL(config.Method + ":" + config.Password)
	host := util.GetIPv6Address(config.Server) + ":" + config.ServerPort

	remarks := ""
	if config.Remarks != "" {
		remarks = "#" + util.URLEncode(config.Remarks)
	}

	return "ss://" + userInfo + "@" + host + remarks
}
