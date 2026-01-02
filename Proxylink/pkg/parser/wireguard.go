package parser

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseWireGuard 解析 WireGuard 链接
// 格式: wireguard://privateKey@server:port?publickey=xxx&address=xxx&mtu=xxx#remarks
func ParseWireGuard(uri string) (*model.ProfileItem, error) {
	// 统一 scheme
	uri = strings.Replace(uri, "wg://", "wireguard://", 1)

	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.WIREGUARD)

	// 基础信息
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.SecretKey = u.User.Username() // 私钥

	// 解析查询参数
	query := u.Query()
	config.PublicKey = query.Get("publickey")
	if config.PublicKey == "" {
		config.PublicKey = query.Get("peer") // 兼容其他格式
	}
	config.LocalAddress = query.Get("address")
	if config.LocalAddress == "" {
		config.LocalAddress = "10.0.0.2/32" // 默认值
	}
	config.Reserved = query.Get("reserved")
	if config.Reserved == "" {
		config.Reserved = "0,0,0" // 默认值
	}
	config.PreSharedKey = query.Get("presharedkey")

	// MTU
	if mtuStr := query.Get("mtu"); mtuStr != "" {
		if mtu, err := strconv.Atoi(mtuStr); err == nil {
			config.MTU = mtu
		}
	} else {
		config.MTU = 1420 // 默认值
	}

	return config, nil
}

// ParseWireGuardConf 解析 WireGuard 配置文件格式
func ParseWireGuardConf(confContent string) (*model.ProfileItem, error) {
	config := model.NewProfileItem(model.WIREGUARD)

	interfaceParams := make(map[string]string)
	peerParams := make(map[string]string)

	var currentSection string

	for _, line := range strings.Split(confContent, "\n") {
		line = strings.TrimSpace(line)

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 检测 section
		if strings.HasPrefix(strings.ToLower(line), "[interface]") {
			currentSection = "Interface"
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "[peer]") {
			currentSection = "Peer"
			continue
		}

		// 解析键值对
		if currentSection != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				value := strings.TrimSpace(parts[1])

				switch currentSection {
				case "Interface":
					interfaceParams[key] = value
				case "Peer":
					peerParams[key] = value
				}
			}
		}
	}

	// 填充配置
	config.SecretKey = interfaceParams["privatekey"]
	config.Remarks = strconv.FormatInt(time.Now().UnixMilli(), 10) // 时间戳作为默认备注
	config.LocalAddress = interfaceParams["address"]
	if config.LocalAddress == "" {
		config.LocalAddress = "10.0.0.2/32"
	}

	// MTU
	if mtuStr := interfaceParams["mtu"]; mtuStr != "" {
		if mtu, err := strconv.Atoi(mtuStr); err == nil {
			config.MTU = mtu
		}
	} else {
		config.MTU = 1420
	}

	// Peer 配置
	config.PublicKey = peerParams["publickey"]
	if psk := peerParams["presharedkey"]; psk != "" {
		config.PreSharedKey = psk
	}

	// Endpoint
	endpoint := peerParams["endpoint"]
	if endpoint != "" {
		// 解析 server:port
		lastColon := strings.LastIndex(endpoint, ":")
		if lastColon != -1 {
			config.Server = endpoint[:lastColon]
			config.ServerPort = endpoint[lastColon+1:]
		} else {
			config.Server = endpoint
		}
	}

	// Reserved
	config.Reserved = peerParams["reserved"]
	if config.Reserved == "" {
		config.Reserved = "0,0,0"
	}

	return config, nil
}

// ToWireGuardURI 生成 WireGuard 链接
func ToWireGuardURI(config *model.ProfileItem) string {
	query := url.Values{}

	query.Set("publickey", config.PublicKey)
	if config.Reserved != "" {
		query.Set("reserved", strings.ReplaceAll(config.Reserved, " ", ""))
	}
	query.Set("address", strings.ReplaceAll(config.LocalAddress, " ", ""))
	if config.MTU > 0 {
		query.Set("mtu", strconv.Itoa(config.MTU))
	}
	if config.PreSharedKey != "" {
		query.Set("presharedkey", strings.ReplaceAll(config.PreSharedKey, " ", ""))
	}

	host := util.GetIPv6Address(config.Server) + ":" + config.ServerPort

	queryStr := ""
	if len(query) > 0 {
		queryStr = "?" + query.Encode()
	}

	remarks := ""
	if config.Remarks != "" {
		remarks = "#" + util.URLEncode(config.Remarks)
	}

	return "wireguard://" + util.URLEncode(config.SecretKey) + "@" + host + queryStr + remarks
}
