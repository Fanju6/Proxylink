package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"proxylink/pkg/generator"
	"proxylink/pkg/model"
)

// ParseSingboxConfig 解析 sing-box 的 JSON 配置文件或单个出站配置
func ParseSingboxConfig(data []byte) ([]*model.ProfileItem, error) {
	// 尝试解析为完整的配置对象 (包含 outbounds 数组)
	var config generator.SingboxConfig
	err := json.Unmarshal(data, &config)
	if err == nil && len(config.Outbounds) > 0 {
		return parseOutbounds(config.Outbounds)
	}

	// 尝试解析为包含多个 outbound 的数组
	var outbounds []*generator.SingboxOutbound
	err = json.Unmarshal(data, &outbounds)
	if err == nil && len(outbounds) > 0 {
		return parseOutbounds(outbounds)
	}

	// 尝试解析为单个 outbound 对象
	var outbound generator.SingboxOutbound
	err = json.Unmarshal(data, &outbound)
	if err == nil && outbound.Type != "" && outbound.Server != "" {
		if p := fromSingboxOutbound(&outbound); p != nil {
			return []*model.ProfileItem{p}, nil
		}
	}

	return nil, fmt.Errorf("无法解析为有效的 sing-box 节点配置格式")
}

func parseOutbounds(outbounds []*generator.SingboxOutbound) ([]*model.ProfileItem, error) {
	var profiles []*model.ProfileItem
	for _, outbound := range outbounds {
		// 跳过直连或阻断等非代理出站
		if outbound.Type == "direct" || outbound.Type == "block" || outbound.Type == "dns" {
			continue
		}

		if p := fromSingboxOutbound(outbound); p != nil {
			profiles = append(profiles, p)
		}
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("未找到支持的代理出站配置")
	}

	return profiles, nil
}

// fromSingboxOutbound 将 sing-box 的 outbound 转换为 ProfileItem
func fromSingboxOutbound(ob *generator.SingboxOutbound) *model.ProfileItem {
	var configType model.ConfigType
	switch strings.ToLower(ob.Type) {
	case "vless":
		configType = model.VLESS
	case "vmess":
		configType = model.VMESS
	case "shadowsocks", "ss":
		configType = model.SHADOWSOCKS
	case "trojan":
		configType = model.TROJAN
	case "hysteria2", "hy2":
		configType = model.HYSTERIA2
	case "anytls":
		configType = model.ANYTLS
	case "tuic":
		configType = model.TUIC
	default:
		return nil // 不支持的协议
	}

	p := model.NewProfileItem(configType)
	p.Remarks = ob.Tag
	p.Server = ob.Server
	if ob.ServerPort > 0 {
		p.ServerPort = strconv.Itoa(ob.ServerPort)
	}

	// 协议特定字段
	switch configType {
	case model.VLESS:
		p.Password = ob.UUID
		p.Flow = ob.Flow
		p.Method = "none"
	case model.VMESS:
		p.Password = ob.UUID
		p.Method = ob.Security
		if p.Method == "" || p.Method == "auto" {
			p.Method = "auto"
		}
		p.AlterId = ob.AlterID
	case model.SHADOWSOCKS:
		p.Method = ob.Method
		p.Password = ob.Password
		p.Plugin = ob.Plugin
		p.PluginOpts = ob.PluginOpts
	case model.TROJAN:
		p.Password = ob.Password
	case model.HYSTERIA2:
		p.Password = ob.Password
		// 带宽
		if ob.UpMbps > 0 {
			p.BandwidthUp = strconv.Itoa(ob.UpMbps) + " Mbps"
		}
		if ob.DownMbps > 0 {
			p.BandwidthDown = strconv.Itoa(ob.DownMbps) + " Mbps"
		}
		// 混淆
		if ob.Obfs != nil && ob.Obfs.Password != "" {
			p.ObfsPassword = ob.Obfs.Password
		}
		// 端口跳跃
		if len(ob.ServerPorts) > 0 {
			p.PortHopping = ob.ServerPorts[0]
			if ob.HopInterval != "" {
				p.PortHoppingInterval = strings.TrimSuffix(ob.HopInterval, "s")
			}
		}
	case model.ANYTLS:
		p.Password = ob.Password
	case model.TUIC:
		p.UUID = ob.UUID
		p.Password = ob.Password
		p.CongestionControl = ob.CongestionControl
		p.UDPRelayMode = ob.UDPRelayMode
		p.UDPOverStream = ob.UDPOverStream
		p.ZeroRTTHandshake = ob.ZeroRTTHandshake
		p.Heartbeat = ob.Heartbeat
	}

	// 传输层
	p.Network = "tcp"
	if configType == model.TUIC {
		if ob.Network != "" {
			p.Network = ob.Network
		}
		p.UDP = ob.Network == "" || strings.Contains(ob.Network, "udp")
	}
	if ob.Transport != nil {
		p.Network = ob.Transport.Type
		if ob.Transport.Path != "" && ob.Transport.Path != "/" {
			p.Path = ob.Transport.Path
		}

		switch p.Network {
		case "ws", "httpupgrade":
			if ob.Transport.Headers != nil {
				if host, ok := ob.Transport.Headers["Host"]; ok {
					p.Host = host
				} else if host, ok := ob.Transport.Headers["host"]; ok {
					p.Host = host
				}
			}
		case "grpc":
			p.ServiceName = ob.Transport.ServiceName
		case "h2", "http":
			if len(ob.Transport.Host) > 0 {
				p.Host = strings.Join(ob.Transport.Host, ",")
			}
		}
	}

	// TLS & Reality
	if ob.TLS != nil && ob.TLS.Enabled {
		if ob.TLS.Reality != nil && ob.TLS.Reality.Enabled {
			p.Security = "reality"
			p.PublicKey = ob.TLS.Reality.PublicKey
			p.ShortID = ob.TLS.Reality.ShortID
		} else {
			p.Security = "tls"
		}

		p.SNI = ob.TLS.ServerName
		p.Insecure = ob.TLS.Insecure
		p.DisableSNI = ob.TLS.DisableSNI

		if len(ob.TLS.ALPN) > 0 {
			p.ALPN = strings.Join(ob.TLS.ALPN, ",")
		}

		if ob.TLS.UTLS != nil && ob.TLS.UTLS.Enabled {
			p.Fingerprint = ob.TLS.UTLS.Fingerprint
		}

		if ob.TLS.ECH != nil && ob.TLS.ECH.Enabled && len(ob.TLS.ECH.Config) > 0 {
			p.EchConfigList = ob.TLS.ECH.Config[0]
		}
		if ob.TLS.ECH != nil && ob.TLS.ECH.Enabled {
			p.EchQueryServerName = ob.TLS.ECH.QueryServerName
		}
	}

	// Trojan 默认 TLS
	if configType == model.TROJAN && p.Security == "" {
		p.Security = "tls"
	}

	// Hysteria2 默认 TLS
	if configType == model.HYSTERIA2 && p.Security == "" {
		p.Security = "tls"
	}

	if (configType == model.ANYTLS || configType == model.TUIC) && p.Security == "" {
		p.Security = "tls"
	}

	return p
}
