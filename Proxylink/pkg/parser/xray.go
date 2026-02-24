package parser

import (
	"encoding/json"
	"fmt"
	"proxylink/pkg/generator"
	"proxylink/pkg/model"
	"strconv"
)

// ParseXrayConfig 解析 Xray JSON 配置并转换为 ProfileItem 列表
func ParseXrayConfig(data []byte) ([]*model.ProfileItem, error) {
	var config generator.XrayConfig
	if err := json.Unmarshal(data, &config); err != nil {
		// 尝试解析单条 outbound
		var outbound generator.XrayOutbound
		if err2 := json.Unmarshal(data, &outbound); err2 == nil {
			if profile := FromXrayOutbound(&outbound); profile != nil {
				return []*model.ProfileItem{profile}, nil
			}
		}
		return nil, fmt.Errorf("failed to unmarshal xray config: %v", err)
	}

	var profiles []*model.ProfileItem
	for _, outbound := range config.Outbounds {
		if profile := FromXrayOutbound(outbound); profile != nil {
			profiles = append(profiles, profile)
		}
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("no valid outbounds found in xray config")
	}

	return profiles, nil
}

// FromXrayOutbound 将 XrayOutbound 转换为 ProfileItem
func FromXrayOutbound(o *generator.XrayOutbound) *model.ProfileItem {
	if o == nil {
		return nil
	}

	p := &model.ProfileItem{
		Remarks: o.Tag,
	}

	switch o.Protocol {
	case "vless":
		p.ConfigType = model.VLESS
		parseVnext(o, p)
	case "vmess":
		p.ConfigType = model.VMESS
		parseVnext(o, p)
	case "shadowsocks":
		p.ConfigType = model.SHADOWSOCKS
		parseServers(o, p)
	case "trojan":
		p.ConfigType = model.TROJAN
		parseServers(o, p)
	case "socks":
		p.ConfigType = model.SOCKS
		parseServers(o, p)
	case "http":
		p.ConfigType = model.HTTP
		parseServers(o, p)
	case "wireguard":
		p.ConfigType = model.WIREGUARD
		parseWireGuard(o, p)
	case "hysteria2":
		p.ConfigType = model.HYSTERIA2
		p.Server = o.Settings.Address.(string)
		p.ServerPort = strconv.Itoa(o.Settings.Port)
	default:
		return nil
	}

	// 填充 StreamSettings
	if o.StreamSettings != nil {
		p.Network = o.StreamSettings.Network
		p.Security = o.StreamSettings.Security

		// 传输设置
		parseStreamSettings(o.StreamSettings, p)
	}

	return p
}

func parseVnext(o *generator.XrayOutbound, p *model.ProfileItem) {
	if o.Settings == nil || len(o.Settings.Vnext) == 0 {
		return
	}
	v := o.Settings.Vnext[0]
	p.Server = v.Address
	p.ServerPort = strconv.Itoa(v.Port)
	if len(v.Users) > 0 {
		u := v.Users[0]
		p.Password = u.ID
		p.Method = u.Encryption
		if u.Flow != nil {
			p.Flow = *u.Flow
		}
		p.AlterId = u.AlterId
	}
}

func parseServers(o *generator.XrayOutbound, p *model.ProfileItem) {
	if o.Settings == nil || len(o.Settings.Servers) == 0 {
		return
	}
	s := o.Settings.Servers[0]
	p.Server = s.Address
	p.ServerPort = strconv.Itoa(s.Port)
	p.Password = s.Password
	p.Method = s.Method
	p.Flow = s.Flow
	if len(s.Users) > 0 {
		u := s.Users[0]
		p.Username = u.User
		p.Password = u.Pass
	}
}

func parseWireGuard(o *generator.XrayOutbound, p *model.ProfileItem) {
	if o.Settings == nil {
		return
	}
	p.SecretKey = o.Settings.SecretKey
	if addr, ok := o.Settings.Address.([]interface{}); ok && len(addr) > 0 {
		var addrs []string
		for _, a := range addr {
			addrs = append(addrs, a.(string))
		}
		p.LocalAddress = fmt.Sprintf("%v", addrs) // 简单合并
	}
}

func parseStreamSettings(ss *generator.StreamSettings, p *model.ProfileItem) {
	switch ss.Network {
	case "tcp":
		if ss.TcpSettings != nil && ss.TcpSettings.Header != nil {
			p.HeaderType = ss.TcpSettings.Header.Type
			if req := ss.TcpSettings.Header.Request; req != nil && req.Headers != nil {
				if len(req.Headers.Host) > 0 {
					p.Host = req.Headers.Host[0]
				}
				if len(req.Path) > 0 {
					p.Path = req.Path[0]
				}
			}
		}
	case "kcp":
		if ss.KcpSettings != nil {
			if ss.KcpSettings.Header != nil {
				p.HeaderType = ss.KcpSettings.Header.Type
			}
			p.Seed = ss.KcpSettings.Seed
		}
	case "ws":
		if ss.WsSettings != nil {
			p.Path = ss.WsSettings.Path
			if ss.WsSettings.Headers != nil {
				p.Host = ss.WsSettings.Headers.Host
			}
		}
	case "httpupgrade":
		if ss.HttpupgradeSettings != nil {
			p.Path = ss.HttpupgradeSettings.Path
			p.Host = ss.HttpupgradeSettings.Host
		}
	case "xhttp":
		if ss.XhttpSettings != nil {
			p.Path = ss.XhttpSettings.Path
			p.Host = ss.XhttpSettings.Host
			p.XhttpMode = ss.XhttpSettings.Mode
			if ss.XhttpSettings.Extra != nil {
				b, _ := json.Marshal(ss.XhttpSettings.Extra)
				p.XhttpExtra = string(b)
			}
		}
	case "h2", "http":
		if ss.HttpSettings != nil {
			p.Path = ss.HttpSettings.Path
			if len(ss.HttpSettings.Host) > 0 {
				p.Host = ss.HttpSettings.Host[0]
			}
		}
	case "grpc":
		if ss.GrpcSettings != nil {
			p.ServiceName = ss.GrpcSettings.ServiceName
			p.Authority = ss.GrpcSettings.Authority
		}
	}

	// TLS / Reality
	var tls *generator.TlsSettingsBean
	if ss.Security == "tls" {
		tls = ss.TlsSettings
	} else if ss.Security == "reality" {
		tls = ss.RealitySettings
		if tls != nil {
			p.PublicKey = tls.PublicKey
			p.ShortID = tls.ShortId
			p.SpiderX = tls.SpiderX
		}
	}

	if tls != nil {
		p.SNI = tls.ServerName
		p.Insecure = tls.AllowInsecure
		p.Fingerprint = tls.Fingerprint
		p.EchConfigList = tls.EchConfigList
		p.EchForceQuery = tls.EchForceQuery
		p.PinnedCA256 = tls.PinnedPeerCertSha256
	}
}
