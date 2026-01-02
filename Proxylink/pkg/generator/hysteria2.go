package generator

import (
	"fmt"

	"proxylink/pkg/model"
)

// Hysteria2Config Hysteria2 原生配置
type Hysteria2Config struct {
	Server    string          `json:"server"`
	Auth      string          `json:"auth"`
	Lazy      bool            `json:"lazy"`
	Socks5    *ListenConfig   `json:"socks5,omitempty"`
	HTTP      *ListenConfig   `json:"http,omitempty"`
	TLS       *Hysteria2TLS   `json:"tls,omitempty"`
	Obfs      *Hysteria2Obfs  `json:"obfs,omitempty"`
	Transport *Hysteria2Trans `json:"transport,omitempty"`
	Bandwidth *Hysteria2BW    `json:"bandwidth,omitempty"`
}

// ListenConfig 监听配置
type ListenConfig struct {
	Listen string `json:"listen"`
}

// Hysteria2TLS TLS 配置
type Hysteria2TLS struct {
	SNI       string `json:"sni,omitempty"`
	Insecure  bool   `json:"insecure,omitempty"`
	PinSHA256 string `json:"pinSHA256,omitempty"`
}

// Hysteria2Obfs 混淆配置
type Hysteria2Obfs struct {
	Type       string            `json:"type"`
	Salamander *SalamanderConfig `json:"salamander,omitempty"`
}

// SalamanderConfig Salamander 混淆配置
type SalamanderConfig struct {
	Password string `json:"password"`
}

// Hysteria2Trans 传输配置
type Hysteria2Trans struct {
	Type string        `json:"type"`
	UDP  *Hysteria2UDP `json:"udp,omitempty"`
}

// Hysteria2UDP UDP 配置
type Hysteria2UDP struct {
	HopInterval string `json:"hopInterval,omitempty"`
}

// Hysteria2BW 带宽配置
type Hysteria2BW struct {
	Down string `json:"down,omitempty"`
	Up   string `json:"up,omitempty"`
}

// GenerateHysteria2Config 生成 Hysteria2 原生配置
func GenerateHysteria2Config(profile *model.ProfileItem, socksPort int) *Hysteria2Config {
	listen := fmt.Sprintf("127.0.0.1:%d", socksPort)

	config := &Hysteria2Config{
		Server: profile.GetServerAddressAndPort(),
		Auth:   profile.Password,
		Lazy:   true,
		Socks5: &ListenConfig{Listen: listen},
		HTTP:   &ListenConfig{Listen: listen},
		TLS: &Hysteria2TLS{
			SNI:      profile.SNI,
			Insecure: profile.Insecure,
		},
	}

	// 如果没有 SNI，使用服务器地址
	if config.TLS.SNI == "" {
		config.TLS.SNI = profile.Server
	}

	// PinSHA256
	if profile.PinSHA256 != "" {
		config.TLS.PinSHA256 = profile.PinSHA256
	}

	// 混淆
	if profile.ObfsPassword != "" {
		config.Obfs = &Hysteria2Obfs{
			Type: "salamander",
			Salamander: &SalamanderConfig{
				Password: profile.ObfsPassword,
			},
		}
	}

	// 端口跳跃
	if profile.PortHopping != "" {
		// 更新服务器地址为端口跳跃格式
		config.Server = fmt.Sprintf("%s:%s", profile.Server, profile.PortHopping)

		interval := profile.PortHoppingInterval
		if interval == "" {
			interval = "30"
		}
		config.Transport = &Hysteria2Trans{
			Type: "udp",
			UDP: &Hysteria2UDP{
				HopInterval: interval + "s",
			},
		}
	}

	// 带宽限制
	if profile.BandwidthDown != "" || profile.BandwidthUp != "" {
		config.Bandwidth = &Hysteria2BW{
			Down: profile.BandwidthDown,
			Up:   profile.BandwidthUp,
		}
	}

	return config
}
