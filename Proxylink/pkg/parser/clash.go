package parser

import (
	"fmt"
	"strconv"
	"strings"

	"proxylink/pkg/model"

	"gopkg.in/yaml.v3"
)

// ClashConfig Clash 配置文件顶层结构
type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

// ClashProxy Clash 代理节点 YAML 结构
type ClashProxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	UDP      bool   `yaml:"udp"`

	// VLESS / VMess
	UUID    string `yaml:"uuid"`
	AlterID int    `yaml:"alterId"`
	Cipher  string `yaml:"cipher"`
	Flow    string `yaml:"flow"`

	// Shadowsocks / Trojan / Hysteria2
	Password string `yaml:"password"`

	// 传输层
	Network string `yaml:"network"`

	// TLS
	TLS               bool     `yaml:"tls"`
	Servername        string   `yaml:"servername"`
	SNI               string   `yaml:"sni"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify"`
	ALPN              []string `yaml:"alpn"`
	ClientFingerprint string   `yaml:"client-fingerprint"`
	Fingerprint       string   `yaml:"fingerprint"`

	// Reality
	RealityOpts *ClashRealityOpts `yaml:"reality-opts"`

	// 传输层选项
	WsOpts    *ClashWsOpts    `yaml:"ws-opts"`
	GrpcOpts  *ClashGrpcOpts  `yaml:"grpc-opts"`
	H2Opts    *ClashH2Opts    `yaml:"h2-opts"`
	HttpOpts  *ClashHttpOpts  `yaml:"http-opts"`
	XhttpOpts *ClashXhttpOpts `yaml:"xhttp-opts"`

	// Hysteria2
	Ports       string `yaml:"ports"`
	HopInterval int    `yaml:"hop-interval"`
	Up          string `yaml:"up"`
	Down        string `yaml:"down"`
	Obfs        string `yaml:"obfs"`
	ObfsPassword string `yaml:"obfs-password"`
}

type ClashRealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

type ClashWsOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type ClashGrpcOpts struct {
	GrpcServiceName string `yaml:"grpc-service-name"`
}

type ClashH2Opts struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

type ClashHttpOpts struct {
	Method  string              `yaml:"method"`
	Path    []string            `yaml:"path"`
	Headers map[string][]string `yaml:"headers"`
}

type ClashXhttpOpts struct {
	Host string `yaml:"host"`
	Path string `yaml:"path"`
	Mode string `yaml:"mode"`
}

// ParseClashConfig 解析 Clash YAML 配置，返回 ProfileItem 列表
func ParseClashConfig(data []byte) ([]*model.ProfileItem, error) {
	var config ClashConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("Clash YAML 解析失败: %w", err)
	}

	if len(config.Proxies) == 0 {
		return nil, fmt.Errorf("未找到 proxies 节点")
	}

	var profiles []*model.ProfileItem
	for i := range config.Proxies {
		p := fromClashProxy(&config.Proxies[i])
		if p != nil {
			profiles = append(profiles, p)
		}
	}

	return profiles, nil
}

// IsClashYAML 检测内容是否为 Clash YAML 格式
func IsClashYAML(content string) bool {
	// 简单检测: 包含 "proxies:" 关键字
	return strings.Contains(content, "proxies:")
}

// fromClashProxy 将 ClashProxy 转为 ProfileItem
func fromClashProxy(cp *ClashProxy) *model.ProfileItem {
	var configType model.ConfigType
	switch strings.ToLower(cp.Type) {
	case "vless":
		configType = model.VLESS
	case "vmess":
		configType = model.VMESS
	case "ss":
		configType = model.SHADOWSOCKS
	case "trojan":
		configType = model.TROJAN
	case "hysteria2", "hy2":
		configType = model.HYSTERIA2
	default:
		return nil // 不支持的协议
	}

	p := model.NewProfileItem(configType)
	p.Remarks = cp.Name
	p.Server = cp.Server
	p.ServerPort = strconv.Itoa(cp.Port)

	// 协议特定字段
	switch configType {
	case model.VLESS:
		p.Password = cp.UUID
		p.Flow = cp.Flow
		p.Method = "none"
	case model.VMESS:
		p.Password = cp.UUID
		p.AlterId = cp.AlterID
		p.Method = cp.Cipher
		if p.Method == "" {
			p.Method = "auto"
		}
	case model.SHADOWSOCKS:
		p.Password = cp.Password
		p.Method = cp.Cipher
	case model.TROJAN:
		p.Password = cp.Password
	case model.HYSTERIA2:
		p.Password = cp.Password
		p.ObfsPassword = cp.ObfsPassword
		p.PortHopping = cp.Ports
		if cp.HopInterval > 0 {
			p.PortHoppingInterval = strconv.Itoa(cp.HopInterval)
		}
		p.BandwidthUp = cp.Up
		p.BandwidthDown = cp.Down
	}

	// 传输层
	p.Network = cp.Network
	if p.Network == "" {
		p.Network = "tcp"
	}

	parseClashTransport(cp, p)

	// TLS
	if cp.TLS || cp.RealityOpts != nil || configType == model.TROJAN {
		if cp.RealityOpts != nil {
			p.Security = "reality"
			p.PublicKey = cp.RealityOpts.PublicKey
			p.ShortID = cp.RealityOpts.ShortID
		} else {
			p.Security = "tls"
		}
	}

	// Hysteria2 默认 TLS
	if configType == model.HYSTERIA2 && p.Security == "" {
		p.Security = "tls"
	}

	// SNI (servername 优先)
	p.SNI = cp.Servername
	if p.SNI == "" {
		p.SNI = cp.SNI
	}

	p.Insecure = cp.SkipCertVerify
	p.Fingerprint = cp.ClientFingerprint
	if p.Fingerprint == "" {
		p.Fingerprint = cp.Fingerprint
	}

	if len(cp.ALPN) > 0 {
		p.ALPN = strings.Join(cp.ALPN, ",")
	}

	return p
}

// parseClashTransport 解析 Clash 传输层选项
func parseClashTransport(cp *ClashProxy, p *model.ProfileItem) {
	switch p.Network {
	case "ws":
		if cp.WsOpts != nil {
			p.Path = cp.WsOpts.Path
			if host, ok := cp.WsOpts.Headers["Host"]; ok {
				p.Host = host
			}
			if host, ok := cp.WsOpts.Headers["host"]; ok && p.Host == "" {
				p.Host = host
			}
		}
	case "grpc":
		if cp.GrpcOpts != nil {
			p.ServiceName = cp.GrpcOpts.GrpcServiceName
		}
	case "h2":
		if cp.H2Opts != nil {
			p.Path = cp.H2Opts.Path
			if len(cp.H2Opts.Host) > 0 {
				p.Host = strings.Join(cp.H2Opts.Host, ",")
			}
		}
	case "http":
		p.Network = "h2" // Clash 的 "http" 即 HTTP/2
		if cp.HttpOpts != nil {
			if len(cp.HttpOpts.Path) > 0 {
				p.Path = cp.HttpOpts.Path[0]
			}
			if hosts, ok := cp.HttpOpts.Headers["Host"]; ok && len(hosts) > 0 {
				p.Host = strings.Join(hosts, ",")
			}
		}
		if cp.H2Opts != nil {
			p.Path = cp.H2Opts.Path
			if len(cp.H2Opts.Host) > 0 {
				p.Host = strings.Join(cp.H2Opts.Host, ",")
			}
		}
	case "xhttp":
		if cp.XhttpOpts != nil {
			p.Host = cp.XhttpOpts.Host
			p.Path = cp.XhttpOpts.Path
			p.XhttpMode = cp.XhttpOpts.Mode
		}
	}
}
