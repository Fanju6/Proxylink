package generator

import (
	"encoding/json"
	"strconv"
	"strings"

	"proxylink/pkg/model"
)

const DEFAULT_LEVEL = 8

// XrayConfig Xray 完整配置结构 (用于包装 outbounds)
type XrayConfig struct {
	Outbounds []*XrayOutbound `json:"outbounds"`
}

// XrayOutbound Xray 出站配置结构
type XrayOutbound struct {
	Mux            *MuxBean        `json:"mux"`
	Protocol       string          `json:"protocol"`
	Settings       *OutSettings    `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Tag            string          `json:"tag"`
}

// OutSettings 出站设置
type OutSettings struct {
	Vnext   []VnextBean   `json:"vnext,omitempty"`
	Servers []ServersBean `json:"servers,omitempty"`
	// WireGuard
	SecretKey string          `json:"secretKey,omitempty"`
	Address   []string        `json:"address,omitempty"`
	Peers     []WireGuardPeer `json:"peers,omitempty"`
	Reserved  []int           `json:"reserved,omitempty"`
	Mtu       int             `json:"mtu,omitempty"`
}

type VnextBean struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []UsersBean `json:"users"`
}

type UsersBean struct {
	Encryption string  `json:"encryption,omitempty"`
	Flow       *string `json:"flow,omitempty"`
	ID         string  `json:"id"`
	Level      int     `json:"level"`
	AlterId    int     `json:"alterId,omitempty"`
	Security   string  `json:"security,omitempty"`
}

type ServersBean struct {
	Address  string           `json:"address"`
	Port     int              `json:"port"`
	Method   string           `json:"method,omitempty"`
	Password string           `json:"password,omitempty"`
	Level    int              `json:"level,omitempty"`
	Flow     string           `json:"flow,omitempty"`
	Users    []SocksUsersBean `json:"users,omitempty"`
}

type SocksUsersBean struct {
	User  string `json:"user"`
	Pass  string `json:"pass"`
	Level int    `json:"level"`
}

type WireGuardPeer struct {
	PublicKey    string `json:"publicKey"`
	PreSharedKey string `json:"preSharedKey,omitempty"`
	Endpoint     string `json:"endpoint"`
}

// StreamSettings 传输层配置
type StreamSettings struct {
	Network             string                   `json:"network,omitempty"`
	Security            string                   `json:"security,omitempty"`
	TcpSettings         *TcpSettingsBean         `json:"tcpSettings,omitempty"`
	KcpSettings         *KcpSettingsBean         `json:"kcpSettings,omitempty"`
	WsSettings          *WsSettingsBean          `json:"wsSettings,omitempty"`
	HttpupgradeSettings *HttpupgradeSettingsBean `json:"httpupgradeSettings,omitempty"`
	XhttpSettings       *XhttpSettingsBean       `json:"xhttpSettings,omitempty"`
	HttpSettings        *HttpSettingsBean        `json:"httpSettings,omitempty"`
	TlsSettings         *TlsSettingsBean         `json:"tlsSettings,omitempty"`
	RealitySettings     *TlsSettingsBean         `json:"realitySettings,omitempty"`
	GrpcSettings        *GrpcSettingsBean        `json:"grpcSettings,omitempty"`
}

type TcpSettingsBean struct {
	Header *TcpHeaderBean `json:"header,omitempty"`
}

type TcpHeaderBean struct {
	Type    string          `json:"type"`
	Request *TcpRequestBean `json:"request,omitempty"`
}

type TcpRequestBean struct {
	Headers *TcpHeadersBean `json:"headers,omitempty"`
	Path    []string        `json:"path,omitempty"`
}

type TcpHeadersBean struct {
	Host []string `json:"Host,omitempty"`
}

type KcpSettingsBean struct {
	Mtu              int            `json:"mtu,omitempty"`
	Tti              int            `json:"tti,omitempty"`
	UplinkCapacity   int            `json:"uplinkCapacity,omitempty"`
	DownlinkCapacity int            `json:"downlinkCapacity,omitempty"`
	Congestion       bool           `json:"congestion,omitempty"`
	ReadBufferSize   int            `json:"readBufferSize,omitempty"`
	WriteBufferSize  int            `json:"writeBufferSize,omitempty"`
	Header           *KcpHeaderBean `json:"header,omitempty"`
	Seed             string         `json:"seed,omitempty"`
}

type KcpHeaderBean struct {
	Type   string `json:"type"`
	Domain string `json:"domain,omitempty"`
}

type WsSettingsBean struct {
	Path    string         `json:"path,omitempty"`
	Headers *WsHeadersBean `json:"headers,omitempty"`
}

type WsHeadersBean struct {
	Host string `json:"Host,omitempty"`
}

type HttpupgradeSettingsBean struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type XhttpSettingsBean struct {
	Host  string      `json:"host"`
	Mode  string      `json:"mode"`
	Path  string      `json:"path"`
	Extra interface{} `json:"extra,omitempty"`
}

type HttpSettingsBean struct {
	Host []string `json:"host,omitempty"`
	Path string   `json:"path,omitempty"`
}

type TlsSettingsBean struct {
	AllowInsecure bool     `json:"allowInsecure"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	PublicKey     string   `json:"publicKey,omitempty"`
	ServerName    string   `json:"serverName,omitempty"`
	ShortId       string   `json:"shortId,omitempty"`
	Show          bool     `json:"show"`
	SpiderX       string   `json:"spiderX,omitempty"`
	Alpn          []string `json:"alpn,omitempty"`
	Mldsa65Verify string   `json:"mldsa65Verify,omitempty"`
}

type GrpcSettingsBean struct {
	ServiceName        string `json:"serviceName,omitempty"`
	Authority          string `json:"authority,omitempty"`
	MultiMode          bool   `json:"multiMode,omitempty"`
	IdleTimeout        int    `json:"idle_timeout,omitempty"`
	HealthCheckTimeout int    `json:"health_check_timeout,omitempty"`
}

type MuxBean struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency,omitempty"`
}

// GenerateXrayOutbound 生成 Xray 出站配置
func GenerateXrayOutbound(profile *model.ProfileItem) *XrayOutbound {
	switch profile.ConfigType {
	case model.VLESS:
		return generateVLessOutbound(profile)
	case model.VMESS:
		return generateVMessOutbound(profile)
	case model.SHADOWSOCKS:
		return generateShadowsocksOutbound(profile)
	case model.TROJAN:
		return generateTrojanOutbound(profile)
	case model.SOCKS:
		return generateSocksOutbound(profile.Server, profile.ServerPort, profile.Username, profile.Password)
	case model.HTTP:
		return generateHTTPOutbound(profile)
	case model.WIREGUARD:
		return generateWireGuardOutbound(profile)
	case model.HYSTERIA2:
		return generateSocksOutbound("127.0.0.1", "1234", "", "")
	default:
		return nil
	}
}

// GenerateXrayConfig 生成带 outbounds 包装的完整 Xray 配置
func GenerateXrayConfig(profile *model.ProfileItem) *XrayConfig {
	outbound := GenerateXrayOutbound(profile)
	if outbound == nil {
		return nil
	}
	return &XrayConfig{
		Outbounds: []*XrayOutbound{outbound},
	}
}

func generateVLessOutbound(p *model.ProfileItem) *XrayOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	return &XrayOutbound{
		Mux:      &MuxBean{Enabled: false, Concurrency: -1},
		Protocol: "vless",
		Settings: &OutSettings{
			Vnext: []VnextBean{{
				Address: p.Server,
				Port:    port,
				Users: []UsersBean{{
					ID:         p.Password,
					Encryption: p.Method,
					Flow:       &p.Flow,
					Level:      DEFAULT_LEVEL,
				}},
			}},
		},
		StreamSettings: buildStreamSettings(p),
		Tag:            "proxy",
	}
}

func generateVMessOutbound(p *model.ProfileItem) *XrayOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	security := p.Method
	if security == "" {
		security = "auto"
	}

	return &XrayOutbound{
		Mux:      &MuxBean{Enabled: false, Concurrency: -1},
		Protocol: "vmess",
		Settings: &OutSettings{
			Vnext: []VnextBean{{
				Address: p.Server,
				Port:    port,
				Users: []UsersBean{{
					ID:       p.Password,
					AlterId:  p.AlterId,
					Security: security,
					Level:    DEFAULT_LEVEL,
				}},
			}},
		},
		StreamSettings: buildStreamSettings(p),
		Tag:            "proxy",
	}
}

func generateShadowsocksOutbound(p *model.ProfileItem) *XrayOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	outbound := &XrayOutbound{
		Mux:      &MuxBean{Enabled: false, Concurrency: -1},
		Protocol: "shadowsocks",
		Settings: &OutSettings{
			Servers: []ServersBean{{
				Address:  p.Server,
				Port:     port,
				Method:   p.Method,
				Password: p.Password,
				Level:    DEFAULT_LEVEL,
			}},
		},
		Tag: "proxy",
	}

	if p.HeaderType == "http" || p.Network != "" {
		outbound.StreamSettings = buildStreamSettings(p)
	}

	return outbound
}

func generateTrojanOutbound(p *model.ProfileItem) *XrayOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	return &XrayOutbound{
		Mux:      &MuxBean{Enabled: false, Concurrency: -1},
		Protocol: "trojan",
		Settings: &OutSettings{
			Servers: []ServersBean{{
				Address:  p.Server,
				Port:     port,
				Password: p.Password,
				Level:    DEFAULT_LEVEL,
				Flow:     p.Flow,
			}},
		},
		StreamSettings: buildStreamSettings(p),
		Tag:            "proxy",
	}
}

func generateSocksOutbound(server, port, username, password string) *XrayOutbound {
	portInt, _ := strconv.Atoi(port)

	serverBean := ServersBean{
		Address: server,
		Port:    portInt,
		Level:   DEFAULT_LEVEL,
	}

	if username != "" {
		serverBean.Users = []SocksUsersBean{{
			User:  username,
			Pass:  password,
			Level: DEFAULT_LEVEL,
		}}
	}

	return &XrayOutbound{
		Mux:      &MuxBean{Enabled: false, Concurrency: -1},
		Protocol: "socks",
		Settings: &OutSettings{
			Servers: []ServersBean{serverBean},
		},
		Tag: "proxy",
	}
}

// generateHTTPOutbound 生成 HTTP 代理出站
func generateHTTPOutbound(p *model.ProfileItem) *XrayOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	serverBean := ServersBean{
		Address: p.Server,
		Port:    port,
	}

	if p.Username != "" {
		serverBean.Users = []SocksUsersBean{{
			User:  p.Username,
			Pass:  p.Password,
			Level: DEFAULT_LEVEL,
		}}
	}

	return &XrayOutbound{
		Mux:      &MuxBean{Enabled: false, Concurrency: -1},
		Protocol: "http",
		Settings: &OutSettings{
			Servers: []ServersBean{serverBean},
		},
		Tag: "proxy",
	}
}

func generateWireGuardOutbound(p *model.ProfileItem) *XrayOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	var reserved []int
	if p.Reserved != "" {
		for _, s := range strings.Split(p.Reserved, ",") {
			s = strings.TrimSpace(s)
			if v, err := strconv.Atoi(s); err == nil {
				reserved = append(reserved, v)
			}
		}
	}

	var address []string
	if p.LocalAddress != "" {
		for _, s := range strings.Split(p.LocalAddress, ",") {
			address = append(address, strings.TrimSpace(s))
		}
	} else {
		address = []string{"10.0.0.2/32"}
	}

	endpoint := p.Server + ":" + strconv.Itoa(port)

	return &XrayOutbound{
		Protocol: "wireguard",
		Settings: &OutSettings{
			SecretKey: p.SecretKey,
			Address:   address,
			Peers: []WireGuardPeer{{
				PublicKey:    p.PublicKey,
				PreSharedKey: p.PreSharedKey,
				Endpoint:     endpoint,
			}},
			Reserved: reserved,
			Mtu:      p.MTU,
		},
		Tag: "proxy",
	}
}

func buildStreamSettings(p *model.ProfileItem) *StreamSettings {
	ss := &StreamSettings{
		Network:  p.Network,
		Security: p.Security,
	}

	if ss.Network == "" {
		ss.Network = "tcp"
	}

	// 传输层配置
	sni := populateTransportSettings(ss, p)

	// TLS/Reality 配置
	populateTlsSettings(ss, p, sni)

	return ss
}

// populateTransportSettings 填充传输层配置
func populateTransportSettings(ss *StreamSettings, p *model.ProfileItem) string {
	var sni string

	switch ss.Network {
	case "tcp":
		tcpSetting := &TcpSettingsBean{
			Header: &TcpHeaderBean{Type: "none"},
		}
		if p.HeaderType == "http" {
			tcpSetting.Header.Type = "http"
			if p.Host != "" || p.Path != "" {
				hosts := splitAndTrim(p.Host, ",")
				paths := splitAndTrim(p.Path, ",")
				if len(paths) == 0 {
					paths = nil // 不输出空 path
				}
				request := &TcpRequestBean{
					Headers: &TcpHeadersBean{
						Host: hosts,
					},
					Path: paths,
				}
				if len(hosts) > 0 {
					sni = hosts[0]
				}
				tcpSetting.Header.Request = request
			}
		} else {
			sni = p.Host
		}
		ss.TcpSettings = tcpSetting

	case "kcp":
		kcpSetting := &KcpSettingsBean{
			Mtu:              1350,
			Tti:              50,
			UplinkCapacity:   12,
			DownlinkCapacity: 100,
			Congestion:       false,
			ReadBufferSize:   1,
			WriteBufferSize:  1,
			Header: &KcpHeaderBean{
				Type: p.HeaderType,
			},
		}
		if p.HeaderType == "" {
			kcpSetting.Header.Type = "none"
		}
		if p.Seed != "" {
			kcpSetting.Seed = p.Seed
		}
		if p.Host != "" {
			kcpSetting.Header.Domain = p.Host
		}
		ss.KcpSettings = kcpSetting

	case "ws":
		wsSetting := &WsSettingsBean{
			Path: p.Path,
		}
		if wsSetting.Path == "" {
			wsSetting.Path = "/"
		}
		if p.Host != "" {
			wsSetting.Headers = &WsHeadersBean{Host: p.Host}
			sni = p.Host
		}
		ss.WsSettings = wsSetting

	case "httpupgrade":
		httpupgradeSetting := &HttpupgradeSettingsBean{
			Host: p.Host,
			Path: p.Path,
		}
		if httpupgradeSetting.Path == "" {
			httpupgradeSetting.Path = "/"
		}
		sni = p.Host
		ss.HttpupgradeSettings = httpupgradeSetting

	case "xhttp":
		xhttpSetting := &XhttpSettingsBean{
			Host: p.Host,
			Path: p.Path,
			Mode: p.XhttpMode,
		}
		if xhttpSetting.Path == "" {
			xhttpSetting.Path = "/"
		}
		if xhttpSetting.Mode == "" {
			xhttpSetting.Mode = "auto"
		}
		// 解析 extra
		if p.XhttpExtra != "" {
			var extra interface{}
			if err := json.Unmarshal([]byte(p.XhttpExtra), &extra); err == nil {
				xhttpSetting.Extra = extra
			}
		}
		sni = p.Host
		ss.XhttpSettings = xhttpSetting

	case "h2", "http":
		ss.Network = "h2"
		h2Setting := &HttpSettingsBean{
			Path: p.Path,
		}
		if h2Setting.Path == "" {
			h2Setting.Path = "/"
		}
		if p.Host != "" {
			h2Setting.Host = splitAndTrim(p.Host, ",")
			if len(h2Setting.Host) > 0 {
				sni = h2Setting.Host[0]
			}
		}
		ss.HttpSettings = h2Setting

	case "grpc":
		grpcSetting := &GrpcSettingsBean{
			ServiceName:        p.ServiceName,
			Authority:          p.Authority,
			MultiMode:          p.Mode == "multi",
			IdleTimeout:        60,
			HealthCheckTimeout: 20,
		}
		sni = p.Authority
		ss.GrpcSettings = grpcSetting
	}

	return sni
}

// populateTlsSettings 填充 TLS/Reality 配置
func populateTlsSettings(ss *StreamSettings, p *model.ProfileItem, sniExt string) {
	if p.Security == "" {
		ss.Security = ""
		return
	}

	// 确定 SNI
	sni := p.SNI
	if sni == "" {
		if sniExt != "" && isDomainName(sniExt) {
			sni = sniExt
		} else if p.Server != "" && isDomainName(p.Server) {
			sni = p.Server
		} else {
			sni = sniExt
		}
	}

	tlsSetting := &TlsSettingsBean{
		AllowInsecure: p.Insecure,
		ServerName:    sni,
		Fingerprint:   p.Fingerprint,
	}

	if p.ALPN != "" {
		tlsSetting.Alpn = splitAndTrim(p.ALPN, ",")
	}

	// Reality 特有字段
	if p.Security == "reality" {
		tlsSetting.Show = false
		tlsSetting.PublicKey = p.PublicKey
		tlsSetting.ShortId = p.ShortID
		tlsSetting.SpiderX = p.SpiderX
		if p.Mldsa65Verify != "" {
			tlsSetting.Mldsa65Verify = p.Mldsa65Verify
		}
		ss.RealitySettings = tlsSetting
		ss.TlsSettings = nil
	} else if p.Security == "tls" {
		ss.TlsSettings = tlsSetting
		ss.RealitySettings = nil
	}
}

// 辅助函数
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func isDomainName(s string) bool {
	if s == "" {
		return false
	}
	// 简单检查：不含冒号（排除IPv6）且含点
	return !strings.Contains(s, ":") && strings.Contains(s, ".")
}
