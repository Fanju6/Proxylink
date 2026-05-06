package generator

import (
	"encoding/json"
	"strconv"
	"strings"

	"proxylink/pkg/model"
)

// ===== sing-box outbound 结构体 =====

type SingboxConfig struct {
	Outbounds []*SingboxOutbound `json:"outbounds"`
}

type SingboxOutbound struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag,omitempty"`
	Server     string            `json:"server"`
	ServerPort int               `json:"server_port"`
	Network    string            `json:"network,omitempty"`
	TLS        *SingboxTLS       `json:"tls,omitempty"`
	Transport  *SingboxTransport `json:"transport,omitempty"`

	// VLESS
	UUID string `json:"uuid,omitempty"`
	Flow string `json:"flow,omitempty"`

	// VMess
	Security string `json:"security,omitempty"`
	AlterID  int    `json:"alter_id,omitempty"`

	// Trojan / SS / Hysteria2
	Password string `json:"password,omitempty"`

	// Shadowsocks
	Method     string `json:"method,omitempty"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`

	// Hysteria2
	UpMbps      int             `json:"up_mbps,omitempty"`
	DownMbps    int             `json:"down_mbps,omitempty"`
	Obfs        *SingboxHy2Obfs `json:"obfs,omitempty"`
	ServerPorts []string        `json:"server_ports,omitempty"`
	HopInterval string          `json:"hop_interval,omitempty"`

	// TUIC
	CongestionControl string `json:"congestion_control,omitempty"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
	UDPOverStream     bool   `json:"udp_over_stream,omitempty"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake,omitempty"`
	Heartbeat         string `json:"heartbeat,omitempty"`
}

type SingboxTLS struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name,omitempty"`
	Insecure   bool            `json:"insecure,omitempty"`
	DisableSNI bool            `json:"disable_sni,omitempty"`
	ALPN       []string        `json:"alpn,omitempty"`
	UTLS       *SingboxUTLS    `json:"utls,omitempty"`
	Reality    *SingboxReality `json:"reality,omitempty"`
	ECH        *SingboxECH     `json:"ech,omitempty"`
}

type SingboxUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type SingboxReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

type SingboxECH struct {
	Enabled         bool     `json:"enabled"`
	Config          []string `json:"config,omitempty"`
	QueryServerName string   `json:"query_server_name,omitempty"`
}

type SingboxTransport struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Host        []string          `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

type SingboxHy2Obfs struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

// GenerateSingboxOutbound 从 ProfileItem 生成 sing-box 配置 JSON
func GenerateSingboxOutbound(p *model.ProfileItem) (string, error) {
	ob := buildSingboxOutbound(p)
	if ob == nil {
		return "", nil
	}

	config := &SingboxConfig{Outbounds: []*SingboxOutbound{ob}}
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// GenerateSingboxOutbounds 从多个 ProfileItem 生成 sing-box 配置 JSON
func GenerateSingboxOutbounds(profiles []*model.ProfileItem) (string, error) {
	var outbounds []*SingboxOutbound
	usedTags := make(map[string]int)

	for i, p := range profiles {
		ob := buildSingboxOutbound(p)
		if ob != nil {
			ob.Tag = nextSingboxTag(p.Remarks, i, usedTags)
			outbounds = append(outbounds, ob)
		}
	}

	config := &SingboxConfig{Outbounds: outbounds}
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func nextSingboxTag(tag string, index int, usedTags map[string]int) string {
	if tag == "" {
		tag = "node_" + strconv.Itoa(index+1)
	}

	usedTags[tag]++
	if usedTags[tag] > 1 {
		return tag + "_" + strconv.Itoa(usedTags[tag])
	}
	return tag
}

func buildSingboxOutbound(p *model.ProfileItem) *SingboxOutbound {
	port, _ := strconv.Atoi(p.ServerPort)

	ob := &SingboxOutbound{
		Server:     p.Server,
		ServerPort: port,
		Tag:        p.Remarks,
	}

	switch p.ConfigType {
	case model.VLESS:
		ob.Type = "vless"
		ob.UUID = p.Password
		ob.Flow = p.Flow
	case model.VMESS:
		ob.Type = "vmess"
		ob.UUID = p.Password
		ob.Security = p.Method
		if ob.Security == "" {
			ob.Security = "auto"
		}
		ob.AlterID = p.AlterId
	case model.SHADOWSOCKS:
		ob.Type = "shadowsocks"
		ob.Method = p.Method
		ob.Password = p.Password
		ob.Plugin = p.Plugin
		ob.PluginOpts = p.PluginOpts
	case model.TROJAN:
		ob.Type = "trojan"
		ob.Password = p.Password
	case model.HYSTERIA2:
		ob.Type = "hysteria2"
		ob.Password = p.Password
		buildSingboxHysteria2(ob, p)
	case model.ANYTLS:
		ob.Type = "anytls"
		ob.Password = p.Password
	case model.TUIC:
		ob.Type = "tuic"
		ob.UUID = p.UUID
		ob.Password = p.Password
		ob.Network = buildSingboxTUICNetwork(p)
		ob.CongestionControl = p.CongestionControl
		ob.UDPRelayMode = p.UDPRelayMode
		ob.UDPOverStream = p.UDPOverStream
		ob.ZeroRTTHandshake = p.ZeroRTTHandshake
		ob.Heartbeat = p.Heartbeat
	default:
		return nil
	}

	// 传输层
	if p.Network != "" && p.Network != "tcp" {
		ob.Transport = buildSingboxTransport(p)
	}

	// TLS
	if p.Security == "tls" || p.Security == "reality" || p.ConfigType == model.TROJAN || p.ConfigType == model.HYSTERIA2 || p.ConfigType == model.ANYTLS || p.ConfigType == model.TUIC {
		ob.TLS = buildSingboxTLS(p)
	}

	return ob
}

func buildSingboxTUICNetwork(p *model.ProfileItem) string {
	if p.Network != "" && p.Network != "tcp" {
		return p.Network
	}
	if !p.UDP {
		return "tcp"
	}
	return ""
}

func buildSingboxTransport(p *model.ProfileItem) *SingboxTransport {
	t := &SingboxTransport{}

	switch p.Network {
	case "ws":
		t.Type = "ws"
		t.Path = p.Path
		if t.Path == "" {
			t.Path = "/"
		}
		if p.Host != "" {
			t.Headers = map[string]string{"Host": p.Host}
		}
	case "grpc":
		t.Type = "grpc"
		t.ServiceName = p.ServiceName
	case "h2", "http":
		t.Type = "http"
		if p.Path != "" {
			t.Path = p.Path
		}
		if p.Host != "" {
			t.Host = splitAndTrim(p.Host, ",")
		}
	case "httpupgrade":
		t.Type = "httpupgrade"
		t.Path = p.Path
		if t.Path == "" {
			t.Path = "/"
		}
		if p.Host != "" {
			t.Headers = map[string]string{"Host": p.Host}
		}
	default:
		return nil
	}

	return t
}

func buildSingboxTLS(p *model.ProfileItem) *SingboxTLS {
	tls := &SingboxTLS{
		Enabled: true,
	}

	// SNI
	sni := p.SNI
	if sni == "" {
		sni = p.Server
	}
	tls.ServerName = sni

	// Insecure
	tls.Insecure = p.Insecure
	tls.DisableSNI = p.DisableSNI

	// ALPN
	if p.ALPN != "" {
		tls.ALPN = splitAndTrim(p.ALPN, ",")
	}

	// uTLS fingerprint
	if p.Fingerprint != "" {
		tls.UTLS = &SingboxUTLS{
			Enabled:     true,
			Fingerprint: p.Fingerprint,
		}
	}

	// Reality
	if p.Security == "reality" {
		tls.Reality = &SingboxReality{
			Enabled:   true,
			PublicKey: p.PublicKey,
			ShortID:   p.ShortID,
		}
	}

	// ECH
	if p.EchConfigList != "" || p.EchQueryServerName != "" {
		tls.ECH = &SingboxECH{
			Enabled:         true,
			QueryServerName: p.EchQueryServerName,
		}
		if p.EchConfigList != "" {
			tls.ECH.Config = []string{p.EchConfigList}
		}
	}

	return tls
}

func buildSingboxHysteria2(ob *SingboxOutbound, p *model.ProfileItem) {
	// 带宽
	if p.BandwidthUp != "" {
		ob.UpMbps = parseMbps(p.BandwidthUp)
	}
	if p.BandwidthDown != "" {
		ob.DownMbps = parseMbps(p.BandwidthDown)
	}

	// obfs
	if p.ObfsPassword != "" {
		ob.Obfs = &SingboxHy2Obfs{
			Type:     "salamander",
			Password: p.ObfsPassword,
		}
	}

	// 端口跳跃
	if p.PortHopping != "" {
		ob.ServerPorts = normalizeHysteriaServerPorts(p.PortHopping)
		if p.PortHoppingInterval != "" {
			ob.HopInterval = p.PortHoppingInterval + "s"
		}
	}
}

func normalizeHysteriaServerPorts(serverPorts string) []string {
	ports := splitAndTrim(serverPorts, ",")
	for i, port := range ports {
		if strings.Count(port, "-") == 1 && !strings.Contains(port, ":") {
			ports[i] = strings.Replace(port, "-", ":", 1)
		}
	}
	return ports
}

// parseMbps 解析带宽字符串为 Mbps 整型值
// 支持 "100 Mbps", "100Mbps", "100" 格式
func parseMbps(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "Mbps")
	s = strings.TrimSuffix(s, " Mbps")
	s = strings.TrimSuffix(s, "mbps")
	s = strings.TrimSuffix(s, " mbps")
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}
