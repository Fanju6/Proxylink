package subscription

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"proxylink/pkg/model"
	"proxylink/pkg/parser"

	C "github.com/sagernet/sing-box/constant"
	sboption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
	"gopkg.in/yaml.v3"
)

type singboxOutboundOptionsRegistry struct{}

type singboxEndpointOptionsRegistry struct{}

type rawSingboxDocument struct {
	Outbounds []stdjson.RawMessage `json:"outbounds"`
	Endpoints []stdjson.RawMessage `json:"endpoints"`
}

type rawTypedObject struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type sip008Document struct {
	Version int            `json:"version"`
	Servers []sip008Server `json:"servers"`
}

type sip008Server struct {
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
}

func (singboxOutboundOptionsRegistry) CreateOptions(outboundType string) (any, bool) {
	switch outboundType {
	case C.TypeVLESS:
		return &sboption.VLESSOutboundOptions{}, true
	case C.TypeVMess:
		return &sboption.VMessOutboundOptions{}, true
	case C.TypeShadowsocks:
		return &sboption.ShadowsocksOutboundOptions{}, true
	case C.TypeTrojan:
		return &sboption.TrojanOutboundOptions{}, true
	case C.TypeSOCKS:
		return &sboption.SOCKSOutboundOptions{}, true
	case C.TypeHTTP:
		return &sboption.HTTPOutboundOptions{}, true
	case C.TypeHysteria2:
		return &sboption.Hysteria2OutboundOptions{}, true
	case C.TypeAnyTLS:
		return &sboption.AnyTLSOutboundOptions{}, true
	case C.TypeTUIC:
		return &sboption.TUICOutboundOptions{}, true
	default:
		return nil, false
	}
}

func (singboxEndpointOptionsRegistry) CreateOptions(endpointType string) (any, bool) {
	switch endpointType {
	case C.TypeWireGuard:
		return &sboption.WireGuardEndpointOptions{}, true
	case C.TypeTailscale:
		return &sboption.TailscaleEndpointOptions{}, true
	default:
		return nil, false
	}
}

func convertContentWithSingboxProvider(content string) (*ConvertResult, bool) {
	for _, parse := range []func(string) (*ConvertResult, bool){
		parseSingboxDocumentContent,
		parseSingboxClashContent,
		parseSingboxSIP008Content,
		parseSingboxRawContent,
	} {
		if result, ok := parse(content); ok {
			return result, true
		}
	}
	return nil, false
}

func parseSingboxDocumentContent(content string) (*ConvertResult, bool) {
	var document rawSingboxDocument
	if err := stdjson.Unmarshal([]byte(content), &document); err != nil {
		return nil, false
	}
	if len(document.Outbounds) == 0 && len(document.Endpoints) == 0 {
		return nil, false
	}

	ctx := singboxProviderContext()
	result := &ConvertResult{}
	for index, rawOutbound := range document.Outbounds {
		var header rawTypedObject
		if err := stdjson.Unmarshal(rawOutbound, &header); err != nil {
			addProviderError(result, fmt.Errorf("parse sing-box outbound[%d]: %w", index, err))
			continue
		}
		if isIgnoredSingboxOutboundType(header.Type) {
			continue
		}
		result.Total++
		if !isSupportedSingboxOutboundType(header.Type) {
			addProviderError(result, fmt.Errorf("unsupported sing-box outbound %q (%s)", header.Tag, header.Type))
			continue
		}
		var outbound sboption.Outbound
		if err := singjson.UnmarshalContext(ctx, rawOutbound, &outbound); err != nil {
			addProviderError(result, fmt.Errorf("parse sing-box outbound %q (%s): %w", header.Tag, header.Type, err))
			continue
		}
		profile, err := profileFromSingboxOutbound(outbound)
		if err != nil {
			addProviderError(result, err)
			continue
		}
		addProviderProfile(result, profile)
	}

	for index, rawEndpoint := range document.Endpoints {
		var header rawTypedObject
		if err := stdjson.Unmarshal(rawEndpoint, &header); err != nil {
			addProviderError(result, fmt.Errorf("parse sing-box endpoint[%d]: %w", index, err))
			continue
		}
		result.Total++
		if !isSupportedSingboxEndpointType(header.Type) {
			addProviderError(result, fmt.Errorf("unsupported sing-box endpoint %q (%s)", header.Tag, header.Type))
			continue
		}
		var endpoint sboption.Endpoint
		if err := singjson.UnmarshalContext(ctx, rawEndpoint, &endpoint); err != nil {
			addProviderError(result, fmt.Errorf("parse sing-box endpoint %q (%s): %w", header.Tag, header.Type, err))
			continue
		}
		profile, err := profileFromSingboxEndpoint(endpoint)
		if err != nil {
			addProviderError(result, err)
			continue
		}
		addProviderProfile(result, profile)
	}

	return result, result.Total > 0
}

func parseSingboxClashContent(content string) (*ConvertResult, bool) {
	if !parser.IsClashYAML(content) {
		return nil, false
	}
	var config parser.ClashConfig
	if err := yaml.Unmarshal([]byte(content), &config); err != nil || len(config.Proxies) == 0 {
		return nil, false
	}
	profiles, err := parser.ParseClashConfig([]byte(content))
	if err != nil {
		return nil, false
	}

	result := &ConvertResult{Total: len(config.Proxies)}
	for _, proxy := range config.Proxies {
		if !isSupportedClashProxyType(proxy.Type) {
			result.Errors = append(result.Errors, fmt.Errorf("unsupported clash proxy %q (%s)", proxy.Name, proxy.Type))
		}
	}
	for _, profile := range profiles {
		addProviderProfile(result, profile)
	}
	result.Failed = result.Total - result.Success
	return result, true
}

func parseSingboxSIP008Content(content string) (*ConvertResult, bool) {
	var document sip008Document
	if err := stdjson.Unmarshal([]byte(content), &document); err != nil {
		return nil, false
	}
	if len(document.Servers) == 0 {
		return nil, false
	}

	result := &ConvertResult{Total: len(document.Servers)}
	for _, server := range document.Servers {
		p := model.NewProfileItem(model.SHADOWSOCKS)
		p.Remarks = server.Remarks
		p.Server = server.Server
		if server.ServerPort > 0 {
			p.ServerPort = strconv.Itoa(server.ServerPort)
		}
		p.Password = server.Password
		p.Method = server.Method
		p.Plugin = server.Plugin
		p.PluginOpts = server.PluginOpts
		addProviderProfile(result, p)
	}
	return result, true
}

func parseSingboxRawContent(content string) (*ConvertResult, bool) {
	lines, err := Decode(content)
	if err != nil || len(lines) == 0 {
		return nil, false
	}

	result := &ConvertResult{Total: len(lines)}
	for _, line := range lines {
		profile, err := parser.Parse(line)
		if err != nil {
			result.Errors = append(result.Errors, err)
			result.Failed++
			continue
		}
		addProviderProfile(result, profile)
	}
	return result, true
}

func singboxProviderContext() context.Context {
	ctx := context.Background()
	ctx = service.ContextWith[sboption.OutboundOptionsRegistry](ctx, singboxOutboundOptionsRegistry{})
	ctx = service.ContextWith[sboption.EndpointOptionsRegistry](ctx, singboxEndpointOptionsRegistry{})
	return ctx
}

func profileFromSingboxOutbound(outbound sboption.Outbound) (*model.ProfileItem, error) {
	switch options := outbound.Options.(type) {
	case *sboption.VLESSOutboundOptions:
		p := newSingboxProfile(model.VLESS, outbound.Tag, options.ServerOptions)
		p.Password = options.UUID
		p.Method = "none"
		p.Flow = options.Flow
		applySingboxNetwork(p, options.Network)
		applySingboxTLS(p, options.TLS)
		applySingboxTransport(p, options.Transport)
		return p, nil
	case *sboption.VMessOutboundOptions:
		p := newSingboxProfile(model.VMESS, outbound.Tag, options.ServerOptions)
		p.Password = options.UUID
		p.Method = options.Security
		if p.Method == "" {
			p.Method = "auto"
		}
		p.AlterId = options.AlterId
		applySingboxNetwork(p, options.Network)
		applySingboxTLS(p, options.TLS)
		applySingboxTransport(p, options.Transport)
		return p, nil
	case *sboption.ShadowsocksOutboundOptions:
		p := newSingboxProfile(model.SHADOWSOCKS, outbound.Tag, options.ServerOptions)
		p.Method = options.Method
		p.Password = options.Password
		p.Plugin = options.Plugin
		p.PluginOpts = options.PluginOptions
		applySingboxNetwork(p, options.Network)
		return p, nil
	case *sboption.TrojanOutboundOptions:
		p := newSingboxProfile(model.TROJAN, outbound.Tag, options.ServerOptions)
		p.Password = options.Password
		applySingboxNetwork(p, options.Network)
		applySingboxTLS(p, options.TLS)
		applySingboxTransport(p, options.Transport)
		if p.Security == "" {
			p.Security = "tls"
		}
		return p, nil
	case *sboption.SOCKSOutboundOptions:
		p := newSingboxProfile(model.SOCKS, outbound.Tag, options.ServerOptions)
		p.Username = options.Username
		p.Password = options.Password
		applySingboxNetwork(p, options.Network)
		return p, nil
	case *sboption.HTTPOutboundOptions:
		p := newSingboxProfile(model.HTTP, outbound.Tag, options.ServerOptions)
		p.Username = options.Username
		p.Password = options.Password
		p.Path = options.Path
		applySingboxTLS(p, options.TLS)
		return p, nil
	case *sboption.Hysteria2OutboundOptions:
		p := newSingboxProfile(model.HYSTERIA2, outbound.Tag, options.ServerOptions)
		p.Password = options.Password
		p.BandwidthUp = mbpsString(options.UpMbps)
		p.BandwidthDown = mbpsString(options.DownMbps)
		if options.Obfs != nil {
			p.ObfsPassword = options.Obfs.Password
		}
		p.PortHopping = validSingboxServerPorts([]string(options.ServerPorts))
		p.PortHoppingInterval = secondsString(time.Duration(options.HopInterval))
		applySingboxNetwork(p, options.Network)
		applySingboxTLS(p, options.TLS)
		if p.Security == "" {
			p.Security = "tls"
		}
		return p, nil
	case *sboption.AnyTLSOutboundOptions:
		p := newSingboxProfile(model.ANYTLS, outbound.Tag, options.ServerOptions)
		p.Password = options.Password
		p.Network = "tcp"
		applySingboxTLS(p, options.TLS)
		if p.Security == "" {
			p.Security = "tls"
		}
		return p, nil
	case *sboption.TUICOutboundOptions:
		p := newSingboxProfile(model.TUIC, outbound.Tag, options.ServerOptions)
		p.UUID = options.UUID
		p.Password = options.Password
		p.CongestionControl = options.CongestionControl
		p.UDPRelayMode = options.UDPRelayMode
		p.UDPOverStream = options.UDPOverStream
		p.ZeroRTTHandshake = options.ZeroRTTHandshake
		p.Heartbeat = durationString(time.Duration(options.Heartbeat))
		applySingboxNetwork(p, options.Network)
		applySingboxTLS(p, options.TLS)
		if p.Security == "" {
			p.Security = "tls"
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unsupported sing-box outbound %q (%s)", outbound.Tag, outbound.Type)
	}
}

func profileFromSingboxEndpoint(endpoint sboption.Endpoint) (*model.ProfileItem, error) {
	switch options := endpoint.Options.(type) {
	case *sboption.WireGuardEndpointOptions:
		if len(options.Peers) != 1 {
			return nil, fmt.Errorf("unsupported sing-box endpoint %q (%s): wireguard peer count %d", endpoint.Tag, endpoint.Type, len(options.Peers))
		}
		peer := options.Peers[0]
		p := model.NewProfileItem(model.WIREGUARD)
		p.Remarks = endpoint.Tag
		p.Server = peer.Address
		if peer.Port > 0 {
			p.ServerPort = strconv.Itoa(int(peer.Port))
		}
		p.SecretKey = options.PrivateKey
		p.PublicKey = peer.PublicKey
		p.PreSharedKey = peer.PreSharedKey
		p.LocalAddress = prefixListString([]netip.Prefix(options.Address))
		p.Reserved = uint8ListString(peer.Reserved)
		p.MTU = int(options.MTU)
		return p, nil
	default:
		return nil, fmt.Errorf("unsupported sing-box endpoint %q (%s)", endpoint.Tag, endpoint.Type)
	}
}

func newSingboxProfile(configType model.ConfigType, tag string, server sboption.ServerOptions) *model.ProfileItem {
	p := model.NewProfileItem(configType)
	p.Remarks = tag
	p.Server = server.Server
	if server.ServerPort > 0 {
		p.ServerPort = strconv.Itoa(int(server.ServerPort))
	}
	return p
}

func addProviderProfile(result *ConvertResult, profile *model.ProfileItem) {
	normalizeProviderProfile(profile)
	result.Profiles = append(result.Profiles, profile)
	result.Success++
}

func addProviderError(result *ConvertResult, err error) {
	result.Errors = append(result.Errors, err)
	result.Failed++
}

func normalizeProviderProfile(profile *model.ProfileItem) {
	if profile == nil || profile.ConfigType != model.HYSTERIA2 {
		return
	}
	profile.PortHopping = validSingboxServerPorts(splitPortHopping(profile.PortHopping))
	if profile.PortHopping == "" {
		profile.PortHoppingInterval = ""
	}
}

func splitPortHopping(portHopping string) []string {
	if portHopping == "" {
		return nil
	}
	return strings.FieldsFunc(portHopping, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
}

func isIgnoredSingboxOutboundType(outboundType string) bool {
	switch outboundType {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest, "pass":
		return true
	default:
		return false
	}
}

func isSupportedSingboxOutboundType(outboundType string) bool {
	_, ok := singboxOutboundOptionsRegistry{}.CreateOptions(outboundType)
	return ok
}

func isSupportedSingboxEndpointType(endpointType string) bool {
	switch endpointType {
	case C.TypeWireGuard, C.TypeTailscale:
		return true
	default:
		return false
	}
}

func isSupportedClashProxyType(proxyType string) bool {
	switch strings.ToLower(proxyType) {
	case "vless", "vmess", "ss", "socks", "socks5", "trojan", "hysteria2", "hy2", "anytls", "tuic":
		return true
	default:
		return false
	}
}

func applySingboxNetwork(p *model.ProfileItem, network sboption.NetworkList) {
	networks := network.Build()
	if len(networks) == 0 {
		return
	}
	if p.ConfigType == model.SOCKS {
		hasTCP := containsString(networks, "tcp")
		hasUDP := containsString(networks, "udp")
		p.UDP = hasUDP
		switch {
		case hasTCP && hasUDP:
			p.Network = ""
		case hasTCP:
			p.Network = "tcp"
		case hasUDP:
			p.Network = "udp"
		}
		return
	}
	if containsString(networks, "udp") {
		p.UDP = true
	}
	if containsString(networks, "tcp") {
		if !p.UDP || p.ConfigType != model.TUIC {
			p.Network = "tcp"
		}
		return
	}
	if len(networks) == 1 {
		p.Network = networks[0]
	}
}

func applySingboxTLS(p *model.ProfileItem, tlsOptions *sboption.OutboundTLSOptions) {
	if tlsOptions == nil || !tlsOptions.Enabled {
		return
	}
	if tlsOptions.Reality != nil && tlsOptions.Reality.Enabled {
		p.Security = "reality"
		p.PublicKey = tlsOptions.Reality.PublicKey
		p.ShortID = tlsOptions.Reality.ShortID
	} else {
		p.Security = "tls"
	}
	p.SNI = tlsOptions.ServerName
	p.Insecure = tlsOptions.Insecure
	p.DisableSNI = tlsOptions.DisableSNI
	p.ALPN = stringListString([]string(tlsOptions.ALPN))
	if tlsOptions.UTLS != nil && tlsOptions.UTLS.Enabled {
		p.Fingerprint = tlsOptions.UTLS.Fingerprint
	}
	if tlsOptions.ECH != nil && tlsOptions.ECH.Enabled {
		configs := []string(tlsOptions.ECH.Config)
		if len(configs) > 0 {
			p.EchConfigList = configs[0]
		}
		p.EchQueryServerName = tlsOptions.ECH.QueryServerName
	}
}

func applySingboxTransport(p *model.ProfileItem, transport *sboption.V2RayTransportOptions) {
	if transport == nil {
		return
	}
	p.Network = transport.Type
	switch transport.Type {
	case C.V2RayTransportTypeWebsocket:
		p.Path = cleanPath(transport.WebsocketOptions.Path)
		p.Host = firstHeaderValue(transport.WebsocketOptions.Headers, "Host")
		if transport.WebsocketOptions.MaxEarlyData > 0 {
			p.MaxEarlyData = int(transport.WebsocketOptions.MaxEarlyData)
			p.EarlyDataHeaderName = transport.WebsocketOptions.EarlyDataHeaderName
		}
	case C.V2RayTransportTypeHTTP:
		p.Network = "h2"
		p.Path = cleanPath(transport.HTTPOptions.Path)
		p.Host = strings.Join([]string(transport.HTTPOptions.Host), ",")
	case C.V2RayTransportTypeGRPC:
		p.ServiceName = transport.GRPCOptions.ServiceName
	case C.V2RayTransportTypeHTTPUpgrade:
		p.Path = cleanPath(transport.HTTPUpgradeOptions.Path)
		p.Host = transport.HTTPUpgradeOptions.Host
		if p.Host == "" {
			p.Host = firstHeaderValue(transport.HTTPUpgradeOptions.Headers, "Host")
		}
	}
}

func validSingboxServerPorts(serverPorts []string) string {
	valid := make([]string, 0, len(serverPorts))
	for _, portRange := range serverPorts {
		if normalized := normalizeSingboxPortRange(portRange); normalized != "" {
			valid = append(valid, normalized)
		}
	}
	return strings.Join(valid, ",")
}

func normalizeSingboxPortRange(portRange string) string {
	portRange = strings.TrimSpace(portRange)
	if portRange == "" {
		return ""
	}
	portRange = strings.ReplaceAll(portRange, "-", ":")
	parts := strings.Split(portRange, ":")
	if len(parts) != 2 {
		return ""
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || start < 1 || start > 65535 {
		return ""
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || end < 1 || end > 65535 || start >= end {
		return ""
	}
	return strconv.Itoa(start) + ":" + strconv.Itoa(end)
}

func mbpsString(value int) string {
	if value <= 0 {
		return ""
	}
	return strconv.Itoa(value) + " Mbps"
}

func secondsString(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	seconds := int64(value / time.Second)
	if seconds <= 0 {
		return ""
	}
	return strconv.FormatInt(seconds, 10)
}

func durationString(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	return value.String()
}

func cleanPath(path string) string {
	if path == "/" {
		return ""
	}
	return path
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstHeaderValue(headers badoption.HTTPHeader, key string) string {
	for headerKey, values := range headers {
		if strings.EqualFold(headerKey, key) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func stringListString(values []string) string {
	return strings.Join(values, ",")
}

func prefixListString(values []netip.Prefix) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, value.String())
	}
	return strings.Join(parts, ",")
}

func uint8ListString(values []uint8) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, ",")
}
