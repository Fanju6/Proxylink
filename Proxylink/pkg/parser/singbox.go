package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"

	"proxylink/pkg/model"
)

var skippedSingboxOutboundTypes = map[string]struct{}{
	"selector": {},
	"urltest":  {},
	"direct":   {},
	"block":    {},
	"dns":      {},
}

// SingboxParseStats 记录 sing-box 配置逐出站解析结果。
type SingboxParseStats struct {
	Total         int
	Success       int
	Failed        int
	Skipped       int
	Compatible    int
	SkippedByType map[string]int
}

// SingboxOutboundError 描述单个出站的解析错误，不包含敏感配置内容。
type SingboxOutboundError struct {
	Index int
	Tag   string
	Type  string
	Err   error
}

func (e SingboxOutboundError) Error() string {
	return fmt.Sprintf("outbounds[%d] tag=%q type=%q: %v", e.Index, e.Tag, e.Type, e.Err)
}

func (e SingboxOutboundError) Unwrap() error {
	return e.Err
}

// SingboxCompatibilityEvent 记录不含凭据的旧格式转换事件。
type SingboxCompatibilityEvent struct {
	Index int
	Tag   string
	Type  string
	Rule  string
}

// SingboxParseResult 保存成功节点、统计、兼容事件和局部错误。
type SingboxParseResult struct {
	Profiles            []*model.ProfileItem
	Stats               SingboxParseStats
	Errors              []SingboxOutboundError
	CompatibilityEvents []SingboxCompatibilityEvent
}

type singboxOutboundHeader struct {
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`
}

// IsSingboxSubscription 判断内容是否为官方完整配置形态。
func IsSingboxSubscription(data []byte) bool {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return false
	}
	outbounds, exists := document["outbounds"]
	if !exists {
		return false
	}
	outbounds = bytes.TrimSpace(outbounds)
	if len(outbounds) == 0 || outbounds[0] != '[' {
		return false
	}
	var values []json.RawMessage
	return json.Unmarshal(outbounds, &values) == nil
}

// ParseSingboxConfig 兼容原接口，返回成功解析的 ProfileItem。
func ParseSingboxConfig(data []byte) ([]*model.ProfileItem, error) {
	result, err := ParseSingboxDetailed(data)
	if err != nil {
		return nil, err
	}
	return result.Profiles, nil
}

// ParseSingboxDetailed 解析完整配置、出站数组或单个出站对象。
func ParseSingboxDetailed(data []byte) (*SingboxParseResult, error) {
	outbounds, err := decodeSingboxOutbounds(data)
	if err != nil {
		return nil, err
	}

	result := &SingboxParseResult{Stats: SingboxParseStats{
		Total:         len(outbounds),
		SkippedByType: make(map[string]int),
	}}
	for index, raw := range outbounds {
		var header singboxOutboundHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			result.Stats.Failed++
			result.Errors = append(result.Errors, SingboxOutboundError{Index: index, Err: err})
			continue
		}
		header.Type = canonicalSingboxOutboundType(header.Type)
		if header.Type == "" {
			result.Stats.Failed++
			result.Errors = append(result.Errors, SingboxOutboundError{
				Index: index,
				Tag:   header.Tag,
				Err:   fmt.Errorf("缺少出站类型"),
			})
			continue
		}

		if _, skipped := skippedSingboxOutboundTypes[header.Type]; skipped {
			result.Stats.Skipped++
			result.Stats.SkippedByType[header.Type]++
			continue
		}
		if _, supported := newOfficialOptions(header.Type); !supported {
			result.Stats.Skipped++
			result.Stats.SkippedByType[header.Type]++
			continue
		}

		outbound, compatible, err := parseOfficialOutbound(context.Background(), raw, header)
		if err != nil {
			result.Stats.Failed++
			result.Errors = append(result.Errors, SingboxOutboundError{
				Index: index,
				Tag:   header.Tag,
				Type:  header.Type,
				Err:   err,
			})
			continue
		}
		profile := fromOfficialSingboxOutbound(outbound)
		if profile == nil {
			result.Stats.Failed++
			result.Errors = append(result.Errors, SingboxOutboundError{
				Index: index,
				Tag:   header.Tag,
				Type:  header.Type,
				Err:   fmt.Errorf("无法映射官方出站类型"),
			})
			continue
		}
		result.Profiles = append(result.Profiles, profile)
		result.Stats.Success++
		if compatible {
			result.Stats.Compatible++
			result.CompatibilityEvents = append(result.CompatibilityEvents, SingboxCompatibilityEvent{
				Index: index,
				Tag:   header.Tag,
				Type:  header.Type,
				Rule:  legacyEmptyTransportArrayRule,
			})
		}
	}

	if result.Stats.Success == 0 {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("未找到可用的 sing-box 代理出站: %w", result.Errors[0])
		}
		return nil, fmt.Errorf("未找到可用的 sing-box 代理出站")
	}
	return result, nil
}

func decodeSingboxOutbounds(data []byte) ([]json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("sing-box 配置为空")
	}

	switch trimmed[0] {
	case '[':
		var outbounds []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &outbounds); err != nil {
			return nil, fmt.Errorf("解析 sing-box 出站数组失败: %w", err)
		}
		return outbounds, nil
	case '{':
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &document); err != nil {
			return nil, fmt.Errorf("解析 sing-box JSON 对象失败: %w", err)
		}
		if rawOutbounds, exists := document["outbounds"]; exists {
			var outbounds []json.RawMessage
			if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
				return nil, fmt.Errorf("sing-box outbounds 必须为数组: %w", err)
			}
			return outbounds, nil
		}
		var header singboxOutboundHeader
		if err := json.Unmarshal([]byte(trimmed), &header); err != nil || header.Type == "" {
			return nil, fmt.Errorf("无法解析为有效的 sing-box 节点配置格式")
		}
		return []json.RawMessage{json.RawMessage(trimmed)}, nil
	default:
		return nil, fmt.Errorf("无法解析为有效的 sing-box 节点配置格式")
	}
}

func canonicalSingboxOutboundType(outboundType string) string {
	switch strings.ToLower(strings.TrimSpace(outboundType)) {
	case "ss":
		return "shadowsocks"
	case "hy2":
		return "hysteria2"
	default:
		return strings.ToLower(strings.TrimSpace(outboundType))
	}
}

func newOfficialOptions(outboundType string) (any, bool) {
	switch outboundType {
	case "vmess":
		return &option.VMessOutboundOptions{}, true
	case "vless":
		return &option.VLESSOutboundOptions{}, true
	case "shadowsocks":
		return &option.ShadowsocksOutboundOptions{}, true
	case "trojan":
		return &option.TrojanOutboundOptions{}, true
	case "hysteria2":
		return &option.Hysteria2OutboundOptions{}, true
	case "anytls":
		return &option.AnyTLSOutboundOptions{}, true
	case "tuic":
		return &option.TUICOutboundOptions{}, true
	default:
		return nil, false
	}
}

func parseOfficialOutbound(ctx context.Context, raw json.RawMessage, header singboxOutboundHeader) (*model.OfficialSingboxOutbound, bool, error) {
	options, supported := newOfficialOptions(header.Type)
	if !supported {
		return nil, false, fmt.Errorf("不支持的出站类型: %s", header.Type)
	}
	if err := singJSON.UnmarshalContext(ctx, raw, options); err == nil {
		return model.NewOfficialSingboxOutbound(header.Type, header.Tag, options), false, nil
	} else {
		officialErr := err
		normalized, compatible, normalizeErr := normalizeLegacyOutbound(raw)
		if normalizeErr != nil {
			return nil, false, fmt.Errorf("官方 %s 出站解析失败: %v；兼容转换失败: %w", header.Type, officialErr, normalizeErr)
		}
		if !compatible {
			return nil, false, fmt.Errorf("官方 %s 出站解析失败: %w", header.Type, officialErr)
		}

		options, _ = newOfficialOptions(header.Type)
		if retryErr := singJSON.UnmarshalContext(ctx, normalized, options); retryErr != nil {
			return nil, false, fmt.Errorf("官方 %s 出站解析失败: %v；兼容规则 %s 转换后仍无效: %w", header.Type, officialErr, legacyEmptyTransportArrayRule, retryErr)
		}
		return model.NewOfficialSingboxOutbound(header.Type, header.Tag, options), true, nil
	}
}

func fromOfficialSingboxOutbound(outbound *model.OfficialSingboxOutbound) *model.ProfileItem {
	var profile *model.ProfileItem

	switch options := outbound.Options().(type) {
	case *option.VMessOutboundOptions:
		profile = model.NewProfileItem(model.VMESS)
		profile.Password = options.UUID
		profile.Method = options.Security
		if profile.Method == "" {
			profile.Method = "auto"
		}
		profile.AlterId = options.AlterId
		applyServerOptions(profile, options.ServerOptions)
		applyV2RayTransport(profile, options.Transport)
		applyOutboundTLS(profile, options.TLS)
	case *option.VLESSOutboundOptions:
		profile = model.NewProfileItem(model.VLESS)
		profile.Password = options.UUID
		profile.Flow = options.Flow
		profile.Method = "none"
		applyServerOptions(profile, options.ServerOptions)
		applyV2RayTransport(profile, options.Transport)
		applyOutboundTLS(profile, options.TLS)
	case *option.ShadowsocksOutboundOptions:
		profile = model.NewProfileItem(model.SHADOWSOCKS)
		profile.Method = options.Method
		profile.Password = options.Password
		profile.Plugin = options.Plugin
		profile.PluginOpts = options.PluginOptions
		applyServerOptions(profile, options.ServerOptions)
	case *option.TrojanOutboundOptions:
		profile = model.NewProfileItem(model.TROJAN)
		profile.Password = options.Password
		applyServerOptions(profile, options.ServerOptions)
		applyV2RayTransport(profile, options.Transport)
		applyOutboundTLS(profile, options.TLS)
	case *option.Hysteria2OutboundOptions:
		profile = model.NewProfileItem(model.HYSTERIA2)
		profile.Password = options.Password
		applyServerOptions(profile, options.ServerOptions)
		applyOutboundTLS(profile, options.TLS)
		if options.UpMbps > 0 {
			profile.BandwidthUp = strconv.Itoa(options.UpMbps) + " Mbps"
		}
		if options.DownMbps > 0 {
			profile.BandwidthDown = strconv.Itoa(options.DownMbps) + " Mbps"
		}
		if options.Obfs != nil {
			profile.ObfsPassword = options.Obfs.Password
		}
		if len(options.ServerPorts) > 0 {
			profile.PortHopping = strings.Join([]string(options.ServerPorts), ",")
		}
		if interval := options.HopInterval.Build(); interval > 0 {
			profile.PortHoppingInterval = strings.TrimSuffix(interval.String(), "s")
		}
	case *option.AnyTLSOutboundOptions:
		profile = model.NewProfileItem(model.ANYTLS)
		profile.Password = options.Password
		applyServerOptions(profile, options.ServerOptions)
		applyOutboundTLS(profile, options.TLS)
	case *option.TUICOutboundOptions:
		profile = model.NewProfileItem(model.TUIC)
		profile.UUID = options.UUID
		profile.Password = options.Password
		profile.CongestionControl = options.CongestionControl
		profile.UDPRelayMode = options.UDPRelayMode
		profile.UDPOverStream = options.UDPOverStream
		profile.ZeroRTTHandshake = options.ZeroRTTHandshake
		if heartbeat := options.Heartbeat.Build(); heartbeat > 0 {
			profile.Heartbeat = heartbeat.String()
		}
		applyServerOptions(profile, options.ServerOptions)
		applyOutboundTLS(profile, options.TLS)
		networks := options.Network.Build()
		if len(networks) > 0 {
			profile.Network = strings.Join(networks, ",")
		}
		profile.UDP = len(networks) == 0 || containsString(networks, "udp")
	default:
		return nil
	}

	profile.Remarks = outbound.Tag()
	profile.OfficialSingboxOutbound = outbound
	if profile.Network == "" {
		profile.Network = "tcp"
	}
	if (profile.ConfigType == model.TROJAN || profile.ConfigType == model.HYSTERIA2 || profile.ConfigType == model.ANYTLS || profile.ConfigType == model.TUIC) && profile.Security == "" {
		profile.Security = "tls"
	}
	return profile
}

func applyServerOptions(profile *model.ProfileItem, server option.ServerOptions) {
	profile.Server = server.Server
	if server.ServerPort > 0 {
		profile.ServerPort = strconv.Itoa(int(server.ServerPort))
	}
}

func applyV2RayTransport(profile *model.ProfileItem, transport *option.V2RayTransportOptions) {
	if transport == nil {
		return
	}
	profile.Network = transport.Type
	switch transport.Type {
	case "ws":
		applyTransportPath(profile, transport.WebsocketOptions.Path)
		profile.Host = strings.Join(transport.WebsocketOptions.Headers.Build().Values("Host"), ",")
	case "http":
		applyTransportPath(profile, transport.HTTPOptions.Path)
		profile.Host = strings.Join([]string(transport.HTTPOptions.Host), ",")
	case "grpc":
		profile.ServiceName = transport.GRPCOptions.ServiceName
	case "httpupgrade":
		applyTransportPath(profile, transport.HTTPUpgradeOptions.Path)
		profile.Host = transport.HTTPUpgradeOptions.Host
		if profile.Host == "" {
			profile.Host = strings.Join(transport.HTTPUpgradeOptions.Headers.Build().Values("Host"), ",")
		}
	}
}

func applyTransportPath(profile *model.ProfileItem, path string) {
	if path != "" && path != "/" {
		profile.Path = path
	}
}

func applyOutboundTLS(profile *model.ProfileItem, tls *option.OutboundTLSOptions) {
	if tls == nil || !tls.Enabled {
		return
	}
	profile.Security = "tls"
	profile.SNI = tls.ServerName
	profile.Insecure = tls.Insecure
	profile.DisableSNI = tls.DisableSNI
	if len(tls.ALPN) > 0 {
		profile.ALPN = strings.Join([]string(tls.ALPN), ",")
	}
	if tls.UTLS != nil && tls.UTLS.Enabled {
		profile.Fingerprint = tls.UTLS.Fingerprint
	}
	if tls.Reality != nil && tls.Reality.Enabled {
		profile.Security = "reality"
		profile.PublicKey = tls.Reality.PublicKey
		profile.ShortID = tls.Reality.ShortID
	}
	if tls.ECH != nil && tls.ECH.Enabled {
		if len(tls.ECH.Config) > 0 {
			profile.EchConfigList = tls.ECH.Config[0]
		}
		profile.EchQueryServerName = tls.ECH.QueryServerName
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
