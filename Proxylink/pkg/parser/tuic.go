package parser

import (
	"net/url"
	"strings"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseTUIC 解析 TUIC 链接
// 格式: tuic://uuid:password@server:port?sni=xxx&congestion_control=bbr#remarks
func ParseTUIC(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.TUIC)
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.UUID = u.User.Username()
	if password, ok := u.User.Password(); ok {
		config.Password = password
	}
	config.Security = "tls"

	query := u.Query()
	if config.UUID == "" {
		config.UUID = query.Get("uuid")
	}
	if config.Password == "" {
		config.Password = query.Get("password")
	}

	parseQueryParams(config, query)
	parseTUICQueryParams(config, query)
	config.Security = "tls"

	return config, nil
}

// ToTUICURI 生成 TUIC 链接
func ToTUICURI(config *model.ProfileItem) string {
	query := buildAnyTLSTUICQueryParams(config)
	if config.CongestionControl != "" {
		query.Set("congestion_control", config.CongestionControl)
	}
	if config.UDPRelayMode != "" {
		query.Set("udp_relay_mode", config.UDPRelayMode)
	}
	if config.UDPOverStream {
		query.Set("udp_over_stream", "1")
	}
	if config.ZeroRTTHandshake {
		query.Set("zero_rtt_handshake", "1")
	}
	if config.Heartbeat != "" {
		query.Set("heartbeat", config.Heartbeat)
	}
	if config.DisableSNI {
		query.Set("disable_sni", "1")
	}
	if config.UDP {
		query.Set("udp", "1")
	}

	return buildUserPasswordURI("tuic://", config.UUID, config.Password, config, query)
}

func parseTUICQueryParams(config *model.ProfileItem, query url.Values) {
	config.CongestionControl = firstQueryValue(query, "congestion_control", "congestion-controller")
	config.UDPRelayMode = firstQueryValue(query, "udp_relay_mode", "udp-relay-mode")
	config.UDPOverStream = queryBool(query, "udp_over_stream", "udp-over-stream")
	config.ZeroRTTHandshake = queryBool(query, "zero_rtt_handshake", "zero-rtt-handshake", "reduce_rtt", "reduce-rtt")
	config.Heartbeat = firstQueryValue(query, "heartbeat", "heartbeat_interval", "heartbeat-interval")
	config.DisableSNI = queryBool(query, "disable_sni", "disable-sni")
	config.UDP = queryBool(query, "udp")

	network := firstQueryValue(query, "network", "type")
	switch {
	case network != "":
		config.Network = network
	case config.UDP:
		config.Network = ""
	default:
		config.Network = "tcp"
	}
}

func buildAnyTLSTUICQueryParams(config *model.ProfileItem) url.Values {
	query := url.Values{}

	if config.SNI != "" {
		query.Set("sni", config.SNI)
	}
	if config.ALPN != "" {
		query.Set("alpn", config.ALPN)
	}
	if config.Fingerprint != "" {
		query.Set("fp", config.Fingerprint)
	}
	if config.Insecure {
		query.Set("insecure", "1")
	}

	return query
}

func firstQueryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func queryBool(query url.Values, keys ...string) bool {
	value := strings.ToLower(firstQueryValue(query, keys...))
	return value == "1" || value == "true" || value == "yes"
}

func buildUserPasswordURI(scheme, username, password string, config *model.ProfileItem, query url.Values) string {
	host := util.GetIPv6Address(config.Server) + ":" + config.ServerPort

	queryStr := ""
	if len(query) > 0 {
		queryStr = "?" + query.Encode()
	}

	remarks := ""
	if config.Remarks != "" {
		remarks = "#" + util.URLEncode(config.Remarks)
	}

	userInfo := ""
	if username != "" {
		userInfo = util.URLEncode(username)
		if password != "" {
			userInfo += ":" + util.URLEncode(password)
		}
		userInfo += "@"
	}

	return scheme + userInfo + host + queryStr + remarks
}
