package model

// ConfigType 协议类型枚举
type ConfigType int

const (
	VMESS ConfigType = iota
	VLESS
	SHADOWSOCKS
	SOCKS
	HTTP
	TROJAN
	WIREGUARD
	HYSTERIA2
	CUSTOM
)

// String 返回协议类型的字符串表示
func (c ConfigType) String() string {
	switch c {
	case VMESS:
		return "vmess"
	case VLESS:
		return "vless"
	case SHADOWSOCKS:
		return "shadowsocks"
	case SOCKS:
		return "socks"
	case HTTP:
		return "http"
	case TROJAN:
		return "trojan"
	case WIREGUARD:
		return "wireguard"
	case HYSTERIA2:
		return "hysteria2"
	case CUSTOM:
		return "custom"
	default:
		return "unknown"
	}
}

// ProtocolScheme 返回协议的 URI scheme
func (c ConfigType) ProtocolScheme() string {
	switch c {
	case VMESS:
		return "vmess://"
	case VLESS:
		return "vless://"
	case SHADOWSOCKS:
		return "ss://"
	case SOCKS:
		return "socks://"
	case HTTP:
		return "http://"
	case TROJAN:
		return "trojan://"
	case WIREGUARD:
		return "wireguard://"
	case HYSTERIA2:
		return "hysteria2://"
	default:
		return ""
	}
}
