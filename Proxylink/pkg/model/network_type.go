package model

// NetworkType 传输协议类型
type NetworkType string

const (
	NetworkTCP         NetworkType = "tcp"
	NetworkKCP         NetworkType = "kcp"
	NetworkWS          NetworkType = "ws"
	NetworkHTTP        NetworkType = "http"
	NetworkH2          NetworkType = "h2"
	NetworkGRPC        NetworkType = "grpc"
	NetworkQUIC        NetworkType = "quic"
	NetworkHTTPUpgrade NetworkType = "httpupgrade"
	NetworkXHTTP       NetworkType = "xhttp"
)

// String 返回传输协议类型的字符串表示
func (n NetworkType) String() string {
	return string(n)
}

// ParseNetworkType 从字符串解析传输协议类型
func ParseNetworkType(s string) NetworkType {
	switch s {
	case "tcp":
		return NetworkTCP
	case "kcp":
		return NetworkKCP
	case "ws", "websocket":
		return NetworkWS
	case "http":
		return NetworkHTTP
	case "h2", "http2":
		return NetworkH2
	case "grpc", "gun":
		return NetworkGRPC
	case "quic":
		return NetworkQUIC
	case "httpupgrade":
		return NetworkHTTPUpgrade
	case "xhttp", "splithttp":
		return NetworkXHTTP
	default:
		return NetworkTCP
	}
}
