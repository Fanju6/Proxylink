package model

import "fmt"

// ProfileItem 代理节点配置结构
type ProfileItem struct {
	ConfigType     ConfigType `json:"configType"`
	SubscriptionID string     `json:"subscriptionId,omitempty"`
	Remarks        string     `json:"remarks"`
	Server         string     `json:"server"`
	ServerPort     string     `json:"serverPort"`

	// 认证信息
	Password string `json:"password,omitempty"` // UUID (VLESS/VMess) / 密码 (SS/Trojan/Hysteria2)
	Method   string `json:"method,omitempty"`   // 加密方法 (SS) / encryption (VLESS) / scy (VMess)
	Flow     string `json:"flow,omitempty"`     // 流控 (VLESS/Trojan)
	Username string `json:"username,omitempty"` // 用户名 (Socks/HTTP)
	AlterId  int    `json:"alterId,omitempty"`  // VMess alterId

	// 传输层配置
	Network      string `json:"network,omitempty"`      // tcp/ws/grpc/h2/kcp/quic/httpupgrade/xhttp
	HeaderType   string `json:"headerType,omitempty"`   // 伪装类型
	Host         string `json:"host,omitempty"`         // 主机头
	Path         string `json:"path,omitempty"`         // 路径
	Seed         string `json:"seed,omitempty"`         // KCP seed
	QuicSecurity string `json:"quicSecurity,omitempty"` // QUIC 加密
	QuicKey      string `json:"quicKey,omitempty"`      // QUIC 密钥
	Mode         string `json:"mode,omitempty"`         // gRPC 模式
	ServiceName  string `json:"serviceName,omitempty"`  // gRPC serviceName
	Authority    string `json:"authority,omitempty"`    // gRPC authority
	XhttpMode    string `json:"xhttpMode,omitempty"`    // XHTTP 模式
	XhttpExtra   string `json:"xhttpExtra,omitempty"`   // XHTTP 额外配置

	// TLS 配置
	Security      string `json:"security,omitempty"`      // tls/reality/none
	SNI           string `json:"sni,omitempty"`           // SNI
	ALPN          string `json:"alpn,omitempty"`          // ALPN
	Fingerprint   string `json:"fingerprint,omitempty"`   // TLS 指纹
	Insecure      bool   `json:"insecure,omitempty"`      // 跳过证书验证
	Mldsa65Verify string `json:"mldsa65Verify,omitempty"` // MLDSA65 验证 (pqv)

	// Reality 配置
	PublicKey string `json:"publicKey,omitempty"` // Reality 公钥
	ShortID   string `json:"shortId,omitempty"`   // Reality shortId
	SpiderX   string `json:"spiderX,omitempty"`   // Reality spiderX

	// WireGuard 配置
	SecretKey    string `json:"secretKey,omitempty"`    // 私钥
	PreSharedKey string `json:"preSharedKey,omitempty"` // 预共享密钥
	LocalAddress string `json:"localAddress,omitempty"` // 本地地址
	Reserved     string `json:"reserved,omitempty"`     // 保留字段
	MTU          int    `json:"mtu,omitempty"`          // MTU

	// Hysteria2 配置
	ObfsPassword        string `json:"obfsPassword,omitempty"`        // 混淆密码
	PortHopping         string `json:"portHopping,omitempty"`         // 端口跳跃范围
	PortHoppingInterval string `json:"portHoppingInterval,omitempty"` // 端口跳跃间隔
	PinSHA256           string `json:"pinSHA256,omitempty"`           // 证书指纹
	BandwidthDown       string `json:"bandwidthDown,omitempty"`       // 下行带宽
	BandwidthUp         string `json:"bandwidthUp,omitempty"`         // 上行带宽
}

// GetServerAddressAndPort 返回 server:port 格式的地址
func (p *ProfileItem) GetServerAddressAndPort() string {
	return fmt.Sprintf("%s:%s", p.Server, p.ServerPort)
}

// NewProfileItem 创建新的 ProfileItem
func NewProfileItem(configType ConfigType) *ProfileItem {
	return &ProfileItem{
		ConfigType: configType,
	}
}
