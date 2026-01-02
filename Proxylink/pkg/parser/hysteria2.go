package parser

import (
	"net/url"
	"strings"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseHysteria2 解析 Hysteria2 链接
// 格式: hysteria2://auth@server:port?sni=xxx&insecure=1&obfs-password=xxx#remarks
// 或: hy2://auth@server:port?...
func ParseHysteria2(uri string) (*model.ProfileItem, error) {
	// 统一 scheme
	uri = strings.Replace(uri, "hy2://", "hysteria2://", 1)

	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.HYSTERIA2)

	// 基础信息
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.Password = u.User.Username() // 认证密码
	config.Security = "tls"             // Hysteria2 默认 TLS

	// 解析查询参数
	query := u.Query()
	config.SNI = query.Get("sni")
	config.ALPN = query.Get("alpn")
	config.Fingerprint = query.Get("fp")

	// Insecure
	insecure := query.Get("insecure")
	if insecure == "" {
		insecure = query.Get("allowInsecure")
	}
	config.Insecure = insecure == "1"

	// Hysteria2 特有参数
	config.ObfsPassword = query.Get("obfs-password")
	config.PortHopping = query.Get("mport")
	config.PortHoppingInterval = query.Get("mportHopInt")
	config.PinSHA256 = query.Get("pinSHA256")

	return config, nil
}

// ToHysteria2URI 生成 Hysteria2 链接
func ToHysteria2URI(config *model.ProfileItem) string {
	query := url.Values{}

	// TLS 参数
	if config.SNI != "" {
		query.Set("sni", config.SNI)
	}
	if config.ALPN != "" {
		query.Set("alpn", config.ALPN)
	}
	if config.Insecure {
		query.Set("insecure", "1")
	} else {
		query.Set("insecure", "0")
	}

	// Hysteria2 特有参数
	if config.ObfsPassword != "" {
		query.Set("obfs", "salamander")
		query.Set("obfs-password", config.ObfsPassword)
	}
	if config.PortHopping != "" {
		query.Set("mport", config.PortHopping)
	}
	if config.PortHoppingInterval != "" {
		query.Set("mportHopInt", config.PortHoppingInterval)
	}
	if config.PinSHA256 != "" {
		query.Set("pinSHA256", config.PinSHA256)
	}

	host := util.GetIPv6Address(config.Server) + ":" + config.ServerPort

	queryStr := ""
	if len(query) > 0 {
		queryStr = "?" + query.Encode()
	}

	remarks := ""
	if config.Remarks != "" {
		remarks = "#" + util.URLEncode(config.Remarks)
	}

	return "hysteria2://" + util.URLEncode(config.Password) + "@" + host + queryStr + remarks
}
