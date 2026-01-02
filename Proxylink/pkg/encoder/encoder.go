package encoder

import (
	"proxylink/pkg/model"
	"proxylink/pkg/parser"
)

// ToURI 将 ProfileItem 转换为 URI 链接
func ToURI(profile *model.ProfileItem) string {
	switch profile.ConfigType {
	case model.VLESS:
		return parser.ToVLessURI(profile)
	case model.VMESS:
		return parser.ToVMessURI(profile)
	case model.SHADOWSOCKS:
		return parser.ToShadowsocksURI(profile)
	case model.TROJAN:
		return parser.ToTrojanURI(profile)
	case model.SOCKS:
		return parser.ToSocksURI(profile)
	case model.HTTP:
		return parser.ToHTTPURI(profile)
	case model.WIREGUARD:
		return parser.ToWireGuardURI(profile)
	case model.HYSTERIA2:
		return parser.ToHysteria2URI(profile)
	default:
		return ""
	}
}

// ToURIBatch 批量生成 URI 链接
func ToURIBatch(profiles []*model.ProfileItem) []string {
	var uris []string
	for _, profile := range profiles {
		if uri := ToURI(profile); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}
