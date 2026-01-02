package parser

import (
	"net/url"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseTrojan 解析 Trojan 链接
// 格式: trojan://password@server:port?type=tcp&security=tls&sni=xxx#remarks
func ParseTrojan(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.TROJAN)

	// 基础信息
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.Password = u.User.Username()

	// 默认值
	config.Network = "tcp"
	config.Security = "tls"

	// 解析查询参数
	if u.RawQuery != "" {
		query := u.Query()
		parseQueryParams(config, query)

		// Trojan 特殊处理：如果没有 security 参数，默认 tls
		security := query.Get("security")
		if security != "" {
			config.Security = security
		} else {
			config.Security = "tls"
		}
	}

	return config, nil
}

// ToTrojanURI 生成 Trojan 链接
func ToTrojanURI(config *model.ProfileItem) string {
	query := buildQueryParams(config)

	// Trojan 默认 tls
	if config.Security == "" || config.Security == "tls" {
		query.Set("security", "tls")
	}

	return buildURI("trojan://", config.Password, config, query)
}
