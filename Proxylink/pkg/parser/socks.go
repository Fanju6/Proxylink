package parser

import (
	"net/url"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseSocks 解析 Socks 链接
// 格式: socks://[user:pass@]server:port#remarks
func ParseSocks(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.SOCKS)

	// 基础信息
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()

	// 认证信息
	if u.User != nil {
		config.Username = u.User.Username()
		if pwd, ok := u.User.Password(); ok {
			config.Password = pwd
		}
	}

	return config, nil
}

// ToSocksURI 生成 Socks 链接
func ToSocksURI(config *model.ProfileItem) string {
	userInfo := ""
	if config.Username != "" {
		userInfo = config.Username
		if config.Password != "" {
			userInfo += ":" + config.Password
		}
	}

	host := util.GetIPv6Address(config.Server) + ":" + config.ServerPort

	remarks := ""
	if config.Remarks != "" {
		remarks = "#" + util.URLEncode(config.Remarks)
	}

	if userInfo != "" {
		return "socks://" + util.URLEncode(userInfo) + "@" + host + remarks
	}
	return "socks://" + host + remarks
}
