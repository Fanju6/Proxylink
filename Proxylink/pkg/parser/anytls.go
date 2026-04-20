package parser

import (
	"net/url"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseAnyTLS 解析 AnyTLS 链接
// 格式: anytls://password@server:port?sni=xxx&insecure=1#remarks
func ParseAnyTLS(uri string) (*model.ProfileItem, error) {
	u, err := url.Parse(util.FixIllegalURL(uri))
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.ANYTLS)
	config.Remarks = util.URLDecode(u.Fragment)
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = u.Hostname()
	config.ServerPort = u.Port()
	config.Password = u.User.Username()
	config.Security = "tls"

	query := u.Query()
	if config.Password == "" {
		config.Password = query.Get("password")
	}
	parseQueryParams(config, query)
	config.Security = "tls"
	config.Network = "tcp"

	return config, nil
}

// ToAnyTLSURI 生成 AnyTLS 链接
func ToAnyTLSURI(config *model.ProfileItem) string {
	query := buildAnyTLSTUICQueryParams(config)
	return buildURI("anytls://", config.Password, config, query)
}
