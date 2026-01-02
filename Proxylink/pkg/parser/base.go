package parser

import (
	"net/url"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// parseQueryParams 解析通用的查询参数到 ProfileItem
func parseQueryParams(config *model.ProfileItem, query url.Values) {
	// 传输层
	config.Network = query.Get("type")
	if config.Network == "" {
		config.Network = "tcp"
	}

	config.HeaderType = query.Get("headerType")
	config.Host = query.Get("host")
	config.Path = query.Get("path")
	config.Seed = query.Get("seed")
	config.QuicSecurity = query.Get("quicSecurity")
	config.QuicKey = query.Get("key")
	config.Mode = query.Get("mode")
	config.ServiceName = query.Get("serviceName")
	config.Authority = query.Get("authority")
	config.XhttpMode = query.Get("mode")
	config.XhttpExtra = query.Get("extra")

	// TLS
	config.Security = query.Get("security")
	if config.Security != "tls" && config.Security != "reality" {
		config.Security = ""
	}

	config.SNI = query.Get("sni")
	config.ALPN = query.Get("alpn")
	config.Fingerprint = query.Get("fp")
	config.Flow = query.Get("flow")
	config.Mldsa65Verify = query.Get("pqv")

	// Insecure - 支持多种参数名
	insecure := query.Get("insecure")
	if insecure == "" {
		insecure = query.Get("allowInsecure")
	}
	if insecure == "" {
		insecure = query.Get("allow_insecure")
	}
	config.Insecure = insecure == "1"

	// Reality
	config.PublicKey = query.Get("pbk")
	config.ShortID = query.Get("sid")
	config.SpiderX = query.Get("spx")
}

// buildQueryParams 从 ProfileItem 构建查询参数
func buildQueryParams(config *model.ProfileItem) url.Values {
	query := url.Values{}

	// Security
	if config.Security != "" {
		query.Set("security", config.Security)
	} else {
		query.Set("security", "none")
	}

	// TLS 参数
	if config.SNI != "" {
		query.Set("sni", config.SNI)
	}
	if config.ALPN != "" {
		query.Set("alpn", config.ALPN)
	}
	if config.Fingerprint != "" {
		query.Set("fp", config.Fingerprint)
	}
	if config.Flow != "" {
		query.Set("flow", config.Flow)
	}
	if config.Mldsa65Verify != "" {
		query.Set("pqv", config.Mldsa65Verify)
	}

	// Insecure
	if config.Security == "tls" {
		if config.Insecure {
			query.Set("allowInsecure", "1")
		} else {
			query.Set("allowInsecure", "0")
		}
	}

	// Reality
	if config.PublicKey != "" {
		query.Set("pbk", config.PublicKey)
	}
	if config.ShortID != "" {
		query.Set("sid", config.ShortID)
	}
	if config.SpiderX != "" {
		query.Set("spx", config.SpiderX)
	}

	// 传输层
	network := config.Network
	if network == "" {
		network = "tcp"
	}
	query.Set("type", network)

	switch network {
	case "tcp":
		if config.HeaderType != "" {
			query.Set("headerType", config.HeaderType)
		}
		if config.Host != "" {
			query.Set("host", config.Host)
		}
	case "kcp":
		if config.HeaderType != "" {
			query.Set("headerType", config.HeaderType)
		}
		if config.Seed != "" {
			query.Set("seed", config.Seed)
		}
	case "ws", "httpupgrade":
		if config.Host != "" {
			query.Set("host", config.Host)
		}
		if config.Path != "" {
			query.Set("path", config.Path)
		}
	case "http", "h2":
		query.Set("type", "http")
		if config.Host != "" {
			query.Set("host", config.Host)
		}
		if config.Path != "" {
			query.Set("path", config.Path)
		}
	case "grpc":
		if config.Mode != "" {
			query.Set("mode", config.Mode)
		}
		if config.Authority != "" {
			query.Set("authority", config.Authority)
		}
		if config.ServiceName != "" {
			query.Set("serviceName", config.ServiceName)
		}
	case "xhttp":
		if config.Host != "" {
			query.Set("host", config.Host)
		}
		if config.Path != "" {
			query.Set("path", config.Path)
		}
		if config.XhttpMode != "" {
			query.Set("mode", config.XhttpMode)
		}
		if config.XhttpExtra != "" {
			query.Set("extra", config.XhttpExtra)
		}
	}

	return query
}

// buildURI 构建 URI 字符串
func buildURI(scheme string, userInfo string, config *model.ProfileItem, query url.Values) string {
	host := util.GetIPv6Address(config.Server) + ":" + config.ServerPort

	queryStr := ""
	if len(query) > 0 {
		queryStr = "?" + query.Encode()
	}

	remarks := ""
	if config.Remarks != "" {
		remarks = "#" + util.URLEncode(config.Remarks)
	}

	if userInfo != "" {
		userInfo = util.URLEncode(userInfo) + "@"
	}

	return scheme + userInfo + host + queryStr + remarks
}
