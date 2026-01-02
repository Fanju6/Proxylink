package parser

import (
	"errors"
	"strings"

	"proxylink/pkg/model"
)

// Parse 解析代理链接，自动检测协议类型
func Parse(uri string) (*model.ProfileItem, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return nil, errors.New("empty uri")
	}

	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return ParseVMess(uri)
	case strings.HasPrefix(uri, "vless://"):
		return ParseVLess(uri)
	case strings.HasPrefix(uri, "ss://"):
		return ParseShadowsocks(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return ParseTrojan(uri)
	case strings.HasPrefix(uri, "socks://"):
		return ParseSocks(uri)
	case strings.HasPrefix(uri, "http://"):
		return ParseHTTP(uri)
	case strings.HasPrefix(uri, "wireguard://"), strings.HasPrefix(uri, "wg://"):
		return ParseWireGuard(uri)
	case strings.HasPrefix(uri, "hysteria2://"), strings.HasPrefix(uri, "hy2://"):
		return ParseHysteria2(uri)
	default:
		return nil, errors.New("unsupported protocol: " + uri[:min(20, len(uri))])
	}
}

// ParseBatch 批量解析多行链接
func ParseBatch(content string) ([]*model.ProfileItem, []error) {
	var profiles []*model.ProfileItem
	var errs []error

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		profile, err := Parse(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		profiles = append(profiles, profile)
	}

	return profiles, errs
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
