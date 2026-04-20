package subscription

import (
	"strings"

	"proxylink/pkg/model"
	"proxylink/pkg/parser"
	"proxylink/pkg/util"
)

var fallbackUserAgents = []string{
	"clash-verge/v2.2.3",
	"ClashMetaForAndroid/2.11.14.Meta",
	"mihomo/1.19.0",
	"sing-box/1.12.0",
	"v2rayN/7.14.0",
}

// ConvertResult 转换结果
type ConvertResult struct {
	Profiles []*model.ProfileItem // 成功解析的配置
	Errors   []error              // 解析错误
	Total    int                  // 总行数
	Success  int                  // 成功数
	Failed   int                  // 失败数
}

// Converter 订阅转换器
type Converter struct {
	fetcher *Fetcher
}

// NewConverter 创建新的转换器
func NewConverter() *Converter {
	return &Converter{
		fetcher: NewFetcher(),
	}
}

// NewConverterInsecure 创建跳过证书验证的转换器
func NewConverterInsecure() *Converter {
	return &Converter{
		fetcher: NewFetcherInsecure(),
	}
}

// NewConverterWithDNS 创建使用公共 DNS 的转换器 (适用于 Android)
func NewConverterWithDNS() *Converter {
	return &Converter{
		fetcher: NewFetcherWithDNS(),
	}
}

// NewConverterFull 创建完整配置的转换器
func NewConverterFull(insecure, useDNS bool) *Converter {
	return &Converter{
		fetcher: NewFetcherFull(insecure, useDNS),
	}
}

// SetInsecure 设置是否跳过证书验证
func (c *Converter) SetInsecure(insecure bool) {
	c.fetcher.SetInsecure(insecure)
}

// SetUseDNS 设置是否使用公共 DNS
func (c *Converter) SetUseDNS(useDNS bool) {
	c.fetcher.SetUseDNS(useDNS)
}

// SetUserAgent 设置订阅请求 User-Agent，手动设置后不再自动换 UA 重试。
func (c *Converter) SetUserAgent(ua string) {
	c.fetcher.SetUserAgent(ua)
}

// Convert 从 URL 获取并转换订阅
func (c *Converter) Convert(url string) (*ConvertResult, error) {
	// 获取订阅内容
	content, err := c.fetcher.Fetch(url)
	if err != nil {
		return nil, err
	}
	if c.fetcher.autoRetry && isOutdatedClientResponse(content) {
		for _, userAgent := range fallbackUserAgents {
			if userAgent == c.fetcher.userAgent {
				continue
			}
			retryContent, retryErr := c.fetcher.fetchWithUserAgent(url, userAgent)
			if retryErr != nil || isOutdatedClientResponse(retryContent) {
				continue
			}
			content = retryContent
			break
		}
	}

	// 转换内容
	return c.ConvertContent(content)
}

// ConvertContent 转换订阅内容
func (c *Converter) ConvertContent(content string) (*ConvertResult, error) {
	// 自动检测 Clash YAML 格式
	if parser.IsClashYAML(content) {
		profiles, err := parser.ParseClashConfig([]byte(content))
		if err == nil && len(profiles) > 0 {
			return &ConvertResult{
				Profiles: profiles,
				Total:    len(profiles),
				Success:  len(profiles),
			}, nil
		}
		// 解析失败则回退到链接解析
	}

	// 解码
	lines, err := Decode(content)
	if err != nil {
		return nil, err
	}

	// 解析
	result := &ConvertResult{
		Total: len(lines),
	}

	for _, line := range lines {
		profile, err := parser.Parse(line)
		if err != nil {
			result.Errors = append(result.Errors, err)
			result.Failed++
			continue
		}
		result.Profiles = append(result.Profiles, profile)
		result.Success++
	}

	return result, nil
}

func isOutdatedClientResponse(content string) bool {
	for _, text := range responseTextCandidates(content) {
		decodedText := util.URLDecode(text)
		lower := strings.ToLower(decodedText)
		if strings.Contains(decodedText, "客户端版本太老") ||
			strings.Contains(decodedText, "版本太老") ||
			strings.Contains(lower, "client version") && strings.Contains(lower, "old") ||
			strings.Contains(lower, "too old") ||
			strings.Contains(lower, "fake_node_password") {
			return true
		}
	}
	return false
}

func responseTextCandidates(content string) []string {
	candidates := []string{content}
	if decoded, err := util.Base64Decode(content); err == nil && decoded != "" && decoded != content {
		candidates = append(candidates, decoded)
	}
	return candidates
}

// ConvertWithFilter 转换并过滤
func (c *Converter) ConvertWithFilter(url string, filter func(*model.ProfileItem) bool) (*ConvertResult, error) {
	result, err := c.Convert(url)
	if err != nil {
		return nil, err
	}

	// 过滤
	var filtered []*model.ProfileItem
	for _, profile := range result.Profiles {
		if filter(profile) {
			filtered = append(filtered, profile)
		}
	}
	result.Profiles = filtered

	return result, nil
}
