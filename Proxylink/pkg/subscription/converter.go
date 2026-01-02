package subscription

import (
	"proxylink/pkg/model"
	"proxylink/pkg/parser"
)

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

// SetInsecure 设置是否跳过证书验证
func (c *Converter) SetInsecure(insecure bool) {
	c.fetcher.SetInsecure(insecure)
}

// Convert 从 URL 获取并转换订阅
func (c *Converter) Convert(url string) (*ConvertResult, error) {
	// 获取订阅内容
	content, err := c.fetcher.Fetch(url)
	if err != nil {
		return nil, err
	}

	// 转换内容
	return c.ConvertContent(content)
}

// ConvertContent 转换订阅内容
func (c *Converter) ConvertContent(content string) (*ConvertResult, error) {
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
