package util

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// URLEncode URL 编码
func URLEncode(s string) string {
	return url.QueryEscape(s)
}

// URLDecode URL 解码，同时处理 Unicode 转义序列
func URLDecode(s string) string {
	// 先进行标准 URL 解码
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		decoded = s
	}

	// 处理 \uXXXX 格式的 Unicode 转义
	decoded = decodeUnicodeEscape(decoded)

	return decoded
}

// decodeUnicodeEscape 解码 \uXXXX 格式的 Unicode 转义序列
func decodeUnicodeEscape(s string) string {
	// 匹配 \uXXXX 模式
	re := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

	return re.ReplaceAllStringFunc(s, func(match string) string {
		// 提取十六进制码点
		hex := match[2:] // 去掉 \u 前缀
		codePoint, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return match
		}
		return string(rune(codePoint))
	})
}

// GetIPv6Address 处理 IPv6 地址格式
// 如果是 IPv6 地址，返回 [addr] 格式
func GetIPv6Address(addr string) string {
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return "[" + addr + "]"
	}
	return addr
}

// FixIllegalURL 修复非法 URL
// 处理一些常见的 URL 格式问题
func FixIllegalURL(urlStr string) string {
	// 替换非法字符
	urlStr = strings.ReplaceAll(urlStr, " ", "%20")
	return urlStr
}
