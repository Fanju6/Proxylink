package subscription

import (
	"strings"

	"proxylink/pkg/util"
)

// Decode 解码订阅内容
// 支持 Base64 编码和纯文本格式
func Decode(content string) ([]string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, nil
	}

	// 尝试 Base64 解码
	decoded, err := util.Base64Decode(content)
	if err == nil && len(decoded) > 0 {
		// Base64 解码成功
		return splitLines(decoded), nil
	}

	// 非 Base64，直接按行分割
	return splitLines(content), nil
}

// splitLines 按行分割字符串
func splitLines(content string) []string {
	var lines []string

	// 处理不同的换行符
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines
}
