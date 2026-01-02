package util

import (
	"encoding/base64"
	"strings"
)

// Base64Decode 解码 Base64 字符串，支持标准和 URL 安全格式
func Base64Decode(s string) (string, error) {
	// 移除可能的空白字符
	s = strings.TrimSpace(s)

	// 补齐 padding
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}

	// 尝试标准 Base64
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}

	// 尝试 URL 安全 Base64
	decoded, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}

	// 尝试 RawStdEncoding (无 padding)
	s = strings.TrimRight(s, "=")
	decoded, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil {
		return string(decoded), nil
	}

	// 尝试 RawURLEncoding (无 padding)
	decoded, err = base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// Base64Encode 使用标准 Base64 编码
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Base64EncodeURL 使用 URL 安全的 Base64 编码 (无 padding)
func Base64EncodeURL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
