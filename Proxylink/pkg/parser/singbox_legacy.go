package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const legacyEmptyTransportArrayRule = "empty-transport-array"

// normalizeLegacyOutbound 只转换已登记的旧格式，不修正其他非法字段。
func normalizeLegacyOutbound(raw json.RawMessage) (json.RawMessage, bool, error) {
	var outbound map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outbound); err != nil {
		return nil, false, fmt.Errorf("解析兼容出站失败: %w", err)
	}

	transport, exists := outbound["transport"]
	if !exists {
		return raw, false, nil
	}
	transport = bytes.TrimSpace(transport)
	if len(transport) == 0 {
		return nil, false, fmt.Errorf("transport 不能为空")
	}

	switch transport[0] {
	case '{':
		return raw, false, nil
	case '[':
		var values []json.RawMessage
		if err := json.Unmarshal(transport, &values); err != nil {
			return nil, false, fmt.Errorf("解析 transport 数组失败: %w", err)
		}
		if len(values) != 0 {
			return nil, false, fmt.Errorf("transport 必须是对象，兼容层只接受空数组")
		}
		delete(outbound, "transport")
		normalized, err := json.Marshal(outbound)
		if err != nil {
			return nil, false, fmt.Errorf("编码兼容出站失败: %w", err)
		}
		return normalized, true, nil
	default:
		return nil, false, fmt.Errorf("transport 必须是对象，收到 %s", transport)
	}
}
