package main

import (
	"testing"

	"proxylink/pkg/parser"
	"proxylink/pkg/subscription"
)

func TestFormatCompatibilityEvent(t *testing.T) {
	event := parser.SingboxCompatibilityEvent{
		Index: 4,
		Tag:   "legacy-node",
		Type:  "vmess",
		Rule:  "empty-transport-array",
	}
	want := `兼容转换: outbounds[4] tag="legacy-node" type="vmess" rule="empty-transport-array"`
	if got := formatCompatibilityEvent(event); got != want {
		t.Fatalf("event=%q, want %q", got, want)
	}
}

func TestFormatSubscriptionSummary(t *testing.T) {
	result := &subscription.ConvertResult{
		Success:    49,
		Failed:     0,
		Skipped:    4,
		Compatible: 27,
		SkippedByType: map[string]int{
			"urltest":  1,
			"block":    1,
			"selector": 1,
			"direct":   1,
		},
	}
	want := "订阅解析: 成功 49, 失败 0, 跳过 4, 兼容转换 27\n" +
		"跳过类型: block=1, direct=1, selector=1, urltest=1"
	if got := formatSubscriptionSummary(result); got != want {
		t.Fatalf("summary mismatch:\n%s\nwant:\n%s", got, want)
	}
}
