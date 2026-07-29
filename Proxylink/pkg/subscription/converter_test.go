package subscription

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestConvertContentDetectsSingboxBeforeLineDecoder(t *testing.T) {
	data, err := os.ReadFile("../parser/testdata/singbox_official_v1.14.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewConverter().ConvertContent(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceFormat != "sing-box" {
		t.Fatalf("source format=%q", result.SourceFormat)
	}
	if result.Success != 7 || result.Skipped != 4 || result.Failed != 0 || len(result.Profiles) != 7 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.SkippedByType["selector"] != 1 || result.SkippedByType["urltest"] != 1 {
		t.Fatalf("unexpected skipped types: %+v", result.SkippedByType)
	}
}

func TestConvertContentDoesNotMisdetectOtherJSON(t *testing.T) {
	result, err := NewConverter().ConvertContent(`{"name":"plain-json"}`)
	if err != nil {
		t.Fatal(err)
	}
	if result.Success != 0 || result.Failed != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestConvertContentKeepsExistingFormats(t *testing.T) {
	uri := "vless://00000000-0000-0000-0000-000000000001@example.com:443#node"
	clash := `proxies:
  - name: clash-node
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
`

	tests := map[string]string{
		"plain URI":  uri,
		"base64 URI": base64.StdEncoding.EncodeToString([]byte(uri)),
		"Clash YAML": clash,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewConverter().ConvertContent(content)
			if err != nil {
				t.Fatal(err)
			}
			if result.Success != 1 || len(result.Profiles) != 1 {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestConvertContentReportsLegacyCompatibility(t *testing.T) {
	content := `{"outbounds":[{"type":"vmess","tag":"legacy","server":"example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","security":"auto","transport":[]}]}`
	result, err := NewConverter().ConvertContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if result.Success != 1 || result.Compatible != 1 || len(result.CompatibilityEvents) != 1 {
		t.Fatalf("unexpected compatibility stats: %+v", result)
	}
	if result.CompatibilityEvents[0].Rule != "empty-transport-array" {
		t.Fatalf("unexpected compatibility event: %+v", result.CompatibilityEvents[0])
	}
}

func TestConvertContentRejectsSingboxWithoutProxyNodes(t *testing.T) {
	content := `{"outbounds":[{"type":"selector","tag":"select","outbounds":[]}]}`
	if _, err := NewConverter().ConvertContent(content); err == nil {
		t.Fatal("expected zero-success sing-box subscription error")
	}
}
