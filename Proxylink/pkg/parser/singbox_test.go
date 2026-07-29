package parser

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"proxylink/pkg/model"
)

func TestParseSingboxDetailedOfficialConfig(t *testing.T) {
	data, err := os.ReadFile("testdata/singbox_official_v1.14.json")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSingboxSubscription(data) {
		t.Fatal("official config was not detected as sing-box subscription")
	}

	result, err := ParseSingboxDetailed(data)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Success != 7 || result.Stats.Skipped != 4 || result.Stats.Failed != 0 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}
	if len(result.Profiles) != 7 {
		t.Fatalf("unexpected profiles: %d", len(result.Profiles))
	}

	wantTypes := []model.ConfigType{
		model.VMESS,
		model.VLESS,
		model.SHADOWSOCKS,
		model.TROJAN,
		model.HYSTERIA2,
		model.ANYTLS,
		model.TUIC,
	}
	for i, want := range wantTypes {
		if result.Profiles[i].ConfigType != want {
			t.Fatalf("profile[%d] type=%v, want %v", i, result.Profiles[i].ConfigType, want)
		}
		if result.Profiles[i].OfficialSingboxOutbound == nil {
			t.Fatalf("profile[%d] missing official outbound", i)
		}
	}

	raw, err := json.Marshal(result.Profiles[0].OfficialSingboxOutbound)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"max_early_data",
		"early_data_header_name",
		"packet_encoding",
		"multiplex",
		"cdn-a.example.com",
		"cdn-b.example.com",
	} {
		if !bytes.Contains(raw, []byte(field)) {
			t.Fatalf("missing %s in %s", field, raw)
		}
	}
	if result.Profiles[0].Host != "cdn-a.example.com,cdn-b.example.com" {
		t.Fatalf("unexpected mapped Host: %q", result.Profiles[0].Host)
	}
}

func TestParseSingboxDetailedCanonicalizesLegacyAliases(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"ss": {
			input: `{"type":"ss","tag":"ss","server":"example.com","server_port":8388,"method":"aes-128-gcm","password":"test"}`,
			want:  "shadowsocks",
		},
		"hy2": {
			input: `{"type":"hy2","tag":"hy2","server":"example.com","server_port":443,"password":"test"}`,
			want:  "hysteria2",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := ParseSingboxDetailed([]byte(test.input))
			if err != nil {
				t.Fatal(err)
			}
			outbound := result.Profiles[0].OfficialSingboxOutbound
			if outbound.Type() != test.want {
				t.Fatalf("type=%q, want %q", outbound.Type(), test.want)
			}
			raw, err := json.Marshal(outbound)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte(`"type":"`+test.want+`"`)) {
				t.Fatalf("non-canonical output: %s", raw)
			}
		})
	}
}

func TestParseSingboxDetailedAcceptsStringHTTPHeader(t *testing.T) {
	input := []byte(`{"type":"vmess","tag":"ws","server":"example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","security":"auto","transport":{"type":"ws","headers":{"Host":"cdn.example.com"}}}`)
	result, err := ParseSingboxDetailed(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profiles[0].Host != "cdn.example.com" {
		t.Fatalf("unexpected Host: %q", result.Profiles[0].Host)
	}
}

func TestParseSingboxDetailedInputShapes(t *testing.T) {
	single := []byte(`{"type":"vmess","tag":"single","server":"example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","security":"auto"}`)
	array := append(append([]byte{'['}, single...), ']')

	for name, input := range map[string][]byte{
		"single": single,
		"array":  array,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := ParseSingboxDetailed(input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Stats.Success != 1 || len(result.Profiles) != 1 {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestIsSingboxSubscriptionRejectsOtherJSON(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(`{"name":"plain-json"}`),
		[]byte(`[{"type":"vmess"}]`),
		[]byte(`{"outbounds":{}}`),
		[]byte(`{"outbounds":null}`),
	} {
		if IsSingboxSubscription(input) {
			t.Fatalf("unexpected sing-box subscription detection: %s", input)
		}
	}
}
