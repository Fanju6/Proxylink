package parser

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNormalizeLegacyOutbound(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		compatible bool
		wantErr    bool
	}{
		{name: "empty array", input: `{"type":"vmess","transport":[]}`, compatible: true},
		{name: "object stays official", input: `{"type":"vmess","transport":{"type":"ws"}}`},
		{name: "non-empty array", input: `{"type":"vmess","transport":[{}]}`, wantErr: true},
		{name: "wrong scalar", input: `{"type":"vmess","transport":"ws"}`, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, compatible, err := normalizeLegacyOutbound([]byte(test.input))
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, test.wantErr)
			}
			if compatible != test.compatible {
				t.Fatalf("compatible=%v, want %v", compatible, test.compatible)
			}
			if compatible && bytes.Contains(output, []byte(`"transport"`)) {
				t.Fatalf("legacy transport was not removed: %s", output)
			}
		})
	}
}

func TestParseSingboxDetailedConvertsEmptyTransportArray(t *testing.T) {
	input := []byte(`{
		"outbounds": [{
			"type":"vmess",
			"tag":"legacy",
			"server":"example.com",
			"server_port":443,
			"uuid":"00000000-0000-0000-0000-000000000001",
			"security":"auto",
			"transport":[]
		}]
	}`)

	result, err := ParseSingboxDetailed(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Success != 1 || result.Stats.Compatible != 1 || result.Stats.Failed != 0 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}
	if len(result.CompatibilityEvents) != 1 {
		t.Fatalf("unexpected compatibility events: %+v", result.CompatibilityEvents)
	}
	event := result.CompatibilityEvents[0]
	if event.Index != 0 || event.Tag != "legacy" || event.Type != "vmess" || event.Rule != legacyEmptyTransportArrayRule {
		t.Fatalf("unexpected compatibility event: %+v", event)
	}
	raw, err := json.Marshal(result.Profiles[0].OfficialSingboxOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"transport"`)) {
		t.Fatalf("legacy transport leaked into official output: %s", raw)
	}
}

func TestParseSingboxDetailedIsolatesInvalidOutbound(t *testing.T) {
	input := []byte(`{
		"outbounds": [
			{"type":"vmess","tag":"bad","server":"bad.example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","security":"auto","transport":[{}]},
			{"type":"vmess","tag":"good","server":"good.example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000002","security":"auto"}
		]
	}`)

	result, err := ParseSingboxDetailed(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Success != 1 || result.Stats.Failed != 1 || len(result.Errors) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Profiles[0].Remarks != "good" {
		t.Fatalf("unexpected surviving node: %s", result.Profiles[0].Remarks)
	}
}
