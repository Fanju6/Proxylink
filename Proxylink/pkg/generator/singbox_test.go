package generator

import (
	"encoding/json"
	"testing"

	"proxylink/pkg/model"
)

func TestGenerateSingboxHTTPUpgradeTransportHost(t *testing.T) {
	profile := model.NewProfileItem(model.VLESS)
	profile.Remarks = "upgrade-node"
	profile.Server = "example.com"
	profile.ServerPort = "443"
	profile.Password = "00000000-0000-0000-0000-000000000000"
	profile.Network = "httpupgrade"
	profile.Path = "/upgrade"
	profile.Host = "cdn.example.com"

	output, err := GenerateSingboxOutbound(profile)
	if err != nil {
		t.Fatalf("GenerateSingboxOutbound() error = %v", err)
	}

	var config map[string][]map[string]any
	if err := json.Unmarshal([]byte(output), &config); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	transport := config["outbounds"][0]["transport"].(map[string]any)
	if transport["type"] != "httpupgrade" {
		t.Fatalf("transport.type = %v, want httpupgrade", transport["type"])
	}
	if transport["host"] != "cdn.example.com" {
		t.Fatalf("transport.host = %v, want cdn.example.com", transport["host"])
	}
	if _, ok := transport["headers"]; ok {
		t.Fatalf("transport.headers should be omitted for HTTPUpgrade host: %v", transport["headers"])
	}
}

func TestGenerateSingboxHTTPTransportHostArray(t *testing.T) {
	profile := model.NewProfileItem(model.VLESS)
	profile.Remarks = "http-node"
	profile.Server = "example.com"
	profile.ServerPort = "443"
	profile.Password = "00000000-0000-0000-0000-000000000000"
	profile.Network = "h2"
	profile.Path = "/h2"
	profile.Host = "a.example.com,b.example.com"

	output, err := GenerateSingboxOutbound(profile)
	if err != nil {
		t.Fatalf("GenerateSingboxOutbound() error = %v", err)
	}

	var config map[string][]map[string]any
	if err := json.Unmarshal([]byte(output), &config); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	transport := config["outbounds"][0]["transport"].(map[string]any)
	hosts, ok := transport["host"].([]any)
	if !ok {
		t.Fatalf("transport.host = %T, want array", transport["host"])
	}
	if len(hosts) != 2 || hosts[0] != "a.example.com" || hosts[1] != "b.example.com" {
		t.Fatalf("transport.host = %v, want [a.example.com b.example.com]", hosts)
	}
}
