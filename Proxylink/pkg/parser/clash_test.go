package parser

import "testing"

func TestParseClashConfigV2rayHTTPUpgrade(t *testing.T) {
	data := []byte(`
proxies:
  - name: upgrade-node
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    network: ws
    tls: true
    ws-opts:
      path: /upgrade
      headers:
        Host: cdn.example.com
      v2ray-http-upgrade: true
`)

	profiles, err := ParseClashConfig(data)
	if err != nil {
		t.Fatalf("ParseClashConfig() error = %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("ParseClashConfig() returned %d profiles, want 1", len(profiles))
	}

	profile := profiles[0]
	if profile.Network != "httpupgrade" {
		t.Fatalf("Network = %q, want %q", profile.Network, "httpupgrade")
	}
	if profile.Path != "/upgrade" {
		t.Fatalf("Path = %q, want %q", profile.Path, "/upgrade")
	}
	if profile.Host != "cdn.example.com" {
		t.Fatalf("Host = %q, want %q", profile.Host, "cdn.example.com")
	}
}

func TestParseClashConfigWebSocketWithoutHTTPUpgrade(t *testing.T) {
	data := []byte(`
proxies:
  - name: ws-node
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    network: ws
    ws-opts:
      path: /ws
`)

	profiles, err := ParseClashConfig(data)
	if err != nil {
		t.Fatalf("ParseClashConfig() error = %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("ParseClashConfig() returned %d profiles, want 1", len(profiles))
	}
	if profiles[0].Network != "ws" {
		t.Fatalf("Network = %q, want %q", profiles[0].Network, "ws")
	}
}
