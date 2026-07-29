package model

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestOfficialSingboxOutboundMarshalAndWithTag(t *testing.T) {
	options := &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "example.com",
			ServerPort: 443,
		},
		UUID:           "00000000-0000-0000-0000-000000000001",
		Security:       "auto",
		PacketEncoding: "xudp",
	}
	original := NewOfficialSingboxOutbound("vmess", "node", options)
	renamed := original.WithTag("node_2")

	raw, err := json.Marshal(renamed)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["tag"] != "node_2" || got["packet_encoding"] != "xudp" {
		t.Fatalf("unexpected official outbound: %s", raw)
	}
	if original.Tag() != "node" {
		t.Fatalf("original tag changed: %s", original.Tag())
	}

	profile := &ProfileItem{
		Remarks:                 "node",
		OfficialSingboxOutbound: original,
	}
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(profileJSON, []byte("packet_encoding")) {
		t.Fatalf("official outbound leaked into ProfileItem JSON: %s", profileJSON)
	}
}
