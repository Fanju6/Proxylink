package generator_test

import (
	"os"
	"strings"
	"testing"

	"proxylink/pkg/generator"
	"proxylink/pkg/model"
	"proxylink/pkg/parser"
)

func TestGenerateSingboxOutboundsPreservesOfficialFields(t *testing.T) {
	data, err := os.ReadFile("../parser/testdata/singbox_official_v1.14.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseSingboxDetailed(data)
	if err != nil {
		t.Fatal(err)
	}
	profiles := parsed.Profiles[:2]
	profiles[0].Remarks = "same"
	profiles[1].Remarks = "same"

	output, err := generator.GenerateSingboxOutbounds(profiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"packet_encoding",
		"max_early_data",
		"early_data_header_name",
		"multiplex",
		"cdn-a.example.com",
		"same_2",
	} {
		if !strings.Contains(output, field) {
			t.Fatalf("missing %s in %s", field, output)
		}
	}

	roundTrip, err := parser.ParseSingboxDetailed([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.Stats.Success != 2 || roundTrip.Stats.Failed != 0 {
		t.Fatalf("unexpected round-trip result: %+v", roundTrip)
	}
}

func TestGenerateSingboxOutboundsDoesNotReserveTagForSkippedProfile(t *testing.T) {
	skipped := model.NewProfileItem(model.CUSTOM)
	skipped.Remarks = "same"
	valid := model.NewProfileItem(model.VMESS)
	valid.Remarks = "same"
	valid.Server = "example.com"
	valid.ServerPort = "443"
	valid.Password = "00000000-0000-0000-0000-000000000001"
	valid.Method = "auto"

	output, err := generator.GenerateSingboxOutbounds([]*model.ProfileItem{skipped, valid})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, `"tag": "same_2"`) || !strings.Contains(output, `"tag": "same"`) {
		t.Fatalf("skipped profile reserved tag: %s", output)
	}
}

func TestGenerateSingboxOutboundsSupportsMixedSources(t *testing.T) {
	data, err := os.ReadFile("../parser/testdata/singbox_official_v1.14.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseSingboxDetailed(data)
	if err != nil {
		t.Fatal(err)
	}
	plain := model.NewProfileItem(model.VLESS)
	plain.Remarks = "plain"
	plain.Server = "plain.example.com"
	plain.ServerPort = "443"
	plain.Password = "00000000-0000-0000-0000-000000000004"
	plain.Method = "none"

	output, err := generator.GenerateSingboxOutbounds([]*model.ProfileItem{parsed.Profiles[0], plain})
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.ParseSingboxDetailed([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Success != 2 || result.Profiles[1].Server != "plain.example.com" {
		t.Fatalf("unexpected mixed result: %+v", result)
	}
}

func TestGenerateSingboxOutboundsKeepsProfileGeneration(t *testing.T) {
	profile := model.NewProfileItem(model.VMESS)
	profile.Remarks = "uri-node"
	profile.Server = "example.com"
	profile.ServerPort = "443"
	profile.Password = "00000000-0000-0000-0000-000000000001"
	profile.Method = "auto"

	output, err := generator.GenerateSingboxOutbounds([]*model.ProfileItem{profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"type": "vmess"`, `"tag": "uri-node"`, `"server": "example.com"`} {
		if !strings.Contains(output, field) {
			t.Fatalf("missing %s in %s", field, output)
		}
	}
}

func TestGenerateSingboxOutboundPreservesOfficialFields(t *testing.T) {
	data, err := os.ReadFile("../parser/testdata/singbox_official_v1.14.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseSingboxDetailed(data)
	if err != nil {
		t.Fatal(err)
	}
	output, err := generator.GenerateSingboxOutbound(parsed.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "max_early_data") || !strings.Contains(output, "packet_encoding") {
		t.Fatalf("official fields were lost: %s", output)
	}
}
