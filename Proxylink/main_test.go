package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"proxylink/pkg/model"
)

func TestWriteMultipleFilesPrefixesFileOrderOnly(t *testing.T) {
	tempDir := t.TempDir()
	oldOutputDir := *outputDir
	oldOutputFormat := *outputFormat
	t.Cleanup(func() {
		*outputDir = oldOutputDir
		*outputFormat = oldOutputFormat
	})

	*outputDir = tempDir
	*outputFormat = "singbox"

	profiles := []*model.ProfileItem{
		testVLESSProfile("US2-Wave-CN2"),
		testVLESSProfile("US10-Wave-CN2"),
		testVLESSProfile("US1-Wave-CF"),
	}

	if err := writeMultipleFiles(profiles); err != nil {
		t.Fatalf("writeMultipleFiles() error = %v", err)
	}

	wantFiles := []string{
		"0001_US2-Wave-CN2.json",
		"0002_US10-Wave-CN2.json",
		"0003_US1-Wave-CF.json",
	}
	for _, name := range wantFiles {
		if _, err := os.Stat(filepath.Join(tempDir, name)); err != nil {
			t.Fatalf("expected output file %s: %v", name, err)
		}
	}

	for i, name := range wantFiles {
		tag := readSingleSingboxTag(t, filepath.Join(tempDir, name))
		if tag != profiles[i].Remarks {
			t.Fatalf("%s tag = %q, want %q", name, tag, profiles[i].Remarks)
		}
	}
}

func testVLESSProfile(name string) *model.ProfileItem {
	profile := model.NewProfileItem(model.VLESS)
	profile.Remarks = name
	profile.Server = "example.com"
	profile.ServerPort = "443"
	profile.Password = "00000000-0000-0000-0000-000000000000"
	return profile
}

func readSingleSingboxTag(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) error = %v", path, err)
	}

	var config struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", path, err)
	}
	if len(config.Outbounds) != 1 {
		t.Fatalf("%s outbounds length = %d, want 1", path, len(config.Outbounds))
	}
	return config.Outbounds[0].Tag
}
