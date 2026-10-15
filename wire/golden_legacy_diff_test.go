package wire_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// TestLegacyExportMatchesCurrent 对照当前冻结向量，同时保留旧版费用池交易候选证据。
// 0.4.0 新增签名报价字段，报价 ID、付款授权和后续消息签名必然变化；
// 旧导出文件保持原样，不再错误要求报价相关签名与旧版完全相同。
var currentExportUpdate = flag.Bool("update-current-export", false, "regenerate current export after reviewing quote format changes")

func TestLegacyExportMatchesCurrent(t *testing.T) {
	legacy := loadJSONMap(t, filepath.Join("testdata", "v1", "legacy_95f5a90_export.json"))
	frozenCurrent := loadJSONMap(t, filepath.Join("testdata", "v1", "current_export.json"))
	rebuilt := exportCurrentGoldenVectors(t)
	if *currentExportUpdate {
		raw, err := json.MarshalIndent(rebuilt, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "v1", "current_export.json"), append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
		return
	}

	for name, legacyHex := range legacy {
		currentHex, ok := frozenCurrent[name]
		if !ok {
			t.Fatalf("vector %q missing from frozen current export", name)
		}
		rebuiltHex, ok := rebuilt[name]
		if !ok {
			t.Fatalf("vector %q missing from rebuilt export", name)
		}
		if currentHex != rebuiltHex || ((name == "unsigned_candidate" || name == "payment_update") && legacyHex != rebuiltHex) {
			t.Fatalf("golden vector %q drifted:\n legacy %s\n frozen %s\n rebuilt %s", name, legacyHex, currentHex, rebuiltHex)
		}
	}
}

func loadJSONMap(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
