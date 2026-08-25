package wire_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLegacyExportMatchesCurrent 独立复现新旧实现的 golden 对照证据：
// legacy_95f5a90_export.json 由硬切换前提交（95f5a90）的旧 API 导出器生成，
// current_export.json 由当前唯一主 API 的导出器生成；本测试用当前实现实时
// 重算全部向量，并与两份冻结文件逐字节比对。任何一侧漂移都会被阻断，
// 不允许"当前实现等于当前 manifest"式的自我证明。
func TestLegacyExportMatchesCurrent(t *testing.T) {
	legacy := loadJSONMap(t, filepath.Join("testdata", "v1", "legacy_95f5a90_export.json"))
	frozenCurrent := loadJSONMap(t, filepath.Join("testdata", "v1", "current_export.json"))
	rebuilt := exportCurrentGoldenVectors(t)

	for name, legacyHex := range legacy {
		currentHex, ok := frozenCurrent[name]
		if !ok {
			t.Fatalf("vector %q missing from frozen current export", name)
		}
		rebuiltHex, ok := rebuilt[name]
		if !ok {
			t.Fatalf("vector %q missing from rebuilt export", name)
		}
		if legacyHex != currentHex || legacyHex != rebuiltHex {
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
