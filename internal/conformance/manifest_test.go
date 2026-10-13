package conformance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixturePathUsesRootManifest(t *testing.T) {
	path, err := FixturePath(filepath.Join("..", "..", "wire"), "wire_manifest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("清单解析出的 wire fixture 不可读: %v", err)
	}
}

func TestFixturePathRejectsUnknownKey(t *testing.T) {
	if _, err := FixturePath(".", "unknown"); err == nil {
		t.Fatal("未知清单字段必须被拒绝")
	}
}
