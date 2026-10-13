// Package conformance 提供跨语言一致性测试共用的 fixture 清单解析能力。
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const manifestRelativePath = "fixtures/manifest.json"

type manifest struct {
	WireManifest        string `json:"wire_manifest"`
	TransactionManifest string `json:"transaction_manifest"`
	ProtocolSchema      string `json:"protocol_schema"`
	TransportProfile    string `json:"transport_profile"`
	InvalidWire         string `json:"invalid_wire"`
	RoleManifest        string `json:"role_manifest"`
}

// FixturePath 从 start 开始向父目录查找根 fixtures/manifest.json，并解析 key
// 对应的仓库相对路径。key 是稳定机器字段；中文含义见 fixtures/manifest.json。
func FixturePath(start, key string) (string, error) {
	repoRoot, value, err := findAndRead(start, key)
	if err != nil {
		return "", err
	}
	path := filepath.Clean(filepath.Join(repoRoot, filepath.FromSlash(value)))
	relative, err := filepath.Rel(repoRoot, path)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("conformance manifest key %q escapes repository root", key)
	}
	return path, nil
}

func findAndRead(start, key string) (string, string, error) {
	directory, err := filepath.Abs(start)
	if err != nil {
		return "", "", fmt.Errorf("resolve start directory: %w", err)
	}
	if info, statErr := os.Stat(directory); statErr == nil && !info.IsDir() {
		directory = filepath.Dir(directory)
	}
	for {
		path := filepath.Join(directory, filepath.FromSlash(manifestRelativePath))
		raw, readErr := os.ReadFile(path)
		if readErr == nil {
			var decoded manifest
			if err := json.Unmarshal(raw, &decoded); err != nil {
				return "", "", fmt.Errorf("decode %s: %w", path, err)
			}
			values := map[string]string{
				"wire_manifest": decoded.WireManifest, "transaction_manifest": decoded.TransactionManifest,
				"protocol_schema": decoded.ProtocolSchema, "transport_profile": decoded.TransportProfile,
				"invalid_wire": decoded.InvalidWire, "role_manifest": decoded.RoleManifest,
			}
			value, ok := values[key]
			if !ok {
				return "", "", fmt.Errorf("unknown conformance manifest key %q", key)
			}
			if value == "" {
				return "", "", fmt.Errorf("conformance manifest key %q is empty", key)
			}
			return directory, value, nil
		}
		if !os.IsNotExist(readErr) {
			return "", "", fmt.Errorf("read %s: %w", path, readErr)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", "", fmt.Errorf("cannot find %s from %s", manifestRelativePath, start)
		}
		directory = parent
	}
}
