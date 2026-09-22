package wire_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bsv8/go-bitfs/internal/conformance"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// TestSharedInvalidWireFixtures 保证 Go 与 TypeScript 对同一批畸形输入返回
// 相同稳定分类；测试不能匹配实现相关的英文错误文本。
func TestSharedInvalidWireFixtures(t *testing.T) {
	path, err := conformance.FixturePath(".", "invalid_wire")
	if err != nil {
		t.Fatalf("resolve invalid_wire from fixtures/manifest.json: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name      string             `json:"name"`
			Hex       string             `json:"hex"`
			ErrorCode protocol.ErrorCode `json:"error_code"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			input, err := hex.DecodeString(item.Hex)
			if err != nil {
				t.Fatal(err)
			}
			_, err = wire.Parse(input)
			code, _ := protocol.CodeOf(err)
			if !protocol.IsCode(err, item.ErrorCode) {
				t.Fatalf("error code = %q, want %q: %v", code, item.ErrorCode, err)
			}
		})
	}
}
