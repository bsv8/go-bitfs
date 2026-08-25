package wire_test

import (
	"testing"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/protocol"
	wire "github.com/bsv8/go-bitfs/wire"
)

// FuzzParse 保证 wire 主解析器对任意输入不 panic、不无限分配：畸形、截断、
// 变异输入只允许返回错误或合法 Artifact。`go test` 会以种子语料做冒烟运行；
// 长期 fuzz 目标由 CI 的 -fuzz 触发。
func FuzzParse(f *testing.F) {
	f.Add([]byte{0x84, 0x01, 0x07, 0x58, 0x20})
	f.Add([]byte{0x85, 0x01, 0x06, 0x58, 0x23, 0x81, 0x58, 0x20})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Add([]byte{0x9f}) // indefinite array head
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, raw []byte) {
		artifact, err := wire.Parse(raw)
		if err != nil {
			return
		}
		if artifact.Kind() == 0 || len(artifact.Bytes()) == 0 {
			t.Fatalf("Parse accepted empty artifact for input %x", raw)
		}
		// 已验证 Artifact 必须能原样重放。
		replay, err := wire.Parse(artifact.Bytes())
		if err != nil || string(replay.Bytes()) != string(artifact.Bytes()) {
			t.Fatalf("verified artifact failed replay for input %x", raw)
		}
	})
}

// FuzzParseAsKind7 限定 Kind 路由交叉验证路径。
func FuzzParseAsKind7(f *testing.F) {
	f.Add([]byte{0x84, 0x01, 0x07, 0x58, 0x20, 0x01})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, err := wire.ParseAs(wire.PaymentUpdate, raw); err == nil {
			artifact, _ := wire.Parse(raw)
			if artifact.Kind() != wire.PaymentUpdate {
				t.Fatal("ParseAs accepted mismatched route kind")
			}
		}
	})
}

// FuzzIDTextRoundTrip 保证 typed ID 文本解析器对任意字符串不 panic。
func FuzzIDTextRoundTrip(f *testing.F) {
	f.Add("fq_00")
	f.Add("pa_")
	f.Add("ac_zzzz")
	f.Fuzz(func(t *testing.T, text string) {
		for _, parse := range []func(string) error{
			func(s string) error { _, err := protocol.ParseFileQuoteTermsID(s); return err },
			func(s string) error { _, err := protocol.ParsePaymentAuthorizationID(s); return err },
			func(s string) error { _, err := protocol.ParseArbitrationClaimID(s); return err },
			func(s string) error { _, err := protocol.ParseContentRetrievalRequestID(s); return err },
			func(s string) error { _, err := protocol.ParseContentPayloadsID(s); return err },
		} {
			_ = parse(text) // 只要求不 panic
		}
	})
}

// TestParseRejectsOversizedInputBeforeDecoding 验证全局大小上限在任何 CBOR
// 解码之前生效：超大不可信输入以 malformed_wire 拒绝，不消耗解码资源。
func TestParseRejectsOversizedInputBeforeDecoding(t *testing.T) {
	oversized := make([]byte, content.MaxContentPayloadsCBORBytes+2048)
	if _, err := wire.Parse(oversized); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("oversized input error = %v, want malformed_wire", err)
	}
	if _, err := wire.ParseAs(wire.ContentRetrievalResponse, oversized); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("oversized ParseAs error = %v, want malformed_wire", err)
	}
}
