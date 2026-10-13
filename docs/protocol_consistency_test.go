package docs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProtocolDocumentationCurrentTruth is a small static gate for the
// documents most likely to regress when an older wire description is copied
// back into the current protocol. Historical records live under
// spec/legacy/ and are intentionally outside this gate; they are allowed to
// describe the superseded v4 implementation.
func TestProtocolDocumentationCurrentTruth(t *testing.T) {
	root := ".."
	checks := map[string]struct {
		required  []string
		forbidden []string
	}{
		// 现行协议真值：v1 统一报文设计稿。
		"docs/protocol/wire-messages.zh.md": {
			required: []string{
				"protocol.WireVersion = 1",
				"[1, wire_kind, ...]",
				`"bitfs/wire-signature"`,
				"SignWireDocument(private_key, wire_version, wire_kind, document_cbor)",
				"arbitration_claim_id = SHA-256(arbitration_claim_cbor)",
				"file_quote_terms_id = SHA-256(file_quote_terms_cbor)",
				"payment_authorization_id = SHA-256(payment_authorization_cbor)",
				"content_payloads_id =\n  SHA-256(content_payloads_cbor)",
				"content_delivery_cbor = deterministic-CBOR([\n  payment_authorization_id\n])",
				"content_retrieval_result =\n  0  unavailable\n  1  available",
				"seller_arbitration_not_received",
				"custody_gone",
				"Kind 11 unavailable = [1, 11,",
				"Kind 11 available = [1, 11,",
				// 006 的关池 Kind 与费用池开池定义共同归属 002；008 不产生 005、不关池。
				"Kind 12/13 交换关池请求和完整关闭交易，报文定义与开池一起归属 002",
				"可交付分支只取回托管内容，\n  不替 Buyer 关池，不产生 005"},
			forbidden: []string{
				// 旧 v4 外形绝不能作为现行真值回归（迁移说明中的“已删除”
				// 表述除外——它们以“删除/改名”字样出现，不会命中这些片段）。
				"[4, 8, arbitration_claim_cbor", "[4, 9, arbitration_receipt_cbor",
				"[4, 10, arbitration_claim_id", "[4, 11, exact_arbitration_request_cbor",
				"exact_arbitration_request_cbor, exact_arbitration_response_cbor]",
				"取件后发送 005", "Kind 11 证明交易已上链", "Arbiter 帮 Buyer 关池"},
		},
		// 新 spec/v1 是唯一现行 CDDL 真值。
		"spec/v1/wire-messages.cddl": {
			required: []string{
				"wire-version = 1",
				"wire-kind = 1..13",
				`wire-signature-domain = "bitfs/wire-signature"`,
				"kind-1-file-quote", "kind-2-refund-presign-request",
				"kind-3-refund-presign-response", "kind-4-funding-transaction-delivery",
				"kind-5-content-request", "kind-6-content-delivery",
				"kind-7-payment-update", "kind-8-arbitration-request",
				"kind-9-arbitration-response", "kind-10-content-retrieval-request",
				"kind-11-unavailable / kind-11-available",
				"arbiter-amount-satoshis: uint .gt 0",
				"nonce = bstr .size 32",
				"recommended-filename: tstr",
				"buyer-payment-transaction-signature",
			},
			forbidden: []string{"MajorVersion = 4", "kind = 13", "kind = 14"},
		},
		// 网站现行 008 spec/requirements 必须与 v1 Kind 10/11 一致。
		"website/docs/protocol/008-buyer-arbitrated-content-retrieval-spec.md": {
			required: []string{
				"[1, 11, result_cbor, arbiter_content_retrieval_result_signature, content_payloads_cbor]",
				"content_payloads_id",
				"seller_arbitration_not_received",
				"SignWireDocument(BuyerKey, 1, 10, content_retrieval_request_cbor)",
				"**334 bytes**",
			},
			forbidden: []string{
				"exact_arbitration_request_cbor", "exact_arbitration_response_cbor",
				"[4, 11", "buyer_retrieval_signing_cbor", "= 16,844,188 bytes"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/008-buyer-arbitrated-content-retrieval-spec.md": {
			required: []string{
				"[1, 11, result_cbor, arbiter_content_retrieval_result_signature, content_payloads_cbor]",
				"content_payloads_id",
				"custody_gone",
				"**334 字节**",
			},
			forbidden: []string{
				"exact_arbitration_request_cbor", "exact_arbitration_response_cbor",
				"[4, 11", "deterministic-CBOR([4, 10, claim_id, nonce])"},
		},
		"website/docs/protocol/008-buyer-arbitrated-content-retrieval-requirements.md": {
			required:  []string{"Arbiter-signed four-element\n  Kind 11 unavailable branches"},
			forbidden: []string{"never as structurally valid\n  Kind 11 responses"},
		},
		// demo README 不再允许残留 v4 表述。
		"demo/README.md": {
			required:  []string{},
			forbidden: []string{"BitFS v4"},
		},
	}
	for relative, check := range checks {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		text := string(data)
		for _, phrase := range check.required {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s is missing current-protocol phrase %q", relative, phrase)
			}
		}
		for _, phrase := range check.forbidden {
			if strings.Contains(text, phrase) {
				t.Errorf("%s still contains stale-protocol phrase %q", relative, phrase)
			}
		}
	}
}

// TestLegacySpecIsArchived pins the hard-switch boundary: the retired CDDL
// iterations must stay out of the current version directory.
func TestLegacySpecIsArchived(t *testing.T) {
	for _, stale := range []string{"spec/v3", "spec/v4"} {
		if _, err := os.Stat(filepath.Join("..", stale)); err == nil {
			t.Errorf("stale spec directory %s still exists; move it under spec/legacy/", stale)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "spec", "legacy", "v4")); err != nil {
		t.Errorf("retired v4 CDDL must be archived at spec/legacy/v4: %v", err)
	}
}
