package docs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProtocolDocumentationCurrentTruth is a small static gate for the
// documents most likely to regress when an older 007 description is copied
// back into the current protocol. Historical records are intentionally outside
// this gate; they are allowed to describe the superseded implementation.
func TestProtocolDocumentationCurrentTruth(t *testing.T) {
	root := ".."
	checks := map[string]struct {
		required  []string
		forbidden []string
	}{
		"docs/protocol/wire-messages.zh.md": {
			required:  []string{"[4, 8, arbitration_claim_cbor", "[4, 9, arbitration_result_cbor", "原子持久化 exact request/payload"},
			forbidden: []string{"开池证据+授权+候选交易", "开池证据编码（内嵌 007）", "Kind 不进入签名字节"},
		},
		"website/docs/protocol/003-content-request-requirements.md": {
			required:  []string{"A 007 Claim does not carry that OpeningProof", "independently rebuild the candidate"},
			forbidden: []string{"007 already carries one and uses this path"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/003-content-request-requirements.md": {
			required:  []string{"007 Claim 不携带 OpeningProof", "独立重建 candidate"},
			forbidden: []string{"007 已携带一份并走该路径"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/005-cumulative-payment-requirements.md": {
			required:  []string{"不接收完整 OpeningProof 或 Seller candidate raw"},
			forbidden: []string{"完整开池证明与精确付款交易"},
		},
		"website/docs/protocol/007-seller-arbitration-submission-requirements.md": {
			required:  []string{"The outer request separately carries the Seller message signature"},
			forbidden: []string{"Its Claim contains only:\n\n- the claimed pool output satoshis", "the Seller message signature over `[4, 8, exact_claim_cbor]`."},
		},
		"spec/v4/bitfs.cddl": {
			required:  []string{"hard-switched four times"},
			forbidden: []string{"hard-switched three times"},
		},
		"spec/v4/arbitration.cddl": {
			required: []string{"arbitration-request", "arbitration-response"},
		},
		"website/docs/sdk/core-boundary-refactor-work-order.md": {
			required:  []string{"Current wire fixtures for 001–007", "five-element Claim/Result"},
			forbidden: []string{"before and after the switch", "Changing the normative 001–007 wire behavior"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk/role-workflow-api.md": {
			required: []string{"prepared.Request()", "prepared.ContentPayloadsCBOR()"},
		},
		// Kind 8/9 body type numbers enter the signed domain; the SDK
		// foundations page must keep stating that instead of the retired
		// "transport kind is never signed" claim.
		"website/docs/sdk/protocol-foundations-and-cbor.md": {
			required: []string{
				"[4, 8, arbitration_claim_cbor]",
				"[4, 9, arbitration_result_cbor]",
				"the Kind 8/9 bodies embed\n// their own body type as the second array element and sign it",
			},
			forbidden: []string{
				"It is not part of a\n// signed 001–007 CBOR body",
				"TypeScript",
				"@bsv/sdk",
				"cross-language vectors",
			},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk/protocol-foundations-and-cbor.md": {
			required: []string{
				"[4, 8, arbitration_claim_cbor]",
				"[4, 9, arbitration_result_cbor]",
				"而 Kind 8/9\n// 的本体在数组第二项显式携带自己的报文类型并进入签名域",
			},
			forbidden: []string{
				"它不进入 001–007 的已签名 CBOR 本体",
				"TypeScript",
				"@bsv/sdk",
				"跨语言向量",
			},
		},
		// The project supports Go only: current-truth SDK pages must not
		// promise TypeScript callers or @bsv/sdk interop.
		"website/docs/sdk/external-hooks-and-data-types.md": {
			required:  []string{"(*ec.PrivateKey).Sign"},
			forbidden: []string{"TypeScript", "@bsv/sdk", "cross-language test vectors", "cross-language vectors"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk/external-hooks-and-data-types.md": {
			required:  []string{"(*ec.PrivateKey).Sign"},
			forbidden: []string{"TypeScript", "TS 侧", "@bsv/sdk", "跨语言测试向量", "跨语言向量"},
		},
		"docs/complete-file-purchase/README.md": {
			required:  []string{"(*ec.PrivateKey).Sign"},
			forbidden: []string{"TypeScript", "TS 侧", "@bsv/sdk", "跨语言"},
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
