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
			required: []string{"[4, 8, arbitration_claim_cbor", "[4, 9, arbitration_receipt_cbor", "arbitration_claim_id, arbiter_amount_sat, arbiter_transaction_signature", "原子持久化 exact request/payload/Claim ID/费用",
				// 008 当前真值：Kind 10/11 形状、Buyer 签名域、exact Kind 8/9 内嵌
				// 与"取件 wire 由 SDK 固定"的边界表述。
				"[4, 10, arbitration_claim_id, retrieval_nonce, buyer_retrieval_signature]",
				"[4, 11, exact_arbitration_request_cbor, exact_arbitration_response_cbor]",
				"deterministic-CBOR(`[4, 10, claim_id, nonce]`)",
				"存储、nonce 去重和传输仍由应用负责",
				"Buyer 关池不在协议内：协商走 006，或等 nLockTime 后广播 002 的预签名 RefundTx"},
			forbidden: []string{"开池证据+授权+候选交易", "开池证据编码（内嵌 007）", "Kind 不进入签名字节", "[4, 9, arbitration_result_cbor", "request_commitment", "content_payloads_hash", "unsigned_state_tx_hash",
				// 禁止回归：把 008 写成关池/005 或宣称链上结算。
				"取件后发送 005", "Kind 11 证明交易已上链", "Arbiter 帮 Buyer 关池"},
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
		"website/docs/protocol/006-pool-close-requirements.md": {
			required:  []string{"explicit, positive `output[2]` allocation", "signs `[4, 9, exact_receipt_cbor]`"},
			forbidden: []string{"out-of-pool", "additional inputs for the submission transaction", "must be specified separately", "signing the Result and transaction separately"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/006-pool-close-requirements.md": {
			required:  []string{"正数 `output[2]` 分配", "签署 `[4, 9, exact_receipt_cbor]`"},
			forbidden: []string{"池外支付", "额外提供输入承担", "必须另行规范", "分别签署 Result 与交易"},
		},
		"website/docs/protocol/007-seller-arbitration-submission-requirements.md": {
			required: []string{
				"The outer request separately carries the Seller message signature",
				"PreparePayment(request, blockHeight, arbiterAmountSat)",
				"persist/send exact Kind 9",
				// 幂等重放的精确条件：exact Kind 8 相同才重放；不同外层证据先
				// 完整验证；无效变体不得计为 hash collision。
				"Identical Claim ID and identical exact Kind 8 bytes replay the persisted\n   response verbatim",
				"fully re-validated with the frozen fee via\n   PreparePayment",
				"never raises a collision alarm",
			},
			forbidden: []string{"Its Claim contains only:\n\n- the claimed pool output satoshis", "the Seller message signature over `[4, 8, exact_claim_cbor]`.", "Result", "three Result hashes"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/007-seller-arbitration-submission-requirements.md": {
			required: []string{
				"PreparePayment(request, blockHeight, arbiterAmountSat)",
				"原子持久化精确入站请求",
				// 幂等重放的精确条件：exact Kind 8 相同才重放；不同外层证据先
				// 完整验证；无效变体不得计为 hash collision。
				"Claim ID 与 exact Kind 8 字节完全相同才原样重放已保存响应",
				"使用已冻结费用完整执行 PreparePayment",
				"不得触发 hash collision 报警",
			},
			forbidden: []string{"三个 Result hash", "五元 Kind 9 响应有效", "ArbiterAmountSat = 0"},
		},
		"spec/v4/bitfs.cddl": {
			required:  []string{"hard-switched six times", "008 added Buyer custody retrieval"},
			forbidden: []string{"hard-switched three times", "hard-switched four times before launch", "hard-switched five times"},
		},
		"spec/v4/arbitration.cddl": {
			required: []string{"arbitration-request", "arbitration-response", "arbitration-receipt = [arbitration-claim-id, arbiter-amount-sat, arbiter-transaction-signature]", "arbiter-amount-sat = uint .gt 0",
				// 008 唯一形状：Kind 10/11、Buyer 签名域与完整验证要求。
				"arbitration-content-request", "arbitration-content-response",
				"retrieval-nonce = bstr .size 32", "buyer-retrieval-signature = bstr .size (1..256)",
				"SignMessage(BuyerKey, deterministic-CBOR([4, 10, claim_id,",
				"MUST\n; fully verify that whole evidence chain"},
		},
		"website/docs/protocol/008-buyer-arbitrated-content-retrieval-spec.md": {
			required: []string{
				"ArbitrationContentRequest",
				"ArbitrationContentResponse",
				"SignMessage(BuyerKey, buyer_retrieval_signing_cbor)",
				"SHA-256(deterministic-CBOR([4, 8, exact_claim_cbor]))",
				"deterministic-CBOR([4, 10, claim_id, nonce])",
				"No third outer signature exists on Kind 11",
				"byte-for-byte equal to the locally rebuilt expected ClaimCBOR",
				"does not produce a 005 PaymentUpdate",
				"= 16,844,188 bytes",
			},
			forbidden: []string{"buyer+arbiter close transaction exists", "BuyerClose", "reuses Kind 6 ContentDelivery"},
		},
		"website/docs/protocol/008-buyer-arbitrated-content-retrieval-requirements.md": {
			required: []string{
				"MUST NOT provide buyer arbitration close",
				"atomically occupy unique (ClaimID, Nonce)",
				"TLS or an equivalently secure transport",
				"a new nonce for every retry",
				"Gone after retention ends with safe deletion",
			},
			forbidden: []string{"Claim ID alone authorizes download", "AcceptDelivery(ctx"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/008-buyer-arbitrated-content-retrieval-spec.md": {
			required: []string{
				"[4, 10, arbitration_claim_id, retrieval_nonce, buyer_retrieval_signature]",
				"[4, 11, exact_arbitration_request_cbor, exact_arbitration_response_cbor]",
				"deterministic-CBOR([4, 10, claim_id, nonce])",
				"逐字节等于本地重建的 expected ClaimCBOR",
				"不产生 005 PaymentUpdate",
			},
			forbidden: []string{"复用 Kind 6 ContentDelivery"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/008-buyer-arbitrated-content-retrieval-requirements.md": {
			required: []string{
				"MUST NOT 提供 Buyer 仲裁关池",
				"原子占用 unique (ClaimID, Nonce)",
				"TLS 或等价安全传输",
				"每次重试使用新 nonce",
				"安全删除后返回 Gone",
			},
			forbidden: []string{"仅凭 Claim ID 即可下载"},
		},
		"website/docs/sdk/core-boundary-refactor-work-order.md": {
			required:  []string{"Current wire fixtures for 001–008", "five-element Kind 8 Claim request plus four-element Kind 9 Receipt response", "four-element Kind 11 custody evidence response"},
			forbidden: []string{"before and after the switch", "Changing the normative 001–007 wire behavior", "five-element Claim/Result"},
		},
		"website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk/core-boundary-refactor-work-order.md": {
			required:  []string{"五元 Kind 8 Claim 请求加四元 Kind 9 回执响应", "五元 Kind 10 买方取件请求加四元 Kind 11 托管证据响应"},
			forbidden: []string{"五元 Claim/Result"},
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
				"[4, 9, arbitration_receipt_cbor]",
				"the Kind 8/9/10/11 bodies\n// embed their own body type as the second array element and sign it",
				"deterministic-CBOR([4, 10, claim_id, nonce])",
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
				"[4, 9, arbitration_receipt_cbor]",
				"而 Kind 8/9\n// 的本体在数组第二项显式携带自己的报文类型并进入签名域",
				"deterministic-CBOR([4, 10, claim_id, nonce])",
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
			required: []string{
				"(*ec.PrivateKey).Sign",
				// 007 余额不足语义：拒绝本次仲裁且不产生 Kind 9，不得自动降费。
				"拒绝本次仲裁",
				"不生成、不保存、不发送 Kind 9",
			},
			forbidden: []string{"TypeScript", "TS 侧", "@bsv/sdk", "跨语言", "再下调费用或转人工"},
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
