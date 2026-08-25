// Package arbitration 是 007/008 的纯领域包：Kind 8/9 托管证据、Kind 10/11
// 取回报文的 DTO、确定性编解码、证据链验证与取回结果验证。它不持有任何角色
// 身份或签名能力；角色编排位于 arbiter/buyer/seller 包，签名一律经受约束
// protocol.Signer 进入。
//
// Kind 9 是硬切换后的四元回执应答：仲裁方获得一笔由调用方显式决定的正数
// 仲裁费，回执通过一次普通消息签名把 Claim ID、该费用与仲裁交易签名绑定为
// 单一真值；arbitration_claim_id = SHA-256(exact claim cbor)。
package arbitration

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Kind 8/9 的统一 wire Kind 值；版本只使用 protocol.WireVersion。
const (
	wireKindArbitrationRequest  uint64 = 8
	wireKindArbitrationResponse uint64 = 9

	// These are protocol limits, applied before CBOR decoding. They bound both
	// the outer messages and the large bstr children that a decoder would
	// otherwise allocate before semantic validation. Applications may impose
	// smaller transport limits, but must not silently raise these limits.
	MaxArbitrationSignatureBytes      = 256
	MaxArbitrationRefundTemplateBytes = 16 * 1024
	MaxArbitrationAuthorizationBytes  = 16 * 1024
	MaxArbitrationClaimBytes          = 64 * 1024

	// maxDeterministicUint64Bytes is the largest canonical CBOR encoding of a
	// uint64 (8-byte value plus its length head).
	maxDeterministicUint64Bytes = 9
	// maxClaimIDBstrBytes is the exact wire width of a 32-byte Claim ID bstr:
	// the two-byte major-type+length head (0x58 0x20) plus the fixed value.
	maxClaimIDBstrBytes = 2 + sha256.Size
	// maxSignatureBstrOverhead is the uint16 length head (0x59 + two bytes)
	// required for any bstr above 255 bytes, i.e. a full-size signature child.
	maxSignatureBstrOverhead = 3

	// MaxArbitrationReceiptBytes is derived from the Receipt child limits:
	// [claim_id(34), amount(9), transaction_signature(3+256)] plus the array
	// head = 1 + 34 + 9 + 259 = 303. It is intentionally NOT an independent
	// quota; raising it silently or shrinking it below the child limits breaks
	// interoperability.
	MaxArbitrationReceiptBytes = 1 + maxClaimIDBstrBytes + maxDeterministicUint64Bytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// MaxArbitrationResponseBytes is derived from the four-element response
	// shape [1, 9, receipt_cbor, receipt_signature]: array head, version,
	// kind, the receipt wrapped in a uint16-headed bstr, and the receipt
	// signature = 1 + 1 + 1 + (3 + 303) + (3 + 256) = 568.
	MaxArbitrationResponseBytes = 1 + 1 + 1 + maxSignatureBstrOverhead + MaxArbitrationReceiptBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// maxArbitrationRequestEnvelopeBytes is the exact deterministic-CBOR
	// overhead of the outer five-element request [1, 8, claim, sig, payloads]:
	// the array head (1), version (1), kind (1), and the maximum bstr heads of
	// the three children — Claim at MaxArbitrationClaimBytes needs a uint32
	// length head (5), a full Seller signature needs uint16 (3), and the
	// payload bundle at content.MaxContentPayloadsCBORBytes needs uint32 (5).
	maxArbitrationRequestEnvelopeBytes = 16
)

var (
	arbitrationEnc cbor.EncMode
	arbitrationDec cbor.DecMode
)

func init() {
	var err error
	arbitrationEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	arbitrationDec, err = cbor.DecOptions{
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  16,
		MaxArrayElements: 64,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// ArbitrationClaim is the versionless, kindless inner Kind 8 authentication
// document. Its exact bytes are both the business truth and the source of the
// Claim ID: arbitration_claim_id = SHA-256(arbitration_claim_cbor).
type ArbitrationClaim struct {
	// PoolOutputSatoshis 是被托管资金池输出的聪数（uint64）；仲裁 candidate
	// 的输入金额必须与它一致。
	PoolOutputSatoshis uint64
	// PoolOutputLockingScript 是角色顺序固定 [Buyer, Seller, Arbiter] 的
	// 2-of-3 压缩公钥锁定脚本（恰好 105 字节）；三方公钥由它恢复。
	PoolOutputLockingScript []byte
	// RefundTemplateRaw 是规范未签名退款模板交易的原始字节；到期后买方凭它
	// 广播退款，仲裁方用它派生 refund_template_txid 与保留矿工费。
	RefundTemplateRaw []byte
	// PaymentAuthorizationCBOR 是买方签名的 exact Kind 5 付款授权子文档；
	// 目标序号与绝对卖方金额由此提供，绝不解码重编码。
	PaymentAuthorizationCBOR []byte
	// BuyerPaymentAuthorizationSignature 是买方对 WireSignatureInput(1, 5,
	// payment_authorization_cbor) 的统一消息签名。
	BuyerPaymentAuthorizationSignature []byte
}

// ArbitrationRequest is the exact five-element Kind 8 message. ArbitrationClaimCBOR is
// the exact deterministic ArbitrationClaim child document; it is not decoded
// and re-encoded on the wire.
type ArbitrationRequest struct {
	// ArbitrationClaimCBOR 是 exact 确定性 Claim 子文档字节；wire 不解码重编码，
	// arbitration_claim_id = SHA-256(该字段)。
	ArbitrationClaimCBOR []byte
	// SellerArbitrationClaimSignature 是卖方对 WireSignatureInput(1, 8,
	// arbitration_claim_cbor) 的统一消息签名；payload 不直接入签。
	SellerArbitrationClaimSignature []byte
	// ContentPayloadsCBOR 是确定性 CBOR payload 批次（attachment）：顺序与
	// 授权哈希一一对应，经买方已签 content_hashes_cbor 间接绑定。
	ContentPayloadsCBOR []byte
}

// ArbitrationReceipt is the versionless, kindless inner Kind 9 document. It
// binds the exact Claim ID, the absolute arbiter fee paid by output[2], and
// the ForkID|All transaction signature over the independently rebuilt
// candidate. A successful receipt always carries a positive fee.
type ArbitrationReceipt struct {
	// ArbitrationClaimID 路由本回执对应的托管记录（SHA-256(exact claim cbor)）；
	// 必须与验证时重算的 Claim ID 一致。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// ArbiterAmountSatoshis 是分配给 output[2] 的冻结绝对仲裁费（单位
	// satoshi）；成功回执恒为正数。
	ArbiterAmountSatoshis uint64
	// ArbiterPaymentTransactionSignature 是仲裁方对独立重建付费 candidate 的
	// ForkID|All 原生交易签名；不能替代回执普通消息签名。
	ArbiterPaymentTransactionSignature []byte
}

// ArbitrationResponse is the exact four-element Kind 9 message. ArbitrationReceiptCBOR is
// the exact deterministic ArbitrationReceipt child document; it is not decoded
// and re-encoded on the wire.
type ArbitrationResponse struct {
	// ArbitrationReceiptCBOR 是 exact 确定性回执子文档字节；wire 不解码重编码。
	ArbitrationReceiptCBOR []byte
	// ArbiterArbitrationReceiptSignature 是仲裁方对 WireSignatureInput(1, 9,
	// arbitration_receipt_cbor) 的统一消息签名，把 Claim ID、费用和交易签名绑定在一起。
	ArbiterArbitrationReceiptSignature []byte
}

func cloneRequest(request *ArbitrationRequest) *ArbitrationRequest {
	if request == nil {
		return nil
	}
	return &ArbitrationRequest{ArbitrationClaimCBOR: append([]byte(nil), request.ArbitrationClaimCBOR...), SellerArbitrationClaimSignature: append([]byte(nil), request.SellerArbitrationClaimSignature...), ContentPayloadsCBOR: append([]byte(nil), request.ContentPayloadsCBOR...)}
}

func cloneClaim(claim *ArbitrationClaim) *ArbitrationClaim {
	if claim == nil {
		return nil
	}
	return &ArbitrationClaim{PoolOutputSatoshis: claim.PoolOutputSatoshis, PoolOutputLockingScript: append([]byte(nil), claim.PoolOutputLockingScript...), RefundTemplateRaw: append([]byte(nil), claim.RefundTemplateRaw...), PaymentAuthorizationCBOR: append([]byte(nil), claim.PaymentAuthorizationCBOR...), BuyerPaymentAuthorizationSignature: append([]byte(nil), claim.BuyerPaymentAuthorizationSignature...)}
}

func cloneReceipt(receipt *ArbitrationReceipt) *ArbitrationReceipt {
	if receipt == nil {
		return nil
	}
	return &ArbitrationReceipt{ArbitrationClaimID: receipt.ArbitrationClaimID, ArbiterAmountSatoshis: receipt.ArbiterAmountSatoshis, ArbiterPaymentTransactionSignature: append([]byte(nil), receipt.ArbiterPaymentTransactionSignature...)}
}

func cloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	if response == nil {
		return nil
	}
	return &ArbitrationResponse{ArbitrationReceiptCBOR: append([]byte(nil), response.ArbitrationReceiptCBOR...), ArbiterArbitrationReceiptSignature: append([]byte(nil), response.ArbiterArbitrationReceiptSignature...)}
}

func decodeArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := arbitrationDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func requireWireSize(data []byte, limit int, label string) error {
	if len(data) == 0 || len(data) > limit {
		return protocol.Errorf("arbitration", protocol.CodeMalformedWire, 0, label, "exceeds %d bytes", limit)
	}
	return nil
}

func bstr(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

// equalBytes 报告两个字节切片是否逐字节相等（nil 与空等价）。
func equalBytes(left, right []byte) bool { return bytes.Equal(left, right) }
