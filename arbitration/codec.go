package arbitration

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

// contentMaxPayloadsLimit 是 Kind 8 payload 附件的协议字节上限（引用
// content 包常量，避免在两处重复定义）。
const contentMaxPayloadsLimit = content.MaxContentPayloadsCBORBytes

// maxArbitrationRequestBytesValue 是 Kind 8 外层报文的派生字节上限：
// payload 上限 + Claim 上限 + 签名上限 + 固定外壳开销。
func maxArbitrationRequestBytesValue() int {
	return contentMaxPayloadsLimit + MaxArbitrationClaimBytes + MaxArbitrationSignatureBytes + maxArbitrationRequestEnvelopeBytes
}

// ValidateClaim validates a decoded arbitration Claim: a positive pool output,
// the canonical 2-of-3 locking script, bounded refund template and
// authorization children, and the buyer signature over the exact Kind 5
// document. It is pure evidence checking; no fee, deadline, or clock input
// exists here.
func ValidateClaim(claim *ArbitrationClaim) error {
	const op = "arbitration.ValidateClaim"
	if claim == nil || claim.PoolOutputSatoshis == 0 || len(claim.PoolOutputLockingScript) == 0 || len(claim.RefundTemplateRaw) == 0 || len(claim.PaymentAuthorizationCBOR) == 0 || len(claim.BuyerPaymentAuthorizationSignature) == 0 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "claim", "arbitration Claim is incomplete")
	}
	if len(claim.PoolOutputLockingScript) != 105 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "pool_output_locking_script", "arbitration Claim pool locking script has invalid size")
	}
	if len(claim.RefundTemplateRaw) > MaxArbitrationRefundTemplateBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 8, "refund_template_raw", "exceeds %d bytes", MaxArbitrationRefundTemplateBytes)
	}
	if len(claim.PaymentAuthorizationCBOR) > MaxArbitrationAuthorizationBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 8, "payment_authorization_cbor", "exceeds %d bytes", MaxArbitrationAuthorizationBytes)
	}
	if len(claim.BuyerPaymentAuthorizationSignature) > MaxArbitrationSignatureBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 8, "buyer_payment_authorization_signature", "exceeds %d bytes", MaxArbitrationSignatureBytes)
	}
	authorization, err := content.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return err
	}
	// 纯结构验证：不依赖任何成功仲裁费，因此不需要占位金额。
	if err := pool.ValidateArbitrationClaimStructure(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis); err != nil {
		return err
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 5, claim.PaymentAuthorizationCBOR, claim.BuyerPaymentAuthorizationSignature); err != nil {
		return protocol.Wrap(fmt.Errorf("buyer payment authorization signature invalid: %v", err), op, protocol.CodeInvalidSignature, 8, "buyer_payment_authorization_signature")
	}
	return nil
}

// MarshalClaim encodes the canonical five-element deterministic CBOR child.
func MarshalClaim(claim *ArbitrationClaim) ([]byte, error) {
	if err := ValidateClaim(claim); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{claim.PoolOutputSatoshis, bstr(claim.PoolOutputLockingScript), bstr(claim.RefundTemplateRaw), bstr(claim.PaymentAuthorizationCBOR), bstr(claim.BuyerPaymentAuthorizationSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationClaimBytes, "arbitration Claim"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalClaim strictly decodes Claim bytes: size limit first, strict decode,
// validation, then deterministic re-encode byte equality.
func UnmarshalClaim(data []byte) (*ArbitrationClaim, error) {
	const op = "arbitration.UnmarshalClaim"
	if err := requireWireSize(data, MaxArbitrationClaimBytes, "arbitration Claim"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeMalformedWire, 8, "arbitration_claim_cbor")
	}
	claim := new(ArbitrationClaim)
	if err := arbitrationDec.Unmarshal(values[0], &claim.PoolOutputSatoshis); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &claim.PoolOutputLockingScript); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &claim.RefundTemplateRaw); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &claim.PaymentAuthorizationCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &claim.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, err
	}
	if err := ValidateClaim(claim); err != nil {
		return nil, err
	}
	canonical, err := MarshalClaim(claim)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 8, "arbitration_claim_cbor", "arbitration Claim is not deterministically encoded")
	}
	return cloneClaim(claim), nil
}

// ValidateRequest enforces the exact five-element Kind 8 shape: bounded Claim
// child, seller signature, and canonical payload bundle attachment.
func ValidateRequest(request *ArbitrationRequest) error {
	const op = "arbitration.ValidateRequest"
	if request == nil || len(request.ArbitrationClaimCBOR) == 0 || len(request.SellerArbitrationClaimSignature) == 0 || len(request.ContentPayloadsCBOR) == 0 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "request", "arbitration request is incomplete")
	}
	if len(request.ArbitrationClaimCBOR) > MaxArbitrationClaimBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 8, "arbitration_claim_cbor", "exceeds %d bytes", MaxArbitrationClaimBytes)
	}
	if len(request.SellerArbitrationClaimSignature) > MaxArbitrationSignatureBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 8, "seller_arbitration_claim_signature", "exceeds %d bytes", MaxArbitrationSignatureBytes)
	}
	if len(request.ContentPayloadsCBOR) > contentMaxPayloadsLimit {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 8, "content_payloads_cbor", "payload bundle exceeds %d bytes", content.MaxContentPayloadsCBORBytes)
	}
	if _, err := UnmarshalClaim(request.ArbitrationClaimCBOR); err != nil {
		return err
	}
	if _, err := content.DecodeContentPayloads(request.ContentPayloadsCBOR); err != nil {
		return err
	}
	return nil
}

// MarshalRequest encodes the complete Kind 8 wire message:
// [1, 8, claim_cbor, seller_claim_signature, content_payloads_cbor].
func MarshalRequest(request *ArbitrationRequest) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{protocol.WireVersion, wireKindArbitrationRequest, bstr(request.ArbitrationClaimCBOR), bstr(request.SellerArbitrationClaimSignature), bstr(request.ContentPayloadsCBOR)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, maxArbitrationRequestBytesValue(), "arbitration request"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalRequest strictly decodes Kind 8 bytes: size limit first, strict
// decode, outer version/kind checks, validation, then deterministic re-encode
// byte equality.
func UnmarshalRequest(data []byte) (*ArbitrationRequest, error) {
	const op = "arbitration.UnmarshalRequest"
	if err := requireWireSize(data, maxArbitrationRequestBytesValue(), "arbitration request"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeMalformedWire, 8, "wire")
	}
	request := new(ArbitrationRequest)
	var version, kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedVersion, 8, "wire_version", "unsupported arbitration request wire version")
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != wireKindArbitrationRequest {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedKind, 8, "wire_kind", "arbitration request kind must be 8")
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.ArbitrationClaimCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.SellerArbitrationClaimSignature); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &request.ContentPayloadsCBOR); err != nil {
		return nil, err
	}
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	canonical, err := MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 8, "wire", "arbitration request is not deterministically encoded")
	}
	return cloneRequest(request), nil
}

// ArbitrationClaimID returns SHA-256(exact_claim_cbor) as the typed Kind 8
// document identity. The Claim document is the sole ID source; no
// signing-domain wrapper participates in the identity.
func ArbitrationClaimID(claimCBOR []byte) (protocol.ArbitrationClaimID, error) {
	if _, err := UnmarshalClaim(claimCBOR); err != nil {
		return protocol.ArbitrationClaimID{}, err
	}
	digest := sha256.Sum256(claimCBOR)
	return protocol.ArbitrationClaimID(digest), nil
}

// ValidateReceipt validates a decoded arbitration receipt: a fixed 32-byte
// Claim ID, a positive arbiter amount, and a bounded transaction signature.
func ValidateReceipt(receipt *ArbitrationReceipt) error {
	const op = "arbitration.ValidateReceipt"
	if receipt == nil || len(receipt.ArbitrationClaimID) != sha256.Size {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 9, "arbitration_claim_id", "must be 32 bytes")
	}
	if receipt.ArbiterAmountSatoshis == 0 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "arbiter_amount_satoshis", "must be positive")
	}
	if len(receipt.ArbiterPaymentTransactionSignature) == 0 || len(receipt.ArbiterPaymentTransactionSignature) > MaxArbitrationSignatureBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 9, "arbiter_payment_transaction_signature", "exceeds %d bytes", MaxArbitrationSignatureBytes)
	}
	return nil
}

// MarshalReceipt encodes the receipt as the canonical three-element
// deterministic CBOR child document.
func MarshalReceipt(receipt *ArbitrationReceipt) ([]byte, error) {
	if err := ValidateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{bstr(receipt.ArbitrationClaimID[:]), receipt.ArbiterAmountSatoshis, bstr(receipt.ArbiterPaymentTransactionSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationReceiptBytes, "arbitration receipt"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalReceipt strictly decodes receipt bytes: size limit first, strict
// decode, validation, then deterministic re-encode byte equality.
func UnmarshalReceipt(data []byte) (*ArbitrationReceipt, error) {
	const op = "arbitration.UnmarshalReceipt"
	if err := requireWireSize(data, MaxArbitrationReceiptBytes, "arbitration receipt"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeMalformedWire, 9, "arbitration_receipt_cbor")
	}
	receipt := new(ArbitrationReceipt)
	if err := arbitrationDec.Unmarshal(values[0], &receipt.ArbitrationClaimID); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &receipt.ArbiterAmountSatoshis); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &receipt.ArbiterPaymentTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidateReceipt(receipt); err != nil {
		return nil, err
	}
	canonical, err := MarshalReceipt(receipt)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 9, "arbitration_receipt_cbor", "arbitration receipt is not deterministically encoded")
	}
	return cloneReceipt(receipt), nil
}

// ValidateResponse enforces the four-element Kind 9 shape: bounded receipt
// child plus the arbiter unified receipt signature.
func ValidateResponse(response *ArbitrationResponse) error {
	const op = "arbitration.ValidateResponse"
	if response == nil || len(response.ArbitrationReceiptCBOR) == 0 || len(response.ArbiterArbitrationReceiptSignature) == 0 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "response", "arbitration response is incomplete")
	}
	if len(response.ArbitrationReceiptCBOR) > MaxArbitrationReceiptBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 9, "arbitration_receipt_cbor", "exceeds %d bytes", MaxArbitrationReceiptBytes)
	}
	if len(response.ArbiterArbitrationReceiptSignature) > MaxArbitrationSignatureBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 9, "arbiter_arbitration_receipt_signature", "exceeds %d bytes", MaxArbitrationSignatureBytes)
	}
	if _, err := UnmarshalReceipt(response.ArbitrationReceiptCBOR); err != nil {
		return err
	}
	return nil
}

// MarshalResponse encodes the complete Kind 9 wire message:
// [1, 9, receipt_cbor, arbiter_receipt_signature].
func MarshalResponse(response *ArbitrationResponse) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{protocol.WireVersion, wireKindArbitrationResponse, bstr(response.ArbitrationReceiptCBOR), bstr(response.ArbiterArbitrationReceiptSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationResponseBytes, "arbitration response"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalResponse strictly decodes Kind 9 bytes: size limit first, strict
// decode, outer version/kind checks, validation, then deterministic re-encode
// byte equality.
func UnmarshalResponse(data []byte) (*ArbitrationResponse, error) {
	const op = "arbitration.UnmarshalResponse"
	if err := requireWireSize(data, MaxArbitrationResponseBytes, "arbitration response"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeMalformedWire, 9, "wire")
	}
	response := new(ArbitrationResponse)
	var version, kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedVersion, 9, "wire_version", "unsupported arbitration response wire version")
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != wireKindArbitrationResponse {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedKind, 9, "wire_kind", "arbitration response kind must be 9")
	}
	if err := arbitrationDec.Unmarshal(values[2], &response.ArbitrationReceiptCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, err
	}
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	canonical, err := MarshalResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 9, "wire", "arbitration response is not deterministically encoded")
	}
	return cloneResponse(response), nil
}

// CloneRequest 返回深拷贝的 Kind 8 请求（跨包防御性复制边界）。
func CloneRequest(request *ArbitrationRequest) *ArbitrationRequest { return cloneRequest(request) }

// CloneResponse 返回深拷贝的 Kind 9 应答（跨包防御性复制边界）。
func CloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	return cloneResponse(response)
}
