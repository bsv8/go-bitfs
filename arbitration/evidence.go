package arbitration

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

// validateRequestEvidence performs the complete pre-signature evidence chain:
// strict Kind 8 decoding, Claim and authorization validation, role recovery,
// Buyer and Seller signature checks, per-payload hash verification, and
// independent candidate reconstruction with the explicit arbitration fee. The
// zero-fee rejection lives in the success builder, so no caller ever passes a
// placeholder amount. 它是纯证据函数：无时钟、无高度、无签名副作用。
func ValidateRequestEvidence(request *ArbitrationRequest, arbiterAmountSatoshis uint64) (*ArbitrationClaim, *content.PaymentAuthorization, [][]byte, *pool.UnsignedPayment, protocol.ArbitrationClaimID, protocol.PaymentAuthorizationID, pool.MultisigPoolPublicKeys, error) {
	const op = "arbitration.validateRequestEvidence"
	if err := ValidateRequest(request); err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	claim, err := UnmarshalClaim(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	authorization, err := content.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 5, claim.PaymentAuthorizationCBOR, claim.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, protocol.Wrap(fmt.Errorf("buyer payment authorization signature invalid: %v", err), op, protocol.CodeInvalidSignature, 8, "buyer_payment_authorization_signature")
	}
	if err := protocol.VerifyWireDocument(keys.SellerPublicKey, protocol.WireVersion, wireKindArbitrationRequest, request.ArbitrationClaimCBOR, request.SellerArbitrationClaimSignature); err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, protocol.Wrap(fmt.Errorf("seller Claim signature invalid: %v", err), op, protocol.CodeInvalidSignature, 8, "seller_arbitration_claim_signature")
	}
	payloads, err := content.DecodeContentPayloads(request.ContentPayloadsCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	hashes, err := content.DecodeContentHashes(authorization.ContentHashesCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	if len(payloads) != len(hashes) {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "content_payloads_cbor", "payload count does not match authorized hash count")
	}
	for index := range payloads {
		digest := sha256.Sum256(payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, fmt.Sprintf("payload[%d]", index), "payload #%d does not match authorized hash", index+1)
		}
	}
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis, arbiterAmountSatoshis)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	refundID := unsigned.RefundTemplateTxID
	if !bytes.Equal(refundID[:], authorization.RefundTemplateTxID) {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "refund_template_txid", "refund template transaction ID does not match Buyer terms")
	}
	authID, err := content.PaymentAuthorizationID(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	claimID, err := ArbitrationClaimID(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	return claim, authorization, payloads, unsigned, claimID, authID, keys, nil
}

// BuiltClaim is the shared, time-independent result of assembling the exact
// Kind 8 Claim evidence from a complete OpeningProof and the Buyer-signed
// payment authorization. Seller arbitration (007) and buyer content retrieval
// (008) both consume this single builder so both roles always derive
// byte-identical ArbitrationClaimCBOR and ArbitrationClaimID from the same
// opening plus authorization.
type BuiltClaim struct {
	// Claim 是 ArbitrationClaimCBOR 背后的已解码、深拷贝 Claim 证据。
	Claim *ArbitrationClaim
	// ArbitrationClaimCBOR 是精确规范的五元 Claim 子文档字节。
	ArbitrationClaimCBOR []byte
	// ArbitrationClaimID = SHA-256(exact_claim_cbor)，Seller 与 Buyer 独立重建必得同一值。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// Authorization 是 Claim 携带的已解码 Kind 5 付款授权（含目标序号与绝对卖方金额）。
	Authorization *content.PaymentAuthorization
}

// BuildClaimFromAuthorization derives the pool output facts from the supplied
// OpeningProof, verifies that the signed payment authorization belongs to that
// exact opening, assembles and canonically encodes the Claim, and computes its
// Claim ID. It clones every input, applies no clock or block-height gate, and
// produces no signature; deadline/refund gates remain with the calling
// workflows.
func BuildClaimFromAuthorization(opening *pool.OpeningProof, signedAuthorization *content.SignedContentRequest) (*BuiltClaim, error) {
	opening = pool.CloneOpeningProof(opening)
	signedAuthorization = content.CloneSignedContentRequest(signedAuthorization)
	const op = "arbitration.BuildClaimFromAuthorization"
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	authorization, err := content.VerifySignedContentRequestForOpening(signedAuthorization, opening)
	if err != nil {
		return nil, protocol.Wrap(fmt.Errorf("%v", err), op, protocol.CodeInvalidEvidence, 8, "payment_authorization_cbor")
	}
	claim := &ArbitrationClaim{
		PoolOutputSatoshis:                 details.PoolOutputSatoshis,
		PoolOutputLockingScript:            details.PoolLockingScript,
		RefundTemplateRaw:                  opening.RefundTemplateRaw,
		PaymentAuthorizationCBOR:           signedAuthorization.PaymentAuthorizationCBOR,
		BuyerPaymentAuthorizationSignature: signedAuthorization.BuyerPaymentAuthorizationSignature,
	}
	claimCBOR, err := MarshalClaim(claim)
	if err != nil {
		return nil, err
	}
	claimID, err := ArbitrationClaimID(claimCBOR)
	if err != nil {
		return nil, err
	}
	return &BuiltClaim{Claim: cloneClaim(claim), ArbitrationClaimCBOR: claimCBOR, ArbitrationClaimID: claimID, Authorization: authorization}, nil
}

// VerifyCustodiedContent performs the complete time-independent custody
// evidence verification over one stored record pair: strict decoding of both
// messages, Seller Claim signature, Buyer authorization signature, payload
// count, order, and hashes, Claim ID recomputation against the Receipt,
// Arbiter receipt signature, candidate rebuild with the Receipt fee, and
// Arbiter transaction signature. Applications use it while deciding which
// Kind 11 branch a stored record supports. It never reads the clock and never
// applies deadline or refund-maturity gates: those were enforced before Kind 9
// was signed.
func VerifyCustodiedContent(arbitrationRequest *ArbitrationRequest, arbitrationResponse *ArbitrationResponse) (*VerifiedCustodiedContent, error) {
	const op = "arbitration.VerifyCustodiedContent"
	if arbitrationRequest == nil || arbitrationResponse == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "custody_pair", "custodied evidence pair is required")
	}
	// 先克隆再做外壳校验：调用方传入的 Go struct 必须与 wire decoder 走同一
	// 套版本/kind/尺寸约束，错误版本或超限子文档在这里被拒绝。
	localRequest := cloneRequest(arbitrationRequest)
	localResponse := cloneResponse(arbitrationResponse)
	if err := ValidateRequest(localRequest); err != nil {
		return nil, err
	}
	if err := ValidateResponse(localResponse); err != nil {
		return nil, err
	}
	receipt, err := UnmarshalReceipt(localResponse.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	claim, _, payloads, unsigned, claimID, _, keys, err := ValidateRequestEvidence(localRequest, receipt.ArbiterAmountSatoshis)
	if err != nil {
		return nil, err
	}
	if receipt.ArbitrationClaimID != claimID {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "arbitration_claim_id", "receipt Claim ID does not match the custody Claim ID")
	}
	if err := protocol.VerifyWireDocument(keys.ArbiterPublicKey, protocol.WireVersion, wireKindArbitrationResponse, localResponse.ArbitrationReceiptCBOR, localResponse.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbiter receipt signature invalid: %v", err), op, protocol.CodeInvalidSignature, 9, "arbiter_arbitration_receipt_signature")
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, receipt.ArbiterPaymentTransactionSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbiter transaction signature invalid over the rebuilt candidate: %v", err), op, protocol.CodeInvalidSignature, 9, "arbiter_payment_transaction_signature")
	}
	return &VerifiedCustodiedContent{
		ArbitrationClaimID: claimID,
		PayloadsCBOR:       append([]byte(nil), localRequest.ContentPayloadsCBOR...),
		Payloads:           cloneByteSlices(payloads),
		Receipt:            cloneReceipt(receipt),
		Request:            localRequest,
		Response:           localResponse,
	}, nil
}

// VerifySellerClaimSignature 验证卖方对精确 Claim 文档的统一签名；供角色包
// 在完整证据链之外复用（例如 seller 仲裁路径的本地证据检查）。
func VerifySellerClaimSignature(request *ArbitrationRequest, keys pool.MultisigPoolPublicKeys) error {
	if err := protocol.VerifyWireDocument(keys.SellerPublicKey, protocol.WireVersion, wireKindArbitrationRequest, request.ArbitrationClaimCBOR, request.SellerArbitrationClaimSignature); err != nil {
		return protocol.Wrap(fmt.Errorf("Seller Claim signature is invalid: %v", err), "arbitration.VerifySellerClaimSignature", protocol.CodeInvalidSignature, 8, "seller_arbitration_claim_signature")
	}
	return nil
}
