// Kind 10/11 buyer custody retrieval: a Buyer-signed request routed by
// ArbitrationClaimID and an Arbiter answer that embeds the exact persisted
// Kind 8/9 evidence pair without re-encoding or adding a second signature.
package arbitration

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

const (
	kindContentRetrievalRequest  uint64 = 10
	kindContentRetrievalResponse uint64 = 11

	// RetrievalNonceBytes is the fixed width of the caller-generated replay
	// key. The nonce must come from the application's cryptographic random
	// source; the SDK never generates, stores, or deduplicates nonces.
	RetrievalNonceBytes = sha256.Size

	// MinContentRetrievalSignatureBytes is the lower bound of the DER buyer
	// retrieval signature child.
	MinContentRetrievalSignatureBytes = 1

	// MaxContentRetrievalRequestBytes is derived from the five-element wire
	// shape [4, 10, claim_id(34), nonce(34), signature(3+256)]:
	// 1 + 1 + 1 + 34 + 34 + 259 = 330 bytes.
	MaxContentRetrievalRequestBytes = 1 + 1 + 1 + maxClaimIDBstrBytes + maxClaimIDBstrBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// MaxContentRetrievalResponseBytes is derived from the four-element wire
	// shape [4, 11, exact_kind8_cbor, exact_kind9_cbor]: array head, version,
	// kind, the exact Kind 8 behind a uint32 length head, and the exact Kind 9
	// behind a uint16 length head = 3 + 5 + MaxArbitrationRequestBytes +
	// 3 + MaxArbitrationResponseBytes. It is not an independent quota.
	MaxContentRetrievalResponseBytes = 1 + 1 + 1 + 5 + MaxArbitrationRequestBytes + maxSignatureBstrOverhead + MaxArbitrationResponseBytes
)

// ContentRetrievalRequest is the exact five-element Kind 10 message. It
// carries no Buyer public key, OpeningProof, TermsCBOR, ClaimCBOR, or
// PaymentAuthorizationHash: the arbiter recovers every role key from the
// stored Claim named by ClaimID.
type ContentRetrievalRequest struct {
	Version        uint64
	ClaimID        []byte
	Nonce          []byte
	BuyerSignature []byte
}

// ContentRetrievalResponse is the exact four-element Kind 11 message. The two
// children are the byte-exact canonical Kind 8 and Kind 9 documents saved in
// one custody record; payloads appear only inside the embedded Kind 8.
type ContentRetrievalResponse struct {
	Version                 uint64
	ArbitrationRequestCBOR  []byte
	ArbitrationResponseCBOR []byte
}

// VerifiedCustodiedContent is the deep-copied result of fully verifying one
// custody record: the recomputed Claim ID plus the verified evidence chain
// from the embedded Kind 8 and Kind 9. It is time-independent: expired
// deadlines or matured refunds never invalidate already signed custody
// evidence that is still inside its application retention window.
type VerifiedCustodiedContent struct {
	ClaimID      []byte
	PayloadsCBOR []byte
	Payloads     [][]byte
	Receipt      *ArbitrationReceipt
	Request      *ArbitrationRequest
	Response     *ArbitrationResponse
}

func validateRetrievalNonce(nonce []byte) error {
	if len(nonce) != RetrievalNonceBytes {
		return fmt.Errorf("%w: retrieval nonce must be 32 bytes", pool.ErrInvalidEvidence)
	}
	for _, value := range nonce {
		if value != 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: retrieval nonce must not be all zero", pool.ErrInvalidEvidence)
}

// ValidateContentRetrievalRequest enforces the fixed Kind 10 field widths: a
// 32-byte Claim ID, a 32-byte non-zero nonce, and a bounded DER signature.
func ValidateContentRetrievalRequest(request *ContentRetrievalRequest) error {
	if request == nil || request.Version != MajorVersion || len(request.ClaimID) == 0 || len(request.Nonce) == 0 || len(request.BuyerSignature) == 0 {
		return fmt.Errorf("%w: content retrieval request is incomplete", pool.ErrInvalidEvidence)
	}
	if len(request.ClaimID) != sha256.Size {
		return fmt.Errorf("%w: content retrieval Claim ID must be 32 bytes", pool.ErrInvalidEvidence)
	}
	if err := validateRetrievalNonce(request.Nonce); err != nil {
		return err
	}
	if len(request.BuyerSignature) < MinContentRetrievalSignatureBytes || len(request.BuyerSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: buyer retrieval signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	return nil
}

// MarshalContentRetrievalRequest encodes the canonical five-element Kind 10.
func MarshalContentRetrievalRequest(request *ContentRetrievalRequest) ([]byte, error) {
	if err := ValidateContentRetrievalRequest(request); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{MajorVersion, kindContentRetrievalRequest, bstr(request.ClaimID), bstr(request.Nonce), bstr(request.BuyerSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxContentRetrievalRequestBytes, "content retrieval request"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalContentRetrievalRequest strictly decodes Kind 10 bytes: size limit,
// strict shape, version/kind checks, validation, then deterministic round-trip
// equality.
func UnmarshalContentRetrievalRequest(data []byte) (*ContentRetrievalRequest, error) {
	if err := requireWireSize(data, MaxContentRetrievalRequestBytes, "content retrieval request"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content retrieval request: %v", pool.ErrInvalidEvidence, err)
	}
	request := new(ContentRetrievalRequest)
	var kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &request.Version); err != nil || request.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported content retrieval request version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != kindContentRetrievalRequest {
		return nil, fmt.Errorf("%w: content retrieval request kind must be 10", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.ClaimID); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.Nonce); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &request.BuyerSignature); err != nil {
		return nil, err
	}
	if err := ValidateContentRetrievalRequest(request); err != nil {
		return nil, err
	}
	canonical, err := MarshalContentRetrievalRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: content retrieval request is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneRetrievalRequest(request), nil
}

// BuyerRetrievalSigningCBOR returns the exact [4,10,claim_id,nonce] signing
// domain. Nothing else — not the bare Claim ID, not the bare nonce, not the
// complete Kind 10 envelope — is ever signed for retrieval.
func BuyerRetrievalSigningCBOR(claimID, nonce []byte) ([]byte, error) {
	if len(claimID) != sha256.Size {
		return nil, fmt.Errorf("%w: content retrieval Claim ID must be 32 bytes", pool.ErrInvalidEvidence)
	}
	if err := validateRetrievalNonce(nonce); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(nonce)})
}

// ValidateContentRetrievalResponse enforces the four-element shell and strict
// canonical decodability of both embedded children. Full evidence-chain
// verification lives in VerifyCustodiedContent.
func ValidateContentRetrievalResponse(response *ContentRetrievalResponse) error {
	if response == nil || response.Version != MajorVersion || len(response.ArbitrationRequestCBOR) == 0 || len(response.ArbitrationResponseCBOR) == 0 {
		return fmt.Errorf("%w: content retrieval response is incomplete", pool.ErrInvalidEvidence)
	}
	if len(response.ArbitrationRequestCBOR) > MaxArbitrationRequestBytes {
		return fmt.Errorf("%w: embedded arbitration request exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationRequestBytes)
	}
	if _, err := UnmarshalRequest(response.ArbitrationRequestCBOR); err != nil {
		return fmt.Errorf("%w: embedded arbitration request is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	if len(response.ArbitrationResponseCBOR) > MaxArbitrationResponseBytes {
		return fmt.Errorf("%w: embedded arbitration response exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationResponseBytes)
	}
	if _, err := UnmarshalResponse(response.ArbitrationResponseCBOR); err != nil {
		return fmt.Errorf("%w: embedded arbitration response is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	return nil
}

// MarshalContentRetrievalResponse encodes the canonical four-element Kind 11.
func MarshalContentRetrievalResponse(response *ContentRetrievalResponse) ([]byte, error) {
	if err := ValidateContentRetrievalResponse(response); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{MajorVersion, kindContentRetrievalResponse, bstr(response.ArbitrationRequestCBOR), bstr(response.ArbitrationResponseCBOR)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxContentRetrievalResponseBytes, "content retrieval response"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalContentRetrievalResponse strictly decodes Kind 11 bytes with the
// same size-limit-first ordering as every other decoder in this package.
func UnmarshalContentRetrievalResponse(data []byte) (*ContentRetrievalResponse, error) {
	if err := requireWireSize(data, MaxContentRetrievalResponseBytes, "content retrieval response"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content retrieval response: %v", pool.ErrInvalidEvidence, err)
	}
	response := new(ContentRetrievalResponse)
	var kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &response.Version); err != nil || response.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported content retrieval response version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != kindContentRetrievalResponse {
		return nil, fmt.Errorf("%w: content retrieval response kind must be 11", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &response.ArbitrationRequestCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.ArbitrationResponseCBOR); err != nil {
		return nil, err
	}
	if err := ValidateContentRetrievalResponse(response); err != nil {
		return nil, err
	}
	canonical, err := MarshalContentRetrievalResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: content retrieval response is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneRetrievalResponse(response), nil
}

// VerifyCustodiedContent performs the complete time-independent custody
// evidence verification over one stored record pair: strict decoding of both
// messages, Seller Claim signature, Buyer terms signature, payload count,
// order, and hashes, Claim ID recomputation against the Receipt, Arbiter
// receipt signature, candidate rebuild with the Receipt fee, and Arbiter
// transaction signature. It never reads the clock and never applies deadline
// or refund-maturity gates: those were enforced before Kind 9 was signed.
func VerifyCustodiedContent(arbitrationRequest *ArbitrationRequest, arbitrationResponse *ArbitrationResponse) (*VerifiedCustodiedContent, error) {
	if arbitrationRequest == nil || arbitrationResponse == nil {
		return nil, fmt.Errorf("%w: custodied evidence pair is required", pool.ErrInvalidEvidence)
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
	receipt, err := UnmarshalReceipt(localResponse.ReceiptCBOR)
	if err != nil {
		return nil, err
	}
	claim, _, payloads, unsigned, claimID, _, keys, err := validateRequestEvidence(localRequest, receipt.ArbiterAmountSat)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(receipt.ClaimID, claimID) {
		return nil, fmt.Errorf("%w: receipt Claim ID does not match the custody Claim ID", pool.ErrInvalidEvidence)
	}
	receiptSigning, err := ArbiterReceiptSigningCBOR(localResponse.ReceiptCBOR)
	if err != nil {
		return nil, err
	}
	if err := bitfs.VerifySignature(keys.ArbiterPubKey, receiptSigning, localResponse.ArbiterReceiptSignature); err != nil {
		return nil, fmt.Errorf("%w: arbiter receipt signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, receipt.ArbiterTransactionSignature); err != nil {
		return nil, fmt.Errorf("%w: arbiter transaction signature invalid over the rebuilt candidate: %v", pool.ErrInvalidEvidence, err)
	}
	return &VerifiedCustodiedContent{
		ClaimID:      append([]byte(nil), claimID...),
		PayloadsCBOR: append([]byte(nil), localRequest.ContentPayloadsCBOR...),
		Payloads:     cloneByteSlices(payloads),
		Receipt:      cloneReceipt(receipt),
		Request:      localRequest,
		Response:     localResponse,
	}, nil
}

// VerifyContentRetrievalRequest authenticates one Kind 10 against a stored
// custody record: full custody evidence verification first, then a check that
// the Claim names this workflow's arbiter key, then buyer signature
// verification over the exact [4,10,claim_id,nonce] domain with the buyer key
// recovered from the stored Claim. A valid signature over any other Claim ID,
// nonce, or kind can never pass.
func (workflow *Workflow) VerifyContentRetrievalRequest(retrievalRequest *ContentRetrievalRequest, storedArbitrationRequest *ArbitrationRequest, storedArbitrationResponse *ArbitrationResponse) (*VerifiedCustodiedContent, error) {
	if workflow == nil {
		return nil, fmt.Errorf("arbitration workflow is required")
	}
	// 第一时间快照可变输入：后续验证只使用局部副本。
	localRetrieval := cloneRetrievalRequest(retrievalRequest)
	if err := ValidateContentRetrievalRequest(localRetrieval); err != nil {
		return nil, err
	}
	verified, err := VerifyCustodiedContent(storedArbitrationRequest, storedArbitrationResponse)
	if err != nil {
		return nil, err
	}
	claim, err := UnmarshalClaim(verified.Request.ClaimCBOR)
	if err != nil {
		return nil, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPubKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: custody Claim names another arbiter", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(localRetrieval.ClaimID, verified.ClaimID) {
		return nil, fmt.Errorf("%w: retrieval Claim ID does not match the custody record", pool.ErrInvalidEvidence)
	}
	signing, err := BuyerRetrievalSigningCBOR(localRetrieval.ClaimID, localRetrieval.Nonce)
	if err != nil {
		return nil, err
	}
	if err := bitfs.VerifySignature(keys.BuyerPubKey, signing, localRetrieval.BuyerSignature); err != nil {
		return nil, fmt.Errorf("%w: buyer retrieval signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	return verified, nil
}

// BuildContentRetrievalResponse wraps two exact persisted custody documents
// into a Kind 11. Both inputs are strict-decoded and fully verified first;
// the returned response embeds the original bytes verbatim — never a decoded
// struct re-encoded back to wire.
func BuildContentRetrievalResponse(exactKind8, exactKind9 []byte) (*ContentRetrievalResponse, error) {
	storedRequest, err := UnmarshalRequest(exactKind8)
	if err != nil {
		return nil, err
	}
	storedResponse, err := UnmarshalResponse(exactKind9)
	if err != nil {
		return nil, err
	}
	if _, err := VerifyCustodiedContent(storedRequest, storedResponse); err != nil {
		return nil, err
	}
	response := &ContentRetrievalResponse{Version: MajorVersion, ArbitrationRequestCBOR: append([]byte(nil), exactKind8...), ArbitrationResponseCBOR: append([]byte(nil), exactKind9...)}
	if _, err := MarshalContentRetrievalResponse(response); err != nil {
		return nil, err
	}
	return response, nil
}

func cloneRetrievalRequest(request *ContentRetrievalRequest) *ContentRetrievalRequest {
	if request == nil {
		return nil
	}
	return &ContentRetrievalRequest{Version: request.Version, ClaimID: append([]byte(nil), request.ClaimID...), Nonce: append([]byte(nil), request.Nonce...), BuyerSignature: append([]byte(nil), request.BuyerSignature...)}
}

func cloneRetrievalResponse(response *ContentRetrievalResponse) *ContentRetrievalResponse {
	if response == nil {
		return nil
	}
	return &ContentRetrievalResponse{Version: response.Version, ArbitrationRequestCBOR: append([]byte(nil), response.ArbitrationRequestCBOR...), ArbitrationResponseCBOR: append([]byte(nil), response.ArbitrationResponseCBOR...)}
}
