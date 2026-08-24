// Kind 10/11 buyer custody retrieval under the unified wire model. A Kind 10
// carries the buyer-signed content_retrieval_request_cbor =
// [arbitration_claim_id, retrieval_nonce]. A Kind 11 is an explicitly
// discriminated two-branch union signed by the arbiter through the unified
// SignWireDocument(1, 11, ...) helper: branch 0 answers "currently
// unavailable" with a structured reason and no attachment; branch 1 binds the
// exact content_payloads_cbor through its SHA-256 content_payloads_id and
// attaches the payloads verbatim. No embedded Kind 8/9 bytes exist anymore.
package arbitration

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

const (
	wireKindContentRetrievalRequest  uint64 = 10
	wireKindContentRetrievalResponse uint64 = 11

	// RetrievalNonceBytes is the fixed width of the caller-generated replay
	// key. The nonce must come from the application's cryptographic random
	// source; the SDK never generates, stores, or deduplicates nonces.
	RetrievalNonceBytes = sha256.Size

	// MinContentRetrievalSignatureBytes is the lower bound of the DER buyer
	// retrieval signature child.
	MinContentRetrievalSignatureBytes = 1

	// maxClaimIDBstrWidth re-exported locally: exact wire width of a 32-byte
	// ID bstr including its 0x58 0x20 head.
	maxClaimIDBstrWidth = maxClaimIDBstrBytes

	// maxContentRetrievalRequestDocBytes bounds the inner
	// content_retrieval_request_cbor: array head plus two 32-byte bstr IDs
	// = 1 + 34 + 34 = 69.
	maxContentRetrievalRequestDocBytes = 1 + 2*maxClaimIDBstrWidth

	// MaxContentRetrievalRequestBytes is derived from the four-element wire
	// shape [1, 10, request_cbor(3+69), signature(3+256)]:
	// 1 + 1 + 1 + 72 + 259 = 334 bytes.
	MaxContentRetrievalRequestBytes = 1 + 1 + 1 + maxSignatureBstrOverhead + maxContentRetrievalRequestDocBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// maxContentRetrievalResultDocBytes bounds the inner
	// content_retrieval_result_cbor: array head, 32-byte request ID,
	// discriminator, and either an unavailable reason or a 32-byte payload ID
	// = 1 + 34 + 1 + 34 = 70.
	maxContentRetrievalResultDocBytes = 1 + maxClaimIDBstrWidth + 1 + maxClaimIDBstrWidth

	// MaxContentRetrievalUnavailableBytes is the fixed upper size of the
	// unavailable branch [1, 11, result(3+70), signature(3+256)] = 335.
	MaxContentRetrievalUnavailableBytes = 1 + 1 + 1 + maxSignatureBstrOverhead + maxContentRetrievalResultDocBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// MaxContentRetrievalAvailableBytes is derived from the five-element
	// available branch shape [1, 11, result(3+70), signature(3+256),
	// payloads(uint32 head + bundle)]. It is not an independent quota.
	MaxContentRetrievalAvailableBytes = 1 + 1 + 1 + maxSignatureBstrOverhead + maxContentRetrievalResultDocBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes + 5 + bitfs.MaxContentPayloadsCBORBytes

	// MaxContentRetrievalResponseBytes is the single pre-allocation guard used
	// before the branch discriminator is known; the unavailable branch is
	// strictly smaller than the available one.
	MaxContentRetrievalResponseBytes = MaxContentRetrievalAvailableBytes
)

// ContentRetrievalResult discriminates the two Kind 11 branches.
type ContentRetrievalResult uint64

const (
	// ContentRetrievalUnavailable: the arbiter currently cannot deliver the
	// custodied content to this buyer.
	ContentRetrievalUnavailable ContentRetrievalResult = 0
	// ContentRetrievalAvailable: the arbiter completed the internal state
	// transition required for retrieval and attached the payloads.
	ContentRetrievalAvailable ContentRetrievalResult = 1
)

// ContentRetrievalUnavailableReason enumerates the three honest reasons a
// Kind 11 unavailable branch can carry.
type ContentRetrievalUnavailableReason uint64

const (
	// RetrievalSellerArbitrationNotReceived: no Kind 8 custody record exists
	// for this Claim ID.
	RetrievalSellerArbitrationNotReceived ContentRetrievalUnavailableReason = 0
	// RetrievalSellerArbitrationNotReady: the Kind 8 record exists and is
	// persisted, but the Kind 9 receipt has not been completed.
	RetrievalSellerArbitrationNotReady ContentRetrievalUnavailableReason = 1
	// RetrievalCustodyGone: a complete custody record existed but the content
	// was deleted under the public retention policy.
	RetrievalCustodyGone ContentRetrievalUnavailableReason = 2
)

// ErrContentUnavailable marks a verified Kind 11 whose arbiter answered with
// the unavailable branch. It never implies that the seller will never
// arbitrate, and it produces no refund, close, or payment state change.
var ErrContentUnavailable = errors.New("arbitrated content is currently unavailable")

// ContentRetrievalRequest is the exact four-element Kind 10 message. It
// carries no Buyer public key, OpeningProof, payment authorization, Claim
// bytes, or payment authorization ID: the arbiter recovers every role key from
// the stored Claim named by the Claim ID inside ContentRetrievalRequestCBOR.
type ContentRetrievalRequest struct {
	// ContentRetrievalRequestCBOR 是 exact 规范子文档
	// [arbitration_claim_id, retrieval_nonce]；它是买方唯一签署的对象，
	// 其 SHA-256 即 content_retrieval_request_id。
	ContentRetrievalRequestCBOR []byte
	// BuyerContentRetrievalRequestSignature 是买方对 WireSignatureInput(1, 10,
	// content_retrieval_request_cbor) 的统一消息签名。
	BuyerContentRetrievalRequestSignature []byte
}

// ContentRetrievalResponse is the exact Kind 11 message. The discriminator
// inside ContentRetrievalResultCBOR selects the only legal outer shape:
//
//	unavailable: [1, 11, result_cbor, signature]
//	available:   [1, 11, result_cbor, signature, content_payloads_cbor]
type ContentRetrievalResponse struct {
	// ContentRetrievalResultCBOR 是 exact 规范结果子文档
	// [content_retrieval_request_id, result, branch_value]；判别值决定外层形状。
	ContentRetrievalResultCBOR []byte
	// ArbiterContentRetrievalResultSignature 是仲裁方对 WireSignatureInput(1, 11,
	// content_retrieval_result_cbor) 的统一消息签名（两分支同域）。
	ArbiterContentRetrievalResultSignature []byte
	// ContentPayloadsCBOR 仅 available 分支存在：exact content_payloads_cbor
	// attachment，经签名的 content_payloads_id 绑定；unavailable 分支禁止携带。
	ContentPayloadsCBOR []byte
}

// DecodedContentRetrievalResult is the typed view of a strictly decoded
// content_retrieval_result_cbor.
type DecodedContentRetrievalResult struct {
	// ContentRetrievalRequestID 必须等于 SHA-256(exact Kind 10 请求文档)，绑定本应答对应的请求。
	ContentRetrievalRequestID protocol.ContentRetrievalRequestID
	// Result 是分支判别值：0 unavailable / 1 available；未知值在严格解码时拒绝。
	Result ContentRetrievalResult
	// UnavailableReason 仅 Result == unavailable 时有意义：
	// 0 seller_arbitration_not_received / 1 not_ready / 2 custody_gone。
	UnavailableReason ContentRetrievalUnavailableReason
	// ContentPayloadsID 仅 Result == available 时有意义：
	// SHA-256(exact content_payloads_cbor)，逐字节绑定附件批次。
	ContentPayloadsID protocol.ContentPayloadsID
}

// VerifiedContentRetrievalResult is the deep-copied outcome of verifying one
// Kind 11 against the exact Kind 10 it answers.
type VerifiedContentRetrievalResult struct {
	// ContentRetrievalRequestID 是已验证绑定的请求 ID（等于买方请求文档哈希）。
	ContentRetrievalRequestID protocol.ContentRetrievalRequestID
	// Available 报告分支结果：true 为可交付；false 表示 unavailable 分支，
	// 此时 Payloads/PayloadsCBOR 均为空且不产生任何付款状态变化。
	Available bool
	// PayloadsCBOR 是 exact content_payloads_cbor 字节；仅 available 分支非空。
	PayloadsCBOR []byte
	// Payloads 是按授权顺序深拷贝的 payload 内容；仅 available 分支非空。
	Payloads [][]byte
}

// VerifiedCustodiedContent is the deep-copied result of fully verifying one
// stored custody record pair (Kind 8 + Kind 9). It is time-independent:
// expired deadlines or matured refunds never invalidate already signed custody
// evidence that is still inside its application retention window.
type VerifiedCustodiedContent struct {
	// ArbitrationClaimID 是重算并与回执比对一致的托管 Claim 身份。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// PayloadsCBOR 是从托管 Kind 8 证据字节派生的唯一 payload 真值。
	PayloadsCBOR []byte
	// Payloads 是按授权顺序深拷贝的 payload 内容。
	Payloads [][]byte
	// Receipt 是已验证的 Kind 9 回执（Claim ID、正费用与交易签名绑定）。
	Receipt *ArbitrationReceipt
	// Request 是存储的 exact Kind 8 证据（深拷贝，只读使用）。
	Request *ArbitrationRequest
	// Response 是存储的 exact Kind 9 证据（深拷贝，只读使用）。
	Response *ArbitrationResponse
}

// EncodeContentRetrievalRequestDocument returns the exact canonical child
// document [arbitration_claim_id, retrieval_nonce] after enforcing both field
// constraints.
func EncodeContentRetrievalRequestDocument(claimID protocol.ArbitrationClaimID, nonce []byte) ([]byte, error) {
	if claimID.IsZero() {
		return nil, fmt.Errorf("%w: content retrieval Claim ID", protocol.ErrZeroIdentifier)
	}
	if err := validateRetrievalNonce(nonce); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{bstr(claimID[:]), bstr(nonce)})
}

// DecodeContentRetrievalRequestDocument strictly decodes the child document
// and returns deep copies of its Claim ID and nonce.
func DecodeContentRetrievalRequestDocument(data []byte) (protocol.ArbitrationClaimID, []byte, error) {
	if err := requireWireSize(data, maxContentRetrievalRequestDocBytes, "content retrieval request document"); err != nil {
		return protocol.ArbitrationClaimID{}, nil, err
	}
	values, err := decodeArray(data, 2)
	if err != nil {
		return protocol.ArbitrationClaimID{}, nil, fmt.Errorf("%w: decode content retrieval request document: %v", pool.ErrInvalidEvidence, err)
	}
	var claimIDBytes, nonce []byte
	if err := arbitrationDec.Unmarshal(values[0], &claimIDBytes); err != nil {
		return protocol.ArbitrationClaimID{}, nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &nonce); err != nil {
		return protocol.ArbitrationClaimID{}, nil, err
	}
	claimID := claimIDBytes
	if len(claimID) != sha256.Size {
		return protocol.ArbitrationClaimID{}, nil, fmt.Errorf("%w: content retrieval Claim ID must be 32 bytes", pool.ErrInvalidEvidence)
	}
	if err := validateRetrievalNonce(nonce); err != nil {
		return protocol.ArbitrationClaimID{}, nil, err
	}
	var typedClaimID protocol.ArbitrationClaimID
	copy(typedClaimID[:], claimID)
	canonical, err := EncodeContentRetrievalRequestDocument(typedClaimID, nonce)
	if err != nil {
		return protocol.ArbitrationClaimID{}, nil, err
	}
	if !bytes.Equal(canonical, data) {
		return protocol.ArbitrationClaimID{}, nil, fmt.Errorf("%w: content retrieval request document is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return typedClaimID, append([]byte(nil), nonce...), nil
}

// NewContentRetrievalRequest builds and signs a complete Kind 10 through the
// unified SignWireDocument(1, 10, ...) helper and self-verifies the result.
// The nonce must be 32 bytes of cryptographic randomness generated by the
// calling application.
func NewContentRetrievalRequest(claimID protocol.ArbitrationClaimID, nonce []byte, buyerKey *ec.PrivateKey) (*ContentRetrievalRequest, error) {
	if buyerKey == nil {
		return nil, errors.New("buyer private key is required")
	}
	requestCBOR, err := EncodeContentRetrievalRequestDocument(claimID, nonce)
	if err != nil {
		return nil, err
	}
	signature, err := protocol.SignWireDocument(buyerKey, protocol.WireVersion, wireKindContentRetrievalRequest, requestCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign content retrieval request: %w", err)
	}
	request := &ContentRetrievalRequest{ContentRetrievalRequestCBOR: append([]byte(nil), requestCBOR...), BuyerContentRetrievalRequestSignature: append([]byte(nil), signature...)}
	if _, err := MarshalContentRetrievalRequest(request); err != nil {
		return nil, err
	}
	return request, nil
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

// ValidateContentRetrievalRequest enforces the fixed Kind 10 shapes: a
// canonical 32-byte Claim ID plus non-zero nonce inside the child document,
// and a bounded DER signature over exactly that document.
func ValidateContentRetrievalRequest(request *ContentRetrievalRequest) error {
	if request == nil || len(request.ContentRetrievalRequestCBOR) == 0 || len(request.BuyerContentRetrievalRequestSignature) == 0 {
		return fmt.Errorf("%w: content retrieval request is incomplete", pool.ErrInvalidEvidence)
	}
	if _, _, err := DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR); err != nil {
		return err
	}
	if len(request.BuyerContentRetrievalRequestSignature) < MinContentRetrievalSignatureBytes || len(request.BuyerContentRetrievalRequestSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: buyer retrieval signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	return nil
}

// MarshalContentRetrievalRequest encodes the canonical four-element Kind 10.
func MarshalContentRetrievalRequest(request *ContentRetrievalRequest) ([]byte, error) {
	if err := ValidateContentRetrievalRequest(request); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{protocol.WireVersion, wireKindContentRetrievalRequest, bstr(request.ContentRetrievalRequestCBOR), bstr(request.BuyerContentRetrievalRequestSignature)})
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
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content retrieval request: %v", pool.ErrInvalidEvidence, err)
	}
	request := new(ContentRetrievalRequest)
	var version, kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, fmt.Errorf("%w: unsupported content retrieval request wire version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != wireKindContentRetrievalRequest {
		return nil, fmt.Errorf("%w: content retrieval request kind must be 10", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.ContentRetrievalRequestCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.BuyerContentRetrievalRequestSignature); err != nil {
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

// EncodeContentRetrievalResultDocument builds the exact canonical
// content_retrieval_result_cbor for either branch. The discriminator decides
// the meaning of the third element; callers cannot mix branches.
func EncodeContentRetrievalResultDocument(requestID protocol.ContentRetrievalRequestID, result ContentRetrievalResult, branchValue []byte) ([]byte, error) {
	if requestID.IsZero() {
		return nil, fmt.Errorf("%w: content_retrieval_request_id", protocol.ErrZeroIdentifier)
	}
	switch result {
	case ContentRetrievalUnavailable:
		if len(branchValue) != 1 {
			return nil, fmt.Errorf("%w: unavailable branch requires the reason scalar", pool.ErrInvalidEvidence)
		}
		reason := ContentRetrievalUnavailableReason(branchValue[0])
		switch reason {
		case RetrievalSellerArbitrationNotReceived, RetrievalSellerArbitrationNotReady, RetrievalCustodyGone:
		default:
			return nil, fmt.Errorf("%w: unknown content retrieval unavailable reason %d", pool.ErrInvalidEvidence, reason)
		}
		return arbitrationEnc.Marshal([]any{bstr(requestID[:]), uint64(result), uint64(reason)})
	case ContentRetrievalAvailable:
		if len(branchValue) != sha256.Size {
			return nil, fmt.Errorf("%w: available branch requires the 32-byte content_payloads_id", pool.ErrInvalidEvidence)
		}
		return arbitrationEnc.Marshal([]any{bstr(requestID[:]), uint64(result), bstr(branchValue)})
	default:
		return nil, fmt.Errorf("%w: unknown content retrieval result %d", pool.ErrInvalidEvidence, result)
	}
}

// DecodeContentRetrievalResultDocument strictly decodes a
// content_retrieval_result_cbor. The discriminator is read before anything
// else; unknown results and wrong shapes are rejected without presence
// guessing.
func DecodeContentRetrievalResultDocument(data []byte) (*DecodedContentRetrievalResult, error) {
	if err := requireWireSize(data, maxContentRetrievalResultDocBytes, "content retrieval result document"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content retrieval result document: %v", pool.ErrInvalidEvidence, err)
	}
	result := new(DecodedContentRetrievalResult)
	if err := arbitrationDec.Unmarshal(values[0], &result.ContentRetrievalRequestID); err != nil {
		return nil, err
	}
	if len(result.ContentRetrievalRequestID) != sha256.Size {
		return nil, fmt.Errorf("%w: content_retrieval_request_id must be 32 bytes", pool.ErrInvalidEvidence)
	}
	var discriminator uint64
	if err := arbitrationDec.Unmarshal(values[1], &discriminator); err != nil {
		return nil, err
	}
	switch ContentRetrievalResult(discriminator) {
	case ContentRetrievalUnavailable:
		var reason uint64
		if err := arbitrationDec.Unmarshal(values[2], &reason); err != nil {
			return nil, err
		}
		switch ContentRetrievalUnavailableReason(reason) {
		case RetrievalSellerArbitrationNotReceived, RetrievalSellerArbitrationNotReady, RetrievalCustodyGone:
		default:
			return nil, fmt.Errorf("%w: unknown content retrieval unavailable reason %d", pool.ErrInvalidEvidence, reason)
		}
		result.Result = ContentRetrievalUnavailable
		result.UnavailableReason = ContentRetrievalUnavailableReason(reason)
	case ContentRetrievalAvailable:
		var payloadsIDBytes []byte
		if err := arbitrationDec.Unmarshal(values[2], &payloadsIDBytes); err != nil {
			return nil, err
		}
		if len(payloadsIDBytes) != sha256.Size {
			return nil, fmt.Errorf("%w: content_payloads_id must be 32 bytes", pool.ErrInvalidEvidence)
		}
		copy(result.ContentPayloadsID[:], payloadsIDBytes)
		result.Result = ContentRetrievalAvailable
	default:
		return nil, fmt.Errorf("%w: unknown content retrieval result %d", pool.ErrInvalidEvidence, discriminator)
	}
	canonical, err := EncodeContentRetrievalResultDocument(result.ContentRetrievalRequestID, result.Result, branchValueForResult(result))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: content retrieval result document is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	// ContentRetrievalRequestID / ContentPayloadsID 均为值类型数组，无需再深拷贝。
	return result, nil
}

func branchValueForResult(result *DecodedContentRetrievalResult) []byte {
	if result.Result == ContentRetrievalUnavailable {
		return []byte{byte(result.UnavailableReason)}
	}
	return result.ContentPayloadsID[:]
}

// BuildContentRetrievalUnavailable constructs and signs the negative Kind 11
// branch. The caller supplies only the structurally valid request ID and the
// honest reason; the signed response carries no Claim, role key, payload, or
// record metadata.
func BuildContentRetrievalUnavailable(requestID protocol.ContentRetrievalRequestID, reason ContentRetrievalUnavailableReason, arbiterKey *ec.PrivateKey) (*ContentRetrievalResponse, error) {
	return buildContentRetrievalResult(requestID, ContentRetrievalUnavailable, []byte{byte(reason)}, nil, arbiterKey)
}

// BuildContentRetrievalAvailable constructs and signs the positive Kind 11
// branch. The payload bundle is canonically encoded here so the signed
// content_payloads_id always binds the exact attached bytes.
func BuildContentRetrievalAvailable(requestID protocol.ContentRetrievalRequestID, payloads [][]byte, arbiterKey *ec.PrivateKey) (*ContentRetrievalResponse, error) {
	payloadsCBOR, err := bitfs.EncodeContentPayloads(payloads)
	if err != nil {
		return nil, err
	}
	payloadsID := sha256.Sum256(payloadsCBOR)
	return buildContentRetrievalResult(requestID, ContentRetrievalAvailable, payloadsID[:], payloadsCBOR, arbiterKey)
}

// BuildContentRetrievalAvailableRaw is the raw-bytes variant of
// BuildContentRetrievalAvailable for applications that persist the exact
// canonical payload bundle. The bundle must already be canonical.
func BuildContentRetrievalAvailableRaw(requestID protocol.ContentRetrievalRequestID, payloadsCBOR []byte, arbiterKey *ec.PrivateKey) (*ContentRetrievalResponse, error) {
	if _, err := bitfs.DecodeContentPayloads(payloadsCBOR); err != nil {
		return nil, err
	}
	payloadsID := sha256.Sum256(payloadsCBOR)
	return buildContentRetrievalResult(requestID, ContentRetrievalAvailable, payloadsID[:], append([]byte(nil), payloadsCBOR...), arbiterKey)
}

func buildContentRetrievalResult(requestID protocol.ContentRetrievalRequestID, result ContentRetrievalResult, branchValue, payloadsCBOR []byte, arbiterKey *ec.PrivateKey) (*ContentRetrievalResponse, error) {
	if arbiterKey == nil {
		return nil, errors.New("arbiter private key is required")
	}
	resultCBOR, err := EncodeContentRetrievalResultDocument(requestID, result, branchValue)
	if err != nil {
		return nil, err
	}
	signature, err := protocol.SignWireDocument(arbiterKey, protocol.WireVersion, wireKindContentRetrievalResponse, resultCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign content retrieval result: %w", err)
	}
	response := &ContentRetrievalResponse{
		ContentRetrievalResultCBOR:             append([]byte(nil), resultCBOR...),
		ArbiterContentRetrievalResultSignature: append([]byte(nil), signature...),
	}
	if payloadsCBOR != nil {
		response.ContentPayloadsCBOR = append([]byte(nil), payloadsCBOR...)
	}
	if _, err := MarshalContentRetrievalResponse(response); err != nil {
		return nil, err
	}
	return response, nil
}

// ValidateContentRetrievalResponse enforces branch-consistent structure: the
// discriminator inside ContentRetrievalResultCBOR decides whether an attachment may exist.
func ValidateContentRetrievalResponse(response *ContentRetrievalResponse) error {
	if response == nil || len(response.ContentRetrievalResultCBOR) == 0 || len(response.ArbiterContentRetrievalResultSignature) == 0 {
		return fmt.Errorf("%w: content retrieval response is incomplete", pool.ErrInvalidEvidence)
	}
	decoded, err := DecodeContentRetrievalResultDocument(response.ContentRetrievalResultCBOR)
	if err != nil {
		return err
	}
	switch decoded.Result {
	case ContentRetrievalUnavailable:
		if response.ContentPayloadsCBOR != nil {
			return fmt.Errorf("%w: unavailable branch must not carry content payloads", pool.ErrInvalidEvidence)
		}
	case ContentRetrievalAvailable:
		if len(response.ContentPayloadsCBOR) == 0 {
			return fmt.Errorf("%w: available branch requires content payloads", pool.ErrInvalidEvidence)
		}
		if _, err := bitfs.DecodeContentPayloads(response.ContentPayloadsCBOR); err != nil {
			return err
		}
	}
	return nil
}

// MarshalContentRetrievalResponse encodes the canonical Kind 11 for whichever
// branch ContentRetrievalResultCBOR declares.
func MarshalContentRetrievalResponse(response *ContentRetrievalResponse) ([]byte, error) {
	if err := ValidateContentRetrievalResponse(response); err != nil {
		return nil, err
	}
	fields := []any{protocol.WireVersion, wireKindContentRetrievalResponse, bstr(response.ContentRetrievalResultCBOR), bstr(response.ArbiterContentRetrievalResultSignature)}
	decoded, err := DecodeContentRetrievalResultDocument(response.ContentRetrievalResultCBOR)
	if err != nil {
		return nil, err
	}
	if decoded.Result == ContentRetrievalAvailable {
		fields = append(fields, bstr(response.ContentPayloadsCBOR))
	}
	raw, err := arbitrationEnc.Marshal(fields)
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxContentRetrievalResponseBytes, "content retrieval response"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalContentRetrievalResponse strictly decodes Kind 11 bytes. It checks
// the size limit first, then the outer version/kind pair, then reads the
// branch discriminator from ContentRetrievalResultCBOR before accepting the unique outer
// length for that branch. Any mismatch, trailing field, unknown reason, or
// non-canonical encoding is rejected.
func UnmarshalContentRetrievalResponse(data []byte) (*ContentRetrievalResponse, error) {
	if err := requireWireSize(data, MaxContentRetrievalResponseBytes, "content retrieval response"); err != nil {
		return nil, err
	}
	rawValues, err := decodePoolStyleArray(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content retrieval response: %v", pool.ErrInvalidEvidence, err)
	}
	if len(rawValues) < 4 || len(rawValues) > 5 {
		return nil, fmt.Errorf("%w: content retrieval response array length is %d, want 4 or 5", pool.ErrInvalidEvidence, len(rawValues))
	}
	response := new(ContentRetrievalResponse)
	var version, kind uint64
	if err := arbitrationDec.Unmarshal(rawValues[0], &version); err != nil || version != protocol.WireVersion {
		return nil, fmt.Errorf("%w: unsupported content retrieval response wire version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(rawValues[1], &kind); err != nil || kind != wireKindContentRetrievalResponse {
		return nil, fmt.Errorf("%w: content retrieval response kind must be 11", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(rawValues[2], &response.ContentRetrievalResultCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(rawValues[3], &response.ArbiterContentRetrievalResultSignature); err != nil {
		return nil, err
	}
	// 先严格解码判别值，再选择该分支唯一合法的外层长度。
	decoded, err := DecodeContentRetrievalResultDocument(response.ContentRetrievalResultCBOR)
	if err != nil {
		return nil, err
	}
	switch decoded.Result {
	case ContentRetrievalUnavailable:
		if len(rawValues) != 4 {
			return nil, fmt.Errorf("%w: unavailable branch must not carry attachments", pool.ErrInvalidEvidence)
		}
	case ContentRetrievalAvailable:
		if len(rawValues) != 5 {
			return nil, fmt.Errorf("%w: available branch requires the content payload attachment", pool.ErrInvalidEvidence)
		}
		if err := arbitrationDec.Unmarshal(rawValues[4], &response.ContentPayloadsCBOR); err != nil {
			return nil, err
		}
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

// decodePoolStyleArray mirrors decodeArray but tolerates the two legal outer
// lengths so the branch discriminator can be examined before final shape
// enforcement.
func decodePoolStyleArray(data []byte) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := arbitrationDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	return values, nil
}

// VerifyContentRetrievalResponse verifies one Kind 11 against the exact Kind
// 10 request it answers: the signed request ID must equal
// SHA-256(exact_request_cbor), the arbiter signature must verify through the
// unified helper over the exact result document, and the available branch must
// additionally bind its payload attachment through content_payloads_id. It
// performs no clock read and no payment state change.
func VerifyContentRetrievalResponse(request *ContentRetrievalRequest, arbiterPublicKey []byte, response *ContentRetrievalResponse) (*VerifiedContentRetrievalResult, error) {
	if err := ValidateContentRetrievalRequest(request); err != nil {
		return nil, err
	}
	if err := ValidateContentRetrievalResponse(response); err != nil {
		return nil, err
	}
	requestID := protocol.ContentRetrievalRequestID(sha256.Sum256(request.ContentRetrievalRequestCBOR))
	decoded, err := DecodeContentRetrievalResultDocument(response.ContentRetrievalResultCBOR)
	if err != nil {
		return nil, err
	}
	if decoded.ContentRetrievalRequestID != requestID {
		return nil, fmt.Errorf("%w: content retrieval result does not answer the supplied request", pool.ErrInvalidEvidence)
	}
	if err := protocol.VerifyWireDocument(arbiterPublicKey, protocol.WireVersion, wireKindContentRetrievalResponse, response.ContentRetrievalResultCBOR, response.ArbiterContentRetrievalResultSignature); err != nil {
		return nil, fmt.Errorf("%w: arbiter content retrieval result signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	verified := &VerifiedContentRetrievalResult{ContentRetrievalRequestID: requestID}
	if decoded.Result == ContentRetrievalUnavailable {
		return verified, nil
	}
	payloadsID := sha256.Sum256(response.ContentPayloadsCBOR)
	if protocol.ContentPayloadsID(payloadsID) != decoded.ContentPayloadsID {
		return nil, fmt.Errorf("%w: content payloads do not match the signed content_payloads_id", pool.ErrInvalidEvidence)
	}
	payloads, err := bitfs.DecodeContentPayloads(response.ContentPayloadsCBOR)
	if err != nil {
		return nil, err
	}
	verified.Available = true
	verified.PayloadsCBOR = append([]byte(nil), response.ContentPayloadsCBOR...)
	verified.Payloads = cloneByteSlices(payloads)
	return verified, nil
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
	receipt, err := UnmarshalReceipt(localResponse.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	claim, _, payloads, unsigned, claimID, _, keys, err := validateRequestEvidence(localRequest, receipt.ArbiterAmountSatoshis)
	if err != nil {
		return nil, err
	}
	if receipt.ArbitrationClaimID != claimID {
		return nil, fmt.Errorf("%w: receipt Claim ID does not match the custody Claim ID", pool.ErrInvalidEvidence)
	}
	if err := protocol.VerifyWireDocument(keys.ArbiterPublicKey, protocol.WireVersion, wireKindArbitrationResponse, localResponse.ArbitrationReceiptCBOR, localResponse.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, fmt.Errorf("%w: arbiter receipt signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, receipt.ArbiterPaymentTransactionSignature); err != nil {
		return nil, fmt.Errorf("%w: arbiter transaction signature invalid over the rebuilt candidate: %v", pool.ErrInvalidEvidence, err)
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

// AuthenticateContentRetrievalRequest 只依赖已持久化的 Kind 8 完成 Buyer 鉴权，
// 不要求 Kind 9 已存在。它用于 not_ready / gone 分支：先从 Claim 的资金池锁定
// 脚本恢复角色公钥，确认 Claim 归属本 Arbiter，再通过统一 helper 验证 Buyer
// 对精确 content_retrieval_request_cbor 的签名。任何其他 Claim ID、nonce 或
// Kind 域下的有效签名都不可能通过。
func (workflow *Workflow) AuthenticateContentRetrievalRequest(retrievalRequest *ContentRetrievalRequest, storedArbitrationRequest *ArbitrationRequest) error {
	if workflow == nil {
		return errors.New("arbitration workflow is required")
	}
	localRetrieval := cloneRetrievalRequest(retrievalRequest)
	if err := ValidateContentRetrievalRequest(localRetrieval); err != nil {
		return err
	}
	localStored := cloneRequest(storedArbitrationRequest)
	if err := ValidateRequest(localStored); err != nil {
		return err
	}
	claim, err := UnmarshalClaim(localStored.ArbitrationClaimCBOR)
	if err != nil {
		return err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return err
	}
	if !bytes.Equal(keys.ArbiterPublicKey, workflow.publicKey) {
		return fmt.Errorf("%w: custody Claim names another arbiter", pool.ErrInvalidEvidence)
	}
	storedClaimID, err := ArbitrationClaimID(localStored.ArbitrationClaimCBOR)
	if err != nil {
		return err
	}
	requestClaimID, _, err := DecodeContentRetrievalRequestDocument(localRetrieval.ContentRetrievalRequestCBOR)
	if err != nil {
		return err
	}
	if requestClaimID != storedClaimID {
		return fmt.Errorf("%w: retrieval Claim ID does not match the custody record", pool.ErrInvalidEvidence)
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, wireKindContentRetrievalRequest, localRetrieval.ContentRetrievalRequestCBOR, localRetrieval.BuyerContentRetrievalRequestSignature); err != nil {
		return fmt.Errorf("%w: buyer retrieval signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	return nil
}

// VerifyContentRetrievalRequest authenticates one Kind 10 against a stored
// custody record pair: full custody evidence verification first, then the same
// claim-binding and buyer-signature checks as
// AuthenticateContentRetrievalRequest over the verified evidence.
func (workflow *Workflow) VerifyContentRetrievalRequest(retrievalRequest *ContentRetrievalRequest, storedArbitrationRequest *ArbitrationRequest, storedArbitrationResponse *ArbitrationResponse) (*VerifiedCustodiedContent, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	localRetrieval := cloneRetrievalRequest(retrievalRequest)
	if err := ValidateContentRetrievalRequest(localRetrieval); err != nil {
		return nil, err
	}
	verified, err := VerifyCustodiedContent(storedArbitrationRequest, storedArbitrationResponse)
	if err != nil {
		return nil, err
	}
	if err := workflow.AuthenticateContentRetrievalRequest(localRetrieval, verified.Request); err != nil {
		return nil, err
	}
	return verified, nil
}

func cloneRetrievalRequest(request *ContentRetrievalRequest) *ContentRetrievalRequest {
	if request == nil {
		return nil
	}
	return &ContentRetrievalRequest{ContentRetrievalRequestCBOR: append([]byte(nil), request.ContentRetrievalRequestCBOR...), BuyerContentRetrievalRequestSignature: append([]byte(nil), request.BuyerContentRetrievalRequestSignature...)}
}

func cloneRetrievalResponse(response *ContentRetrievalResponse) *ContentRetrievalResponse {
	if response == nil {
		return nil
	}
	cloned := &ContentRetrievalResponse{ContentRetrievalResultCBOR: append([]byte(nil), response.ContentRetrievalResultCBOR...), ArbiterContentRetrievalResultSignature: append([]byte(nil), response.ArbiterContentRetrievalResultSignature...)}
	if response.ContentPayloadsCBOR != nil {
		cloned.ContentPayloadsCBOR = append([]byte(nil), response.ContentPayloadsCBOR...)
	}
	return cloned
}
