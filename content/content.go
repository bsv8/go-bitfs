package content

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/protocol"
)

// Kind 5/Kind 6 wire kind values for the unified signature context.
const (
	contentRequestWireKind  = uint64(5)
	contentDeliveryWireKind = uint64(6)
)

// UnixSeconds is the protocol's UTC Unix-seconds representation.
type UnixSeconds int64

// PaymentAuthorization is the unsigned, signed-bytes portion of the canonical
// Kind 5 ContentRequest: the buyer's final payment authorization. It carries
// no public keys or fee rates: those are uniquely determined by
// RefundTemplateTxID's OpeningProof, and the quote is selected by
// FileQuoteTermsID alone.
type PaymentAuthorization struct {
	// FileQuoteTermsID 选择本授权购买的报价（SHA-256(exact
	// file_quote_terms_cbor)，32 字节）；全零哨兵不得上线。
	FileQuoteTermsID protocol.FileQuoteTermsID
	// RefundTemplateTxID 选择费用池并经其不可变的 OpeningProof 唯一确定
	// 买/卖/仲裁三方角色与费率（32 字节，按交易 TxID 算法派生）。
	RefundTemplateTxID []byte
	// PaymentSequence 是本次授权的目标付款状态序号；接收方验证它恰好等于
	// previous + 1，范围 1..4294967294。
	PaymentSequence uint32
	// SellerAmountAfterSatoshis 是批次付款后卖方的绝对累计金额（单位
	// satoshi），绝不是本批增量。
	SellerAmountAfterSatoshis uint64
	// ContentHashesCBOR 是确定性 CBOR 子文档：1..64 个有序且不重复的
	// 32 字节内容哈希，与 payload 批次顺序一一对应。
	ContentHashesCBOR []byte
	// DeliveryDeadlineUnixSeconds 是交付截止时间（UTC Unix 秒，int64）；
	// 必须为正数且不超过报价有效期。
	DeliveryDeadlineUnixSeconds int64
}

// SignedContentRequest is the complete Kind 5 ContentRequest wire message:
// the canonical payment_authorization_cbor plus the buyer signature over
// WireSignatureInput(1, 5, payment_authorization_cbor).
type SignedContentRequest struct {
	// PaymentAuthorizationCBOR 是 exact 规范付款授权字节（确定性 CBOR），
	// 也是 payment_authorization_id = SHA-256(...) 的计算来源。
	PaymentAuthorizationCBOR []byte
	// BuyerPaymentAuthorizationSignature 是买方对 WireSignatureInput(1, 5,
	// payment_authorization_cbor) 的 low-S DER 统一消息签名。
	BuyerPaymentAuthorizationSignature []byte
}

// SignedContentDelivery is the complete Kind 6 ContentDelivery wire message.
// The seller signature covers exactly content_delivery_cbor through the
// unified SignWireDocument(1, 6, ...) helper; payloads are bound indirectly
// via the hashes committed in the referenced payment authorization and are
// carried as the trailing attachment.
type SignedContentDelivery struct {
	// ContentDeliveryCBOR 是确定性 CBOR 认证文档 [payment_authorization_id]，
	// 把交付钉死到一次授权；它也是应用路由 004 到本地原始 003 的索引来源。
	ContentDeliveryCBOR []byte
	// SellerContentDeliverySignature 是卖方对精确 content_delivery_cbor 的
	// 统一普通消息签名（SignWireDocument(1, 6, ...)）。它不覆盖 payload。
	SellerContentDeliverySignature []byte
	// ContentPayloadsCBOR 是确定性 CBOR 子文档，按顺序承载与 003 哈希一一对应
	// 的 payload 数组；作为 attachment 不进入签名预映像。
	ContentPayloadsCBOR []byte
}

// invalidEvidence 构造本包统一的 invalid_evidence 结构化错误。
func invalidEvidence(op string, cause error) error {
	return protocol.Wrap(cause, op, protocol.CodeInvalidEvidence, 0, "")
}

// malformed 构造本包统一的 malformed_wire 结构化错误。
func malformed(op string, field string, cause error) error {
	return protocol.Wrap(cause, op, protocol.CodeMalformedWire, 0, field)
}

// EncodeContentHashes returns the sole canonical representation of the 003
// content_hashes child document: an array of 1..MaxContentBatchItems unique,
// ordered 32-byte hashes encoded as a deterministic CBOR byte string.
func EncodeContentHashes(hashes [][]byte) ([]byte, error) {
	if err := validateContentHashes(hashes); err != nil {
		return nil, invalidEvidence("content.EncodeContentHashes", err)
	}
	return canonicalEnc.Marshal(cloneByteSlices(hashes))
}

// DecodeContentHashes strictly decodes the content_hashes child document. It
// rejects indefinite lengths, tags, trailing data, non-canonical encodings,
// wrong counts, wrong hash widths, duplicates, and reordering attempts by
// requiring byte equality with the deterministic re-encoding. The returned
// slices are deep copies owned by the caller.
func DecodeContentHashes(raw []byte) ([][]byte, error) {
	const op = "content.DecodeContentHashes"
	var hashes [][]byte
	if err := strictDec.Unmarshal(raw, &hashes); err != nil {
		return nil, malformed(op, "content_hashes_cbor", err)
	}
	if err := validateContentHashes(hashes); err != nil {
		return nil, invalidEvidence(op, err)
	}
	canonical, err := canonicalEnc.Marshal(hashes)
	if err != nil {
		return nil, malformed(op, "content_hashes_cbor", err)
	}
	if !bytes.Equal(canonical, raw) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 0, "content_hashes_cbor", "content hashes are not deterministically encoded")
	}
	return cloneByteSlices(hashes), nil
}

// EncodeContentPayloads returns the sole canonical representation of the 004
// content_payloads child document: an array of 1..MaxContentBatchItems
// non-empty payloads, each at most masterseed.BlockSize bytes.
func EncodeContentPayloads(payloads [][]byte) ([]byte, error) {
	if err := validateContentPayloads(payloads); err != nil {
		return nil, invalidEvidence("content.EncodeContentPayloads", err)
	}
	return canonicalEnc.Marshal(cloneByteSlices(payloads))
}

// DecodeContentPayloads strictly decodes the content_payloads child document
// with the same canonicality rules as DecodeContentHashes, plus per-item
// non-empty and maximum-length checks. Inputs above MaxContentPayloadsCBORBytes
// are rejected before decoding so a hostile length cannot bypass the item
// count limit. The returned slices are deep copies owned by the caller.
func DecodeContentPayloads(raw []byte) ([][]byte, error) {
	const op = "content.DecodeContentPayloads"
	if len(raw) == 0 || len(raw) > MaxContentPayloadsCBORBytes {
		return nil, invalidEvidence(op, fmt.Errorf("content payloads exceed the protocol size limit"))
	}
	var payloads [][]byte
	if err := strictDec.Unmarshal(raw, &payloads); err != nil {
		return nil, malformed(op, "content_payloads_cbor", err)
	}
	if err := validateContentPayloads(payloads); err != nil {
		return nil, invalidEvidence(op, err)
	}
	canonical, err := canonicalEnc.Marshal(payloads)
	if err != nil {
		return nil, malformed(op, "content_payloads_cbor", err)
	}
	if !bytes.Equal(canonical, raw) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 0, "content_payloads_cbor", "content payloads are not deterministically encoded")
	}
	return cloneByteSlices(payloads), nil
}

func validateContentHashes(hashes [][]byte) error {
	if len(hashes) == 0 || len(hashes) > MaxContentBatchItems {
		return fmt.Errorf("content hash count must be between 1 and %d", MaxContentBatchItems)
	}
	for index, hash := range hashes {
		if len(hash) != sha256.Size {
			return fmt.Errorf("content hash #%d must be %d bytes", index+1, sha256.Size)
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(hashes[previous], hash) {
				return fmt.Errorf("content hash #%d duplicates #%d", index+1, previous+1)
			}
		}
	}
	return nil
}

func validateContentPayloads(payloads [][]byte) error {
	if len(payloads) == 0 || len(payloads) > MaxContentBatchItems {
		return fmt.Errorf("content payload count must be between 1 and %d", MaxContentBatchItems)
	}
	for index, payload := range payloads {
		if len(payload) == 0 {
			return fmt.Errorf("content payload #%d must not be empty", index+1)
		}
		if uint64(len(payload)) > masterseed.BlockSize {
			return fmt.Errorf("content payload #%d exceeds %d bytes", index+1, masterseed.BlockSize)
		}
	}
	return nil
}

// EncodeContentDeliveryDocument returns the exact canonical one-element
// content_delivery_cbor authentication document: [payment_authorization_id].
func EncodeContentDeliveryDocument(paymentAuthorizationID protocol.PaymentAuthorizationID) ([]byte, error) {
	if paymentAuthorizationID.IsZero() {
		return nil, protocol.Errorf("content.EncodeContentDeliveryDocument", protocol.CodeInvalidEvidence, 0, "payment_authorization_id", "%w", protocol.ErrZeroIdentifier)
	}
	return canonicalEnc.Marshal([]any{bstr(paymentAuthorizationID[:])})
}

// EncodePaymentAuthorization returns the exact deterministic CBOR bytes signed
// by the buyer for a Kind 5 request: the six-element business-field array.
func EncodePaymentAuthorization(authorization *PaymentAuthorization) ([]byte, error) {
	if err := ValidatePaymentAuthorization(authorization); err != nil {
		return nil, invalidEvidence("content.EncodePaymentAuthorization", err)
	}
	return canonicalEnc.Marshal([]any{
		bstr(authorization.FileQuoteTermsID[:]),
		bstr(authorization.RefundTemplateTxID),
		authorization.PaymentSequence,
		authorization.SellerAmountAfterSatoshis,
		bstr(authorization.ContentHashesCBOR),
		authorization.DeliveryDeadlineUnixSeconds,
	})
}

// DecodePaymentAuthorization accepts only canonical six-element Kind 5
// authentication documents. Legacy versions, inner kinds, single-hash
// requests, missing or extra fields, and non-canonical encodings all return a
// structured malformed_wire/non_canonical/invalid_evidence error.
func DecodePaymentAuthorization(data []byte) (*PaymentAuthorization, error) {
	const op = "content.DecodePaymentAuthorization"
	values, err := decodeArray(data, 6)
	if err != nil {
		return nil, malformed(op, "payment_authorization_cbor", err)
	}
	authorization := new(PaymentAuthorization)
	var fileQuoteTermsID []byte
	if err := decode(values[0], &fileQuoteTermsID); err != nil {
		return nil, malformed(op, "file_quote_terms_id", err)
	}
	if len(fileQuoteTermsID) != sha256.Size {
		return nil, protocol.Errorf(op, protocol.CodeMalformedWire, 0, "file_quote_terms_id", "must be 32 bytes")
	}
	copy(authorization.FileQuoteTermsID[:], fileQuoteTermsID)
	if err := decode(values[1], &authorization.RefundTemplateTxID); err != nil {
		return nil, malformed(op, "refund_template_txid", err)
	}
	if err := decode(values[2], &authorization.PaymentSequence); err != nil {
		return nil, malformed(op, "payment_sequence", err)
	}
	if err := decode(values[3], &authorization.SellerAmountAfterSatoshis); err != nil {
		return nil, malformed(op, "seller_amount_after_satoshis", err)
	}
	if err := decode(values[4], &authorization.ContentHashesCBOR); err != nil {
		return nil, malformed(op, "content_hashes_cbor", err)
	}
	if err := decode(values[5], &authorization.DeliveryDeadlineUnixSeconds); err != nil {
		return nil, malformed(op, "delivery_deadline_unix_seconds", err)
	}
	if err := ValidatePaymentAuthorization(authorization); err != nil {
		return nil, invalidEvidence(op, err)
	}
	canonical, err := EncodePaymentAuthorization(authorization)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 0, "payment_authorization_cbor", "payment authorization is not deterministically encoded")
	}
	return clonePaymentAuthorization(authorization), nil
}

// PaymentAuthorizationID validates canonical payment authorization CBOR and
// returns its SHA-256 digest. It is defined exclusively over the exact
// payment_authorization_cbor and shares its namespace with that document.
func PaymentAuthorizationID(paymentAuthorizationCBOR []byte) (protocol.PaymentAuthorizationID, error) {
	id, err := rawPaymentAuthorizationID(paymentAuthorizationCBOR)
	if err != nil {
		return id, err
	}
	digest := sha256.Sum256(paymentAuthorizationCBOR)
	return protocol.PaymentAuthorizationID(digest), nil
}

// rawPaymentAuthorizationID 只做结构验证并返回零值 ID（内部辅助）。
func rawPaymentAuthorizationID(paymentAuthorizationCBOR []byte) (protocol.PaymentAuthorizationID, error) {
	if _, err := DecodePaymentAuthorization(paymentAuthorizationCBOR); err != nil {
		return protocol.PaymentAuthorizationID{}, err
	}
	return protocol.PaymentAuthorizationID{}, nil
}

// NewSignedContentRequest deterministically encodes the payment authorization
// and signs those exact bytes through the unified SignWireDocument(1, 5, ...)
// helper with the supplied constrained Signer. The signature is immediately
// self-verified against the Signer's fixed public key; the private key never
// enters any wire message, local result, log, or persisted structure.
func NewSignedContentRequest(ctx context.Context, authorization *PaymentAuthorization, signer protocol.Signer) (*SignedContentRequest, error) {
	if ctx == nil {
		return nil, protocol.Errorf("content.NewSignedContentRequest", protocol.CodeCanceled, 0, "ctx", "a non-nil context is required")
	}
	if signer == nil {
		return nil, protocol.Errorf("content.NewSignedContentRequest", protocol.CodeSignerUnavailable, 0, "signer", "buyer signer is required")
	}
	authorizationCBOR, err := EncodePaymentAuthorization(authorization)
	if err != nil {
		return nil, err
	}
	signature, err := protocol.SignWireDocument(ctx, signer, protocol.WireVersion, contentRequestWireKind, authorizationCBOR)
	if err != nil {
		return nil, err
	}
	return &SignedContentRequest{
		PaymentAuthorizationCBOR:           append([]byte(nil), authorizationCBOR...),
		BuyerPaymentAuthorizationSignature: append([]byte(nil), signature...),
	}, nil
}

// EncodeSignedContentRequest encodes the complete Kind 5 wire message:
// [1, 5, payment_authorization_cbor, buyer_payment_authorization_signature].
func EncodeSignedContentRequest(request *SignedContentRequest) ([]byte, error) {
	const op = "content.EncodeSignedContentRequest"
	if request == nil || len(request.BuyerPaymentAuthorizationSignature) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "request", "signed content request and buyer payment authorization signature are required")
	}
	if _, err := DecodePaymentAuthorization(request.PaymentAuthorizationCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		protocol.WireVersion,
		contentRequestWireKind,
		bstr(request.PaymentAuthorizationCBOR),
		bstr(request.BuyerPaymentAuthorizationSignature),
	})
}

// DecodeSignedContentRequest decodes a canonical Kind 5 wire message and
// rejects malformed array shapes, outer version/kind pairs, and byte fields
// before returning a copy.
func DecodeSignedContentRequest(data []byte) (*SignedContentRequest, error) {
	const op = "content.DecodeSignedContentRequest"
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, malformed(op, "wire", err)
	}
	request := new(SignedContentRequest)
	var version, kind uint64
	if err := decode(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedVersion, 5, "wire_version", "unsupported signed content request wire version")
	}
	if err := decode(values[1], &kind); err != nil || kind != contentRequestWireKind {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedKind, 5, "wire_kind", "signed content request wire kind must be 5")
	}
	if err := decode(values[2], &request.PaymentAuthorizationCBOR); err != nil {
		return nil, malformed(op, "payment_authorization_cbor", err)
	}
	if err := decode(values[3], &request.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, malformed(op, "buyer_payment_authorization_signature", err)
	}
	canonical, err := EncodeSignedContentRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 5, "wire", "signed content request is not deterministically encoded")
	}
	return cloneSignedContentRequest(request), nil
}

// NewSignedContentDelivery builds the one-element content_delivery_cbor over
// the referenced payment authorization ID, signs it through the unified
// SignWireDocument(1, 6, ...) helper, and attaches the canonically encoded
// payload batch. Callers must fully verify the referenced 003, the quote, the
// opening proof, and every payload before invoking this constructor.
func NewSignedContentDelivery(ctx context.Context, paymentAuthorizationID protocol.PaymentAuthorizationID, payloads [][]byte, signer protocol.Signer) (*SignedContentDelivery, error) {
	if ctx == nil {
		return nil, protocol.Errorf("content.NewSignedContentDelivery", protocol.CodeCanceled, 0, "ctx", "a non-nil context is required")
	}
	if signer == nil {
		return nil, protocol.Errorf("content.NewSignedContentDelivery", protocol.CodeSignerUnavailable, 0, "signer", "seller signer is required")
	}
	payloadsCBOR, err := EncodeContentPayloads(payloads)
	if err != nil {
		return nil, err
	}
	deliveryCBOR, err := EncodeContentDeliveryDocument(paymentAuthorizationID)
	if err != nil {
		return nil, err
	}
	signature, err := protocol.SignWireDocument(ctx, signer, protocol.WireVersion, contentDeliveryWireKind, deliveryCBOR)
	if err != nil {
		return nil, err
	}
	return &SignedContentDelivery{
		ContentDeliveryCBOR:            append([]byte(nil), deliveryCBOR...),
		SellerContentDeliverySignature: append([]byte(nil), signature...),
		ContentPayloadsCBOR:            payloadsCBOR,
	}, nil
}

// DecodeContentDeliveryDocument strictly decodes a content_delivery_cbor and
// returns the payment authorization ID it commits to.
func DecodeContentDeliveryDocument(data []byte) (protocol.PaymentAuthorizationID, error) {
	const op = "content.DecodeContentDeliveryDocument"
	values, err := decodeArray(data, 1)
	if err != nil {
		return protocol.PaymentAuthorizationID{}, malformed(op, "content_delivery_cbor", err)
	}
	var paymentAuthorizationIDBytes []byte
	if err := decode(values[0], &paymentAuthorizationIDBytes); err != nil {
		return protocol.PaymentAuthorizationID{}, malformed(op, "payment_authorization_id", err)
	}
	if len(paymentAuthorizationIDBytes) != sha256.Size {
		return protocol.PaymentAuthorizationID{}, protocol.Errorf(op, protocol.CodeMalformedWire, 0, "payment_authorization_id", "must be 32 bytes")
	}
	var paymentAuthorizationID protocol.PaymentAuthorizationID
	copy(paymentAuthorizationID[:], paymentAuthorizationIDBytes)
	if paymentAuthorizationID.IsZero() {
		return protocol.PaymentAuthorizationID{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "payment_authorization_id", "%w", protocol.ErrZeroIdentifier)
	}
	canonical, err := EncodeContentDeliveryDocument(paymentAuthorizationID)
	if err != nil {
		return protocol.PaymentAuthorizationID{}, err
	}
	if !bytes.Equal(canonical, data) {
		return protocol.PaymentAuthorizationID{}, protocol.Errorf(op, protocol.CodeNonCanonical, 0, "content_delivery_cbor", "content delivery document is not deterministically encoded")
	}
	return paymentAuthorizationID, nil
}

// EncodeSignedContentDelivery encodes the complete Kind 6 wire message:
// [1, 6, content_delivery_cbor, seller_content_delivery_signature,
// content_payloads_cbor].
func EncodeSignedContentDelivery(delivery *SignedContentDelivery) ([]byte, error) {
	const op = "content.EncodeSignedContentDelivery"
	if delivery == nil || len(delivery.SellerContentDeliverySignature) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "delivery", "signed content delivery and seller signature are required")
	}
	if _, err := DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR); err != nil {
		return nil, err
	}
	if _, err := DecodeContentPayloads(delivery.ContentPayloadsCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		protocol.WireVersion,
		contentDeliveryWireKind,
		bstr(delivery.ContentDeliveryCBOR),
		bstr(delivery.SellerContentDeliverySignature),
		bstr(delivery.ContentPayloadsCBOR),
	})
}

// DecodeSignedContentDelivery decodes canonical Kind 6 wire message bytes.
func DecodeSignedContentDelivery(data []byte) (*SignedContentDelivery, error) {
	const op = "content.DecodeSignedContentDelivery"
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, malformed(op, "wire", err)
	}
	delivery := new(SignedContentDelivery)
	var version, kind uint64
	if err := decode(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedVersion, 6, "wire_version", "unsupported signed content delivery wire version")
	}
	if err := decode(values[1], &kind); err != nil || kind != contentDeliveryWireKind {
		return nil, protocol.Errorf(op, protocol.CodeUnsupportedKind, 6, "wire_kind", "signed content delivery wire kind must be 6")
	}
	if err := decode(values[2], &delivery.ContentDeliveryCBOR); err != nil {
		return nil, malformed(op, "content_delivery_cbor", err)
	}
	if err := decode(values[3], &delivery.SellerContentDeliverySignature); err != nil {
		return nil, malformed(op, "seller_content_delivery_signature", err)
	}
	if err := decode(values[4], &delivery.ContentPayloadsCBOR); err != nil {
		return nil, malformed(op, "content_payloads_cbor", err)
	}
	canonical, err := EncodeSignedContentDelivery(delivery)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, protocol.Errorf(op, protocol.CodeNonCanonical, 6, "wire", "signed content delivery is not deterministically encoded")
	}
	return cloneSignedContentDelivery(delivery), nil
}

// PoolOpeningEvidence is the minimal opening-proof view needed to bind a 003
// to its fee pool without importing the pool package. *pool.OpeningProof
// implements it with exported helper methods.
type PoolOpeningEvidence interface {
	OpeningBuyerPublicKey() []byte
	OpeningSellerPublicKey() []byte
	OpeningArbiterPublicKey() []byte
	OpeningRefundTemplateTxID() []byte
}

// VerifySignedContentRequestForOpening verifies the pool binding and buyer
// signature of a Kind 5 against caller-supplied local opening evidence. A
// seller may use it while forming the Kind 8 Claim, but the OpeningProof is
// not part of the Kind 8 wire request. It derives the RefundTemplateTxID from
// the supplied opening, requires an exact match, and verifies the buyer
// signature through VerifyWireDocument(1, 5, ...) against the opening's buyer
// key. Quote, content, and timing facts are intentionally out of scope here.
func VerifySignedContentRequestForOpening(request *SignedContentRequest, opening PoolOpeningEvidence) (*PaymentAuthorization, error) {
	const op = "content.VerifySignedContentRequestForOpening"
	if request == nil || len(request.BuyerPaymentAuthorizationSignature) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "request", "signed content request is required")
	}
	if opening == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "opening", "opening proof is required")
	}
	authorization, err := DecodePaymentAuthorization(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	derived := opening.OpeningRefundTemplateTxID()
	if len(derived) != sha256.Size || !bytes.Equal(derived, authorization.RefundTemplateTxID) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "refund_template_txid", "content request is not bound to supplied opening proof")
	}
	if err := protocol.VerifyWireDocument(opening.OpeningBuyerPublicKey(), protocol.WireVersion, contentRequestWireKind, request.PaymentAuthorizationCBOR, request.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("buyer payment authorization signature invalid: %v", err), op, protocol.CodeInvalidSignature, 5, "buyer_payment_authorization_signature")
	}
	return authorization, nil
}

// VerifyContentRequestEvidence 是时间无关的 003 完整证据验证：报价证据与
// 卖方签名、池绑定、买方统一签名、FileQuoteTermsID 比对以及
// Buyer/Seller/Arbiter 与开池证据的绑定。它不检查报价过期或交付截止时间；
// 角色工作流用它保证整个操作只使用调用方显式传入的一份时间事实。
func VerifyContentRequestEvidence(request *SignedContentRequest, quote *SignedFileQuote, opening PoolOpeningEvidence) (*PaymentAuthorization, *FileQuoteTerms, error) {
	const op = "content.VerifyContentRequestEvidence"
	quoteTerms, err := VerifyFileQuoteEvidence(quote)
	if err != nil {
		return nil, nil, err
	}
	authorization, err := VerifySignedContentRequestForOpening(request, opening)
	if err != nil {
		return nil, nil, err
	}
	quoteID, err := FileQuoteTermsID(quote.FileQuoteTermsCBOR)
	if err != nil {
		return nil, nil, err
	}
	if authorization.FileQuoteTermsID != quoteID {
		return nil, nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "file_quote_terms_id", "request does not reference supplied quote")
	}
	if !bytes.Equal(opening.OpeningBuyerPublicKey(), quoteTerms.BuyerPublicKey) || !bytes.Equal(opening.OpeningSellerPublicKey(), quote.SellerPublicKey) {
		return nil, nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "participant_public_keys", "request participant keys do not match supplied quote")
	}
	if !containsArbiterPublicKey(quoteTerms.SupportedArbiterPublicKeysCBOR, opening.OpeningArbiterPublicKey()) {
		return nil, nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "supported_arbiter_public_keys", "opening arbiter is not allowed by quote")
	}
	return authorization, quoteTerms, nil
}

// CheckContentRequestTiming 应用 003 请求的两项显式时间比较：报价过期与交付
// 截止。at 是调用方显式传入的本操作唯一时间事实。
func CheckContentRequestTiming(authorization *PaymentAuthorization, quoteTerms *FileQuoteTerms, at time.Time) error {
	const op = "content.CheckContentRequestTiming"
	if !at.Before(time.Unix(quoteTerms.QuoteExpiresAtUnixSeconds, 0)) {
		return protocol.Errorf(op, protocol.CodeExpired, 5, "quote_expires_at_unix_seconds", "file quote is expired")
	}
	if !at.Before(time.Unix(authorization.DeliveryDeadlineUnixSeconds, 0)) {
		return protocol.Errorf(op, protocol.CodeExpired, 5, "delivery_deadline_unix_seconds", "delivery deadline has passed")
	}
	if authorization.DeliveryDeadlineUnixSeconds > quoteTerms.QuoteExpiresAtUnixSeconds {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "delivery_deadline_unix_seconds", "delivery deadline exceeds quote expiry")
	}
	return nil
}

// containsArbiterPublicKey 报告编码的仲裁公钥数组是否包含目标公钥。
func containsArbiterPublicKey(encodedPublicKeys []byte, wanted []byte) bool {
	publicKeys, err := DecodeSupportedArbiterPublicKeys(encodedPublicKeys)
	if err != nil {
		return false
	}
	for _, publicKey := range publicKeys {
		if bytes.Equal(publicKey, wanted) {
			return true
		}
	}
	return false
}

// mapMasterSeedError 把 MasterSeed 依赖错误映射到统一分类：取消原样透传，
// 块不在 seed 中映射为 invalid_evidence 并保留底层原因。
func mapMasterSeedError(err error) error {
	if err == nil {
		return nil
	}
	if masterseed.CodeOf(err) == masterseed.Aborted || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return protocol.Wrap(err, "content.VerifyContentPayloadsContext", protocol.CodeCanceled, 0, "")
	}
	if masterseed.CodeOf(err) == masterseed.BlockNotInSeed {
		return protocol.Wrap(err, "content.VerifyContentPayloadsContext", protocol.CodeInvalidEvidence, 0, "payload")
	}
	return protocol.Wrap(err, "content.VerifyContentPayloadsContext", protocol.CodeInvalidEvidence, 0, "")
}

// VerifyContentPayloadsContext 验证交付批次：数量严格等于授权哈希数量、顺序
// 一一对应、逐项 SHA-256、seed/block 归属与协议期望长度。当批次内携带与报价
// SeedHash 对应的 seed payload 时，先完整验证它，再用它做块成员校验；返回值
// 是实际用于成员校验的 seed 深复制，调用方可用它继续计算聚合价格。ctx 仅用
// 于可取消的大 payload 计算。
func VerifyContentPayloadsContext(ctx context.Context, quoteTerms *FileQuoteTerms, contentHashes, payloads [][]byte, seed []byte) ([]byte, error) {
	const op = "content.VerifyContentPayloadsContext"
	// 导出入口自身 fail-closed：外部直接调用时同样强制协议数组约束
	//（1..64、32 字节宽度、不重复；payload 非空且不超过一个块长）。
	if err := validateContentHashes(contentHashes); err != nil {
		return nil, invalidEvidence(op, err)
	}
	if err := validateContentPayloads(payloads); err != nil {
		return nil, invalidEvidence(op, err)
	}
	if err := ValidateFileQuoteTerms(quoteTerms); err != nil {
		return nil, invalidEvidence(op, fmt.Errorf("quote terms: %v", err))
	}
	if len(contentHashes) == 0 || len(contentHashes) > MaxContentBatchItems {
		return nil, invalidEvidence(op, fmt.Errorf("authorized content hash count must be between 1 and %d", MaxContentBatchItems))
	}
	if len(payloads) != len(contentHashes) {
		return nil, invalidEvidence(op, fmt.Errorf("payload count %d does not match authorized hash count %d", len(payloads), len(contentHashes)))
	}
	digests := make([]masterseed.Digest, len(contentHashes))
	seedItemIndex := -1
	requiresBlocks := false
	for index, hash := range contentHashes {
		digest, err := masterseed.DigestFromBytes(hash)
		if err != nil {
			return nil, mapMasterSeedError(err)
		}
		digests[index] = digest
		payloadDigest := masterseed.Sum256(payloads[index])
		if !bytes.Equal(payloadDigest.Bytes(), hash) {
			return nil, invalidEvidence(op, fmt.Errorf("payload #%d does not match authorized content hash", index+1))
		}
		if bytes.Equal(hash, quoteTerms.SeedHash) {
			if _, err := masterseed.VerifySeedForSourceSize(ctx, bytes.NewReader(payloads[index]), digest, quoteTerms.FileSizeBytes); err != nil {
				return nil, mapMasterSeedError(err)
			}
			seedItemIndex = index
		} else {
			requiresBlocks = true
		}
	}
	effectiveSeed := seed
	if len(effectiveSeed) == 0 && seedItemIndex >= 0 {
		effectiveSeed = append([]byte(nil), payloads[seedItemIndex]...)
	}
	if requiresBlocks && len(effectiveSeed) == 0 {
		return nil, invalidEvidence(op, errors.New("a verified seed is required to validate block payloads"))
	}
	if requiresBlocks {
		seedDigest, err := masterseed.DigestFromBytes(quoteTerms.SeedHash)
		if err != nil {
			return nil, mapMasterSeedError(err)
		}
		for index, hash := range contentHashes {
			if bytes.Equal(hash, quoteTerms.SeedHash) {
				continue
			}
			if _, err := masterseed.VerifyBlock(ctx, payloads[index], digests[index]); err != nil {
				return nil, mapMasterSeedError(err)
			}
			if _, err := masterseed.VerifyBlockInSeed(ctx, bytes.NewReader(effectiveSeed), seedDigest, quoteTerms.FileSizeBytes, payloads[index]); err != nil {
				return nil, mapMasterSeedError(err)
			}
		}
	}
	if len(effectiveSeed) == 0 {
		return nil, nil
	}
	return append([]byte(nil), effectiveSeed...), nil
}

// classifiedContent records the evidence-derived kind and expected protocol
// length of one requested content hash. The kind is never sender-declared.
type classifiedContent struct {
	IsSeed    bool
	BlockSize uint64
}

// classifyContentHashes derives the kind and price-relevant expected length of
// each ordered content hash from the quote and the verified seed. A hash equal
// to the quote SeedHash is the seed; every other hash must appear in the seed's
// block list, priced at that position's protocol length. Duplicate positions
// are charged once, but matches implying conflicting expected lengths are an
// ambiguous-evidence conflict and reject the whole batch.
func classifyContentHashes(ctx context.Context, quoteTerms *FileQuoteTerms, contentHashes [][]byte, seed []byte) ([]classifiedContent, error) {
	if err := ValidateFileQuoteTerms(quoteTerms); err != nil {
		return nil, invalidEvidence("content.classifyContentHashes", fmt.Errorf("quote terms: %v", err))
	}
	result := make([]classifiedContent, len(contentHashes))
	for index, hash := range contentHashes {
		if len(hash) != sha256.Size {
			return nil, invalidEvidence("content.classifyContentHashes", fmt.Errorf("content hash #%d must be %d bytes", index+1, sha256.Size))
		}
		if bytes.Equal(hash, quoteTerms.SeedHash) {
			result[index] = classifiedContent{IsSeed: true}
			continue
		}
		matches, err := findBlockMatches(ctx, quoteTerms, hash, seed)
		if err != nil {
			return nil, fmt.Errorf("content hash #%d: %w", index+1, err)
		}
		firstSize, err := masterseed.ExpectedBlockSize(quoteTerms.FileSizeBytes, matches.FirstIndex)
		if err != nil {
			return nil, mapMasterSeedError(err)
		}
		lastSize, err := masterseed.ExpectedBlockSize(quoteTerms.FileSizeBytes, matches.LastIndex)
		if err != nil {
			return nil, mapMasterSeedError(err)
		}
		if firstSize != lastSize {
			return nil, invalidEvidence("content.classifyContentHashes", fmt.Errorf("content hash #%d matches positions with conflicting expected lengths", index+1))
		}
		result[index] = classifiedContent{BlockSize: firstSize}
	}
	return result, nil
}

// findBlockMatches locates all seed positions of one block hash. It scans the
// full seed so integrity, source-size binding, and membership are proven in a
// single pass before any pricing or delivery decision.
func findBlockMatches(ctx context.Context, quoteTerms *FileQuoteTerms, blockHash, seed []byte) (masterseed.BlockMatches, error) {
	var result masterseed.BlockMatches
	if len(seed) == 0 {
		return result, invalidEvidence("content.findBlockMatches", errors.New("the verified seed is required for block content"))
	}
	digest, err := masterseed.DigestFromBytes(blockHash)
	if err != nil {
		return result, mapMasterSeedError(err)
	}
	seedDigest, err := masterseed.DigestFromBytes(quoteTerms.SeedHash)
	if err != nil {
		return result, mapMasterSeedError(err)
	}
	result, err = masterseed.FindBlockHash(ctx, bytes.NewReader(seed), seedDigest, quoteTerms.FileSizeBytes, digest)
	if err != nil {
		return result, mapMasterSeedError(err)
	}
	if result.MatchCount == 0 {
		return result, invalidEvidence("content.findBlockMatches", errors.New("block hash is not listed by the verified seed"))
	}
	return result, nil
}

// refundTemplateTxIDIsZero reports whether a decoded hash is the all-zero "unset"
// sentinel, which must never enter encoding, storage, or network paths.
func refundTemplateTxIDIsZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}

// ValidatePaymentAuthorization checks the Kind 5 field widths, pool reference,
// target payment sequence bounds, canonical content-hash batch, and delivery
// deadline before signing.
func ValidatePaymentAuthorization(authorization *PaymentAuthorization) error {
	const op = "content.ValidatePaymentAuthorization"
	if authorization == nil {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "authorization", "payment authorization is required")
	}
	if authorization.FileQuoteTermsID.IsZero() {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "file_quote_terms_id", "%w", protocol.ErrZeroIdentifier)
	}
	if len(authorization.RefundTemplateTxID) != sha256.Size {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 5, "refund_template_txid", "must be 32 bytes")
	}
	if refundTemplateTxIDIsZero(authorization.RefundTemplateTxID) {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "refund_template_txid", "must not be all zero")
	}
	if authorization.PaymentSequence == 0 || authorization.PaymentSequence > ^uint32(0)-1 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "payment_sequence", "must be between 1 and 4294967294")
	}
	if _, err := DecodeContentHashes(authorization.ContentHashesCBOR); err != nil {
		return err
	}
	if authorization.DeliveryDeadlineUnixSeconds <= 0 {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "delivery_deadline_unix_seconds", "is required")
	}
	return nil
}

func clonePaymentAuthorization(authorization *PaymentAuthorization) *PaymentAuthorization {
	if authorization == nil {
		return nil
	}
	cloned := *authorization
	// FileQuoteTermsID 是值类型数组，结构体浅拷贝即深拷贝。
	cloned.RefundTemplateTxID = append([]byte(nil), authorization.RefundTemplateTxID...)
	cloned.ContentHashesCBOR = append([]byte(nil), authorization.ContentHashesCBOR...)
	return &cloned
}

func cloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	if request == nil {
		return nil
	}
	return &SignedContentRequest{PaymentAuthorizationCBOR: append([]byte(nil), request.PaymentAuthorizationCBOR...), BuyerPaymentAuthorizationSignature: append([]byte(nil), request.BuyerPaymentAuthorizationSignature...)}
}

func cloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	if delivery == nil {
		return nil
	}
	return &SignedContentDelivery{
		ContentDeliveryCBOR:            append([]byte(nil), delivery.ContentDeliveryCBOR...),
		SellerContentDeliverySignature: append([]byte(nil), delivery.SellerContentDeliverySignature...),
		ContentPayloadsCBOR:            append([]byte(nil), delivery.ContentPayloadsCBOR...),
	}
}
