package bitfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/internal/protoclock"
)

const contentProtocolVersion uint64 = 4

// Hash32 is a fixed-size SHA-256 reference used by the new protocol.
type Hash32 [sha256.Size]byte

// UnixSeconds is the protocol's UTC Unix-seconds representation.
type UnixSeconds int64

// ContentRequestTerms is the unsigned, signed-bytes portion of the canonical
// 003 final payment authorization. It carries no public keys or fee rates:
// those are uniquely determined by RefundTemplateTxID's OpeningProof, and the
// quote is selected by QuoteTermsHash alone.
type ContentRequestTerms struct {
	// QuoteTermsHash selects the quote this authorization purchases from.
	QuoteTermsHash []byte
	// RefundTemplateTxID selects the fee pool and, through its immutable
	// OpeningProof, the Buyer/Seller/Arbiter roles and miner fee rate.
	RefundTemplateTxID []byte
	// PaymentSequence is the single target payment state sequence of this
	// authorization; receivers verify it equals previous + 1.
	PaymentSequence uint32
	// SellerAmountAfterSat is the seller's absolute cumulative amount after
	// the batch payment, never a per-batch increment.
	SellerAmountAfterSat uint64
	// ContentHashesCBOR is the deterministic CBOR child document holding the
	// ordered batch of 1..MaxContentBatchItems content hashes.
	ContentHashesCBOR []byte
	// DeliveryDeadlineUnix is the UTC deadline after which delivery is late.
	DeliveryDeadlineUnix int64
}

// SignedContentRequest is the complete 003 final payment authorization. The
// buyer signature covers exactly TermsCBOR.
type SignedContentRequest struct {
	TermsCBOR      []byte
	BuyerSignature []byte
}

// SignedContentDelivery is the complete 004 credential. The seller signature
// covers exactly the 32-byte PaymentAuthorizationHash through the fixed
// SignMessage path; payloads are bound indirectly via the hashes committed in
// the referenced 003 terms and are carried after the signature fields.
type SignedContentDelivery struct {
	// PaymentAuthorizationHash 是被引用 003 条款规范编码的 SHA-256，长度固定
	// 为 32 字节。它是内容寻址与证据关联 ID，不是访问授权令牌。
	PaymentAuthorizationHash []byte
	// SellerPaymentAuthorizationHashSignature 是卖方对精确 32 字节
	// PaymentAuthorizationHash 的普通消息签名（SignMessage：再哈希一次后输出
	// low-S DER）。它不覆盖 004 外壳、payload 或任何 CBOR 包装。
	SellerPaymentAuthorizationHashSignature []byte
	// ContentPayloadsCBOR 是确定性 CBOR 子文档，按顺序承载与 003 哈希一一对应
	// 的 payload 数组。
	ContentPayloadsCBOR []byte
}

// EncodeContentHashes returns the sole canonical representation of the 003
// content_hashes child document: an array of 1..MaxContentBatchItems unique,
// ordered 32-byte hashes encoded as a deterministic CBOR byte string.
func EncodeContentHashes(hashes [][]byte) ([]byte, error) {
	if err := validateContentHashes(hashes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal(cloneByteSlices(hashes))
}

// DecodeContentHashes strictly decodes the content_hashes child document. It
// rejects indefinite lengths, tags, trailing data, non-canonical encodings,
// wrong counts, wrong hash widths, duplicates, and reordering attempts by
// requiring byte equality with the deterministic re-encoding. The returned
// slices are deep copies owned by the caller.
func DecodeContentHashes(raw []byte) ([][]byte, error) {
	var hashes [][]byte
	if err := strictDec.Unmarshal(raw, &hashes); err != nil {
		return nil, fmt.Errorf("%w: decode content hashes: %v", ErrInvalidEvidence, err)
	}
	if err := validateContentHashes(hashes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	canonical, err := canonicalEnc.Marshal(hashes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, raw) {
		return nil, fmt.Errorf("%w: content hashes are not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneByteSlices(hashes), nil
}

// EncodeContentPayloads returns the sole canonical representation of the 004
// content_payloads child document: an array of 1..MaxContentBatchItems
// non-empty payloads, each at most masterseed.BlockSize bytes.
func EncodeContentPayloads(payloads [][]byte) ([]byte, error) {
	if err := validateContentPayloads(payloads); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal(cloneByteSlices(payloads))
}

// DecodeContentPayloads strictly decodes the content_payloads child document
// with the same canonicality rules as DecodeContentHashes, plus per-item
// non-empty and maximum-length checks. Inputs above MaxContentPayloadsCBORBytes
// are rejected before decoding so a hostile length cannot bypass the item
// count limit. The returned slices are deep copies owned by the caller.
func DecodeContentPayloads(raw []byte) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > MaxContentPayloadsCBORBytes {
		return nil, fmt.Errorf("%w: content payloads exceed the protocol size limit", ErrInvalidEvidence)
	}
	var payloads [][]byte
	if err := strictDec.Unmarshal(raw, &payloads); err != nil {
		return nil, fmt.Errorf("%w: decode content payloads: %v", ErrInvalidEvidence, err)
	}
	if err := validateContentPayloads(payloads); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	canonical, err := canonicalEnc.Marshal(payloads)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, raw) {
		return nil, fmt.Errorf("%w: content payloads are not deterministically encoded", ErrInvalidEvidence)
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

// EncodeContentRequestTerms returns the exact deterministic CBOR bytes signed
// by the buyer for a 003 request: the six-element versionless terms array.
func EncodeContentRequestTerms(terms *ContentRequestTerms) ([]byte, error) {
	if err := ValidateContentRequestTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content request terms: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal([]any{
		bstr(terms.QuoteTermsHash),
		bstr(terms.RefundTemplateTxID),
		terms.PaymentSequence,
		terms.SellerAmountAfterSat,
		bstr(terms.ContentHashesCBOR),
		terms.DeliveryDeadlineUnix,
	})
}

// DecodeContentRequestTerms accepts only canonical six-element 003 terms CBOR.
// Legacy thirteen-element terms, inner versions, single-hash requests, missing
// or extra fields, and non-canonical encodings all return ErrInvalidEvidence.
func DecodeContentRequestTerms(data []byte) (*ContentRequestTerms, error) {
	values, err := decodeArray(data, 6)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content request terms: %v", ErrInvalidEvidence, err)
	}
	terms := new(ContentRequestTerms)
	if err := decode(values[0], &terms.QuoteTermsHash); err != nil {
		return nil, fmt.Errorf("%w: quote_terms_hash: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[1], &terms.RefundTemplateTxID); err != nil {
		return nil, fmt.Errorf("%w: refund_template_txid: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &terms.PaymentSequence); err != nil {
		return nil, fmt.Errorf("%w: payment_sequence: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[3], &terms.SellerAmountAfterSat); err != nil {
		return nil, fmt.Errorf("%w: seller_amount_after_sat: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[4], &terms.ContentHashesCBOR); err != nil {
		return nil, fmt.Errorf("%w: content_hashes_cbor: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[5], &terms.DeliveryDeadlineUnix); err != nil {
		return nil, fmt.Errorf("%w: delivery_deadline_unix: %v", ErrInvalidEvidence, err)
	}
	if err := ValidateContentRequestTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content request terms: %v", ErrInvalidEvidence, err)
	}
	canonical, err := EncodeContentRequestTerms(terms)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: content request terms are not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneContentRequestTerms(terms), nil
}

// PaymentAuthorizationHash validates canonical request terms and returns their
// SHA-256 digest. It is defined exclusively over the 003 TermsCBOR.
func PaymentAuthorizationHash(termsCBOR []byte) (Hash32, error) {
	if _, err := DecodeContentRequestTerms(termsCBOR); err != nil {
		return Hash32{}, err
	}
	return Hash32(sha256.Sum256(termsCBOR)), nil
}

// NewSignedContentRequest deterministically encodes request terms and signs
// those exact bytes with the official BSV private key through the fixed
// single-SHA-256 message path. The signature is later verified against the
// BuyerPubKey restored from the referenced OpeningProof; the private key never
// enters any wire message, local result, log, or persisted structure.
func NewSignedContentRequest(terms *ContentRequestTerms, buyerKey *ec.PrivateKey) (*SignedContentRequest, error) {
	if buyerKey == nil {
		return nil, errors.New("buyer private key is required")
	}
	termsCBOR, err := EncodeContentRequestTerms(terms)
	if err != nil {
		return nil, err
	}
	signature, err := SignMessage(buyerKey, termsCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign content request terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("buyer signature is required")
	}
	return &SignedContentRequest{
		TermsCBOR:      append([]byte(nil), termsCBOR...),
		BuyerSignature: append([]byte(nil), signature...),
	}, nil
}

// EncodeSignedContentRequest encodes the complete 003 credential:
// [version, terms_cbor, buyer_signature].
func EncodeSignedContentRequest(request *SignedContentRequest) ([]byte, error) {
	if request == nil || len(request.BuyerSignature) == 0 {
		return nil, errors.New("signed content request and buyer signature are required")
	}
	if _, err := DecodeContentRequestTerms(request.TermsCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(request.TermsCBOR),
		bstr(request.BuyerSignature),
	})
}

// DecodeSignedContentRequest decodes a canonical 003 credential and rejects
// malformed array shapes, versions, and byte fields before returning a copy.
func DecodeSignedContentRequest(data []byte) (*SignedContentRequest, error) {
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signed content request: %v", ErrInvalidEvidence, err)
	}
	request := new(SignedContentRequest)
	var version uint64
	if err := decode(values[0], &version); err != nil || version != contentProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported signed content request version", ErrInvalidEvidence)
	}
	if err := decode(values[1], &request.TermsCBOR); err != nil {
		return nil, fmt.Errorf("%w: request terms: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &request.BuyerSignature); err != nil {
		return nil, fmt.Errorf("%w: buyer signature: %v", ErrInvalidEvidence, err)
	}
	canonical, err := EncodeSignedContentRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: signed content request is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneSignedContentRequest(request), nil
}

// NewSignedContentDelivery signs the exact 32-byte payment authorization hash
// with the official BSV private key through the fixed SignMessage path and
// attaches the canonically encoded payload batch. Callers must fully verify
// the referenced 003, the quote, the opening proof, and every payload before
// invoking this constructor.
func NewSignedContentDelivery(paymentAuthorizationHash []byte, payloads [][]byte, sellerKey *ec.PrivateKey) (*SignedContentDelivery, error) {
	if sellerKey == nil {
		return nil, errors.New("seller private key is required")
	}
	if len(paymentAuthorizationHash) != sha256.Size {
		return nil, fmt.Errorf("%w: payment_authorization_hash must be 32 bytes", ErrInvalidEvidence)
	}
	payloadsCBOR, err := EncodeContentPayloads(payloads)
	if err != nil {
		return nil, err
	}
	signature, err := SignMessage(sellerKey, paymentAuthorizationHash)
	if err != nil {
		return nil, fmt.Errorf("sign payment authorization hash: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("seller signature is required")
	}
	return &SignedContentDelivery{
		PaymentAuthorizationHash:                append([]byte(nil), paymentAuthorizationHash...),
		SellerPaymentAuthorizationHashSignature: append([]byte(nil), signature...),
		ContentPayloadsCBOR:                     payloadsCBOR,
	}, nil
}

// EncodeSignedContentDelivery encodes the complete 004 credential:
// [version, payment_authorization_hash, seller_signature, content_payloads_cbor].
func EncodeSignedContentDelivery(delivery *SignedContentDelivery) ([]byte, error) {
	if delivery == nil || len(delivery.SellerPaymentAuthorizationHashSignature) == 0 {
		return nil, errors.New("signed content delivery and seller signature are required")
	}
	if len(delivery.PaymentAuthorizationHash) != sha256.Size {
		return nil, fmt.Errorf("%w: payment_authorization_hash must be 32 bytes", ErrInvalidEvidence)
	}
	if _, err := DecodeContentPayloads(delivery.ContentPayloadsCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(delivery.PaymentAuthorizationHash),
		bstr(delivery.SellerPaymentAuthorizationHashSignature),
		bstr(delivery.ContentPayloadsCBOR),
	})
}

// DecodeSignedContentDelivery decodes canonical 004 credential bytes. The
// four-element shell is mandatory: legacy three-element deliveries, pool IDs
// inside 004, and payloads inside signed terms all fail here.
func DecodeSignedContentDelivery(data []byte) (*SignedContentDelivery, error) {
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signed content delivery: %v", ErrInvalidEvidence, err)
	}
	delivery := new(SignedContentDelivery)
	var version uint64
	if err := decode(values[0], &version); err != nil || version != contentProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported signed content delivery version", ErrInvalidEvidence)
	}
	if err := decode(values[1], &delivery.PaymentAuthorizationHash); err != nil {
		return nil, fmt.Errorf("%w: payment_authorization_hash: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &delivery.SellerPaymentAuthorizationHashSignature); err != nil {
		return nil, fmt.Errorf("%w: seller_payment_authorization_hash_signature: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[3], &delivery.ContentPayloadsCBOR); err != nil {
		return nil, fmt.Errorf("%w: content_payloads_cbor: %v", ErrInvalidEvidence, err)
	}
	canonical, err := EncodeSignedContentDelivery(delivery)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: signed content delivery is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneSignedContentDelivery(delivery), nil
}

// PoolOpeningEvidence is the minimal opening-proof view needed to bind a 003
// to its fee pool without importing the pool package. *pool.OpeningProof
// implements it with exported helper methods.
type PoolOpeningEvidence interface {
	OpeningBuyerPubKey() []byte
	OpeningSellerPubKey() []byte
	OpeningArbiterPubKey() []byte
	OpeningRefundTemplateTxID() []byte
}

// VerifySignedContentRequestForOpening verifies the pool binding and buyer
// signature of a 003 for evidence that already carries its OpeningProof, such
// as the 007 arbitration submission. It derives the RefundTemplateTxID from
// the supplied opening, requires an exact match, and verifies the buyer
// signature against the opening's buyer key over the exact TermsCBOR. Quote,
// content, and timing facts are intentionally out of scope here.
func VerifySignedContentRequestForOpening(request *SignedContentRequest, opening PoolOpeningEvidence) (*ContentRequestTerms, error) {
	if request == nil || len(request.BuyerSignature) == 0 {
		return nil, fmt.Errorf("%w: signed content request is required", ErrInvalidEvidence)
	}
	if opening == nil {
		return nil, fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	terms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	derived := opening.OpeningRefundTemplateTxID()
	if len(derived) != sha256.Size || !bytes.Equal(derived, terms.RefundTemplateTxID) {
		return nil, fmt.Errorf("%w: content request is not bound to supplied opening proof", ErrInvalidEvidence)
	}
	if err := VerifySignature(opening.OpeningBuyerPubKey(), request.TermsCBOR, request.BuyerSignature); err != nil {
		return nil, fmt.Errorf("%w: buyer authorization signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, nil
}

// VerifyContentRequestEvidence 是时间无关的 003 完整证据验证：报价证据与
// 卖方签名、池绑定、买方对精确 TermsCBOR 的签名、QuoteTermsHash 比对以及
// Buyer/Seller/Arbiter 与开池证据的绑定。它不检查报价过期或交付截止时间；
// 角色工作流用它保证整个操作只读取一次系统 UTC，再对返回值自行做时间比较。
func VerifyContentRequestEvidence(request *SignedContentRequest, quote *SignedFileQuote, opening PoolOpeningEvidence) (*ContentRequestTerms, *FileQuoteTerms, error) {
	return verifyContentRequestEvidence(request, quote, opening)
}

// VerifySignedContentRequest verifies the quote binding, pool participants,
// buyer signature, quote expiry, and request deadline. It reads system UTC
// exactly once at entry and uses only the fixed SDK verifiers.
func VerifySignedContentRequest(request *SignedContentRequest, quote *SignedFileQuote, opening PoolOpeningEvidence) (*ContentRequestTerms, error) {
	at := protoclock.Now()
	terms, quoteTerms, err := verifyContentRequestEvidence(request, quote, opening)
	if err != nil {
		return nil, err
	}
	if err := checkContentRequestTiming(terms, quoteTerms, at); err != nil {
		return nil, err
	}
	return terms, nil
}

// VerifySignedContentRequestWithSeed additionally proves that every requested
// block hash is present in the quote-bound seed and derives each item's
// protocol expected length. It reads system UTC once at entry like every other
// public verification entry point.
func VerifySignedContentRequestWithSeed(request *SignedContentRequest, quote *SignedFileQuote, opening PoolOpeningEvidence, seed []byte) (*ContentRequestTerms, error) {
	at := protoclock.Now()
	terms, quoteTerms, err := verifyContentRequestEvidence(request, quote, opening)
	if err != nil {
		return nil, err
	}
	hashes, err := DecodeContentHashes(terms.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	if _, err := classifyContentHashes(context.Background(), quoteTerms, hashes, seed); err != nil {
		return nil, err
	}
	if err := checkContentRequestTiming(terms, quoteTerms, at); err != nil {
		return nil, err
	}
	return terms, nil
}

// VerifyContentPayloadsContext 验证交付批次：数量严格等于授权哈希数量、顺序
// 一一对应、逐项 SHA-256、seed/block 归属与协议期望长度。当批次内携带与报价
// SeedHash 对应的 seed payload 时，先完整验证它，再用它做块成员校验；返回值
// 是实际用于成员校验的 seed 深复制，调用方可用它继续计算聚合价格。
func VerifyContentPayloadsContext(ctx context.Context, quoteTerms *FileQuoteTerms, contentHashes, payloads [][]byte, seed []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// 导出入口自身 fail-closed：外部直接调用时同样强制协议数组约束
	//（1..64、32 字节宽度、不重复；payload 非空且不超过一个块长）。
	if err := validateContentHashes(contentHashes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	if err := validateContentPayloads(payloads); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	if err := ValidateFileQuoteTerms(quoteTerms); err != nil {
		return nil, fmt.Errorf("%w: quote terms: %v", ErrInvalidEvidence, err)
	}
	if len(contentHashes) == 0 || len(contentHashes) > MaxContentBatchItems {
		return nil, fmt.Errorf("%w: authorized content hash count must be between 1 and %d", ErrInvalidEvidence, MaxContentBatchItems)
	}
	if len(payloads) != len(contentHashes) {
		return nil, fmt.Errorf("%w: payload count %d does not match authorized hash count %d", ErrInvalidEvidence, len(payloads), len(contentHashes))
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
			return nil, fmt.Errorf("%w: payload #%d does not match authorized content hash", ErrInvalidEvidence, index+1)
		}
		if bytes.Equal(hash, quoteTerms.SeedHash) {
			if _, err := masterseed.VerifySeedForSourceSize(ctx, bytes.NewReader(payloads[index]), digest, quoteTerms.FileSize); err != nil {
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
		return nil, fmt.Errorf("%w: a verified seed is required to validate block payloads", ErrContentNotInSeed)
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
			if _, err := masterseed.VerifyBlockInSeed(ctx, bytes.NewReader(effectiveSeed), seedDigest, quoteTerms.FileSize, payloads[index]); err != nil {
				return nil, mapMasterSeedError(err)
			}
		}
	}
	if len(effectiveSeed) == 0 {
		return nil, nil
	}
	return append([]byte(nil), effectiveSeed...), nil
}

// VerifyContentPayloads is the context-free wrapper of VerifyContentPayloadsContext.
func VerifyContentPayloads(quoteTerms *FileQuoteTerms, contentHashes, payloads [][]byte, seed []byte) ([]byte, error) {
	return VerifyContentPayloadsContext(context.Background(), quoteTerms, contentHashes, payloads, seed)
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
		return nil, fmt.Errorf("%w: quote terms: %v", ErrInvalidEvidence, err)
	}
	result := make([]classifiedContent, len(contentHashes))
	for index, hash := range contentHashes {
		if len(hash) != sha256.Size {
			return nil, fmt.Errorf("%w: content hash #%d must be %d bytes", ErrInvalidEvidence, index+1, sha256.Size)
		}
		if bytes.Equal(hash, quoteTerms.SeedHash) {
			result[index] = classifiedContent{IsSeed: true}
			continue
		}
		matches, err := findBlockMatches(ctx, quoteTerms, hash, seed)
		if err != nil {
			return nil, fmt.Errorf("content hash #%d: %w", index+1, err)
		}
		firstSize, err := masterseed.ExpectedBlockSize(quoteTerms.FileSize, matches.FirstIndex)
		if err != nil {
			return nil, mapMasterSeedError(err)
		}
		lastSize, err := masterseed.ExpectedBlockSize(quoteTerms.FileSize, matches.LastIndex)
		if err != nil {
			return nil, mapMasterSeedError(err)
		}
		if firstSize != lastSize {
			return nil, fmt.Errorf("%w: content hash #%d matches positions with conflicting expected lengths", ErrInvalidEvidence, index+1)
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
		return result, fmt.Errorf("%w: the verified seed is required for block content", ErrContentNotInSeed)
	}
	digest, err := masterseed.DigestFromBytes(blockHash)
	if err != nil {
		return result, mapMasterSeedError(err)
	}
	seedDigest, err := masterseed.DigestFromBytes(quoteTerms.SeedHash)
	if err != nil {
		return result, mapMasterSeedError(err)
	}
	result, err = masterseed.FindBlockHash(ctx, bytes.NewReader(seed), seedDigest, quoteTerms.FileSize, digest)
	if err != nil {
		return result, mapMasterSeedError(err)
	}
	if result.MatchCount == 0 {
		return result, ErrContentNotInSeed
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

// ValidateContentRequestTerms checks the 003 field widths, pool reference,
// target payment sequence bounds, canonical content-hash batch, and delivery
// deadline before signing.
func ValidateContentRequestTerms(terms *ContentRequestTerms) error {
	if terms == nil {
		return errors.New("content request terms are required")
	}
	if len(terms.QuoteTermsHash) != sha256.Size {
		return errors.New("quote_terms_hash must be 32 bytes")
	}
	if len(terms.RefundTemplateTxID) != sha256.Size {
		return errors.New("refund_template_txid must be 32 bytes")
	}
	if refundTemplateTxIDIsZero(terms.RefundTemplateTxID) {
		return errors.New("refund_template_txid must not be all zero")
	}
	if terms.PaymentSequence == 0 || terms.PaymentSequence > ^uint32(0)-1 {
		return errors.New("payment_sequence must be between 1 and 4294967294")
	}
	if _, err := DecodeContentHashes(terms.ContentHashesCBOR); err != nil {
		return err
	}
	if terms.DeliveryDeadlineUnix <= 0 {
		return errors.New("delivery_deadline_unix is required")
	}
	return nil
}

// checkContentRequestTiming 应用 003 请求的两项当前时间比较：报价过期与交付
// 截止。at 必须是公开入口唯一一次读取的时间；跨包调用方用返回的 terms 自行
// 做同样的纯比较（见 buyer/seller 包内同名逻辑）。
func checkContentRequestTiming(terms *ContentRequestTerms, quoteTerms *FileQuoteTerms, at time.Time) error {
	if !at.Before(time.Unix(quoteTerms.QuoteExpiresAtUnix, 0)) {
		return fmt.Errorf("%w: file quote is expired", ErrQuoteExpired)
	}
	if !at.Before(time.Unix(terms.DeliveryDeadlineUnix, 0)) {
		return fmt.Errorf("%w: delivery deadline has passed", ErrDeliveryDeadline)
	}
	if terms.DeliveryDeadlineUnix > quoteTerms.QuoteExpiresAtUnix {
		return fmt.Errorf("%w: delivery deadline exceeds quote expiry", ErrDeliveryDeadline)
	}
	return nil
}

func containsBytes(encodedPubkeys []byte, wanted []byte) bool {
	pubkeys, err := DecodeSupportedArbiterPubkeys(encodedPubkeys)
	if err != nil {
		return false
	}
	for _, pubkey := range pubkeys {
		if bytes.Equal(pubkey, wanted) {
			return true
		}
	}
	return false
}

func invalidEvidence(err error) error { return errors.Join(ErrInvalidEvidence, err) }

func mapMasterSeedError(err error) error {
	if err == nil {
		return nil
	}
	if masterseed.CodeOf(err) == masterseed.Aborted || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if masterseed.CodeOf(err) == masterseed.BlockNotInSeed {
		return errors.Join(ErrContentNotInSeed, err)
	}
	return errors.Join(ErrInvalidEvidence, err)
}

// verifyContentRequestEvidence 是时间无关的 003 纯证据验证：结构、池绑定、
// 报价绑定、参与方一致性与买方签名。它不检查报价过期或交付截止时间。
func verifyContentRequestEvidence(request *SignedContentRequest, quote *SignedFileQuote, opening PoolOpeningEvidence) (*ContentRequestTerms, *FileQuoteTerms, error) {
	quoteTerms, err := VerifyFileQuoteEvidence(quote)
	if err != nil {
		return nil, nil, err
	}
	terms, err := VerifySignedContentRequestForOpening(request, opening)
	if err != nil {
		return nil, nil, err
	}
	quoteHash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(terms.QuoteTermsHash, quoteHash[:]) {
		return nil, nil, fmt.Errorf("%w: request does not reference supplied quote", ErrInvalidEvidence)
	}
	if !bytes.Equal(opening.OpeningBuyerPubKey(), quoteTerms.BuyerPubkey) || !bytes.Equal(opening.OpeningSellerPubKey(), quote.SellerPubkey) {
		return nil, nil, fmt.Errorf("%w: request participant keys do not match supplied quote", ErrInvalidEvidence)
	}
	if !containsBytes(quoteTerms.SupportedArbiterPubkeysCBOR, opening.OpeningArbiterPubKey()) {
		return nil, nil, fmt.Errorf("%w: opening arbiter is not allowed by quote", ErrInvalidEvidence)
	}
	return terms, quoteTerms, nil
}

func cloneContentRequestTerms(terms *ContentRequestTerms) *ContentRequestTerms {
	if terms == nil {
		return nil
	}
	cloned := *terms
	cloned.QuoteTermsHash = append([]byte(nil), terms.QuoteTermsHash...)
	cloned.RefundTemplateTxID = append([]byte(nil), terms.RefundTemplateTxID...)
	cloned.ContentHashesCBOR = append([]byte(nil), terms.ContentHashesCBOR...)
	return &cloned
}

func cloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	if request == nil {
		return nil
	}
	return &SignedContentRequest{TermsCBOR: append([]byte(nil), request.TermsCBOR...), BuyerSignature: append([]byte(nil), request.BuyerSignature...)}
}

func cloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	if delivery == nil {
		return nil
	}
	return &SignedContentDelivery{
		PaymentAuthorizationHash:                append([]byte(nil), delivery.PaymentAuthorizationHash...),
		SellerPaymentAuthorizationHashSignature: append([]byte(nil), delivery.SellerPaymentAuthorizationHashSignature...),
		ContentPayloadsCBOR:                     append([]byte(nil), delivery.ContentPayloadsCBOR...),
	}
}
