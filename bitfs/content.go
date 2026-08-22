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
	"github.com/bsv8/go-bitfs/protocol"
)

const contentProtocolVersion uint64 = 4

// Hash32 is a fixed-size SHA-256 reference used by the new protocol.
type Hash32 [sha256.Size]byte

// UnixSeconds is the protocol's UTC Unix-seconds representation.
type UnixSeconds int64

// ContentType identifies the two kinds of content addressable by a request.
type ContentType uint64

const (
	// ContentSeed selects the seed payload in a content reference.
	ContentSeed ContentType = 0
	// ContentBlock identifies a block payload.
	ContentBlock ContentType = 1
)

// ContentRef is the only content choice exposed by the new request API.
type ContentRef struct {
	Type ContentType
	Hash []byte
}

// ContentRequestTerms is the unsigned, signed-bytes portion of the canonical
// 003 final payment authorization. The historical type name is retained so
// callers do not accidentally create a second authorization model.
type ContentRequestTerms struct {
	QuoteTermsHash        []byte
	RefundTemplateTxID    []byte
	BasePaymentSequence   uint64
	PaymentSequenceAfter  uint64
	SellerAmountAfterSat  uint64
	MinerFeeRateSatPerKB  uint64
	BuyerPubkey           []byte
	SellerPubkey          []byte
	SelectedArbiterPubkey []byte
	ContentType           ContentType
	ContentHash           []byte
	DeliveryDeadlineUnix  int64
}

// SignedContentRequest is the complete 003 final payment authorization.
type SignedContentRequest struct {
	TermsCBOR      []byte
	BuyerSignature []byte
}

// ContentDeliveryTerms is the unsigned, signed-bytes portion of 004. The
// seller signature covers the pool's RefundTemplateTxID so an independently
// delivered credential routes directly to its fee pool.
type ContentDeliveryTerms struct {
	RefundTemplateTxID       []byte
	PaymentAuthorizationHash []byte
	ContentBytes             []byte
}

// SignedContentDelivery is the complete 004 credential.
type SignedContentDelivery struct {
	TermsCBOR       []byte
	SellerSignature []byte
}

// EncodeContentRequestTerms returns the exact deterministic CBOR array signed by
// the buyer for a 003 request. It rejects nil terms and invalid field lengths.
func EncodeContentRequestTerms(terms *ContentRequestTerms) ([]byte, error) {
	if err := ValidateContentRequestTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content request terms: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(terms.QuoteTermsHash),
		bstr(terms.RefundTemplateTxID),
		terms.BasePaymentSequence,
		terms.PaymentSequenceAfter,
		terms.SellerAmountAfterSat,
		terms.MinerFeeRateSatPerKB,
		bstr(terms.BuyerPubkey),
		bstr(terms.SellerPubkey),
		bstr(terms.SelectedArbiterPubkey),
		terms.ContentType,
		bstr(terms.ContentHash),
		terms.DeliveryDeadlineUnix,
	})
}

// DecodeContentRequestTerms accepts only canonical 003 terms CBOR, checks the
// fixed array shape and field encodings, and returns an independently owned value.
func DecodeContentRequestTerms(data []byte) (*ContentRequestTerms, error) {
	values, err := decodeArray(data, 13)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content request terms: %v", ErrInvalidEvidence, err)
	}
	terms := new(ContentRequestTerms)
	var version uint64
	if err := decode(values[0], &version); err != nil || version != contentProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported content request terms version", ErrInvalidEvidence)
	}
	if err := decode(values[1], &terms.QuoteTermsHash); err != nil {
		return nil, fmt.Errorf("%w: quote_terms_hash: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &terms.RefundTemplateTxID); err != nil {
		return nil, fmt.Errorf("%w: refund_template_txid: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[3], &terms.BasePaymentSequence); err != nil {
		return nil, fmt.Errorf("%w: base_payment_sequence: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[4], &terms.PaymentSequenceAfter); err != nil {
		return nil, fmt.Errorf("%w: payment_sequence_after: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[5], &terms.SellerAmountAfterSat); err != nil {
		return nil, fmt.Errorf("%w: seller_amount_after_sat: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[6], &terms.MinerFeeRateSatPerKB); err != nil {
		return nil, fmt.Errorf("%w: miner_fee_rate_sat_per_kb: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[7], &terms.BuyerPubkey); err != nil {
		return nil, fmt.Errorf("%w: buyer_pubkey: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[8], &terms.SellerPubkey); err != nil {
		return nil, fmt.Errorf("%w: seller_pubkey: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[9], &terms.SelectedArbiterPubkey); err != nil {
		return nil, fmt.Errorf("%w: selected_arbiter_pubkey: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[10], &terms.ContentType); err != nil {
		return nil, fmt.Errorf("%w: content_type: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[11], &terms.ContentHash); err != nil {
		return nil, fmt.Errorf("%w: content_hash: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[12], &terms.DeliveryDeadlineUnix); err != nil {
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

// PaymentAuthorizationHash validates canonical request terms and returns their SHA-256 digest.
func PaymentAuthorizationHash(termsCBOR []byte) (Hash32, error) {
	if _, err := DecodeContentRequestTerms(termsCBOR); err != nil {
		return Hash32{}, err
	}
	return Hash32(sha256.Sum256(termsCBOR)), nil
}

// NewSignedContentRequest deterministically encodes request terms and signs
// those exact bytes with the official BSV private key through the fixed
// single-SHA-256 message path. The derived public key must match
// terms.BuyerPubkey, and the fixed verifier re-checks the signature before the
// credential is returned. The private key never enters any wire message,
// local result, log, or persisted structure.
func NewSignedContentRequest(terms *ContentRequestTerms, buyerKey *ec.PrivateKey) (*SignedContentRequest, error) {
	if buyerKey == nil {
		return nil, errors.New("buyer private key is required")
	}
	if !bytes.Equal(buyerKey.PubKey().Compressed(), terms.BuyerPubkey) {
		return nil, fmt.Errorf("%w: buyer private key does not match request terms pubkey", ErrInvalidEvidence)
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

// EncodeSignedContentRequest encodes the complete 003 credential, including the
// original terms bytes, buyer key, and signature, without re-signing it.
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
// malformed array shape, versions, and byte fields before returning a copy.
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

// EncodeContentDeliveryTerms returns the deterministic 004 terms bytes that bind
// delivery content to a previously authorized request and seller identity.
func EncodeContentDeliveryTerms(terms *ContentDeliveryTerms) ([]byte, error) {
	if err := ValidateContentDeliveryTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content delivery terms: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(terms.RefundTemplateTxID),
		bstr(terms.PaymentAuthorizationHash),
		bstr(terms.ContentBytes),
	})
}

// DecodeContentDeliveryTerms decodes canonical 004 terms and validates its fixed
// array shape and byte-field lengths.
func DecodeContentDeliveryTerms(data []byte) (*ContentDeliveryTerms, error) {
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content delivery terms: %v", ErrInvalidEvidence, err)
	}
	terms := new(ContentDeliveryTerms)
	var version uint64
	if err := decode(values[0], &version); err != nil || version != contentProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported content delivery terms version", ErrInvalidEvidence)
	}
	if err := decode(values[1], &terms.RefundTemplateTxID); err != nil {
		return nil, fmt.Errorf("%w: refund_template_txid: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &terms.PaymentAuthorizationHash); err != nil {
		return nil, fmt.Errorf("%w: payment_authorization_hash: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[3], &terms.ContentBytes); err != nil {
		return nil, fmt.Errorf("%w: content bytes: %v", ErrInvalidEvidence, err)
	}
	if err := ValidateContentDeliveryTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content delivery terms: %v", ErrInvalidEvidence, err)
	}
	canonical, err := EncodeContentDeliveryTerms(terms)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: content delivery terms are not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneContentDeliveryTerms(terms), nil
}

// ContentDeliveryTermsHash validates canonical delivery terms and returns their SHA-256 digest.
func ContentDeliveryTermsHash(termsCBOR []byte) (Hash32, error) {
	if _, err := DecodeContentDeliveryTerms(termsCBOR); err != nil {
		return Hash32{}, err
	}
	return Hash32(sha256.Sum256(termsCBOR)), nil
}

// NewSignedContentDelivery binds payload bytes to the request authorization
// hash and signs the resulting deterministic delivery terms with the official
// BSV private key through the fixed single-SHA-256 message path. The derived
// public key must match the seller key committed by the request, and the fixed
// verifier re-checks the signature before the credential is returned.
func NewSignedContentDelivery(request *SignedContentRequest, payload []byte, sellerKey *ec.PrivateKey) (*SignedContentDelivery, error) {
	if sellerKey == nil {
		return nil, errors.New("seller private key is required")
	}
	if request == nil {
		return nil, errors.New("signed content request is required")
	}
	requestHash, err := PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestTerms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sellerKey.PubKey().Compressed(), requestTerms.SellerPubkey) {
		return nil, fmt.Errorf("%w: seller private key does not match request terms pubkey", ErrInvalidEvidence)
	}
	terms, err := EncodeContentDeliveryTerms(&ContentDeliveryTerms{
		RefundTemplateTxID:       append([]byte(nil), requestTerms.RefundTemplateTxID...),
		PaymentAuthorizationHash: requestHash[:],
		ContentBytes:             append([]byte(nil), payload...),
	})
	if err != nil {
		return nil, err
	}
	signature, err := SignMessage(sellerKey, terms)
	if err != nil {
		return nil, fmt.Errorf("sign content delivery terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("seller signature is required")
	}
	return &SignedContentDelivery{TermsCBOR: terms, SellerSignature: append([]byte(nil), signature...)}, nil
}

// EncodeSignedContentDelivery encodes the complete seller-signed 004 credential;
// it preserves the supplied terms bytes and detached seller signature exactly.
func EncodeSignedContentDelivery(delivery *SignedContentDelivery) ([]byte, error) {
	if delivery == nil || len(delivery.SellerSignature) == 0 {
		return nil, errors.New("signed content delivery and seller signature are required")
	}
	if _, err := DecodeContentDeliveryTerms(delivery.TermsCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(delivery.TermsCBOR),
		bstr(delivery.SellerSignature),
	})
}

// DecodeSignedContentDelivery decodes canonical 004 credential bytes and rejects
// malformed shape or fields before returning an independently owned value.
func DecodeSignedContentDelivery(data []byte) (*SignedContentDelivery, error) {
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signed content delivery: %v", ErrInvalidEvidence, err)
	}
	delivery := new(SignedContentDelivery)
	var version uint64
	if err := decode(values[0], &version); err != nil || version != contentProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported signed content delivery version", ErrInvalidEvidence)
	}
	if err := decode(values[1], &delivery.TermsCBOR); err != nil {
		return nil, fmt.Errorf("%w: delivery terms: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &delivery.SellerSignature); err != nil {
		return nil, fmt.Errorf("%w: seller signature: %v", ErrInvalidEvidence, err)
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

// ValidateContentRequestTerms checks the 003 version, quote hash, pool reference,
// content selector, arbiter key, size, and delivery deadline before signing.
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
	if terms.PaymentSequenceAfter == 0 || terms.BasePaymentSequence == ^uint64(0) || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 || terms.PaymentSequenceAfter > uint64(^uint32(0)-1) {
		return errors.New("payment_sequence_after must equal base_payment_sequence plus one")
	}
	if err := protocol.ValidateCompressedPubKey(terms.BuyerPubkey); err != nil {
		return fmt.Errorf("buyer_pubkey: %w", err)
	}
	if err := protocol.ValidateCompressedPubKey(terms.SellerPubkey); err != nil {
		return fmt.Errorf("seller_pubkey: %w", err)
	}
	if err := protocol.ValidateCompressedPubKey(terms.SelectedArbiterPubkey); err != nil {
		return fmt.Errorf("selected_arbiter_pubkey: %w", err)
	}
	if terms.ContentType != ContentSeed && terms.ContentType != ContentBlock {
		return fmt.Errorf("unsupported content_type %d", terms.ContentType)
	}
	if len(terms.ContentHash) != masterseed.DigestSize {
		return errors.New("content_hash must be 32 bytes")
	}
	if terms.DeliveryDeadlineUnix <= 0 {
		return errors.New("delivery_deadline_unix is required")
	}
	return nil
}

// ValidateContentDeliveryTerms checks the 004 version, authorization hash, seller
// key, content hash, and declared payload length before delivery is accepted.
func ValidateContentDeliveryTerms(terms *ContentDeliveryTerms) error {
	if terms == nil {
		return errors.New("content delivery terms are required")
	}
	if len(terms.RefundTemplateTxID) != sha256.Size {
		return errors.New("refund_template_txid must be 32 bytes")
	}
	if refundTemplateTxIDIsZero(terms.RefundTemplateTxID) {
		return errors.New("refund_template_txid must not be all zero")
	}
	if len(terms.PaymentAuthorizationHash) != sha256.Size {
		return errors.New("payment_authorization_hash must be 32 bytes")
	}
	if len(terms.ContentBytes) > masterseed.BlockSize {
		return fmt.Errorf("content_bytes exceeds %d bytes", BlockSize)
	}
	return nil
}

// VerifyContentReference verifies the relationship between a quote and a
// requested content hash. Seed requests are self-contained; block requests
// additionally require the raw seed previously obtained by the buyer or held
// by the seller.
func VerifyContentReference(quoteTerms *FileQuoteTerms, contentType ContentType, contentHash, seed []byte, requireBlockMembership bool) error {
	return VerifyContentReferenceContext(context.Background(), quoteTerms, contentType, contentHash, seed, requireBlockMembership)
}

// VerifyContentReferenceContext is the context-aware content reference verifier.
func VerifyContentReferenceContext(ctx context.Context, quoteTerms *FileQuoteTerms, contentType ContentType, contentHash, seed []byte, requireBlockMembership bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ValidateFileQuoteTerms(quoteTerms); err != nil {
		return fmt.Errorf("%w: quote terms: %v", ErrInvalidEvidence, err)
	}
	if len(contentHash) != masterseed.DigestSize {
		return fmt.Errorf("%w: content hash must be 32 bytes", ErrInvalidEvidence)
	}
	switch contentType {
	case ContentSeed:
		if !bytes.Equal(contentHash, quoteTerms.SeedHash) {
			return fmt.Errorf("%w: requested seed does not match quote", ErrInvalidEvidence)
		}
		return nil
	case ContentBlock:
		if !requireBlockMembership {
			return nil
		}
		_, err := VerifyBlockReference(ctx, quoteTerms, contentHash, seed)
		return err
	default:
		return fmt.Errorf("%w: unsupported content type %d", ErrInvalidEvidence, contentType)
	}
}

// VerifyContentPayload verifies a delivered payload against the quoted
// content reference. For a block it also enforces the exact full/tail length
// derivable from the block's position in the seed.
func VerifyContentPayload(quoteTerms *FileQuoteTerms, contentType ContentType, contentHash, payload, seed []byte, requireBlockMembership bool) error {
	return VerifyContentPayloadContext(context.Background(), quoteTerms, contentType, contentHash, payload, seed, requireBlockMembership)
}

// VerifyContentPayloadContext verifies payload bytes and, for block payloads,
// combines block hashing, membership and protocol-size checks in one pass.
func VerifyContentPayloadContext(ctx context.Context, quoteTerms *FileQuoteTerms, contentType ContentType, contentHash, payload, seed []byte, requireBlockMembership bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := VerifyContentReferenceContext(ctx, quoteTerms, contentType, contentHash, seed, requireBlockMembership && contentType == ContentSeed); err != nil {
		return err
	}
	switch contentType {
	case ContentSeed:
		digest, err := masterseed.DigestFromBytes(contentHash)
		if err != nil {
			return mapMasterSeedError(err)
		}
		if _, err := masterseed.VerifySeedForSourceSize(ctx, bytes.NewReader(payload), digest, quoteTerms.FileSize); err != nil {
			return mapMasterSeedError(err)
		}
	case ContentBlock:
		if len(payload) == 0 {
			return fmt.Errorf("%w: block payload cannot be empty", ErrInvalidEvidence)
		}
		digest, err := masterseed.DigestFromBytes(contentHash)
		if err != nil {
			return mapMasterSeedError(err)
		}
		if _, err := masterseed.VerifyBlock(ctx, payload, digest); err != nil {
			return mapMasterSeedError(err)
		}
		if requireBlockMembership {
			seedDigest, err := masterseed.DigestFromBytes(quoteTerms.SeedHash)
			if err != nil {
				return mapMasterSeedError(err)
			}
			if _, err := masterseed.VerifyBlockInSeed(ctx, bytes.NewReader(seed), seedDigest, quoteTerms.FileSize, payload); err != nil {
				return mapMasterSeedError(err)
			}
		}
	}
	return nil
}

// VerifyBlockReference verifies a block digest against a quote-bound seed and
// returns all matching positions (including duplicate and tail occurrences).
func VerifyBlockReference(ctx context.Context, quoteTerms *FileQuoteTerms, blockHash, seed []byte) (masterseed.BlockMatches, error) {
	var result masterseed.BlockMatches
	if err := ValidateFileQuoteTerms(quoteTerms); err != nil {
		return result, invalidEvidence(err)
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

// VerifySignedContentRequest verifies the quote binding, buyer signature,
// arbiter selection, quote expiry, and request deadline. It reads system UTC
// exactly once at entry and uses only the fixed SDK verifiers.
func VerifySignedContentRequest(request *SignedContentRequest, quote *SignedFileQuote) (*ContentRequestTerms, error) {
	at := protoclock.Now()
	terms, quoteTerms, err := verifyContentRequestEvidence(context.Background(), request, quote, nil, false)
	if err != nil {
		return nil, err
	}
	if err := checkContentRequestTiming(terms, quoteTerms, at); err != nil {
		return nil, err
	}
	return terms, nil
}

// VerifySignedContentRequestWithSeed additionally proves that a block hash is
// present in the quote's seed. It reads UTC once at entry like every other
// public verification entry point.
func VerifySignedContentRequestWithSeed(request *SignedContentRequest, quote *SignedFileQuote, seed []byte) (*ContentRequestTerms, error) {
	at := protoclock.Now()
	terms, quoteTerms, err := verifyContentRequestEvidence(context.Background(), request, quote, seed, true)
	if err != nil {
		return nil, err
	}
	if err := checkContentRequestTiming(terms, quoteTerms, at); err != nil {
		return nil, err
	}
	return terms, nil
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

// VerifySignedContentRequestStandalone verifies the self-contained buyer
// authorization used by arbitration with the fixed SDK verifier. It
// deliberately does not load or validate a quote, delivery, payload, or
// payment history.
func VerifySignedContentRequestStandalone(request *SignedContentRequest) (*ContentRequestTerms, error) {
	if request == nil {
		return nil, errors.New("signed content request is required")
	}
	terms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if terms.PaymentSequenceAfter == 0 || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 || terms.PaymentSequenceAfter > uint64(^uint32(0)-1) || len(terms.BuyerPubkey) == 0 || len(terms.SellerPubkey) == 0 {
		return nil, fmt.Errorf("%w: final payment authorization economic fields are incomplete", ErrInvalidEvidence)
	}
	if err := VerifySignature(terms.BuyerPubkey, request.TermsCBOR, request.BuyerSignature); err != nil {
		return nil, fmt.Errorf("%w: buyer authorization signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, nil
}

// VerifyContentRequestEvidence 验证时间无关的 003 证据：结构、报价绑定、
// 参与方密钥、仲裁者选择、内容引用和买方签名。它不检查报价过期或交付截止
// 时间；调用方用返回的 terms 与报价 terms 结合自己读取的一次时间判断。
func VerifyContentRequestEvidence(request *SignedContentRequest, quote *SignedFileQuote) (*ContentRequestTerms, *FileQuoteTerms, error) {
	return verifyContentRequestEvidence(context.Background(), request, quote, nil, false)
}

func VerifyContentRequestEvidenceWithSeed(request *SignedContentRequest, quote *SignedFileQuote, seed []byte) (*ContentRequestTerms, *FileQuoteTerms, error) {
	return verifyContentRequestEvidence(context.Background(), request, quote, seed, true)
}

func VerifyContentDeliveryEvidence(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote) ([]byte, *ContentRequestTerms, *FileQuoteTerms, error) {
	return verifyContentDeliveryEvidence(context.Background(), request, delivery, quote, nil, false)
}

func VerifyContentDeliveryEvidenceWithSeed(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte) ([]byte, *ContentRequestTerms, *FileQuoteTerms, error) {
	return verifyContentDeliveryEvidence(context.Background(), request, delivery, quote, seed, true)
}

// verifyContentRequestEvidence 是时间无关的 003 纯证据验证。
func verifyContentRequestEvidence(ctx context.Context, request *SignedContentRequest, quote *SignedFileQuote, seed []byte, requireBlockMembership bool) (*ContentRequestTerms, *FileQuoteTerms, error) {
	if request == nil || len(request.BuyerSignature) == 0 {
		return nil, nil, fmt.Errorf("%w: signed content request is required", ErrInvalidEvidence)
	}
	quoteTerms, err := VerifyFileQuoteEvidence(quote)
	if err != nil {
		return nil, nil, err
	}
	terms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, nil, err
	}
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	if !bytes.Equal(terms.QuoteTermsHash, quoteHash[:]) {
		return nil, nil, fmt.Errorf("%w: request does not reference supplied quote", ErrInvalidEvidence)
	}
	if !bytes.Equal(terms.BuyerPubkey, quoteTerms.BuyerPubkey) || !bytes.Equal(terms.SellerPubkey, quote.SellerPubkey) {
		return nil, nil, fmt.Errorf("%w: request participant keys do not match supplied quote", ErrInvalidEvidence)
	}
	if err := VerifyContentReferenceContext(ctx, quoteTerms, terms.ContentType, terms.ContentHash, seed, requireBlockMembership); err != nil {
		return nil, nil, err
	}
	if !containsBytes(quoteTerms.SupportedArbiterPubkeysCBOR, terms.SelectedArbiterPubkey) {
		return nil, nil, fmt.Errorf("%w: selected arbiter is not allowed by quote", ErrInvalidEvidence)
	}
	if err := VerifySignature(quoteTerms.BuyerPubkey, request.TermsCBOR, request.BuyerSignature); err != nil {
		return nil, nil, fmt.Errorf("%w: buyer signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, quoteTerms, nil
}

// verifyContentDeliveryEvidence 是时间无关的 004 纯证据验证；payload 校验中
// 的块扫描保持不变，但所有"是否已过期/超时"的比较都留给公开入口或调用方。
func verifyContentDeliveryEvidence(ctx context.Context, request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, requireBlockMembership bool) ([]byte, *ContentRequestTerms, *FileQuoteTerms, error) {
	if delivery == nil || len(delivery.SellerSignature) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: signed content delivery is required", ErrInvalidEvidence)
	}
	requestSeed := seed
	requestMembership := requireBlockMembership
	if requireBlockMembership {
		requestSeed, requestMembership = nil, false
	}
	requestTerms, quoteTerms, err := verifyContentRequestEvidence(ctx, request, quote, requestSeed, requestMembership)
	if err != nil {
		return nil, nil, nil, err
	}
	deliveryTerms, err := DecodeContentDeliveryTerms(delivery.TermsCBOR)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(deliveryTerms.RefundTemplateTxID, requestTerms.RefundTemplateTxID) {
		return nil, nil, nil, fmt.Errorf("%w: delivery refund_template_txid does not reference supplied request", ErrInvalidEvidence)
	}
	requestHash, _ := PaymentAuthorizationHash(request.TermsCBOR)
	if !bytes.Equal(deliveryTerms.PaymentAuthorizationHash, requestHash[:]) {
		return nil, nil, nil, fmt.Errorf("%w: delivery does not reference supplied request", ErrInvalidEvidence)
	}
	if err := VerifySignature(quote.SellerPubkey, delivery.TermsCBOR, delivery.SellerSignature); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: seller signature invalid: %v", ErrInvalidEvidence, err)
	}
	if err := VerifyContentPayloadContext(ctx, quoteTerms, requestTerms.ContentType, requestTerms.ContentHash, deliveryTerms.ContentBytes, seed, requireBlockMembership); err != nil {
		return nil, nil, nil, err
	}
	return append([]byte(nil), deliveryTerms.ContentBytes...), requestTerms, quoteTerms, nil
}

// VerifySignedContentDelivery verifies the exact request reference, seller
// signature, content binding and the 003 timing facts (quote expiry, delivery
// deadline) with system UTC read exactly once at entry.
func VerifySignedContentDelivery(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote) ([]byte, error) {
	at := protoclock.Now()
	payload, requestTerms, quoteTerms, err := verifyContentDeliveryEvidence(context.Background(), request, delivery, quote, nil, false)
	if err != nil {
		return nil, err
	}
	if err := checkContentRequestTiming(requestTerms, quoteTerms, at); err != nil {
		return nil, err
	}
	return payload, nil
}

// VerifySignedContentDeliveryWithSeed additionally validates block membership
// and the exact full/tail block size derived from a caller-owned seed.
func VerifySignedContentDeliveryWithSeed(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte) ([]byte, error) {
	at := protoclock.Now()
	payload, requestTerms, quoteTerms, err := verifyContentDeliveryEvidence(context.Background(), request, delivery, quote, seed, true)
	if err != nil {
		return nil, err
	}
	if err := checkContentRequestTiming(requestTerms, quoteTerms, at); err != nil {
		return nil, err
	}
	return payload, nil
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

func cloneContentRequestTerms(terms *ContentRequestTerms) *ContentRequestTerms {
	if terms == nil {
		return nil
	}
	cloned := *terms
	cloned.QuoteTermsHash = append([]byte(nil), terms.QuoteTermsHash...)
	cloned.RefundTemplateTxID = append([]byte(nil), terms.RefundTemplateTxID...)
	cloned.BuyerPubkey = append([]byte(nil), terms.BuyerPubkey...)
	cloned.SellerPubkey = append([]byte(nil), terms.SellerPubkey...)
	cloned.SelectedArbiterPubkey = append([]byte(nil), terms.SelectedArbiterPubkey...)
	cloned.ContentHash = append([]byte(nil), terms.ContentHash...)
	return &cloned
}

func cloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	if request == nil {
		return nil
	}
	return &SignedContentRequest{TermsCBOR: append([]byte(nil), request.TermsCBOR...), BuyerSignature: append([]byte(nil), request.BuyerSignature...)}
}

func cloneContentDeliveryTerms(terms *ContentDeliveryTerms) *ContentDeliveryTerms {
	if terms == nil {
		return nil
	}
	return &ContentDeliveryTerms{RefundTemplateTxID: append([]byte(nil), terms.RefundTemplateTxID...), PaymentAuthorizationHash: append([]byte(nil), terms.PaymentAuthorizationHash...), ContentBytes: append([]byte(nil), terms.ContentBytes...)}
}

func cloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	if delivery == nil {
		return nil
	}
	return &SignedContentDelivery{TermsCBOR: append([]byte(nil), delivery.TermsCBOR...), SellerSignature: append([]byte(nil), delivery.SellerSignature...)}
}
