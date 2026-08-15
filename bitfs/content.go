package bitfs

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

const contentProtocolVersion uint64 = 3

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
	SpendTxID             []byte
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

// ContentDeliveryTerms is the unsigned, signed-bytes portion of 004.
type ContentDeliveryTerms struct {
	PaymentAuthorizationHash []byte
	ContentBytes             []byte
}

// SignedContentDelivery is the complete 004 credential.
type SignedContentDelivery struct {
	TermsCBOR       []byte
	SellerSignature []byte
}

// ContentTermsSigner receives the exact canonical CBOR bytes of a content
// request or delivery terms document. It must hash those bytes once with
// SHA-256 and return the resulting DER-only signature.
type ContentTermsSigner func(termsCBOR []byte) ([]byte, error)

// ContentTermsSignatureVerifier verifies a signature over exact bytes.
type ContentTermsSignatureVerifier func(pubkey, termsCBOR, signature []byte) error

// EncodeContentRequestTerms returns the exact deterministic CBOR array signed by
// the buyer for a 003 request. It rejects nil terms and invalid field lengths.
func EncodeContentRequestTerms(terms *ContentRequestTerms) ([]byte, error) {
	if err := ValidateContentRequestTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content request terms: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(terms.QuoteTermsHash),
		bstr(terms.SpendTxID),
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
	if err := decode(values[2], &terms.SpendTxID); err != nil {
		return nil, fmt.Errorf("%w: spend_txid: %v", ErrInvalidEvidence, err)
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

// NewSignedContentRequest deterministically encodes request terms and asks the
// buyer-supplied signer to sign those exact bytes. The callback must apply the
// single SHA-256 digest and return DER-only bytes; the fixed verifier checks
// the signature before the credential is returned.
func NewSignedContentRequest(terms *ContentRequestTerms, signer ContentTermsSigner) (*SignedContentRequest, error) {
	if signer == nil {
		return nil, errors.New("content request signer is required")
	}
	termsCBOR, err := EncodeContentRequestTerms(terms)
	if err != nil {
		return nil, err
	}
	signature, err := signer(termsCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign content request terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("buyer signature is required")
	}
	if err := VerifySignature(terms.BuyerPubkey, termsCBOR, signature); err != nil {
		return nil, fmt.Errorf("%w: buyer signature invalid: %v", ErrInvalidEvidence, err)
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
		bstr(terms.PaymentAuthorizationHash),
		bstr(terms.ContentBytes),
	})
}

// DecodeContentDeliveryTerms decodes canonical 004 terms and validates its fixed
// array shape and byte-field lengths.
func DecodeContentDeliveryTerms(data []byte) (*ContentDeliveryTerms, error) {
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode content delivery terms: %v", ErrInvalidEvidence, err)
	}
	terms := new(ContentDeliveryTerms)
	var version uint64
	if err := decode(values[0], &version); err != nil || version != contentProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported content delivery terms version", ErrInvalidEvidence)
	}
	if err := decode(values[1], &terms.PaymentAuthorizationHash); err != nil {
		return nil, fmt.Errorf("%w: request terms hash: %v", ErrInvalidEvidence, err)
	}
	if err := decode(values[2], &terms.ContentBytes); err != nil {
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
// hash and asks signer to sign the resulting deterministic delivery terms.
// The callback must apply the single SHA-256 digest and return DER-only bytes;
// the fixed verifier checks it against the seller key committed by the request
// before the credential is returned.
func NewSignedContentDelivery(request *SignedContentRequest, payload []byte, signer ContentTermsSigner) (*SignedContentDelivery, error) {
	if signer == nil {
		return nil, errors.New("content delivery signer is required")
	}
	if request == nil {
		return nil, errors.New("signed content request is required")
	}
	requestHash, err := PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	terms, err := EncodeContentDeliveryTerms(&ContentDeliveryTerms{
		PaymentAuthorizationHash: requestHash[:],
		ContentBytes:             append([]byte(nil), payload...),
	})
	if err != nil {
		return nil, err
	}
	signature, err := signer(terms)
	if err != nil {
		return nil, fmt.Errorf("sign content delivery terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("seller signature is required")
	}
	requestTerms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if err := VerifySignature(requestTerms.SellerPubkey, terms, signature); err != nil {
		return nil, fmt.Errorf("%w: seller signature invalid: %v", ErrInvalidEvidence, err)
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

// ValidateContentRequestTerms checks the 003 version, quote hash, pool reference,
// content selector, arbiter key, size, and delivery deadline before signing.
func ValidateContentRequestTerms(terms *ContentRequestTerms) error {
	if terms == nil {
		return errors.New("content request terms are required")
	}
	if len(terms.QuoteTermsHash) != sha256.Size {
		return errors.New("quote_terms_hash must be 32 bytes")
	}
	if len(terms.SpendTxID) != sha256.Size {
		return errors.New("spend_txid must be 32 bytes")
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

// VerifySignedContentRequestAt verifies the quote binding, buyer signature,
// arbiter selection and request deadline. Pool ownership and current sequence
// are deliberately delegated to the pool workflow layer.
func VerifySignedContentRequestAt(request *SignedContentRequest, quote *SignedFileQuote, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier) (*ContentRequestTerms, error) {
	return verifySignedContentRequestAtContext(context.Background(), request, quote, now, quoteVerifier, buyerVerifier, nil, false)
}

// VerifySignedContentRequestStandalone verifies the self-contained buyer
// authorization used by arbitration. It deliberately does not load or
// validate a quote, delivery, payload, or payment history.
func VerifySignedContentRequestStandalone(request *SignedContentRequest, buyerVerifier ContentTermsSignatureVerifier) (*ContentRequestTerms, error) {
	if request == nil || buyerVerifier == nil {
		return nil, errors.New("signed content request and buyer verifier are required")
	}
	terms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if terms.PaymentSequenceAfter == 0 || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 || terms.PaymentSequenceAfter > uint64(^uint32(0)-1) || len(terms.BuyerPubkey) == 0 || len(terms.SellerPubkey) == 0 {
		return nil, fmt.Errorf("%w: final payment authorization economic fields are incomplete", ErrInvalidEvidence)
	}
	if err := buyerVerifier(terms.BuyerPubkey, request.TermsCBOR, request.BuyerSignature); err != nil {
		return nil, fmt.Errorf("%w: buyer authorization signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, nil
}

// VerifySignedContentRequestWithSeedAt is the workflow-level form of
// VerifySignedContentRequestAt. It additionally proves that a block hash is
// present in the quote's seed.
func VerifySignedContentRequestWithSeedAt(request *SignedContentRequest, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier) (*ContentRequestTerms, error) {
	return VerifySignedContentRequestWithSeedAtContext(context.Background(), request, quote, seed, now, quoteVerifier, buyerVerifier)
}

// VerifySignedContentRequestWithSeedAtContext is the context-aware workflow
// verifier; cancellation is propagated through seed scanning.
func VerifySignedContentRequestWithSeedAtContext(ctx context.Context, request *SignedContentRequest, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier) (*ContentRequestTerms, error) {
	return verifySignedContentRequestAtContext(ctx, request, quote, now, quoteVerifier, buyerVerifier, seed, true)
}

func verifySignedContentRequestAt(request *SignedContentRequest, quote *SignedFileQuote, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, seed []byte, requireBlockMembership bool) (*ContentRequestTerms, error) {
	return verifySignedContentRequestAtContext(context.Background(), request, quote, now, quoteVerifier, buyerVerifier, seed, requireBlockMembership)
}

func verifySignedContentRequestAtContext(ctx context.Context, request *SignedContentRequest, quote *SignedFileQuote, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, seed []byte, requireBlockMembership bool) (*ContentRequestTerms, error) {
	if request == nil || len(request.BuyerSignature) == 0 {
		return nil, fmt.Errorf("%w: signed content request is required", ErrInvalidEvidence)
	}
	quoteTerms, err := VerifySignedFileQuoteAt(quote, now, quoteVerifier)
	if err != nil {
		return nil, err
	}
	terms, err := DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	if !bytes.Equal(terms.QuoteTermsHash, quoteHash[:]) {
		return nil, fmt.Errorf("%w: request does not reference supplied quote", ErrInvalidEvidence)
	}
	if !bytes.Equal(terms.BuyerPubkey, quoteTerms.BuyerPubkey) || !bytes.Equal(terms.SellerPubkey, quote.SellerPubkey) {
		return nil, fmt.Errorf("%w: request participant keys do not match supplied quote", ErrInvalidEvidence)
	}
	if !now.Before(time.Unix(terms.DeliveryDeadlineUnix, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline has passed", ErrDeliveryDeadline)
	}
	if terms.DeliveryDeadlineUnix > quoteTerms.QuoteExpiresAtUnix {
		return nil, fmt.Errorf("%w: delivery deadline exceeds quote expiry", ErrDeliveryDeadline)
	}
	if err := VerifyContentReferenceContext(ctx, quoteTerms, terms.ContentType, terms.ContentHash, seed, requireBlockMembership); err != nil {
		return nil, err
	}
	if !containsBytes(quoteTerms.SupportedArbiterPubkeysCBOR, terms.SelectedArbiterPubkey) {
		return nil, fmt.Errorf("%w: selected arbiter is not allowed by quote", ErrInvalidEvidence)
	}
	if buyerVerifier == nil {
		return nil, errors.New("buyer signature verifier is required")
	}
	if err := buyerVerifier(quoteTerms.BuyerPubkey, request.TermsCBOR, request.BuyerSignature); err != nil {
		return nil, fmt.Errorf("%w: buyer signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, nil
}

// VerifySignedContentDeliveryAt verifies the exact request reference, seller
// signature and raw content hash. The caller may additionally validate a block
// against a previously received seed index.
func VerifySignedContentDeliveryAt(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier) ([]byte, error) {
	return verifySignedContentDeliveryAtContext(context.Background(), request, delivery, quote, nil, now, quoteVerifier, buyerVerifier, sellerVerifier, false)
}

// VerifySignedContentDeliveryWithSeedAt additionally validates block
// membership and the exact full/tail block size derived from the seed.
func VerifySignedContentDeliveryWithSeedAt(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier) ([]byte, error) {
	return VerifySignedContentDeliveryWithSeedAtContext(context.Background(), request, delivery, quote, seed, now, quoteVerifier, buyerVerifier, sellerVerifier)
}

func verifySignedContentDeliveryAt(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier, requireBlockMembership bool) ([]byte, error) {
	return verifySignedContentDeliveryAtContext(context.Background(), request, delivery, quote, seed, now, quoteVerifier, buyerVerifier, sellerVerifier, requireBlockMembership)
}

// VerifySignedContentDeliveryWithSeedAtContext verifies delivery content with
// a caller-owned seed while preserving cancellation during seed scans.
func VerifySignedContentDeliveryWithSeedAtContext(ctx context.Context, request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier) ([]byte, error) {
	return verifySignedContentDeliveryAtContext(ctx, request, delivery, quote, seed, now, quoteVerifier, buyerVerifier, sellerVerifier, true)
}

func verifySignedContentDeliveryAtContext(ctx context.Context, request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier, requireBlockMembership bool) ([]byte, error) {
	if delivery == nil || len(delivery.SellerSignature) == 0 {
		return nil, fmt.Errorf("%w: signed content delivery is required", ErrInvalidEvidence)
	}
	requestSeed := seed
	requestMembership := requireBlockMembership
	// Payload verification performs the single authoritative block scan; the
	// request half still validates all signatures and quote bindings first.
	if requireBlockMembership {
		requestSeed, requestMembership = nil, false
	}
	requestTerms, err := verifySignedContentRequestAtContext(ctx, request, quote, now, quoteVerifier, buyerVerifier, requestSeed, requestMembership)
	if err != nil {
		return nil, err
	}
	deliveryTerms, err := DecodeContentDeliveryTerms(delivery.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestHash, _ := PaymentAuthorizationHash(request.TermsCBOR)
	if !bytes.Equal(deliveryTerms.PaymentAuthorizationHash, requestHash[:]) {
		return nil, fmt.Errorf("%w: delivery does not reference supplied request", ErrInvalidEvidence)
	}
	if sellerVerifier == nil {
		return nil, errors.New("seller signature verifier is required")
	}
	if err := sellerVerifier(quote.SellerPubkey, delivery.TermsCBOR, delivery.SellerSignature); err != nil {
		return nil, fmt.Errorf("%w: seller signature invalid: %v", ErrInvalidEvidence, err)
	}
	quoteTerms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if err := VerifyContentPayloadContext(ctx, quoteTerms, requestTerms.ContentType, requestTerms.ContentHash, deliveryTerms.ContentBytes, seed, requireBlockMembership); err != nil {
		return nil, err
	}
	return append([]byte(nil), deliveryTerms.ContentBytes...), nil
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
	cloned.SpendTxID = append([]byte(nil), terms.SpendTxID...)
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
	return &ContentDeliveryTerms{PaymentAuthorizationHash: append([]byte(nil), terms.PaymentAuthorizationHash...), ContentBytes: append([]byte(nil), terms.ContentBytes...)}
}

func cloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	if delivery == nil {
		return nil
	}
	return &SignedContentDelivery{TermsCBOR: append([]byte(nil), delivery.TermsCBOR...), SellerSignature: append([]byte(nil), delivery.SellerSignature...)}
}
