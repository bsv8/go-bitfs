package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const contentProtocolVersion uint64 = 2

// Hash32 is a fixed-size SHA-256 reference used by the new protocol.
type Hash32 [sha256.Size]byte

// UnixSeconds is the protocol's UTC Unix-seconds representation.
type UnixSeconds int64

// ContentType identifies the two kinds of content addressable by a request.
type ContentType uint64

const (
	ContentSeed  ContentType = 0
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
	ContentRequestTermsHash []byte
	ContentBytes            []byte
}

// SignedContentDelivery is the complete 004 credential.
type SignedContentDelivery struct {
	TermsCBOR       []byte
	SellerSignature []byte
}

// ContentTermsSigner signs the exact canonical CBOR bytes of a content
// request or delivery terms document.
type ContentTermsSigner func(termsCBOR []byte) ([]byte, error)

// ContentTermsSignatureVerifier verifies a signature over exact bytes.
type ContentTermsSignatureVerifier func(pubkey, termsCBOR, signature []byte) error

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

func ContentRequestTermsHash(termsCBOR []byte) (Hash32, error) {
	if _, err := DecodeContentRequestTerms(termsCBOR); err != nil {
		return Hash32{}, err
	}
	return Hash32(sha256.Sum256(termsCBOR)), nil
}

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
	return &SignedContentRequest{
		TermsCBOR:      append([]byte(nil), termsCBOR...),
		BuyerSignature: append([]byte(nil), signature...),
	}, nil
}

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

func EncodeContentDeliveryTerms(terms *ContentDeliveryTerms) ([]byte, error) {
	if err := ValidateContentDeliveryTerms(terms); err != nil {
		return nil, fmt.Errorf("%w: content delivery terms: %v", ErrInvalidEvidence, err)
	}
	return canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(terms.ContentRequestTermsHash),
		bstr(terms.ContentBytes),
	})
}

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
	if err := decode(values[1], &terms.ContentRequestTermsHash); err != nil {
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

func ContentDeliveryTermsHash(termsCBOR []byte) (Hash32, error) {
	if _, err := DecodeContentDeliveryTerms(termsCBOR); err != nil {
		return Hash32{}, err
	}
	return Hash32(sha256.Sum256(termsCBOR)), nil
}

func NewSignedContentDelivery(request *SignedContentRequest, payload []byte, signer ContentTermsSigner) (*SignedContentDelivery, error) {
	if signer == nil {
		return nil, errors.New("content delivery signer is required")
	}
	if request == nil {
		return nil, errors.New("signed content request is required")
	}
	requestHash, err := ContentRequestTermsHash(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	terms, err := EncodeContentDeliveryTerms(&ContentDeliveryTerms{
		ContentRequestTermsHash: requestHash[:],
		ContentBytes:            append([]byte(nil), payload...),
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
	return &SignedContentDelivery{TermsCBOR: terms, SellerSignature: append([]byte(nil), signature...)}, nil
}

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
	if terms.PaymentSequenceAfter == 0 || terms.BasePaymentSequence == ^uint64(0) || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 {
		return errors.New("payment_sequence_after must equal base_payment_sequence plus one")
	}
	if len(terms.BuyerPubkey) == 0 || len(terms.SellerPubkey) == 0 {
		return errors.New("buyer_pubkey and seller_pubkey are required")
	}
	if len(terms.SelectedArbiterPubkey) == 0 {
		return errors.New("selected_arbiter_pubkey is required")
	}
	if terms.ContentType != ContentSeed && terms.ContentType != ContentBlock {
		return fmt.Errorf("unsupported content_type %d", terms.ContentType)
	}
	if len(terms.ContentHash) != sha256.Size {
		return errors.New("content_hash must be 32 bytes")
	}
	if terms.DeliveryDeadlineUnix <= 0 {
		return errors.New("delivery_deadline_unix is required")
	}
	return nil
}

func ValidateContentDeliveryTerms(terms *ContentDeliveryTerms) error {
	if terms == nil {
		return errors.New("content delivery terms are required")
	}
	if len(terms.ContentRequestTermsHash) != sha256.Size {
		return errors.New("content_request_terms_hash must be 32 bytes")
	}
	if len(terms.ContentBytes) > int(BlockSize) {
		return fmt.Errorf("content_bytes exceeds %d bytes", BlockSize)
	}
	return nil
}

// VerifyContentReference verifies the relationship between a quote and a
// requested content hash. Seed requests are self-contained; block requests
// additionally require the raw seed previously obtained by the buyer or held
// by the seller.
func VerifyContentReference(quoteTerms *FileQuoteTerms, contentType ContentType, contentHash, seed []byte, requireBlockMembership bool) error {
	if err := ValidateFileQuoteTerms(quoteTerms); err != nil {
		return fmt.Errorf("%w: quote terms: %v", ErrInvalidEvidence, err)
	}
	if len(contentHash) != sha256.Size {
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
		expectedSeedSize := fileQuoteBlockCount(quoteTerms.FileSize) * sha256.Size
		if uint64(len(seed)) != expectedSeedSize {
			return fmt.Errorf("%w: seed payload size %d does not match quoted file size %d", ErrInvalidEvidence, len(seed), expectedSeedSize)
		}
		matched, err := BlockHashInSeed(seed, quoteTerms.SeedHash, contentHash)
		if err != nil {
			return err
		}
		if !matched {
			return ErrContentNotInSeed
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported content type %d", ErrInvalidEvidence, contentType)
	}
}

// VerifyContentPayload verifies a delivered payload against the quoted
// content reference. For a block it also enforces the exact full/tail length
// derivable from the block's position in the seed.
func VerifyContentPayload(quoteTerms *FileQuoteTerms, contentType ContentType, contentHash, payload, seed []byte, requireBlockMembership bool) error {
	if err := VerifyContentReference(quoteTerms, contentType, contentHash, seed, requireBlockMembership); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], contentHash) {
		return fmt.Errorf("%w: content payload hash does not match request", ErrInvalidEvidence)
	}
	switch contentType {
	case ContentSeed:
		if _, err := ParseSeedBytes(payload); err != nil {
			return fmt.Errorf("%w: seed payload format: %v", ErrInvalidEvidence, err)
		}
		expected := fileQuoteBlockCount(quoteTerms.FileSize) * sha256.Size
		if uint64(len(payload)) != expected {
			return fmt.Errorf("%w: seed payload size %d does not match quote seed size %d", ErrInvalidEvidence, len(payload), expected)
		}
	case ContentBlock:
		if len(payload) == 0 || uint64(len(payload)) > BlockSize {
			return fmt.Errorf("%w: block payload size is invalid", ErrInvalidEvidence)
		}
		if requireBlockMembership {
			if err := verifyBlockPayloadSize(quoteTerms.FileSize, seed, contentHash, len(payload)); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyBlockPayloadSize(fileSize uint64, seed, blockHash []byte, payloadSize int) error {
	blockHashes, err := ParseSeedBytes(seed)
	if err != nil {
		return fmt.Errorf("%w: parse seed: %v", ErrInvalidEvidence, err)
	}
	for index, candidate := range blockHashes {
		if !bytes.Equal(candidate, blockHash) {
			continue
		}
		expected := uint64(BlockSize)
		if index == len(blockHashes)-1 {
			start := uint64(index) * BlockSize
			if fileSize <= start {
				return fmt.Errorf("%w: seed contains a block outside quoted file size", ErrInvalidEvidence)
			}
			expected = fileSize - start
			if expected > BlockSize {
				expected = BlockSize
			}
		}
		if uint64(payloadSize) == expected {
			return nil
		}
	}
	return fmt.Errorf("%w: block payload size does not match the quoted block position", ErrInvalidEvidence)
}

// VerifySignedContentRequestAt verifies the quote binding, buyer signature,
// arbiter selection and request deadline. Pool ownership and current sequence
// are deliberately delegated to the pool workflow layer.
func VerifySignedContentRequestAt(request *SignedContentRequest, quote *SignedFileQuote, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier) (*ContentRequestTerms, error) {
	return verifySignedContentRequestAt(request, quote, now, quoteVerifier, buyerVerifier, nil, false)
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
	if terms.PaymentSequenceAfter == 0 || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 || len(terms.BuyerPubkey) == 0 || len(terms.SellerPubkey) == 0 {
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
	return verifySignedContentRequestAt(request, quote, now, quoteVerifier, buyerVerifier, seed, true)
}

func verifySignedContentRequestAt(request *SignedContentRequest, quote *SignedFileQuote, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, seed []byte, requireBlockMembership bool) (*ContentRequestTerms, error) {
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
	if !now.Before(time.Unix(terms.DeliveryDeadlineUnix, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline has passed", ErrDeliveryDeadline)
	}
	if terms.DeliveryDeadlineUnix > quoteTerms.QuoteExpiresAtUnix {
		return nil, fmt.Errorf("%w: delivery deadline exceeds quote expiry", ErrDeliveryDeadline)
	}
	if err := VerifyContentReference(quoteTerms, terms.ContentType, terms.ContentHash, seed, requireBlockMembership); err != nil {
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
	return verifySignedContentDeliveryAt(request, delivery, quote, nil, now, quoteVerifier, buyerVerifier, sellerVerifier, false)
}

// VerifySignedContentDeliveryWithSeedAt additionally validates block
// membership and the exact full/tail block size derived from the seed.
func VerifySignedContentDeliveryWithSeedAt(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier) ([]byte, error) {
	return verifySignedContentDeliveryAt(request, delivery, quote, seed, now, quoteVerifier, buyerVerifier, sellerVerifier, true)
}

func verifySignedContentDeliveryAt(request *SignedContentRequest, delivery *SignedContentDelivery, quote *SignedFileQuote, seed []byte, now time.Time, quoteVerifier QuoteTermsSignatureVerifier, buyerVerifier ContentTermsSignatureVerifier, sellerVerifier ContentTermsSignatureVerifier, requireBlockMembership bool) ([]byte, error) {
	if delivery == nil || len(delivery.SellerSignature) == 0 {
		return nil, fmt.Errorf("%w: signed content delivery is required", ErrInvalidEvidence)
	}
	requestTerms, err := verifySignedContentRequestAt(request, quote, now, quoteVerifier, buyerVerifier, seed, requireBlockMembership)
	if err != nil {
		return nil, err
	}
	deliveryTerms, err := DecodeContentDeliveryTerms(delivery.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestHash, _ := ContentRequestTermsHash(request.TermsCBOR)
	if !bytes.Equal(deliveryTerms.ContentRequestTermsHash, requestHash[:]) {
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
	if err := VerifyContentPayload(quoteTerms, requestTerms.ContentType, requestTerms.ContentHash, deliveryTerms.ContentBytes, seed, requireBlockMembership); err != nil {
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
	return &ContentDeliveryTerms{ContentRequestTermsHash: append([]byte(nil), terms.ContentRequestTermsHash...), ContentBytes: append([]byte(nil), terms.ContentBytes...)}
}

func cloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	if delivery == nil {
		return nil
	}
	return &SignedContentDelivery{TermsCBOR: append([]byte(nil), delivery.TermsCBOR...), SellerSignature: append([]byte(nil), delivery.SellerSignature...)}
}
