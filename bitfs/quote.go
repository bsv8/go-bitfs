package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const quoteTermsVersion uint64 = 1

// MaxQuoteSeedBlocks is the greatest block count whose seed fits the BitFS
// payload limit. A seed contains one 32-byte hash for each block.
const MaxQuoteSeedBlocks uint64 = BlockSize / sha256.Size

// MaxQuoteFileSize is the largest file a quote can describe while the seed is
// delivered in one BitFS payload.
const MaxQuoteFileSize uint64 = MaxQuoteSeedBlocks * BlockSize

// QuoteTermsSigner signs the exact canonical TermsCBOR bytes.
type QuoteTermsSigner func(termsCBOR []byte) ([]byte, error)

// QuoteTermsSignatureVerifier verifies a seller signature over the exact
// canonical TermsCBOR bytes.
type QuoteTermsSignatureVerifier func(sellerPubkey, termsCBOR, signature []byte) error

// EncodeSupportedArbiterPubkeys returns the sole allowed representation of the
// supported-arbiter child structure.
func EncodeSupportedArbiterPubkeys(pubkeys [][]byte) ([]byte, error) {
	if err := validateSupportedArbiterPubkeys(pubkeys); err != nil {
		return nil, err
	}
	if pubkeys == nil {
		pubkeys = [][]byte{}
	}
	return canonicalEnc.Marshal(pubkeys)
}

// DecodeSupportedArbiterPubkeys validates and decodes a canonical
// supported-arbiter child structure.
func DecodeSupportedArbiterPubkeys(data []byte) ([][]byte, error) {
	var pubkeys [][]byte
	if err := strictDec.Unmarshal(data, &pubkeys); err != nil {
		return nil, fmt.Errorf("decode supported arbiter pubkeys: %w", err)
	}
	if err := validateSupportedArbiterPubkeys(pubkeys); err != nil {
		return nil, err
	}
	canonical, err := EncodeSupportedArbiterPubkeys(pubkeys)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("supported arbiter pubkeys CBOR is not deterministically encoded")
	}
	return cloneByteSlices(pubkeys), nil
}

// EncodeFileQuoteTerms returns the exact canonical CBOR bytes signed by a
// seller. The terms are an independent child document and therefore carry a
// version of their own.
func EncodeFileQuoteTerms(terms *FileQuoteTerms) ([]byte, error) {
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		quoteTermsVersion,
		bstr(terms.SeedHash),
		bstr(terms.BuyerPubkey),
		terms.SeedPriceSat,
		terms.FullBlockPriceSat,
		terms.FileSize,
		terms.QuoteExpiresAtUnix,
		bstr(terms.SupportedArbiterPubkeysCBOR),
	})
}

// DecodeFileQuoteTerms validates and decodes canonical FileQuoteTerms bytes.
func DecodeFileQuoteTerms(data []byte) (*FileQuoteTerms, error) {
	values, err := decodeArray(data, 8)
	if err != nil {
		return nil, fmt.Errorf("decode file quote terms: %w", err)
	}
	var version uint64
	terms := new(FileQuoteTerms)
	if err := decode(values[0], &version); err != nil || version != quoteTermsVersion {
		return nil, errors.New("unsupported file quote terms version")
	}
	if err := decode(values[1], &terms.SeedHash); err != nil {
		return nil, err
	}
	if err := decode(values[2], &terms.BuyerPubkey); err != nil {
		return nil, err
	}
	if err := decode(values[3], &terms.SeedPriceSat); err != nil {
		return nil, err
	}
	if err := decode(values[4], &terms.FullBlockPriceSat); err != nil {
		return nil, err
	}
	if err := decode(values[5], &terms.FileSize); err != nil {
		return nil, err
	}
	if err := decode(values[6], &terms.QuoteExpiresAtUnix); err != nil {
		return nil, err
	}
	if err := decode(values[7], &terms.SupportedArbiterPubkeysCBOR); err != nil {
		return nil, err
	}
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return nil, err
	}
	canonical, err := EncodeFileQuoteTerms(terms)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("file quote terms CBOR is not deterministically encoded")
	}
	return cloneFileQuoteTerms(terms), nil
}

// FileQuoteTermsHash returns the content-derived reference for canonical quote
// terms. It is a cache and evidence index, never a database-generated ID.
func FileQuoteTermsHash(termsCBOR []byte) ([sha256.Size]byte, error) {
	if _, err := DecodeFileQuoteTerms(termsCBOR); err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(termsCBOR), nil
}

// NewSignedFileQuote creates a portable seller quote credential.
func NewSignedFileQuote(terms *FileQuoteTerms, sellerPubkey []byte, recommendedFilename string, signer QuoteTermsSigner) (*SignedFileQuote, error) {
	if len(sellerPubkey) == 0 {
		return nil, errors.New("seller pubkey is required")
	}
	if signer == nil {
		return nil, errors.New("quote terms signer is required")
	}
	termsCBOR, err := EncodeFileQuoteTerms(terms)
	if err != nil {
		return nil, err
	}
	signature, err := signer(termsCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign quote terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("quote terms signature is required")
	}
	return &SignedFileQuote{
		TermsCBOR:           append([]byte(nil), termsCBOR...),
		SellerPubkey:        append([]byte(nil), sellerPubkey...),
		TermsSignature:      append([]byte(nil), signature...),
		RecommendedFilename: recommendedFilename,
	}, nil
}

// VerifySignedFileQuote verifies structural validity, quote expiry, and the
// seller signature. It returns independently owned parsed terms.
func VerifySignedFileQuote(quote *SignedFileQuote, verifier QuoteTermsSignatureVerifier) (*FileQuoteTerms, error) {
	return VerifySignedFileQuoteAt(quote, time.Now(), verifier)
}

// VerifySignedFileQuoteAt is VerifySignedFileQuote with an injected clock.
func VerifySignedFileQuoteAt(quote *SignedFileQuote, now time.Time, verifier QuoteTermsSignatureVerifier) (*FileQuoteTerms, error) {
	if quote == nil {
		return nil, errors.New("signed file quote is required")
	}
	if len(quote.SellerPubkey) == 0 {
		return nil, errors.New("seller pubkey is required")
	}
	if len(quote.TermsSignature) == 0 {
		return nil, errors.New("quote terms signature is required")
	}
	if verifier == nil {
		return nil, errors.New("quote terms signature verifier is required")
	}
	terms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if err := ValidateFileQuoteTermsAt(terms, now); err != nil {
		return nil, err
	}
	if err := verifier(quote.SellerPubkey, quote.TermsCBOR, quote.TermsSignature); err != nil {
		return nil, fmt.Errorf("quote terms signature invalid: %w", err)
	}
	return terms, nil
}

// EncodeSignedFileQuote returns the canonical CBOR representation of a quote
// credential. RecommendedFilename is intentionally not in TermsSignature.
func EncodeSignedFileQuote(quote *SignedFileQuote) ([]byte, error) {
	if quote == nil {
		return nil, errors.New("signed file quote is required")
	}
	if len(quote.SellerPubkey) == 0 {
		return nil, errors.New("seller pubkey is required")
	}
	if len(quote.TermsSignature) == 0 {
		return nil, errors.New("quote terms signature is required")
	}
	if _, err := DecodeFileQuoteTerms(quote.TermsCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{quoteTermsVersion, bstr(quote.TermsCBOR), bstr(quote.SellerPubkey), bstr(quote.TermsSignature), quote.RecommendedFilename})
}

// DecodeSignedFileQuote decodes one canonical quote credential. Signature and
// expiry verification is intentionally separate so callers can inject their
// wallet verifier and clock through VerifySignedFileQuoteAt.
func DecodeSignedFileQuote(data []byte) (*SignedFileQuote, error) {
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("decode signed file quote: %w", err)
	}
	var version uint64
	quote := new(SignedFileQuote)
	if err := decode(values[0], &version); err != nil || version != quoteTermsVersion {
		return nil, errors.New("unsupported signed file quote version")
	}
	if err := decode(values[1], &quote.TermsCBOR); err != nil {
		return nil, err
	}
	if err := decode(values[2], &quote.SellerPubkey); err != nil {
		return nil, err
	}
	if err := decode(values[3], &quote.TermsSignature); err != nil {
		return nil, err
	}
	if err := decode(values[4], &quote.RecommendedFilename); err != nil {
		return nil, err
	}
	canonical, err := EncodeSignedFileQuote(quote)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("signed file quote CBOR is not deterministically encoded")
	}
	return cloneSignedFileQuote(quote), nil
}

// ValidateFileQuoteTerms validates quote terms without considering time or a
// seller signature.
func ValidateFileQuoteTerms(terms *FileQuoteTerms) error {
	if terms == nil {
		return errors.New("file quote terms are required")
	}
	if len(terms.SeedHash) != sha256.Size {
		return fmt.Errorf("quote seed_hash length must be %d", sha256.Size)
	}
	if len(terms.BuyerPubkey) == 0 {
		return errors.New("quote buyer_pubkey is required")
	}
	if terms.FileSize == 0 {
		emptySeedHash := sha256.Sum256(nil)
		if !bytes.Equal(terms.SeedHash, emptySeedHash[:]) {
			return errors.New("empty-file quote seed_hash must equal sha256 of empty seed")
		}
	}
	if terms.QuoteExpiresAtUnix <= 0 {
		return errors.New("quote expires_at_unix is required")
	}
	if fileQuoteBlockCount(terms.FileSize) > MaxQuoteSeedBlocks {
		return fmt.Errorf("quote file_size exceeds maximum %d", MaxQuoteFileSize)
	}
	if _, err := DecodeSupportedArbiterPubkeys(terms.SupportedArbiterPubkeysCBOR); err != nil {
		return err
	}
	return nil
}

// ValidateFileQuoteTermsAt additionally verifies that terms have not expired.
func ValidateFileQuoteTermsAt(terms *FileQuoteTerms, now time.Time) error {
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return err
	}
	if !now.Before(time.Unix(terms.QuoteExpiresAtUnix, 0)) {
		return errors.New("file quote is expired")
	}
	return nil
}

func fileQuoteBlockCount(fileSize uint64) uint64 {
	if fileSize == 0 {
		return 0
	}
	return 1 + (fileSize-1)/BlockSize
}

func validateSupportedArbiterPubkeys(pubkeys [][]byte) error {
	for index, pubkey := range pubkeys {
		if len(pubkey) == 0 {
			return fmt.Errorf("supported arbiter pubkey #%d is required", index)
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(pubkeys[previous], pubkey) {
				return fmt.Errorf("supported arbiter pubkey #%d is duplicated", index)
			}
		}
	}
	return nil
}

func cloneByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = append([]byte(nil), values[index]...)
	}
	return cloned
}

func cloneFileQuoteTerms(terms *FileQuoteTerms) *FileQuoteTerms {
	if terms == nil {
		return nil
	}
	cloned := *terms
	cloned.SeedHash = append([]byte(nil), terms.SeedHash...)
	cloned.BuyerPubkey = append([]byte(nil), terms.BuyerPubkey...)
	cloned.SupportedArbiterPubkeysCBOR = append([]byte(nil), terms.SupportedArbiterPubkeysCBOR...)
	return &cloned
}

func cloneSignedFileQuote(quote *SignedFileQuote) *SignedFileQuote {
	if quote == nil {
		return nil
	}
	cloned := *quote
	cloned.TermsCBOR = append([]byte(nil), quote.TermsCBOR...)
	cloned.SellerPubkey = append([]byte(nil), quote.SellerPubkey...)
	cloned.TermsSignature = append([]byte(nil), quote.TermsSignature...)
	return &cloned
}
