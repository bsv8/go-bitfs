package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"path"
	"strings"
	"time"
	"unicode"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/internal/protoclock"
	"github.com/bsv8/go-bitfs/protocol"
)

const quoteTermsVersion uint64 = 1

// MaxQuoteSeedBlocks is the greatest block count whose seed fits the BitFS
// payload limit. A seed contains one 32-byte hash for each block.
const MaxQuoteSeedBlocks uint64 = masterseed.BlockSize / masterseed.DigestSize

// MaxQuoteFileSize is the largest file a quote can describe while the seed is
// delivered in one BitFS payload.
const MaxQuoteFileSize uint64 = MaxQuoteSeedBlocks * BlockSize

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

// NewSignedFileQuote validates quote terms, encodes the canonical TermsCBOR,
// signs those exact bytes with the official BSV private key through the fixed
// single-SHA-256 message path, and fixedly re-verifies the signature with the
// derived public key before returning a portable 001 credential. The private
// key never enters any wire message, local result, log, or persisted structure.
func NewSignedFileQuote(terms *FileQuoteTerms, sellerKey *ec.PrivateKey, recommendedFilename string) (*SignedFileQuote, error) {
	if sellerKey == nil {
		return nil, errors.New("seller private key is required")
	}
	sellerPubkey := sellerKey.PubKey().Compressed()
	if err := protocol.ValidateCompressedPubKey(sellerPubkey); err != nil {
		return nil, fmt.Errorf("seller pubkey: %w", err)
	}
	termsCBOR, err := EncodeFileQuoteTerms(terms)
	if err != nil {
		return nil, err
	}
	signature, err := SignMessage(sellerKey, termsCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign quote terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("quote terms signature is required")
	}
	if err := VerifySignature(sellerPubkey, termsCBOR, signature); err != nil {
		return nil, fmt.Errorf("%w: quote terms signature invalid: %v", ErrInvalidEvidence, err)
	}
	return &SignedFileQuote{
		TermsCBOR:           append([]byte(nil), termsCBOR...),
		SellerPubkey:        append([]byte(nil), sellerPubkey...),
		TermsSignature:      append([]byte(nil), signature...),
		RecommendedFilename: SanitizeRecommendedFilename(recommendedFilename),
	}, nil
}

// VerifySignedFileQuote verifies structural validity, quote expiry, and the
// seller signature. It reads system UTC once at entry and always uses the
// fixed SDK verifier; callers cannot replace either. It returns independently
// owned parsed terms.
func VerifySignedFileQuote(quote *SignedFileQuote) (*FileQuoteTerms, error) {
	return verifySignedFileQuote(quote, protoclock.Now())
}

// VerifyFileQuoteEvidence 验证时间无关的报价证据：结构、CBOR、压缩公钥与
// DER 卖方签名。它不检查当前是否过期；过期判断由调用方用返回 terms 的
// QuoteExpiresAtUnix 与自己读取的一次时间完成。
func VerifyFileQuoteEvidence(quote *SignedFileQuote) (*FileQuoteTerms, error) {
	if quote == nil {
		return nil, fmt.Errorf("%w: signed file quote is required", ErrInvalidEvidence)
	}
	if len(quote.SellerPubkey) == 0 {
		return nil, fmt.Errorf("%w: seller pubkey is required", ErrInvalidEvidence)
	}
	if err := protocol.ValidateCompressedPubKey(quote.SellerPubkey); err != nil {
		return nil, fmt.Errorf("%w: seller pubkey: %v", ErrInvalidEvidence, err)
	}
	if len(quote.TermsSignature) == 0 {
		return nil, fmt.Errorf("%w: quote terms signature is required", ErrInvalidEvidence)
	}
	terms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, fmt.Errorf("%w: decode file quote terms: %v", ErrInvalidEvidence, err)
	}
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return nil, err
	}
	if err := VerifySignature(quote.SellerPubkey, quote.TermsCBOR, quote.TermsSignature); err != nil {
		return nil, fmt.Errorf("%w: quote terms signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, nil
}

// verifySignedFileQuote is the package-private pure helper taking an explicit
// now; it exists only so boundary tests stay deterministic without a public
// ...At variant.
func verifySignedFileQuote(quote *SignedFileQuote, at time.Time) (*FileQuoteTerms, error) {
	if quote == nil {
		return nil, fmt.Errorf("%w: signed file quote is required", ErrInvalidEvidence)
	}
	if len(quote.SellerPubkey) == 0 {
		return nil, fmt.Errorf("%w: seller pubkey is required", ErrInvalidEvidence)
	}
	if err := protocol.ValidateCompressedPubKey(quote.SellerPubkey); err != nil {
		return nil, fmt.Errorf("%w: seller pubkey: %v", ErrInvalidEvidence, err)
	}
	if len(quote.TermsSignature) == 0 {
		return nil, fmt.Errorf("%w: quote terms signature is required", ErrInvalidEvidence)
	}
	terms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, fmt.Errorf("%w: decode file quote terms: %v", ErrInvalidEvidence, err)
	}
	if err := validateFileQuoteTermsNotExpired(terms, at); err != nil {
		return nil, err
	}
	if err := VerifySignature(quote.SellerPubkey, quote.TermsCBOR, quote.TermsSignature); err != nil {
		return nil, fmt.Errorf("%w: quote terms signature invalid: %v", ErrInvalidEvidence, err)
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
	if err := protocol.ValidateCompressedPubKey(quote.SellerPubkey); err != nil {
		return nil, fmt.Errorf("seller pubkey: %w", err)
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
// expiry verification is intentionally separate so callers verify through the
// fixed VerifySignedFileQuote path.
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
	if len(terms.SeedHash) != masterseed.DigestSize {
		return fmt.Errorf("quote seed_hash length must be %d", masterseed.DigestSize)
	}
	if len(terms.BuyerPubkey) == 0 {
		return errors.New("quote buyer_pubkey is required")
	}
	if err := protocol.ValidateCompressedPubKey(terms.BuyerPubkey); err != nil {
		return fmt.Errorf("quote buyer_pubkey: %w", err)
	}
	if terms.FileSize == 0 {
		emptySeedHash := masterseed.Sum256(nil)
		if !bytes.Equal(terms.SeedHash, emptySeedHash.Bytes()) {
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

// validateFileQuoteTermsNotExpired additionally verifies that terms have not
// expired at the explicitly provided now. It is not part of the public API;
// public entries read UTC once and delegate here.
func validateFileQuoteTermsNotExpired(terms *FileQuoteTerms, at time.Time) error {
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return err
	}
	if !at.Before(time.Unix(terms.QuoteExpiresAtUnix, 0)) {
		return fmt.Errorf("%w: file quote is expired", ErrQuoteExpired)
	}
	return nil
}

// SanitizeRecommendedFilename converts unsigned display metadata into a safe
// single filename. It must be applied before displaying or using the value as
// a local path; the original field remains outside the quote's economic truth.
func SanitizeRecommendedFilename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "download"
	}
	return name
}

// ContentPriceSat derives the buyer-signed amount from the verified quote and
// the delivered content size. Full blocks use the quoted price. A tail block
// is charged proportionally, rounded up, with the specified 10% seller
// calculation allowance. The computation uses big integers so malformed
// uint64 prices cannot overflow into a lower amount.
func ContentPriceSat(terms *FileQuoteTerms, contentType ContentType, contentSize uint64) (uint64, error) {
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return 0, err
	}
	switch contentType {
	case ContentSeed:
		return terms.SeedPriceSat, nil
	case ContentBlock:
		if contentSize == 0 || contentSize > BlockSize {
			return 0, fmt.Errorf("invalid block content size %d", contentSize)
		}
		if contentSize == BlockSize {
			return terms.FullBlockPriceSat, nil
		}
		if terms.FullBlockPriceSat == 0 {
			return 0, nil
		}
		numerator := new(big.Int).SetUint64(terms.FullBlockPriceSat)
		numerator.Mul(numerator, new(big.Int).SetUint64(contentSize))
		numerator.Mul(numerator, big.NewInt(90))
		denominator := new(big.Int).SetUint64(BlockSize)
		denominator.Mul(denominator, big.NewInt(100))
		price := new(big.Int).Add(numerator, new(big.Int).Sub(denominator, big.NewInt(1)))
		price.Quo(price, denominator)
		if price.Sign() == 0 {
			price.SetUint64(1)
		}
		if !price.IsUint64() {
			return 0, errors.New("content price overflows uint64")
		}
		return price.Uint64(), nil
	default:
		return 0, fmt.Errorf("unsupported content type %d", contentType)
	}
}

func fileQuoteBlockCount(fileSize uint64) uint64 {
	return masterseed.BlockCountForSourceSize(fileSize)
}

func validateSupportedArbiterPubkeys(pubkeys [][]byte) error {
	for index, pubkey := range pubkeys {
		if err := protocol.ValidateCompressedPubKey(pubkey); err != nil {
			return fmt.Errorf("supported arbiter pubkey #%d: %w", index, err)
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
