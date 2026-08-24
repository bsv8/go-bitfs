package bitfs

import (
	"bytes"
	"context"
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

// fileQuoteWireVersion and fileQuoteWireKind fix the Kind 1 signature context.
// The encoder injects the same outer pair into the complete wire message.
const (
	fileQuoteWireVersion = protocol.WireVersion
	fileQuoteWireKind    = uint64(1)
)

// MaxQuoteSeedBlocks is the greatest block count whose seed fits the BitFS
// payload limit. A seed contains one 32-byte hash for each block.
const MaxQuoteSeedBlocks uint64 = masterseed.BlockSize / masterseed.DigestSize

// MaxQuoteFileSize is the largest file a quote can describe while the seed is
// delivered in one BitFS payload.
const MaxQuoteFileSize uint64 = MaxQuoteSeedBlocks * BlockSize

// EncodeSupportedArbiterPublicKeys returns the sole allowed representation of
// the supported-arbiter child structure.
func EncodeSupportedArbiterPublicKeys(publicKeys [][]byte) ([]byte, error) {
	if err := validateSupportedArbiterPublicKeys(publicKeys); err != nil {
		return nil, err
	}
	if publicKeys == nil {
		publicKeys = [][]byte{}
	}
	return canonicalEnc.Marshal(publicKeys)
}

// DecodeSupportedArbiterPublicKeys validates and decodes a canonical
// supported-arbiter child structure.
func DecodeSupportedArbiterPublicKeys(data []byte) ([][]byte, error) {
	var publicKeys [][]byte
	if err := strictDec.Unmarshal(data, &publicKeys); err != nil {
		return nil, fmt.Errorf("decode supported arbiter public keys: %w", err)
	}
	if err := validateSupportedArbiterPublicKeys(publicKeys); err != nil {
		return nil, err
	}
	canonical, err := EncodeSupportedArbiterPublicKeys(publicKeys)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("supported arbiter public keys CBOR is not deterministically encoded")
	}
	return cloneByteSlices(publicKeys), nil
}

// EncodeFileQuoteTerms returns the exact canonical CBOR bytes signed by a
// seller. The authenticated document contains business fields only; version
// and kind live exclusively in the outer [1, 1, ...] wire message.
func EncodeFileQuoteTerms(terms *FileQuoteTerms) ([]byte, error) {
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		bstr(terms.SeedHash),
		bstr(terms.BuyerPublicKey),
		terms.SeedPriceSatoshis,
		terms.FullBlockPriceSatoshis,
		terms.FileSizeBytes,
		terms.QuoteExpiresAtUnixSeconds,
		bstr(terms.SupportedArbiterPublicKeysCBOR),
		terms.RecommendedFilename,
	})
}

// DecodeFileQuoteTerms validates and decodes canonical FileQuoteTerms bytes.
func DecodeFileQuoteTerms(data []byte) (*FileQuoteTerms, error) {
	values, err := decodeArray(data, 8)
	if err != nil {
		return nil, fmt.Errorf("decode file quote terms: %w", err)
	}
	terms := new(FileQuoteTerms)
	if err := decode(values[0], &terms.SeedHash); err != nil {
		return nil, err
	}
	if err := decode(values[1], &terms.BuyerPublicKey); err != nil {
		return nil, err
	}
	if err := decode(values[2], &terms.SeedPriceSatoshis); err != nil {
		return nil, err
	}
	if err := decode(values[3], &terms.FullBlockPriceSatoshis); err != nil {
		return nil, err
	}
	if err := decode(values[4], &terms.FileSizeBytes); err != nil {
		return nil, err
	}
	if err := decode(values[5], &terms.QuoteExpiresAtUnixSeconds); err != nil {
		return nil, err
	}
	if err := decode(values[6], &terms.SupportedArbiterPublicKeysCBOR); err != nil {
		return nil, err
	}
	if err := decode(values[7], &terms.RecommendedFilename); err != nil {
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

// FileQuoteTermsID returns SHA-256 over the exact canonical quote terms. It
// lives in the Kind 1 document ID namespace and anchors every later payment
// authorization to one quote.
func FileQuoteTermsID(termsCBOR []byte) (protocol.FileQuoteTermsID, error) {
	if _, err := DecodeFileQuoteTerms(termsCBOR); err != nil {
		return protocol.FileQuoteTermsID{}, err
	}
	digest := sha256.Sum256(termsCBOR)
	return protocol.FileQuoteTermsID(digest), nil
}

// NewSignedFileQuote validates quote terms, encodes the canonical FileQuoteTermsCBOR,
// signs those exact bytes through the unified SignWireDocument(1, 1, ...)
// helper, and fixedly re-verifies the signature with the derived public key
// before returning a portable Kind 1 credential. The recommended filename is
// sanitized first, then folded into the signed terms; the private key never
// enters any wire message, local result, log, or persisted structure.
func NewSignedFileQuote(terms *FileQuoteTerms, sellerKey *ec.PrivateKey, recommendedFilename string) (*SignedFileQuote, error) {
	if sellerKey == nil {
		return nil, errors.New("seller private key is required")
	}
	sellerPublicKey := sellerKey.PubKey().Compressed()
	if err := protocol.ValidateCompressedPubKey(sellerPublicKey); err != nil {
		return nil, fmt.Errorf("seller public key: %w", err)
	}
	signedTerms := cloneFileQuoteTerms(terms)
	if signedTerms == nil {
		signedTerms = new(FileQuoteTerms)
	}
	signedTerms.RecommendedFilename = SanitizeRecommendedFilename(recommendedFilename)
	termsCBOR, err := EncodeFileQuoteTerms(signedTerms)
	if err != nil {
		return nil, err
	}
	signature, err := protocol.SignWireDocument(sellerKey, fileQuoteWireVersion, fileQuoteWireKind, termsCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign file quote terms: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("file quote terms signature is required")
	}
	if err := protocol.VerifyWireDocument(sellerPublicKey, fileQuoteWireVersion, fileQuoteWireKind, termsCBOR, signature); err != nil {
		return nil, fmt.Errorf("%w: file quote terms signature invalid: %v", ErrInvalidEvidence, err)
	}
	return &SignedFileQuote{
		FileQuoteTermsCBOR:            append([]byte(nil), termsCBOR...),
		SellerPublicKey:               append([]byte(nil), sellerPublicKey...),
		SellerFileQuoteTermsSignature: append([]byte(nil), signature...),
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
// 统一 SignWireDocument(1, 1, ...) 卖方签名。它不检查当前是否过期；过期判断
// 由调用方用返回 terms 的 QuoteExpiresAtUnixSeconds 与自己读取的一次时间完成。
func VerifyFileQuoteEvidence(quote *SignedFileQuote) (*FileQuoteTerms, error) {
	if quote == nil {
		return nil, fmt.Errorf("%w: signed file quote is required", ErrInvalidEvidence)
	}
	if len(quote.SellerPublicKey) == 0 {
		return nil, fmt.Errorf("%w: seller public key is required", ErrInvalidEvidence)
	}
	if err := protocol.ValidateCompressedPubKey(quote.SellerPublicKey); err != nil {
		return nil, fmt.Errorf("%w: seller public key: %v", ErrInvalidEvidence, err)
	}
	if len(quote.SellerFileQuoteTermsSignature) == 0 {
		return nil, fmt.Errorf("%w: file quote terms signature is required", ErrInvalidEvidence)
	}
	terms, err := DecodeFileQuoteTerms(quote.FileQuoteTermsCBOR)
	if err != nil {
		return nil, fmt.Errorf("%w: decode file quote terms: %v", ErrInvalidEvidence, err)
	}
	if err := ValidateFileQuoteTerms(terms); err != nil {
		return nil, err
	}
	if err := protocol.VerifyWireDocument(quote.SellerPublicKey, fileQuoteWireVersion, fileQuoteWireKind, quote.FileQuoteTermsCBOR, quote.SellerFileQuoteTermsSignature); err != nil {
		return nil, fmt.Errorf("%w: file quote terms signature invalid: %v", ErrInvalidEvidence, err)
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
	if len(quote.SellerPublicKey) == 0 {
		return nil, fmt.Errorf("%w: seller public key is required", ErrInvalidEvidence)
	}
	if err := protocol.ValidateCompressedPubKey(quote.SellerPublicKey); err != nil {
		return nil, fmt.Errorf("%w: seller public key: %v", ErrInvalidEvidence, err)
	}
	if len(quote.SellerFileQuoteTermsSignature) == 0 {
		return nil, fmt.Errorf("%w: file quote terms signature is required", ErrInvalidEvidence)
	}
	terms, err := DecodeFileQuoteTerms(quote.FileQuoteTermsCBOR)
	if err != nil {
		return nil, fmt.Errorf("%w: decode file quote terms: %v", ErrInvalidEvidence, err)
	}
	if err := validateFileQuoteTermsNotExpired(terms, at); err != nil {
		return nil, err
	}
	if err := protocol.VerifyWireDocument(quote.SellerPublicKey, fileQuoteWireVersion, fileQuoteWireKind, quote.FileQuoteTermsCBOR, quote.SellerFileQuoteTermsSignature); err != nil {
		return nil, fmt.Errorf("%w: file quote terms signature invalid: %v", ErrInvalidEvidence, err)
	}
	return terms, nil
}

// EncodeSignedFileQuote returns the complete Kind 1 wire message:
// [1, 1, terms_cbor, seller_public_key, seller_file_quote_terms_signature].
func EncodeSignedFileQuote(quote *SignedFileQuote) ([]byte, error) {
	if quote == nil {
		return nil, errors.New("signed file quote is required")
	}
	if len(quote.SellerPublicKey) == 0 {
		return nil, errors.New("seller public key is required")
	}
	if err := protocol.ValidateCompressedPubKey(quote.SellerPublicKey); err != nil {
		return nil, fmt.Errorf("seller public key: %w", err)
	}
	if len(quote.SellerFileQuoteTermsSignature) == 0 {
		return nil, errors.New("file quote terms signature is required")
	}
	if _, err := DecodeFileQuoteTerms(quote.FileQuoteTermsCBOR); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal([]any{
		fileQuoteWireVersion,
		fileQuoteWireKind,
		bstr(quote.FileQuoteTermsCBOR),
		bstr(quote.SellerPublicKey),
		bstr(quote.SellerFileQuoteTermsSignature),
	})
}

// DecodeSignedFileQuote decodes one canonical Kind 1 wire message. Signature
// and expiry verification is intentionally separate so callers verify through
// the fixed VerifySignedFileQuote path.
func DecodeSignedFileQuote(data []byte) (*SignedFileQuote, error) {
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("decode signed file quote: %w", err)
	}
	var version, kind uint64
	quote := new(SignedFileQuote)
	if err := decode(values[0], &version); err != nil || version != fileQuoteWireVersion {
		return nil, errors.New("unsupported signed file quote wire version")
	}
	if err := decode(values[1], &kind); err != nil || kind != fileQuoteWireKind {
		return nil, errors.New("signed file quote wire kind must be 1")
	}
	if err := decode(values[2], &quote.FileQuoteTermsCBOR); err != nil {
		return nil, err
	}
	if err := decode(values[3], &quote.SellerPublicKey); err != nil {
		return nil, err
	}
	if err := decode(values[4], &quote.SellerFileQuoteTermsSignature); err != nil {
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
// seller signature. The recommended filename must already satisfy the single
// sanitize rule: sellers sanitize before encoding and signing, buyers only
// verify that the received field obeys the same rule and never rewrite it.
func ValidateFileQuoteTerms(terms *FileQuoteTerms) error {
	if terms == nil {
		return errors.New("file quote terms are required")
	}
	if len(terms.SeedHash) != masterseed.DigestSize {
		return fmt.Errorf("quote seed_hash length must be %d", masterseed.DigestSize)
	}
	if len(terms.BuyerPublicKey) == 0 {
		return errors.New("quote buyer_public_key is required")
	}
	if err := protocol.ValidateCompressedPubKey(terms.BuyerPublicKey); err != nil {
		return fmt.Errorf("quote buyer_public_key: %w", err)
	}
	if terms.FileSizeBytes == 0 {
		emptySeedHash := masterseed.Sum256(nil)
		if !bytes.Equal(terms.SeedHash, emptySeedHash.Bytes()) {
			return errors.New("empty-file quote seed_hash must equal sha256 of empty seed")
		}
	}
	if terms.QuoteExpiresAtUnixSeconds <= 0 {
		return errors.New("quote expires_at_unix_seconds is required")
	}
	if fileQuoteBlockCount(terms.FileSizeBytes) > MaxQuoteSeedBlocks {
		return fmt.Errorf("quote file_size_bytes exceeds maximum %d", MaxQuoteFileSize)
	}
	if _, err := DecodeSupportedArbiterPublicKeys(terms.SupportedArbiterPublicKeysCBOR); err != nil {
		return err
	}
	if SanitizeRecommendedFilename(terms.RecommendedFilename) != terms.RecommendedFilename {
		return errors.New("recommended_filename does not satisfy the sanitize rule")
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
	if !at.Before(time.Unix(terms.QuoteExpiresAtUnixSeconds, 0)) {
		return fmt.Errorf("%w: file quote is expired", ErrQuoteExpired)
	}
	return nil
}

// SanitizeRecommendedFilename converts the seller-supplied display name into a
// safe single filename. Sellers must apply it before encoding and signing the
// terms; receivers use the identical rule to reject any field that was not
// sanitized upstream instead of silently rewriting signed bytes.
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

// ContentHashesPriceSatoshis derives the aggregate buyer-signed amount for an
// ordered batch of content hashes against the verified quote. Each hash equal
// to the quote SeedHash is priced at SeedPriceSatoshis; every other hash must
// be found in the verified seed and is priced at its position's protocol
// expected length (full blocks at FullBlockPriceSatoshis, tail blocks with the
// proportional round-up and the specified 10% seller allowance). Duplicate
// block positions behind one hash are charged once; matches with conflicting
// expected lengths reject the batch. The total is accumulated with checked
// addition so any overflow fails before signing instead of wrapping.
func ContentHashesPriceSatoshis(terms *FileQuoteTerms, contentHashes [][]byte, seed []byte) (uint64, error) {
	// 导出入口自身 fail-closed：数量上限、哈希宽度与重复检查不依赖调用方
	// 先行经过 Encode/Decode。
	if err := validateContentHashes(contentHashes); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	items, err := classifyContentHashes(context.Background(), terms, contentHashes, seed)
	if err != nil {
		return 0, err
	}
	total := uint64(0)
	for _, item := range items {
		price := terms.SeedPriceSatoshis
		if !item.IsSeed {
			price, err = blockPriceSatoshis(terms.FullBlockPriceSatoshis, item.BlockSize)
			if err != nil {
				return 0, err
			}
		}
		if total > ^uint64(0)-price {
			return 0, fmt.Errorf("%w: aggregate content price overflows uint64", ErrInvalidEvidence)
		}
		total += price
	}
	return total, nil
}

// blockPriceSatoshis prices one block by its protocol expected length using
// big integers so malformed uint64 prices cannot overflow into a lower amount.
func blockPriceSatoshis(fullBlockPriceSatoshis, blockSize uint64) (uint64, error) {
	if blockSize == 0 || blockSize > BlockSize {
		return 0, fmt.Errorf("invalid block expected size %d", blockSize)
	}
	if blockSize == BlockSize {
		return fullBlockPriceSatoshis, nil
	}
	if fullBlockPriceSatoshis == 0 {
		return 0, nil
	}
	numerator := new(big.Int).SetUint64(fullBlockPriceSatoshis)
	numerator.Mul(numerator, new(big.Int).SetUint64(blockSize))
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
}

func fileQuoteBlockCount(fileSizeBytes uint64) uint64 {
	return masterseed.BlockCountForSourceSize(fileSizeBytes)
}

func validateSupportedArbiterPublicKeys(publicKeys [][]byte) error {
	for index, publicKey := range publicKeys {
		if err := protocol.ValidateCompressedPubKey(publicKey); err != nil {
			return fmt.Errorf("supported arbiter public key #%d: %w", index, err)
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(publicKeys[previous], publicKey) {
				return fmt.Errorf("supported arbiter public key #%d is duplicated", index)
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
	cloned.BuyerPublicKey = append([]byte(nil), terms.BuyerPublicKey...)
	cloned.SupportedArbiterPublicKeysCBOR = append([]byte(nil), terms.SupportedArbiterPublicKeysCBOR...)
	return &cloned
}

func cloneSignedFileQuote(quote *SignedFileQuote) *SignedFileQuote {
	if quote == nil {
		return nil
	}
	cloned := *quote
	cloned.FileQuoteTermsCBOR = append([]byte(nil), quote.FileQuoteTermsCBOR...)
	cloned.SellerPublicKey = append([]byte(nil), quote.SellerPublicKey...)
	cloned.SellerFileQuoteTermsSignature = append([]byte(nil), quote.SellerFileQuoteTermsSignature...)
	return &cloned
}
