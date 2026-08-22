package bitfs

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestSignedFileQuoteRoundTripAndVerification(t *testing.T) {
	arbiters, err := EncodeSupportedArbiterPubkeys([][]byte{quoteTestArbiterPubkey(), quoteTestOtherArbiterPubkey()})
	if err != nil {
		t.Fatalf("EncodeSupportedArbiterPubkeys() error = %v", err)
	}
	terms := &FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{0x11}, sha256.Size),
		BuyerPubkey:                 quoteTestPubkey(),
		SeedPriceSat:                5,
		FullBlockPriceSat:           100,
		FileSize:                    BlockSize + 7,
		QuoteExpiresAtUnix:          quoteTestFutureUnix(),
		SupportedArbiterPubkeysCBOR: arbiters,
	}
	quote, err := NewSignedFileQuote(terms, quoteTestKey(), "report.bin")
	if err != nil {
		t.Fatalf("NewSignedFileQuote() error = %v", err)
	}
	encoded, err := EncodeSignedFileQuote(quote)
	if err != nil {
		t.Fatalf("EncodeSignedFileQuote() error = %v", err)
	}
	decoded, err := DecodeSignedFileQuote(encoded)
	if err != nil {
		t.Fatalf("DecodeSignedFileQuote() error = %v", err)
	}
	verified, err := VerifySignedFileQuote(decoded)
	if err != nil {
		t.Fatalf("VerifySignedFileQuote() error = %v", err)
	}
	if !bytes.Equal(verified.BuyerPubkey, terms.BuyerPubkey) || verified.FileSize != terms.FileSize {
		t.Fatalf("verified terms = %#v, want %#v", verified, terms)
	}
	hash, err := FileQuoteTermsHash(decoded.TermsCBOR)
	if err != nil {
		t.Fatalf("FileQuoteTermsHash() error = %v", err)
	}
	if hash != sha256.Sum256(decoded.TermsCBOR) {
		t.Fatal("terms hash is not the canonical terms CBOR hash")
	}
}

func TestRecommendedFilenameIsNotSigned(t *testing.T) {
	terms := quoteTestTerms(t)
	quote, err := NewSignedFileQuote(terms, quoteTestKey(), "original.bin")
	if err != nil {
		t.Fatal(err)
	}
	quote.RecommendedFilename = "renamed-by-relay.bin"
	if _, err := VerifySignedFileQuote(quote); err != nil {
		t.Fatalf("unsigned filename unexpectedly invalidated terms signature: %v", err)
	}
}

func TestSanitizeRecommendedFilename(t *testing.T) {
	if got := SanitizeRecommendedFilename("../../secret.txt"); got != "secret.txt" {
		t.Fatalf("sanitized filename = %q", got)
	}
	if got := SanitizeRecommendedFilename("..\\secret.txt"); got != "secret.txt" {
		t.Fatalf("sanitized Windows filename = %q", got)
	}
	if got := SanitizeRecommendedFilename("../"); got != "download" {
		t.Fatalf("invalid filename fallback = %q", got)
	}
}

func TestSignedFileQuoteRejectsChangedTerms(t *testing.T) {
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestKey(), "f")
	if err != nil {
		t.Fatal(err)
	}
	terms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms.FullBlockPriceSat++
	quote.TermsCBOR, err = EncodeFileQuoteTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedFileQuote(quote); err == nil {
		t.Fatal("VerifySignedFileQuote() accepted changed terms")
	}
}

func TestFileQuoteTermsRejectsOversizedFile(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.FileSize = MaxQuoteFileSize + 1
	if err := ValidateFileQuoteTerms(terms); err == nil {
		t.Fatal("ValidateFileQuoteTerms() accepted a file whose seed cannot fit in one payload")
	}
}

func TestEmptyFileQuoteRequiresEmptySeedHash(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.FileSize = 0
	if err := ValidateFileQuoteTerms(terms); err == nil {
		t.Fatal("ValidateFileQuoteTerms() accepted a non-empty seed hash for an empty file")
	}
	emptySeedHash := sha256.Sum256(nil)
	terms.SeedHash = emptySeedHash[:]
	if err := ValidateFileQuoteTerms(terms); err != nil {
		t.Fatalf("ValidateFileQuoteTerms() rejected a valid empty file: %v", err)
	}
}

func TestSupportedArbiterPubkeysRejectDuplicates(t *testing.T) {
	duplicate := quoteTestArbiterPubkey()
	if _, err := EncodeSupportedArbiterPubkeys([][]byte{duplicate, duplicate}); err == nil {
		t.Fatal("EncodeSupportedArbiterPubkeys() accepted duplicate pubkeys")
	}
}

func TestProtocolIdentityKeysRequireCompressedEncoding(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.BuyerPubkey = quoteTestKey().PubKey().Uncompressed()
	if _, err := EncodeFileQuoteTerms(terms); err == nil {
		t.Fatal("uncompressed quote buyer key was accepted")
	}
	if _, err := EncodeSupportedArbiterPubkeys([][]byte{quoteTestKey().PubKey().Uncompressed()}); err == nil {
		t.Fatal("uncompressed supported arbiter key was accepted")
	}
}

func quoteTestTerms(t *testing.T) *FileQuoteTerms {
	t.Helper()
	arbiters, err := EncodeSupportedArbiterPubkeys([][]byte{quoteTestArbiterPubkey()})
	if err != nil {
		t.Fatal(err)
	}
	return &FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{0x11}, sha256.Size),
		BuyerPubkey:                 quoteTestPubkey(),
		SeedPriceSat:                1,
		FullBlockPriceSat:           2,
		FileSize:                    1,
		QuoteExpiresAtUnix:          quoteTestFutureUnix(),
		SupportedArbiterPubkeysCBOR: arbiters,
	}
}

// quoteTestFutureUnix returns a UTC timestamp safely in the future so tests
// stay deterministic without an injectable clock.
func quoteTestFutureUnix() int64 { return time.Now().UTC().Add(time.Hour).Unix() }

func quoteTestKey() *ec.PrivateKey {
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("11"), 32)))
	if err != nil {
		panic(err)
	}
	return key
}

func quoteTestPubkey() []byte { return quoteTestKey().PubKey().Compressed() }

func quoteTestArbiterPubkey() []byte {
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("12"), 32)))
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}

func quoteTestOtherArbiterPubkey() []byte {
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("13"), 32)))
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}
