package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestSignedFileQuoteRoundTripAndVerification(t *testing.T) {
	arbiters, err := EncodeSupportedArbiterPubkeys([][]byte{{0x02, 0x01}, {0x03, 0x02}})
	if err != nil {
		t.Fatalf("EncodeSupportedArbiterPubkeys() error = %v", err)
	}
	terms := &FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{0x11}, sha256.Size),
		BuyerPubkey:                 []byte{0x02, 0x99},
		SeedPriceSat:                5,
		FullBlockPriceSat:           100,
		FileSize:                    BlockSize + 7,
		QuoteExpiresAtUnix:          200,
		SupportedArbiterPubkeysCBOR: arbiters,
	}
	quote, err := NewSignedFileQuote(terms, []byte{0x03, 0x88}, "report.bin", quoteTestSigner)
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
	verified, err := VerifySignedFileQuoteAt(decoded, time.Unix(100, 0), quoteTestVerifier)
	if err != nil {
		t.Fatalf("VerifySignedFileQuoteAt() error = %v", err)
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
	quote, err := NewSignedFileQuote(terms, []byte{0x03}, "original.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	quote.RecommendedFilename = "renamed-by-relay.bin"
	if _, err := VerifySignedFileQuoteAt(quote, time.Unix(100, 0), quoteTestVerifier); err != nil {
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
	quote, err := NewSignedFileQuote(quoteTestTerms(t), []byte{0x03}, "f", quoteTestSigner)
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
	if _, err := VerifySignedFileQuoteAt(quote, time.Unix(100, 0), quoteTestVerifier); err == nil {
		t.Fatal("VerifySignedFileQuoteAt() accepted changed terms")
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
	if _, err := EncodeSupportedArbiterPubkeys([][]byte{{0x02}, {0x02}}); err == nil {
		t.Fatal("EncodeSupportedArbiterPubkeys() accepted duplicate pubkeys")
	}
}

func quoteTestTerms(t *testing.T) *FileQuoteTerms {
	t.Helper()
	arbiters, err := EncodeSupportedArbiterPubkeys([][]byte{{0x02}})
	if err != nil {
		t.Fatal(err)
	}
	return &FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{0x11}, sha256.Size),
		BuyerPubkey:                 []byte{0x02},
		SeedPriceSat:                1,
		FullBlockPriceSat:           2,
		FileSize:                    1,
		QuoteExpiresAtUnix:          200,
		SupportedArbiterPubkeysCBOR: arbiters,
	}
}

func quoteTestSigner(termsCBOR []byte) ([]byte, error) {
	digest := sha256.Sum256(termsCBOR)
	return digest[:], nil
}

func quoteTestVerifier(_ []byte, termsCBOR, signature []byte) error {
	digest := sha256.Sum256(termsCBOR)
	if !bytes.Equal(digest[:], signature) {
		return errors.New("test signature does not match terms")
	}
	return nil
}
