package content

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/protocol"
)

func TestSignedFileQuoteRoundTripAndVerification(t *testing.T) {
	arbiters, err := EncodeSupportedArbiterPublicKeys([][]byte{quoteTestArbiterPubkey(), quoteTestOtherArbiterPubkey()})
	if err != nil {
		t.Fatalf("EncodeSupportedArbiterPublicKeys() error = %v", err)
	}
	terms := &FileQuoteTerms{
		SeedHash:                       bytes.Repeat([]byte{0x11}, sha256.Size),
		BuyerPublicKey:                 quoteTestPubkey(),
		SeedPriceSatoshis:              5,
		FullBlockPriceSatoshis:         100,
		FileSizeBytes:                  BlockSize + 7,
		QuoteExpiresAtUnixSeconds:      quoteTestFutureUnix(),
		SupportedArbiterPublicKeysCBOR: arbiters,
		RecommendedFilename:            "report.bin",
	}
	quote, err := NewSignedFileQuote(context.Background(), terms, quoteTestSigner())
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
	verified, err := VerifySignedFileQuote(decoded, time.Unix(quoteTestFutureUnix()-60, 0))
	if err != nil {
		t.Fatalf("VerifySignedFileQuote() error = %v", err)
	}
	if !bytes.Equal(verified.BuyerPublicKey, terms.BuyerPublicKey) || verified.FileSizeBytes != terms.FileSizeBytes {
		t.Fatalf("verified terms = %#v, want %#v", verified, terms)
	}
	hash, err := FileQuoteTermsID(decoded.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatalf("FileQuoteTermsID() error = %v", err)
	}
	if hash != sha256.Sum256(decoded.FileQuoteTermsCBOR) {
		t.Fatal("terms hash is not the canonical terms CBOR hash")
	}
}

func TestRecommendedFilenameIsSignedInsideTerms(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.RecommendedFilename = "original.bin"
	quote, err := NewSignedFileQuote(context.Background(), terms, quoteTestSigner())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFileQuoteTerms(quote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RecommendedFilename != "original.bin" {
		t.Fatalf("signed recommended filename = %q", decoded.RecommendedFilename)
	}
	// 文件名不同的两份报价必须产生不同的 file_quote_terms_id。
	renamed := quoteTestTerms(t)
	renamed.RecommendedFilename = "renamed-by-seller.bin"
	otherQuote, err := NewSignedFileQuote(context.Background(), renamed, quoteTestSigner())
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := FileQuoteTermsID(quote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := FileQuoteTermsID(otherQuote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatal("different filenames must yield different file_quote_terms_id values")
	}
	// 未经过 sanitize 规则的文件名不能进入条款：Buyer 只验证不改写。
	unsanitized := quoteTestTerms(t)
	unsanitized.RecommendedFilename = "../../escape.bin"
	if err := ValidateFileQuoteTerms(unsanitized); err == nil {
		t.Fatal("unsanitized recommended filename accepted")
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
	quote, err := NewSignedFileQuote(context.Background(), quoteTestTerms(t), quoteTestSigner())
	if err != nil {
		t.Fatal(err)
	}
	terms, err := DecodeFileQuoteTerms(quote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms.FullBlockPriceSatoshis++
	quote.FileQuoteTermsCBOR, err = EncodeFileQuoteTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedFileQuote(quote, time.Unix(quoteTestFutureUnix()-60, 0)); err == nil {
		t.Fatal("VerifySignedFileQuote() accepted changed terms")
	}
}

func TestFileQuoteTermsRejectsOversizedFile(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.FileSizeBytes = MaxQuoteFileSize + 1
	if err := ValidateFileQuoteTerms(terms); err == nil {
		t.Fatal("ValidateFileQuoteTerms() accepted a file whose seed cannot fit in one payload")
	}
}

func TestEmptyFileQuoteRequiresEmptySeedHash(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.FileSizeBytes = 0
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
	if _, err := EncodeSupportedArbiterPublicKeys([][]byte{duplicate, duplicate}); err == nil {
		t.Fatal("EncodeSupportedArbiterPublicKeys() accepted duplicate pubkeys")
	}
}

func TestProtocolIdentityKeysRequireCompressedEncoding(t *testing.T) {
	terms := quoteTestTerms(t)
	terms.BuyerPublicKey = quoteTestKey().PubKey().Uncompressed()
	if _, err := EncodeFileQuoteTerms(terms); err == nil {
		t.Fatal("uncompressed quote buyer key was accepted")
	}
	if _, err := EncodeSupportedArbiterPublicKeys([][]byte{quoteTestKey().PubKey().Uncompressed()}); err == nil {
		t.Fatal("uncompressed supported arbiter key was accepted")
	}
}

func quoteTestTerms(t *testing.T) *FileQuoteTerms {
	t.Helper()
	arbiters, err := EncodeSupportedArbiterPublicKeys([][]byte{quoteTestArbiterPubkey()})
	if err != nil {
		t.Fatal(err)
	}
	return &FileQuoteTerms{
		SeedHash:                       bytes.Repeat([]byte{0x11}, sha256.Size),
		BuyerPublicKey:                 quoteTestPubkey(),
		SeedPriceSatoshis:              1,
		FullBlockPriceSatoshis:         2,
		FileSizeBytes:                  1,
		QuoteExpiresAtUnixSeconds:      quoteTestFutureUnix(),
		SupportedArbiterPublicKeysCBOR: arbiters,
		RecommendedFilename:            "file.bin",
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

// quoteTestSigner 把报价测试私钥包装成受约束 Signer（新构造器唯一入口）。
func quoteTestSigner() *protocol.PrivateKeySigner {
	signer, err := protocol.NewPrivateKeySigner(quoteTestKey())
	if err != nil {
		panic(err)
	}
	return signer
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
