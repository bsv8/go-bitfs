package bitfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
)

func TestContentRequestAndDeliveryRoundTrip(t *testing.T) {
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("block")
	contentHash := sha256.Sum256(content)
	quoteHash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   7,
		PaymentSequenceAfter:  8,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           contentHash[:],
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	requestCBOR, err := EncodeSignedContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := DecodeSignedContentRequest(requestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedRequest.TermsCBOR, request.TermsCBOR) {
		t.Fatal("request terms changed after round trip")
	}
	if _, err := VerifySignedContentRequest(decodedRequest, quote); err != nil {
		t.Fatalf("VerifySignedContentRequest() error = %v", err)
	}

	delivery, err := NewSignedContentDelivery(decodedRequest, content, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	deliveryCBOR, err := EncodeSignedContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	decodedDelivery, err := DecodeSignedContentDelivery(deliveryCBOR)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifySignedContentDelivery(decodedRequest, decodedDelivery, quote)
	if err != nil {
		t.Fatalf("VerifySignedContentDelivery() error = %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("verified content = %q, want %q", got, content)
	}
}

func TestContentIdentityKeysRequireCompressedEncoding(t *testing.T) {
	terms := &ContentRequestTerms{
		QuoteTermsHash: bytes.Repeat([]byte{1}, 32), RefundTemplateTxID: bytes.Repeat([]byte{2}, 32),
		BasePaymentSequence: 1, PaymentSequenceAfter: 2, SellerAmountAfterSat: 1,
		MinerFeeRateSatPerKB: 1, BuyerPubkey: quoteTestKey().PubKey().Uncompressed(),
		SellerPubkey: quoteTestPubkey(), SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType: ContentSeed, ContentHash: bytes.Repeat([]byte{3}, 32), DeliveryDeadlineUnix: quoteDeadline(t),
	}
	if _, err := EncodeContentRequestTerms(terms); err == nil {
		t.Fatal("uncompressed content buyer key was accepted")
	}
}

func TestStandaloneContentAuthorizationBindsEconomicTerms(t *testing.T) {
	terms := &ContentRequestTerms{
		QuoteTermsHash:        bytes.Repeat([]byte{0x01}, sha256.Size),
		RefundTemplateTxID:    bytes.Repeat([]byte{0x02}, sha256.Size),
		BasePaymentSequence:   3,
		PaymentSequenceAfter:  4,
		SellerAmountAfterSat:  125,
		MinerFeeRateSatPerKB:  100,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestOtherArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           bytes.Repeat([]byte{0x04}, sha256.Size),
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}
	request, err := NewSignedContentRequest(terms, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestStandalone(request); err != nil {
		t.Fatalf("standalone authorization rejected: %v", err)
	}

	terms.SellerAmountAfterSat++
	request.TermsCBOR, err = EncodeContentRequestTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestStandalone(request); err == nil {
		t.Fatal("standalone authorization accepted changed economic terms")
	}
}

func TestContentRequestRejectsWrongQuoteAndArbiter(t *testing.T) {
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	contentHash := sha256.Sum256([]byte("block"))
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		PaymentSequenceAfter:  2,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestOtherArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           contentHash[:],
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequest(request, quote); err == nil {
		t.Fatal("request with an unsupported arbiter was accepted")
	}
}

func TestContentDeliveryRejectsChangedPayload(t *testing.T) {
	quote := mustContentQuote(t, 1)
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	content := []byte("block")
	contentHash := sha256.Sum256(content)
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		PaymentSequenceAfter:  2,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           contentHash[:],
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := NewSignedContentDelivery(request, content, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	terms, err := DecodeContentDeliveryTerms(delivery.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms.ContentBytes = []byte("tampered")
	delivery.TermsCBOR, err = EncodeContentDeliveryTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentDelivery(request, delivery, quote); err == nil {
		t.Fatal("delivery with changed payload was accepted")
	}
}

func TestContentBlockMustBeCommittedByQuoteSeed(t *testing.T) {
	content := []byte("tail block")
	blockHash := sha256.Sum256(content)
	var seedBuffer bytes.Buffer
	_, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(content), &seedBuffer)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedBuffer.Bytes()
	seedHash := masterseed.Sum256(seed)
	terms := quoteTestTerms(t)
	terms.FileSize = uint64(len(content))
	terms.SeedHash = seedHash.Bytes()
	quote, err := NewSignedFileQuote(terms, quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	quoteHash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		PaymentSequenceAfter:  2,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           blockHash[:],
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestWithSeed(request, quote, seed); err != nil {
		t.Fatalf("committed block was rejected: %v", err)
	}
	delivery, err := NewSignedContentDelivery(request, content, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentDeliveryWithSeed(request, delivery, quote, seed); err != nil {
		t.Fatalf("committed block delivery was rejected: %v", err)
	}
	otherHash := sha256.Sum256([]byte("other block"))
	request.TermsCBOR, err = EncodeContentRequestTerms(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		PaymentSequenceAfter:  2,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           otherHash[:],
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestWithSeed(request, quote, seed); err == nil {
		t.Fatal("uncommitted block was accepted")
	}
}

func TestSeedDeliveryRequiresCanonicalSeedPayload(t *testing.T) {
	var seedBuffer bytes.Buffer
	_, err := masterseed.CreateSeed(context.Background(), bytes.NewReader([]byte("block")), &seedBuffer)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedBuffer.Bytes()
	seedHash := masterseed.Sum256(seed)
	terms := quoteTestTerms(t)
	terms.FileSize = 5
	terms.SeedHash = seedHash.Bytes()
	quote, err := NewSignedFileQuote(terms, quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		PaymentSequenceAfter:  2,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType:           ContentSeed,
		ContentHash:           seedHash.Bytes(),
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := NewSignedContentDelivery(request, seed, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentDeliveryWithSeed(request, delivery, quote, nil); err != nil {
		t.Fatalf("valid seed delivery was rejected: %v", err)
	}
}

func TestContentCBORVector(t *testing.T) {
	terms := &ContentRequestTerms{
		QuoteTermsHash:        bytes.Repeat([]byte{0x01}, sha256.Size),
		RefundTemplateTxID:    bytes.Repeat([]byte{0x02}, sha256.Size),
		BasePaymentSequence:   3,
		PaymentSequenceAfter:  4,
		SellerAmountAfterSat:  125,
		MinerFeeRateSatPerKB:  100,
		BuyerPubkey:           quoteTestPubkey(),
		SellerPubkey:          quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestOtherArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           bytes.Repeat([]byte{0x05}, sha256.Size),
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}
	raw, err := EncodeContentRequestTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(raw); got == "" {
		t.Fatal("empty content request vector")
	}
	if _, err := DecodeContentRequestTerms(raw); err != nil {
		t.Fatal(err)
	}
}

func TestContentRequestRejectsLegacyWeakTerms(t *testing.T) {
	terms := &ContentRequestTerms{
		QuoteTermsHash:        bytes.Repeat([]byte{1}, sha256.Size),
		RefundTemplateTxID:    bytes.Repeat([]byte{2}, sha256.Size),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(),
		ContentType:           ContentBlock,
		ContentHash:           bytes.Repeat([]byte{4}, sha256.Size),
		DeliveryDeadlineUnix:  quoteDeadline(t), // 与报价同刻或更晚由断言覆盖
	}
	if _, err := EncodeContentRequestTerms(terms); err == nil {
		t.Fatal("legacy weak content request terms were accepted")
	}
}

func TestMasterSeedErrorsMapToBitFSCategories(t *testing.T) {
	source := []byte("seed source")
	seed := createTestSeed(t, source)
	seedHash := masterseed.Sum256(seed)

	seedMismatch := quoteTestTerms(t)
	seedMismatch.FileSize = uint64(len(source))
	seedMismatch.SeedHash = bytes.Repeat([]byte{0x99}, masterseed.DigestSize)
	err := VerifyContentPayloadContext(context.Background(), seedMismatch, ContentSeed, seedMismatch.SeedHash, seed, nil, true)
	assertMasterSeedCode(t, err, masterseed.SeedHashMismatch)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("seed hash mismatch does not map to ErrInvalidEvidence: %v", err)
	}

	sizeMismatch := quoteTestTerms(t)
	sizeMismatch.FileSize = masterseed.BlockSize + 1
	sizeMismatch.SeedHash = seedHash.Bytes()
	err = VerifyContentPayloadContext(context.Background(), sizeMismatch, ContentSeed, sizeMismatch.SeedHash, seed, nil, true)
	assertMasterSeedCode(t, err, masterseed.SeedSizeMismatch)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("seed size mismatch does not map to ErrInvalidEvidence: %v", err)
	}

	blockTerms := quoteTestTerms(t)
	blockTerms.FileSize = uint64(len(source))
	blockTerms.SeedHash = seedHash.Bytes()
	other := []byte("uncommitted")
	otherHash := masterseed.Sum256(other)
	err = VerifyContentPayloadContext(context.Background(), blockTerms, ContentBlock, otherHash.Bytes(), other, seed, true)
	assertMasterSeedCode(t, err, masterseed.BlockNotInSeed)
	if !errors.Is(err, ErrContentNotInSeed) {
		t.Fatalf("block-not-in-seed does not map to ErrContentNotInSeed: %v", err)
	}

	short := []byte("x")
	shortSeed := createTestSeed(t, short)
	shortTerms := quoteTestTerms(t)
	shortTerms.FileSize = masterseed.BlockSize
	shortTerms.SeedHash = masterseed.Sum256(shortSeed).Bytes()
	shortHash := masterseed.Sum256(short)
	err = VerifyContentPayloadContext(context.Background(), shortTerms, ContentBlock, shortHash.Bytes(), short, shortSeed, true)
	assertMasterSeedCode(t, err, masterseed.BlockSizeMismatch)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("block size mismatch does not map to ErrInvalidEvidence: %v", err)
	}
}

func TestMasterSeedEmptyAndAlignedSeedPayloads(t *testing.T) {
	emptyTerms := quoteTestTerms(t)
	emptyTerms.FileSize = 0
	emptyTerms.SeedHash = masterseed.Sum256(nil).Bytes()
	if err := VerifyContentPayloadContext(context.Background(), emptyTerms, ContentSeed, emptyTerms.SeedHash, nil, nil, true); err != nil {
		t.Fatalf("empty seed payload rejected: %v", err)
	}

	alignedSource := bytes.Repeat([]byte{0x42}, masterseed.BlockSize)
	alignedSeed := createTestSeed(t, alignedSource)
	alignedTerms := quoteTestTerms(t)
	alignedTerms.FileSize = masterseed.BlockSize
	alignedTerms.SeedHash = masterseed.Sum256(alignedSeed).Bytes()
	if err := VerifyContentPayloadContext(context.Background(), alignedTerms, ContentSeed, alignedTerms.SeedHash, alignedSeed, nil, true); err != nil {
		t.Fatalf("aligned seed payload rejected: %v", err)
	}
}

func TestMasterSeedDuplicateHashReportsFirstLastAndTailSizes(t *testing.T) {
	blockHash := masterseed.Sum256([]byte("duplicate"))
	seed := bytes.Repeat(blockHash.Bytes(), 3)
	terms := quoteTestTerms(t)
	terms.FileSize = 2*masterseed.BlockSize + 1
	terms.SeedHash = masterseed.Sum256(seed).Bytes()
	matches, err := VerifyBlockReference(context.Background(), terms, blockHash.Bytes(), seed)
	if err != nil {
		t.Fatalf("duplicate hash reference rejected: %v", err)
	}
	if matches.MatchCount != 3 || matches.FirstIndex != 0 || matches.LastIndex != 2 {
		t.Fatalf("matches = %+v, want count=3 first=0 last=2", matches)
	}
	full, err := masterseed.ExpectedBlockSize(terms.FileSize, matches.FirstIndex)
	if err != nil || full != masterseed.BlockSize {
		t.Fatalf("first duplicate size = %d, %v", full, err)
	}
	tail, err := masterseed.ExpectedBlockSize(terms.FileSize, matches.LastIndex)
	if err != nil || tail != 1 {
		t.Fatalf("last duplicate tail size = %d, %v", tail, err)
	}
	err = VerifyContentPayloadContext(context.Background(), terms, ContentBlock, blockHash.Bytes(), []byte("duplicate"), seed, true)
	assertMasterSeedCode(t, err, masterseed.BlockSizeMismatch)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("nonmatching duplicate size does not map to ErrInvalidEvidence: %v", err)
	}
}

func TestMasterSeedContextCancellationIsNotInvalidEvidence(t *testing.T) {
	source := []byte("cancel me")
	seed := createTestSeed(t, source)
	seedHash := masterseed.Sum256(seed)
	terms := quoteTestTerms(t)
	terms.FileSize = uint64(len(source))
	terms.SeedHash = seedHash.Bytes()
	blockHash := masterseed.Sum256(source)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := VerifyContentPayloadContext(ctx, terms, ContentBlock, blockHash.Bytes(), source, seed, true)
	assertMasterSeedCode(t, err, masterseed.Aborted)
	if errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("context cancellation was classified as invalid evidence: %v", err)
	}
}

func createTestSeed(t *testing.T, source []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	if _, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(source), &output); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func assertMasterSeedCode(t *testing.T, err error, want masterseed.ErrorCode) {
	t.Helper()
	if err == nil || masterseed.CodeOf(err) != want {
		t.Fatalf("masterseed code = %q, err=%v, want %q", masterseed.CodeOf(err), err, want)
	}
}

func mustContentQuote(t *testing.T, fileSize uint64) *SignedFileQuote {
	t.Helper()
	terms := quoteTestTerms(t)
	terms.FileSize = fileSize
	quote, err := NewSignedFileQuote(terms, quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

func TestContentTermsRejectAllZeroRefundTemplateTxID(t *testing.T) {
	base := ContentRequestTerms{
		QuoteTermsHash:        bytes.Repeat([]byte{1}, sha256.Size),
		RefundTemplateTxID:    bytes.Repeat([]byte{2}, sha256.Size),
		BasePaymentSequence:   1,
		PaymentSequenceAfter:  2,
		SellerAmountAfterSat:  10,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           contentTestPubkey("11"),
		SellerPubkey:          contentTestPubkey("22"),
		SelectedArbiterPubkey: contentTestPubkey("33"),
		ContentType:           ContentSeed,
		ContentHash:           bytes.Repeat([]byte{4}, sha256.Size),
		DeliveryDeadlineUnix:  2_000_000_000,
	}
	zero := base
	zero.RefundTemplateTxID = make([]byte, sha256.Size)
	if err := ValidateContentRequestTerms(&zero); err == nil || !strings.Contains(err.Error(), "must not be all zero") {
		t.Fatalf("003 accepted all-zero refund_template_txid: %v", err)
	}
	if _, err := EncodeContentRequestTerms(&zero); err == nil {
		t.Fatal("003 encoder accepted all-zero refund_template_txid")
	}
	short := base
	short.RefundTemplateTxID = bytes.Repeat([]byte{2}, 31)
	if err := ValidateContentRequestTerms(&short); err == nil {
		t.Fatal("003 accepted 31-byte refund_template_txid")
	}
	delivery := ContentDeliveryTerms{
		RefundTemplateTxID:       bytes.Repeat([]byte{2}, sha256.Size),
		PaymentAuthorizationHash: bytes.Repeat([]byte{3}, sha256.Size),
		ContentBytes:             []byte("payload"),
	}
	if err := ValidateContentDeliveryTerms(&delivery); err != nil {
		t.Fatal(err)
	}
	zeroDelivery := delivery
	zeroDelivery.RefundTemplateTxID = make([]byte, sha256.Size)
	if err := ValidateContentDeliveryTerms(&zeroDelivery); err == nil || !strings.Contains(err.Error(), "must not be all zero") {
		t.Fatalf("004 accepted all-zero refund_template_txid: %v", err)
	}
	if _, err := EncodeContentDeliveryTerms(&zeroDelivery); err == nil {
		t.Fatal("004 encoder accepted all-zero refund_template_txid")
	}
	shortDelivery := delivery
	shortDelivery.RefundTemplateTxID = bytes.Repeat([]byte{2}, 33)
	if err := ValidateContentDeliveryTerms(&shortDelivery); err == nil {
		t.Fatal("004 accepted 33-byte refund_template_txid")
	}
	legacyDelivery, err := canonicalEnc.Marshal([]any{contentProtocolVersion, delivery.PaymentAuthorizationHash, delivery.ContentBytes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentDeliveryTerms(legacyDelivery); err == nil {
		t.Fatal("legacy three-element 004 content delivery terms decoded")
	}
}

func contentTestPubkey(hexKey string) []byte {
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexKey, 64)[:64])
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}
