package bitfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
)

// contentTestOpening 是 PoolOpeningEvidence 的测试实现：模拟应用从本地保存的
// OpeningProof 提供角色公钥与统一关联 ID。
type contentTestOpening struct {
	buyer, seller, arbiter, txid []byte
}

func (o *contentTestOpening) OpeningBuyerPubKey() []byte        { return o.buyer }
func (o *contentTestOpening) OpeningSellerPubKey() []byte       { return o.seller }
func (o *contentTestOpening) OpeningArbiterPubKey() []byte      { return o.arbiter }
func (o *contentTestOpening) OpeningRefundTemplateTxID() []byte { return o.txid }

func contentBatchOpening(quote *SignedFileQuote, refundTxID []byte) *contentTestOpening {
	return &contentTestOpening{buyer: quoteTestPubkey(), seller: quote.SellerPubkey, arbiter: quoteTestArbiterPubkey(), txid: refundTxID}
}

func contentBatchRequestTerms(t *testing.T, quote *SignedFileQuote, hashes [][]byte, sequence uint32, amount uint64) *ContentRequestTerms {
	t.Helper()
	quoteHash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	hashesCBOR, err := EncodeContentHashes(hashes)
	if err != nil {
		t.Fatal(err)
	}
	return &ContentRequestTerms{
		QuoteTermsHash:       quoteHash[:],
		RefundTemplateTxID:   bytes.Repeat([]byte{0x09}, sha256.Size),
		PaymentSequence:      sequence,
		SellerAmountAfterSat: amount,
		ContentHashesCBOR:    hashesCBOR,
		DeliveryDeadlineUnix: quoteDeadline(t),
	}
}

func mustBatchQuote(t *testing.T) *SignedFileQuote {
	t.Helper()
	quote, _, _ := mustSeededQuote(t, []byte("block"))
	return quote
}

// mustSeededQuote 建立一条绑定真实 seed 的报价：source 的长度与 seed hash 都
// 写进报价条款，返回报价、seed 和条款。
func mustSeededQuote(t *testing.T, source []byte) (*SignedFileQuote, []byte, *FileQuoteTerms) {
	t.Helper()
	seed := createTestSeed(t, source)
	terms := quoteTestTerms(t)
	terms.FileSize = uint64(len(source))
	terms.SeedHash = masterseed.Sum256(seed).Bytes()
	quote, err := NewSignedFileQuote(terms, quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote, seed, terms
}

func TestContentRequestAndDeliveryBatchRoundTrip(t *testing.T) {
	source := []byte("block")
	quote, _, _ := mustSeededQuote(t, source)
	seedHash := masterseed.Sum256(createTestSeed(t, source))
	request, err := NewSignedContentRequest(contentBatchRequestTerms(t, quote, [][]byte{seedHash.Bytes()}, 3, 10), quoteTestKey())
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
	if !bytes.Equal(decodedRequest.TermsCBOR, request.TermsCBOR) || !bytes.Equal(decodedRequest.BuyerSignature, request.BuyerSignature) {
		t.Fatal("request changed after round trip")
	}
	opening := contentBatchOpening(quote, bytes.Repeat([]byte{0x09}, sha256.Size))
	if _, err := VerifySignedContentRequest(decodedRequest, quote, opening); err != nil {
		t.Fatalf("VerifySignedContentRequest() error = %v", err)
	}
	authHash, err := PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if authHash != Hash32(sha256.Sum256(request.TermsCBOR)) {
		t.Fatal("authorization hash is not the SHA-256 of the exact terms CBOR")
	}

	delivery, err := NewSignedContentDelivery(authHash[:], [][]byte{createTestSeed(t, source)}, mustSellerDeliveryKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// 卖方签名必须只覆盖精确 32 字节哈希；验证由调用方用 OpeningProof 的
	// SellerPubKey 完成。
	if err := VerifySignature(mustSellerDeliveryKey(t).PubKey().Compressed(), authHash[:], delivery.SellerPaymentAuthorizationHashSignature); err != nil {
		t.Fatalf("bare-hash signature verification failed: %v", err)
	}
	deliveryCBOR, err := EncodeSignedContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	decodedDelivery, err := DecodeSignedContentDelivery(deliveryCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedDelivery.PaymentAuthorizationHash, authHash[:]) {
		t.Fatal("delivery authorization hash changed after round trip")
	}
	payloads, err := DecodeContentPayloads(decodedDelivery.ContentPayloadsCBOR)
	if err != nil || len(payloads) != 1 {
		t.Fatalf("decoded payload batch = %v, %v", payloads, err)
	}
}

func mustSellerDeliveryKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat("22", 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDecodeContentRequestTermsRejectsLegacyShapes(t *testing.T) {
	valid := contentBatchRequestTerms(t, mustBatchQuote(t), [][]byte{bytes.Repeat([]byte{1}, sha256.Size)}, 3, 10)
	canonical, err := EncodeContentRequestTerms(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentRequestTerms(canonical); err != nil {
		t.Fatalf("canonical six-element terms rejected: %v", err)
	}
	legacyThirteen := append([]any{uint64(4)},
		bstr(bytes.Repeat([]byte{1}, sha256.Size)), bstr(bytes.Repeat([]byte{2}, sha256.Size)),
		uint64(2), uint64(3), uint64(10), uint64(1),
		bstr(quoteTestPubkey()), bstr(quoteTestPubkey()), bstr(quoteTestArbiterPubkey()),
		uint64(0), bstr(bytes.Repeat([]byte{5}, sha256.Size)), int64(valid.DeliveryDeadlineUnix))
	legacyRaw, err := canonicalEnc.Marshal(legacyThirteen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentRequestTerms(legacyRaw); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("legacy thirteen-element terms decoded: %v", err)
	}
	innerVersion := append([]any{uint64(4)},
		bstr(bytes.Repeat([]byte{1}, sha256.Size)), bstr(bytes.Repeat([]byte{2}, sha256.Size)),
		uint64(3), uint64(10), bstr(canonical[len(canonical):len(canonical)]), int64(valid.DeliveryDeadlineUnix))
	innerVersion[5] = valid.ContentHashesCBOR
	innerVersionRaw, err := canonicalEnc.Marshal(innerVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentRequestTerms(innerVersionRaw); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("terms with an inner version decoded: %v", err)
	}
	legacySingleHash, err := canonicalEnc.Marshal([]any{
		bstr(valid.QuoteTermsHash), bstr(valid.RefundTemplateTxID), uint64(3), uint64(10),
		bstr(bytes.Repeat([]byte{5}, sha256.Size)), int64(valid.DeliveryDeadlineUnix)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentRequestTerms(legacySingleHash); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("legacy single-hash terms decoded: %v", err)
	}
	sevenRaw, err := canonicalEnc.Marshal([]any{
		bstr(valid.QuoteTermsHash), bstr(valid.RefundTemplateTxID), uint64(3), uint64(10),
		bstr(valid.ContentHashesCBOR), int64(valid.DeliveryDeadlineUnix), uint64(0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentRequestTerms(sevenRaw); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("seven-element terms decoded: %v", err)
	}
}

func TestDecodeSignedContentDeliveryRejectsLegacyShape(t *testing.T) {
	legacyRaw, err := canonicalEnc.Marshal([]any{
		contentProtocolVersion,
		bstr(contentBatchRequestTerms(t, mustBatchQuote(t), [][]byte{bytes.Repeat([]byte{1}, sha256.Size)}, 3, 10).ContentHashesCBOR),
		bstr(bytes.Repeat([]byte{7}, 70)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSignedContentDelivery(legacyRaw); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("legacy three-element delivery decoded: %v", err)
	}
}

func TestContentHashesSubCBORValidation(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, sha256.Size)
	if _, err := EncodeContentHashes(nil); err == nil {
		t.Fatal("nil hash batch accepted")
	}
	if _, err := EncodeContentHashes([][]byte{}); err == nil {
		t.Fatal("empty hash batch accepted")
	}
	tooMany := make([][]byte, MaxContentBatchItems+1)
	for index := range tooMany {
		tooMany[index] = bytes.Repeat([]byte{byte(index + 1)}, sha256.Size)
	}
	if _, err := EncodeContentHashes(tooMany); err == nil {
		t.Fatal("oversized hash batch accepted")
	}
	short := bytes.Repeat([]byte{1}, sha256.Size-1)
	if _, err := EncodeContentHashes([][]byte{short}); err == nil {
		t.Fatal("31-byte hash accepted")
	}
	if _, err := EncodeContentHashes([][]byte{hash, hash}); err == nil {
		t.Fatal("duplicate hash accepted")
	}
	raw, err := EncodeContentHashes([][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte(nil), raw...), 0x00)
	if _, err := DecodeContentHashes(trailing); err == nil {
		t.Fatal("trailing CBOR data accepted")
	}
	indefinite := append([]byte(nil), raw...)
	indefinite[0] = 0x9f
	indefinite = append(indefinite, 0xff)
	if _, err := DecodeContentHashes(indefinite); err == nil {
		t.Fatal("indefinite-length array accepted")
	}
	decoded, err := DecodeContentHashes(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0][0] ^= 0xff
	if again, err := DecodeContentHashes(raw); err != nil || !bytes.Equal(again[0], hash) {
		t.Fatal("decode result is not a deep copy or input was mutated")
	}
	reordered, err := EncodeContentHashes([][]byte{bytes.Repeat([]byte{2}, sha256.Size), bytes.Repeat([]byte{3}, sha256.Size)})
	if err != nil {
		t.Fatal(err)
	}
	swapped, err := EncodeContentHashes([][]byte{bytes.Repeat([]byte{3}, sha256.Size), bytes.Repeat([]byte{2}, sha256.Size)})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reordered, swapped) {
		t.Fatal("hash order was not preserved by the encoder")
	}
}

func TestContentPayloadsSubCBORValidation(t *testing.T) {
	payload := []byte("payload")
	if _, err := EncodeContentPayloads(nil); err == nil {
		t.Fatal("nil payload batch accepted")
	}
	if _, err := EncodeContentPayloads([][]byte{nil}); err == nil {
		t.Fatal("empty payload accepted")
	}
	oversize := make([]byte, masterseed.BlockSize+1)
	if _, err := EncodeContentPayloads([][]byte{oversize}); err == nil {
		t.Fatal("oversized payload accepted")
	}
	tooMany := make([][]byte, MaxContentBatchItems+1)
	for index := range tooMany {
		tooMany[index] = []byte{byte(index + 1)}
	}
	if _, err := EncodeContentPayloads(tooMany); err == nil {
		t.Fatal("oversized payload batch accepted")
	}
	raw, err := EncodeContentPayloads([][]byte{payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeContentPayloads(nil); err == nil {
		t.Fatal("empty raw payload document accepted")
	}
	if _, err := DecodeContentPayloads(append(append([]byte(nil), raw...), 0x00)); err == nil {
		t.Fatal("non-canonical payload document accepted")
	}
	decoded, err := DecodeContentPayloads(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0][0] ^= 0xff
	if again, err := DecodeContentPayloads(raw); err != nil || !bytes.Equal(again[0], payload) {
		t.Fatal("payload decode result is not a deep copy")
	}
	huge := make([]byte, MaxContentPayloadsCBORBytes+1)
	for index := range huge {
		huge[index] = 0x01
	}
	if _, err := DecodeContentPayloads(huge); err == nil {
		t.Fatal("payload document above the protocol size limit was not rejected before decoding")
	}
}

func TestVerifyContentRequestRejectsWrongPoolOrParticipants(t *testing.T) {
	source := []byte("block")
	quote, _, _ := mustSeededQuote(t, source)
	seedHash := masterseed.Sum256(createTestSeed(t, source)).Bytes()
	request, err := NewSignedContentRequest(contentBatchRequestTerms(t, quote, [][]byte{seedHash}, 3, 10), quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	goodTxID := bytes.Repeat([]byte{0x09}, sha256.Size)
	if _, err := VerifySignedContentRequest(request, quote, contentBatchOpening(quote, goodTxID)); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	wrongPool := contentBatchOpening(quote, bytes.Repeat([]byte{0x08}, sha256.Size))
	if _, err := VerifySignedContentRequest(request, quote, wrongPool); err == nil {
		t.Fatal("request bound to another pool was accepted")
	}
	wrongBuyer := contentBatchOpening(quote, goodTxID)
	wrongBuyer.buyer = quoteTestOtherArbiterPubkey()
	if _, err := VerifySignedContentRequest(request, quote, wrongBuyer); err == nil {
		t.Fatal("buyer key mismatch was accepted")
	}
	wrongArbiter := contentBatchOpening(quote, goodTxID)
	wrongArbiter.arbiter = quoteTestOtherArbiterPubkey()
	if _, err := VerifySignedContentRequest(request, quote, wrongArbiter); err == nil {
		t.Fatal("arbiter outside the quote whitelist was accepted")
	}
}

func TestVerifyContentRequestWithSeedChecksMembership(t *testing.T) {
	source := []byte("committed block content")
	quote, seed, _ := mustSeededQuote(t, source)
	blockHash := masterseed.Sum256(source).Bytes()
	request, err := NewSignedContentRequest(contentBatchRequestTerms(t, quote, [][]byte{blockHash}, 3, 10), quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	opening := contentBatchOpening(quote, bytes.Repeat([]byte{0x09}, sha256.Size))
	if _, err := VerifySignedContentRequestWithSeed(request, quote, opening, seed); err != nil {
		t.Fatalf("committed block rejected: %v", err)
	}
	otherHash := masterseed.Sum256([]byte("uncommitted")).Bytes()
	uncommitted, err := NewSignedContentRequest(contentBatchRequestTerms(t, quote, [][]byte{otherHash}, 3, 10), quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestWithSeed(uncommitted, quote, opening, seed); !errors.Is(err, ErrContentNotInSeed) {
		t.Fatalf("uncommitted block error = %v", err)
	}
}

func TestVerifyContentPayloadsBatchAtomicity(t *testing.T) {
	source := bytes.Repeat([]byte{7}, int(masterseed.BlockSize)+100)
	quote, seed, _ := mustSeededQuote(t, source)
	blockZero := source[:masterseed.BlockSize]
	tail := source[masterseed.BlockSize:]
	seedHash := quoteSeedHash(t, quote)
	batch := [][]byte{seedHash, masterseed.Sum256(blockZero).Bytes(), masterseed.Sum256(tail).Bytes()}
	payloads := [][]byte{seed, blockZero, tail}
	effective, err := VerifyContentPayloads(batchTerms(t, quote), batch, payloads, seed)
	if err != nil {
		t.Fatalf("valid mixed batch rejected: %v", err)
	}
	if !bytes.Equal(effective, seed) {
		t.Fatal("effective seed does not match the caller-provided verified seed")
	}
	// 批次内自带 seed 时，纯块批次可以不传调用方 seed，但成员校验仍必须完成。
	if _, err := VerifyContentPayloads(batchTerms(t, quote), batch, payloads, nil); err != nil {
		t.Fatalf("batch-carried seed rejected: %v", err)
	}
	// 错序整批拒绝。
	swapped := [][]byte{payloads[1], payloads[0], payloads[2]}
	if _, err := VerifyContentPayloads(batchTerms(t, quote), batch, swapped, seed); err == nil {
		t.Fatal("reordered payload batch accepted")
	}
	// 数量不符整批拒绝。
	if _, err := VerifyContentPayloads(batchTerms(t, quote), batch, payloads[:2], seed); err == nil {
		t.Fatal("missing payload accepted")
	}
	extra := append(append([][]byte(nil), payloads...), []byte("extra"))
	if _, err := VerifyContentPayloads(batchTerms(t, quote), batch, extra, seed); err == nil {
		t.Fatal("extra payload accepted")
	}
	// 篡改单项整批拒绝。
	tampered := append([][]byte(nil), payloads...)
	tampered[2] = append([]byte(nil), tampered[2]...)
	tampered[2][0] ^= 0xff
	if _, err := VerifyContentPayloads(batchTerms(t, quote), batch, tampered, seed); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// 无 seed 且批次不含 seed 时拒绝块校验。
	blockOnly := batch[1:2]
	if _, err := VerifyContentPayloads(batchTerms(t, quote), blockOnly, payloads[1:2], nil); !errors.Is(err, ErrContentNotInSeed) {
		t.Fatalf("block-only batch without seed error = %v", err)
	}
	// 纯 seed 批次不需要调用方 seed。
	if _, err := VerifyContentPayloads(batchTerms(t, quote), batch[:1], payloads[:1], nil); err != nil {
		t.Fatalf("pure-seed batch rejected: %v", err)
	}
}

func batchTerms(t *testing.T, quote *SignedFileQuote) *FileQuoteTerms {
	t.Helper()
	terms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return terms
}

func quoteSeedHash(t *testing.T, quote *SignedFileQuote) []byte {
	t.Helper()
	terms, err := DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return terms.SeedHash
}

func TestContentHashesPriceSatAggregation(t *testing.T) {
	fileSize := 2*masterseed.BlockSize + 10
	fullBlock := bytes.Repeat([]byte{7}, int(masterseed.BlockSize))
	secondBlock := bytes.Repeat([]byte{8}, int(masterseed.BlockSize))
	tailBlock := bytes.Repeat([]byte{9}, 10)
	source := append(append(append([]byte(nil), fullBlock...), secondBlock...), tailBlock...)
	_, seed, _ := mustSeededQuote(t, source)
	terms := quoteTestTerms(t)
	terms.FileSize = uint64(fileSize)
	terms.SeedHash = masterseed.Sum256(seed).Bytes()
	terms.SeedPriceSat = 100
	terms.FullBlockPriceSat = 1000

	seedOnly := [][]byte{masterseed.Sum256(seed).Bytes()}
	price, err := ContentHashesPriceSat(terms, seedOnly, nil)
	if err != nil || price != 100 {
		t.Fatalf("seed price = %d, %v", price, err)
	}
	fullBatch := [][]byte{masterseed.Sum256(fullBlock).Bytes(), masterseed.Sum256(secondBlock).Bytes()}
	price, err = ContentHashesPriceSat(terms, fullBatch, seed)
	if err != nil || price != 2000 {
		t.Fatalf("full blocks price = %d, %v", price, err)
	}
	mixed := append(append([][]byte(nil), seedOnly...), fullBatch...)
	price, err = ContentHashesPriceSat(terms, mixed, seed)
	if err != nil || price != 2100 {
		t.Fatalf("mixed batch price = %d, %v", price, err)
	}
	tailBatch := [][]byte{masterseed.Sum256(tailBlock).Bytes()}
	expectedTail := tailPriceSat(1000, 10)
	price, err = ContentHashesPriceSat(terms, tailBatch, seed)
	if err != nil || price != expectedTail {
		t.Fatalf("tail price = %d, want %d, %v", price, expectedTail, err)
	}
	zeroPrice := quoteTestTerms(t)
	zeroPrice.FullBlockPriceSat = 0
	zeroSource := bytes.Repeat([]byte("x"), int(masterseed.BlockSize))
	zeroSeed := createTestSeed(t, zeroSource)
	zeroPrice.FileSize = masterseed.BlockSize
	zeroPrice.SeedHash = masterseed.Sum256(zeroSeed).Bytes()
	price, err = ContentHashesPriceSat(zeroPrice, [][]byte{masterseed.Sum256(zeroSource).Bytes()}, zeroSeed)
	if err != nil || price != 0 {
		t.Fatalf("zero-price tail = %d, %v", price, err)
	}
	// 溢出用例必须真正走到累计加法：两个内容不同的完整块都由 seed 提交，
	// 单价取 math.MaxUint64，第二项 checked-add 必然溢出。
	firstOverflowBlock := bytes.Repeat([]byte{0x61}, int(masterseed.BlockSize))
	secondOverflowBlock := bytes.Repeat([]byte{0x62}, int(masterseed.BlockSize))
	overflowSource := append(append([]byte(nil), firstOverflowBlock...), secondOverflowBlock...)
	overflowSeed := createTestSeed(t, overflowSource)
	overflow := quoteTestTerms(t)
	overflow.FullBlockPriceSat = ^uint64(0)
	overflow.FileSize = 2 * masterseed.BlockSize
	overflow.SeedHash = masterseed.Sum256(overflowSeed).Bytes()
	_, err = ContentHashesPriceSat(overflow, [][]byte{
		masterseed.Sum256(firstOverflowBlock).Bytes(),
		masterseed.Sum256(secondOverflowBlock).Bytes(),
	}, overflowSeed)
	if err == nil {
		t.Fatal("aggregate price overflow accepted")
	}
	if !strings.Contains(err.Error(), "aggregate content price overflows uint64") {
		t.Fatalf("overflow error came from an earlier check, not the accumulation: %v", err)
	}
}

func tailPriceSat(fullPrice uint64, size uint64) uint64 {
	if fullPrice == 0 {
		return 0
	}
	value := fullPrice * size * 90 / (masterseed.BlockSize * 100)
	if value == 0 {
		return 1
	}
	return value
}

// 导出批量入口自身 fail-closed：重复哈希等非协议输入即使语义上可分类也必须拒绝。
func TestExportedBatchEntriesFailClosedOnNonProtocolInput(t *testing.T) {
	source := bytes.Repeat([]byte{7}, int(masterseed.BlockSize))
	seed := createTestSeed(t, source)
	terms := quoteTestTerms(t)
	terms.FileSize = uint64(len(source))
	terms.SeedHash = masterseed.Sum256(seed).Bytes()

	duplicate := masterseed.Sum256(source).Bytes()
	if _, err := ContentHashesPriceSat(terms, [][]byte{append([]byte(nil), duplicate...), append([]byte(nil), duplicate...)}, seed); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("pricing accepted duplicate hashes: %v", err)
	}
	tooMany := make([][]byte, MaxContentBatchItems+1)
	for index := range tooMany {
		tooMany[index] = bytes.Repeat([]byte{byte(index + 1)}, sha256.Size)
	}
	if _, err := ContentHashesPriceSat(terms, tooMany, seed); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("pricing accepted an oversized batch: %v", err)
	}
	payloads := [][]byte{source[:10], source[10:20]}
	hashes := [][]byte{masterseed.Sum256(payloads[0]).Bytes(), masterseed.Sum256(payloads[0]).Bytes()}
	if _, err := VerifyContentPayloads(terms, hashes, payloads, seed); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("payload verification accepted duplicate hashes: %v", err)
	}
	emptyPayloads := [][]byte{nil}
	singleHash := [][]byte{duplicate}
	if _, err := VerifyContentPayloads(terms, singleHash, emptyPayloads, seed); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("payload verification accepted an empty payload: %v", err)
	}
}

func TestDuplicateHashPositionsArePricedOnceAndConflictsRejected(t *testing.T) {
	duplicate := masterseed.Sum256([]byte("duplicate")).Bytes()
	seed := bytes.Repeat(duplicate, 3)
	terms := quoteTestTerms(t)
	terms.FileSize = 2*masterseed.BlockSize + 1
	terms.SeedHash = masterseed.Sum256(seed).Bytes()

	ambiguous := quoteTestTerms(t)
	ambiguous.FileSize = 2*masterseed.BlockSize + 1
	ambiguousSeed := bytes.Repeat(duplicate, 3)
	ambiguous.SeedHash = masterseed.Sum256(ambiguousSeed).Bytes()
	ambiguous.FullBlockPriceSat = 500
	if _, err := ContentHashesPriceSat(ambiguous, [][]byte{append([]byte(nil), duplicate...)}, ambiguousSeed); err == nil {
		t.Fatal("conflicting expected lengths accepted")
	}
	consistent := quoteTestTerms(t)
	consistent.FileSize = 2 * masterseed.BlockSize
	consistentSeed := bytes.Repeat(duplicate, 2)
	consistent.SeedHash = masterseed.Sum256(consistentSeed).Bytes()
	consistent.FullBlockPriceSat = 400
	price, err := ContentHashesPriceSat(consistent, [][]byte{append([]byte(nil), duplicate...)}, consistentSeed)
	if err != nil || price != 400 {
		t.Fatalf("duplicate positions priced = %d, %v; want single charge of 400", price, err)
	}
	_ = seed
}

func TestMasterSeedErrorsMapToBitFSCategories(t *testing.T) {
	source := []byte("seed source")
	seed := createTestSeed(t, source)
	seedHash := masterseed.Sum256(seed)

	hashMismatch := quoteTestTerms(t)
	hashMismatch.FileSize = uint64(len(source))
	hashMismatch.SeedHash = bytes.Repeat([]byte{0x99}, masterseed.DigestSize)
	_, err := findBlockMatches(context.Background(), hashMismatch, masterseed.Sum256(source).Bytes(), seed)
	assertMasterSeedCode(t, err, masterseed.SeedHashMismatch)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("seed hash mismatch does not map to ErrInvalidEvidence: %v", err)
	}

	sizeMismatch := quoteTestTerms(t)
	sizeMismatch.FileSize = masterseed.BlockSize + 1
	sizeMismatch.SeedHash = seedHash.Bytes()
	_, err = findBlockMatches(context.Background(), sizeMismatch, masterseed.Sum256(source).Bytes(), seed)
	assertMasterSeedCode(t, err, masterseed.SeedSizeMismatch)

	blockTerms := quoteTestTerms(t)
	blockTerms.FileSize = uint64(len(source))
	blockTerms.SeedHash = seedHash.Bytes()
	other := []byte("uncommitted")
	_, err = VerifyContentPayloads(blockTerms, [][]byte{masterseed.Sum256(other).Bytes()}, [][]byte{append([]byte(nil), other...)}, seed)
	assertMasterSeedCode(t, err, masterseed.BlockNotInSeed)
	if !errors.Is(err, ErrContentNotInSeed) {
		t.Fatalf("block-not-in-seed does not map to ErrContentNotInSeed: %v", err)
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
	_, err := findBlockMatches(ctx, terms, blockHash.Bytes(), seed)
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

func TestContentTermsRejectAllZeroRefundTemplateTxID(t *testing.T) {
	base := ContentRequestTerms{
		QuoteTermsHash:       bytes.Repeat([]byte{1}, sha256.Size),
		RefundTemplateTxID:   bytes.Repeat([]byte{2}, sha256.Size),
		PaymentSequence:      3,
		SellerAmountAfterSat: 10,
		ContentHashesCBOR:    mustEncodeHashesForTest(t, bytes.Repeat([]byte{4}, sha256.Size)),
		DeliveryDeadlineUnix: 2_000_000_000,
	}
	if err := ValidateContentRequestTerms(&base); err != nil {
		t.Fatal(err)
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
	sequenceZero := base
	sequenceZero.PaymentSequence = 0
	if err := ValidateContentRequestTerms(&sequenceZero); err == nil {
		t.Fatal("003 accepted payment sequence zero")
	}
	sequenceMax := base
	sequenceMax.PaymentSequence = ^uint32(0) - 1
	if err := ValidateContentRequestTerms(&sequenceMax); err != nil {
		t.Fatalf("003 rejected the last allowed payment sequence: %v", err)
	}
	sequenceExhausted := base
	sequenceExhausted.PaymentSequence = ^uint32(0)
	if err := ValidateContentRequestTerms(&sequenceExhausted); err == nil {
		t.Fatal("003 accepted the reserved final sequence")
	}
}

func mustEncodeHashesForTest(t *testing.T, hashes ...[]byte) []byte {
	t.Helper()
	raw, err := EncodeContentHashes(hashes)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
