package bitfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestContentRequestAndDeliveryRoundTrip(t *testing.T) {
	quote, err := NewSignedFileQuote(quoteTestTerms(t), []byte{0x03}, "file.bin", quoteTestSigner)
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
		SpendTxID:             bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   7,
		SelectedArbiterPubkey: []byte{0x02},
		ContentType:           ContentBlock,
		ContentHash:           contentHash[:],
		DeliveryDeadlineUnix:  200,
	}, quoteTestSigner)
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
	if _, err := VerifySignedContentRequestAt(decodedRequest, quote, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier); err != nil {
		t.Fatalf("VerifySignedContentRequestAt() error = %v", err)
	}

	delivery, err := NewSignedContentDelivery(decodedRequest, content, quoteTestSigner)
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
	got, err := VerifySignedContentDeliveryAt(decodedRequest, decodedDelivery, quote, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier, quoteTestVerifier)
	if err != nil {
		t.Fatalf("VerifySignedContentDeliveryAt() error = %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("verified content = %q, want %q", got, content)
	}
}

func TestContentRequestRejectsWrongQuoteAndArbiter(t *testing.T) {
	quote, err := NewSignedFileQuote(quoteTestTerms(t), []byte{0x03}, "file.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	contentHash := sha256.Sum256([]byte("block"))
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		SpendTxID:             bytes.Repeat([]byte{0x09}, sha256.Size),
		SelectedArbiterPubkey: []byte{0xff},
		ContentType:           ContentBlock,
		ContentHash:           contentHash[:],
		DeliveryDeadlineUnix:  200,
	}, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestAt(request, quote, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier); err == nil {
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
		SpendTxID:             bytes.Repeat([]byte{0x09}, sha256.Size),
		SelectedArbiterPubkey: []byte{0x02},
		ContentType:           ContentBlock,
		ContentHash:           contentHash[:],
		DeliveryDeadlineUnix:  200,
	}, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := NewSignedContentDelivery(request, content, quoteTestSigner)
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
	if _, err := VerifySignedContentDeliveryAt(request, delivery, quote, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier, quoteTestVerifier); err == nil {
		t.Fatal("delivery with changed payload was accepted")
	}
}

func TestContentBlockMustBeCommittedByQuoteSeed(t *testing.T) {
	content := []byte("tail block")
	blockHash := sha256.Sum256(content)
	seed, err := BuildSeedBytes([][]byte{blockHash[:]})
	if err != nil {
		t.Fatal(err)
	}
	seedHash := SeedHash(seed)
	terms := quoteTestTerms(t)
	terms.FileSize = uint64(len(content))
	terms.SeedHash = seedHash[:]
	quote, err := NewSignedFileQuote(terms, []byte{0x03}, "file.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	quoteHash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		SpendTxID:             bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		SelectedArbiterPubkey: []byte{0x02},
		ContentType:           ContentBlock,
		ContentHash:           blockHash[:],
		DeliveryDeadlineUnix:  200,
	}, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestWithSeedAt(request, quote, seed, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier); err != nil {
		t.Fatalf("committed block was rejected: %v", err)
	}
	delivery, err := NewSignedContentDelivery(request, content, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentDeliveryWithSeedAt(request, delivery, quote, seed, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier, quoteTestVerifier); err != nil {
		t.Fatalf("committed block delivery was rejected: %v", err)
	}
	otherHash := sha256.Sum256([]byte("other block"))
	request.TermsCBOR, err = EncodeContentRequestTerms(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		SpendTxID:             bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		SelectedArbiterPubkey: []byte{0x02},
		ContentType:           ContentBlock,
		ContentHash:           otherHash[:],
		DeliveryDeadlineUnix:  200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentRequestWithSeedAt(request, quote, seed, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier); err == nil {
		t.Fatal("uncommitted block was accepted")
	}
}

func TestSeedDeliveryRequiresCanonicalSeedPayload(t *testing.T) {
	blockHash := sha256.Sum256([]byte("block"))
	seed, err := BuildSeedBytes([][]byte{blockHash[:]})
	if err != nil {
		t.Fatal(err)
	}
	seedHash := SeedHash(seed)
	terms := quoteTestTerms(t)
	terms.FileSize = 5
	terms.SeedHash = seedHash[:]
	quote, err := NewSignedFileQuote(terms, []byte{0x03}, "file.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	quoteHash, _ := FileQuoteTermsHash(quote.TermsCBOR)
	request, err := NewSignedContentRequest(&ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		SpendTxID:             bytes.Repeat([]byte{0x09}, sha256.Size),
		BasePaymentSequence:   1,
		SelectedArbiterPubkey: []byte{0x02},
		ContentType:           ContentSeed,
		ContentHash:           seedHash[:],
		DeliveryDeadlineUnix:  200,
	}, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := NewSignedContentDelivery(request, seed, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedContentDeliveryWithSeedAt(request, delivery, quote, nil, time.Unix(100, 0), quoteTestVerifier, quoteTestVerifier, quoteTestVerifier); err != nil {
		t.Fatalf("valid seed delivery was rejected: %v", err)
	}
}

func TestContentCBORVector(t *testing.T) {
	terms := &ContentRequestTerms{
		QuoteTermsHash:        bytes.Repeat([]byte{0x01}, sha256.Size),
		SpendTxID:             bytes.Repeat([]byte{0x02}, sha256.Size),
		BasePaymentSequence:   3,
		SelectedArbiterPubkey: []byte{0x04},
		ContentType:           ContentBlock,
		ContentHash:           bytes.Repeat([]byte{0x05}, sha256.Size),
		DeliveryDeadlineUnix:  99,
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

func mustContentQuote(t *testing.T, fileSize uint64) *SignedFileQuote {
	t.Helper()
	terms := quoteTestTerms(t)
	terms.FileSize = fileSize
	quote, err := NewSignedFileQuote(terms, []byte{0x03}, "file.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	return quote
}
