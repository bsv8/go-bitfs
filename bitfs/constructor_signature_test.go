package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func constructorOtherKey() []byte {
	return []byte("3333333333333333333333333333333333333333333333333333333333333333")
}

func constructorOtherSigner(raw []byte) ([]byte, error) {
	key, err := ec.PrivateKeyFromHex(string(constructorOtherKey()))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	signature, err := key.Sign(digest[:])
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func constructorWrongDigestSigner([]byte) ([]byte, error) {
	digest := sha256.Sum256([]byte("different protocol payload"))
	signature, err := quoteTestKey().Sign(digest[:])
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func constructorRequestTerms(t *testing.T) *ContentRequestTerms {
	t.Helper()
	quoteHash, err := FileQuoteTermsHash(mustConstructorQuote(t).TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256([]byte("payload"))
	return &ContentRequestTerms{
		QuoteTermsHash: quoteHash[:], SpendTxID: bytes.Repeat([]byte{1}, sha256.Size),
		BasePaymentSequence: 1, PaymentSequenceAfter: 2, SellerAmountAfterSat: 1,
		MinerFeeRateSatPerKB: 1, BuyerPubkey: quoteTestPubkey(), SellerPubkey: quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(), ContentType: ContentSeed,
		ContentHash: contentHash[:], DeliveryDeadlineUnix: 200,
	}
}

func mustConstructorQuote(t *testing.T) *SignedFileQuote {
	t.Helper()
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestPubkey(), "file.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

func TestSignedConstructorsRejectWrongKeySignatures(t *testing.T) {
	if _, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestPubkey(), "file.bin", constructorOtherSigner); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("quote constructor error = %v, want ErrInvalidEvidence", err)
	}
	terms := constructorRequestTerms(t)
	if _, err := NewSignedContentRequest(terms, constructorOtherSigner); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("request constructor error = %v, want ErrInvalidEvidence", err)
	}
	request, err := NewSignedContentRequest(terms, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignedContentDelivery(request, []byte("payload"), constructorOtherSigner); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("delivery constructor error = %v, want ErrInvalidEvidence", err)
	}
}

func TestSignedConstructorsRejectWrongDigestSignatures(t *testing.T) {
	if _, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestPubkey(), "file.bin", constructorWrongDigestSigner); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("quote constructor error = %v, want ErrInvalidEvidence", err)
	}
	terms := constructorRequestTerms(t)
	if _, err := NewSignedContentRequest(terms, constructorWrongDigestSigner); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("request constructor error = %v, want ErrInvalidEvidence", err)
	}
	request, err := NewSignedContentRequest(terms, quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignedContentDelivery(request, []byte("payload"), constructorWrongDigestSigner); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("delivery constructor error = %v, want ErrInvalidEvidence", err)
	}
}
