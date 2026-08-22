package bitfs

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// quoteDeadline returns a delivery deadline safely in the future; deadline vs
// expiry relations are tested with dedicated fixtures.
func quoteDeadline(t *testing.T) int64 {
	t.Helper()
	return time.Now().UTC().Add(55 * time.Minute).Unix()
}

func constructorOtherKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("33"), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func constructorRequestTerms(t *testing.T) *ContentRequestTerms {
	t.Helper()
	quoteHash, err := FileQuoteTermsHash(mustConstructorQuote(t).TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256([]byte("payload"))
	return &ContentRequestTerms{
		QuoteTermsHash: quoteHash[:], RefundTemplateTxID: bytes.Repeat([]byte{1}, sha256.Size),
		BasePaymentSequence: 1, PaymentSequenceAfter: 2, SellerAmountAfterSat: 1,
		MinerFeeRateSatPerKB: 1, BuyerPubkey: quoteTestPubkey(), SellerPubkey: quoteTestPubkey(),
		SelectedArbiterPubkey: quoteTestArbiterPubkey(), ContentType: ContentSeed,
		ContentHash: contentHash[:], DeliveryDeadlineUnix: quoteDeadline(t),
	}
}

func mustConstructorQuote(t *testing.T) *SignedFileQuote {
	t.Helper()
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

// With the signer and verifier callbacks removed, a constructor can only be
// misused by supplying a private key that does not match the role committed in
// the terms; the fixed path rejects that before any signature is produced.
func TestSignedConstructorsRejectWrongRoleKeys(t *testing.T) {
	terms := constructorRequestTerms(t)
	if _, err := NewSignedContentRequest(terms, constructorOtherKey(t)); err == nil {
		t.Fatal("request constructor accepted a non-buyer key")
	}
	request, err := NewSignedContentRequest(terms, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignedContentDelivery(request, []byte("payload"), constructorOtherKey(t)); err == nil {
		t.Fatal("delivery constructor accepted a non-seller key")
	}
	if _, err := NewSignedContentDelivery(request, []byte("payload"), quoteTestKey()); err != nil {
		t.Fatalf("fixed delivery signing failed: %v", err)
	}
}
