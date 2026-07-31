package wire

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

func TestNewWirePreservesTypedCBOR(t *testing.T) {
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{1}, 32),
		BuyerPubkey:                 []byte{2},
		SeedPriceSat:                1,
		FullBlockPriceSat:           2,
		FileSize:                    1,
		QuoteExpiresAtUnix:          200,
		SupportedArbiterPubkeysCBOR: mustArbiterCBOR(t),
	}
	quote, err := bitfs.NewSignedFileQuote(terms, []byte{3}, "file.bin", func(raw []byte) ([]byte, error) {
		digest := sha256.Sum256(raw)
		return digest[:], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.TermsCBOR, quote.TermsCBOR) {
		t.Fatal("wire round trip changed quote terms")
	}
	if _, err := Unmarshal(Quote, append(raw, 0)); err == nil {
		t.Fatal("wire decoder accepted trailing bytes")
	}
}

func TestPaymentUpdateUsesNewWireNamespace(t *testing.T) {
	update := &pool.PaymentUpdate{
		Version:                 pool.MajorVersion,
		ContentRequestTermsHash: bytes.Repeat([]byte{1}, 32),
		PartialSpendTx:          []byte{2, 3},
	}
	raw, err := MarshalPaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PartialSpendTx, update.PartialSpendTx) {
		t.Fatal("payment update changed during wire round trip")
	}
}

func mustArbiterCBOR(t *testing.T) []byte {
	t.Helper()
	raw, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{{4}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
