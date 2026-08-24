package wire

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

func TestNewWirePreservesTypedCBOR(t *testing.T) {
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                       bytes.Repeat([]byte{1}, 32),
		BuyerPublicKey:                 wireTestPubkey(),
		SeedPriceSatoshis:              1,
		FullBlockPriceSatoshis:         2,
		FileSizeBytes:                  1,
		QuoteExpiresAtUnixSeconds:      200,
		SupportedArbiterPublicKeysCBOR: mustArbiterCBOR(t),
	}
	quote, err := bitfs.NewSignedFileQuote(terms, wireTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalFileQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x85 || raw[1] != 0x01 || raw[2] != 0x01 {
		t.Fatalf("Kind 1 must be a five-element [1,1,...] array: %x", raw)
	}
	decoded, err := UnmarshalFileQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.FileQuoteTermsCBOR, quote.FileQuoteTermsCBOR) {
		t.Fatal("wire round trip changed quote terms")
	}
	if _, err := Unmarshal(FileQuote, append(raw, 0)); err == nil {
		t.Fatal("wire decoder accepted trailing bytes")
	}
}

func TestPaymentUpdateUsesNewWireNamespace(t *testing.T) {
	update := &pool.PaymentUpdate{
		PaymentAuthorizationID:           protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, 32)),
		BuyerPaymentTransactionSignature: []byte{4},
	}
	raw, err := MarshalPaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x07 {
		t.Fatalf("minimal Kind 7 must be a four-element [1,7,...] array: %x", raw)
	}
	decoded, err := UnmarshalPaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PaymentAuthorizationID != update.PaymentAuthorizationID || !bytes.Equal(decoded.BuyerPaymentTransactionSignature, update.BuyerPaymentTransactionSignature) {
		t.Fatal("payment update changed during wire round trip")
	}
	// The transport adds no pool header or session fallback: decoding the
	// payload under Kind isolation is already covered by wire_pool_test.
	mutated := &pool.PaymentUpdate{PaymentAuthorizationID: update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: []byte{5}}
	if _, err := MarshalPaymentUpdate(mutated); err != nil {
		t.Fatal(err)
	}
	update.PaymentAuthorizationID[0] = 9
	if decoded.PaymentAuthorizationID[0] != 1 {
		t.Fatal("decoded payment update aliases input data")
	}
}

func mustArbiterCBOR(t *testing.T) []byte {
	t.Helper()
	raw, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{wireTestArbiterPubkey()})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wireTestKey() *ec.PrivateKey {
	key, err := ec.PrivateKeyFromHex("2222222222222222222222222222222222222222222222222222222222222222")
	if err != nil {
		panic(err)
	}
	return key
}

func wireTestPubkey() []byte { return wireTestKey().PubKey().Compressed() }

func wireTestArbiterPubkey() []byte {
	key, err := ec.PrivateKeyFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}
