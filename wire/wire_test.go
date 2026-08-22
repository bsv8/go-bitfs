package wire

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

func TestNewWirePreservesTypedCBOR(t *testing.T) {
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{1}, 32),
		BuyerPubkey:                 wireTestPubkey(),
		SeedPriceSat:                1,
		FullBlockPriceSat:           2,
		FileSize:                    1,
		QuoteExpiresAtUnix:          200,
		SupportedArbiterPubkeysCBOR: mustArbiterCBOR(t),
	}
	quote, err := bitfs.NewSignedFileQuote(terms, wireTestKey(), "file.bin")
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
		Version:                   pool.MajorVersion,
		RefundTemplateTxID:        pool.RefundTemplateTxID(bytes.Repeat([]byte{7}, 32)),
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, 32),
		UnsignedStateTxRaw:        []byte{2, 3},
		BuyerTransactionSignature: []byte{4},
	}
	raw, err := MarshalPaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.UnsignedStateTxRaw, update.UnsignedStateTxRaw) {
		t.Fatal("payment update changed during wire round trip")
	}
}

func mustArbiterCBOR(t *testing.T) []byte {
	t.Helper()
	raw, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{wireTestArbiterPubkey()})
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
