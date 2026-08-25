package wire_test

import (
	"bytes"
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

func TestNewWirePreservesTypedCBOR(t *testing.T) {
	terms := &content.FileQuoteTerms{
		SeedHash:                       bytes.Repeat([]byte{1}, 32),
		BuyerPublicKey:                 wireTestPubkey(),
		SeedPriceSatoshis:              1,
		FullBlockPriceSatoshis:         2,
		FileSizeBytes:                  1,
		QuoteExpiresAtUnixSeconds:      200,
		SupportedArbiterPublicKeysCBOR: mustArbiterCBOR(t),
		RecommendedFilename:            "file.bin",
	}
	signer, err := protocol.NewPrivateKeySigner(wireTestKey())
	if err != nil {
		t.Fatal(err)
	}
	quote, err := content.NewSignedFileQuote(context.Background(), terms, signer)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := wire.EncodeFileQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	raw := artifact.Bytes()
	if len(raw) < 3 || raw[0] != 0x85 || raw[1] != 0x01 || raw[2] != 0x01 {
		t.Fatalf("Kind 1 must be a five-element [1,1,...] array: %x", raw)
	}
	decoded, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.FileQuoteTermsCBOR, quote.FileQuoteTermsCBOR) {
		t.Fatal("wire round trip changed quote terms")
	}
	if _, err := wire.ParseAs(wire.FileQuote, append(raw, 0)); err == nil {
		t.Fatal("wire decoder accepted trailing bytes")
	}
}

func TestPaymentUpdateUsesNewWireNamespace(t *testing.T) {
	update := &pool.PaymentUpdate{
		PaymentAuthorizationID:           protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, 32)),
		BuyerPaymentTransactionSignature: []byte{4},
	}
	artifact, err := wire.EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	raw := artifact.Bytes()
	if len(raw) == 0 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x07 {
		t.Fatalf("minimal Kind 7 must be a four-element [1,7,...] array: %x", raw)
	}
	decoded, err := wire.DecodePaymentUpdate(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PaymentAuthorizationID != update.PaymentAuthorizationID || !bytes.Equal(decoded.BuyerPaymentTransactionSignature, update.BuyerPaymentTransactionSignature) {
		t.Fatal("payment update changed during wire round trip")
	}
	// The transport adds no pool header or session fallback: decoding the
	// payload under Kind isolation is already covered by wire_pool_test.
	mutated := &pool.PaymentUpdate{PaymentAuthorizationID: update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: []byte{5}}
	if _, err := wire.EncodePaymentUpdate(mutated); err != nil {
		t.Fatal(err)
	}
	update.PaymentAuthorizationID[0] = 9
	if decoded.PaymentAuthorizationID[0] != 1 {
		t.Fatal("decoded payment update aliases input data")
	}
}

func mustArbiterCBOR(t *testing.T) []byte {
	t.Helper()
	raw, err := content.EncodeSupportedArbiterPublicKeys([][]byte{wireTestArbiterPubkey()})
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

// wireTestSigner 把测试私钥包装成受约束 Signer（角色与构造器唯一入口）。
func wireTestSigner(t *testing.T, key *ec.PrivateKey) *protocol.PrivateKeySigner {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func wireTestPubkey() []byte { return wireTestKey().PubKey().Compressed() }

func wireTestArbiterPubkey() []byte {
	key, err := ec.PrivateKeyFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}
