package wire

import (
	"bytes"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

// Golden bytes freeze the 001/003/004/005 wire encoders and decoders against
// compatibility breaks. Every fixture uses deterministic keys and fixed Unix
// timestamps so the expected hex never depends on wall-clock time.
func mustGoldenKey(t *testing.T, repeat string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(repeat), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func goldenQuote(t *testing.T) *bitfs.SignedFileQuote {
	t.Helper()
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{mustGoldenKey(t, "33").PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{1}, 32),
		BuyerPubkey:                 mustGoldenKey(t, "44").PubKey().Compressed(),
		SeedPriceSat:                100,
		FullBlockPriceSat:           1000,
		FileSize:                    4096,
		QuoteExpiresAtUnix:          2000000000,
		SupportedArbiterPubkeysCBOR: arbiters,
	}
	quote, err := bitfs.NewSignedFileQuote(terms, mustGoldenKey(t, "22"), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

func TestGoldenWireBytes001(t *testing.T) {
	quote := goldenQuote(t)
	raw, err := MarshalQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "8501587a8801582001010101010101010101010101010101010101010101010101010101010101015821032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e66868099118641903e81910001a773594005824815821023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1582102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2758473045022100c9958b9a1fd3e41bfafa4331c27a175cfa26a66247c11fa3562bc7eeeefab42a02201130aff00a33915d7da3972ed0ce50cc426f9dcbcd45913da4bdddb96052b9386866696c652e62696e"
	if got != want {
		t.Fatalf("golden 001 mismatch:\n got %s\nwant %s", got, want)
	}
	decoded, err := UnmarshalQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalQuote(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("001 decode/encode round trip changed bytes")
	}
}

func TestGoldenWireBytes003(t *testing.T) {
	quoteHash, err := bitfs.FileQuoteTermsHash(goldenQuote(t).TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := bytes.Repeat([]byte{5}, 32)
	terms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{9}, 32),
		BasePaymentSequence:   2,
		PaymentSequenceAfter:  3,
		SellerAmountAfterSat:  1100,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           mustGoldenKey(t, "44").PubKey().Compressed(),
		SellerPubkey:          mustGoldenKey(t, "22").PubKey().Compressed(),
		SelectedArbiterPubkey: mustGoldenKey(t, "33").PubKey().Compressed(),
		ContentType:           bitfs.ContentBlock,
		ContentHash:           contentHash,
		DeliveryDeadlineUnix:  1999999000,
	}
	request, err := bitfs.NewSignedContentRequest(terms, mustGoldenKey(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "830458dd8d04582096f04221834fb5f0fd57eef01d2ec1463cc363960b3fbd49d5faf0a1b60282d458200909090909090909090909090909090909090909090909090909090909090909020319044c015821032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991582102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f275821023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b101582005050505050505050505050505050505050505050505050505050505050505051a7735901858473045022100e6dcb003c84727bdb643fc5c220ae6c0f5e54a17e975634ccefd53ccbb7b5f8e022035ce6849f7afce412c7b0e6d306b5c4fa94ce264950e9032fecaeb1c555b03d7"
	if got != want {
		t.Fatalf("golden 003 mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestGoldenWireBytes004(t *testing.T) {
	quote := goldenQuote(t)
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    bytes.Repeat([]byte{9}, 32),
		BasePaymentSequence:   2,
		PaymentSequenceAfter:  3,
		SellerAmountAfterSat:  100,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           mustGoldenKey(t, "44").PubKey().Compressed(),
		SellerPubkey:          mustGoldenKey(t, "22").PubKey().Compressed(),
		SelectedArbiterPubkey: mustGoldenKey(t, "33").PubKey().Compressed(),
		ContentType:           bitfs.ContentSeed,
		ContentHash:           bytes.Repeat([]byte{6}, 32),
		DeliveryDeadlineUnix:  1999999000,
	}
	request, err := bitfs.NewSignedContentRequest(terms, mustGoldenKey(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := bitfs.NewSignedContentDelivery(request, []byte("seed-payload"), mustGoldenKey(t, "22"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "83045853840458200909090909090909090909090909090909090909090909090909090909090909582075e8f6695392a904ccb444cfdcd7b4ae86e11516851059630583488e01ae67004c736565642d7061796c6f61645846304402203f2558b3cc3a7c61797be17bfba82cea17d9bc5649c059f29d13d7917faeaaac022055313d72acbc25f5c1e43a5b23ab4db40f708728e14faf01bef4d55291e5e435"
	if got != want {
		t.Fatalf("golden 004 mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestGoldenWireBytes005(t *testing.T) {
	update := &pool.PaymentUpdate{
		Version:                   pool.MajorVersion,
		RefundTemplateTxID:        pool.RefundTemplateTxID(bytes.Repeat([]byte{7}, 32)),
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, 32),
		UnsignedStateTxRaw:        []byte{2, 3, 4},
		BuyerTransactionSignature: []byte{5, 6},
	}
	raw, err := MarshalPaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "8504582007070707070707070707070707070707070707070707070707070707070707075820010101010101010101010101010101010101010101010101010101010101010143020304420506"
	if got != want {
		t.Fatalf("golden 005 mismatch:\n got %s\nwant %s", got, want)
	}
	decoded, err := UnmarshalPaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RefundTemplateTxID != update.RefundTemplateTxID || !bytes.Equal(decoded.UnsignedStateTxRaw, update.UnsignedStateTxRaw) {
		t.Fatal("005 round trip changed fields")
	}
}
