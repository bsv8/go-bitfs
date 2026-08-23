package wire

import (
	"bytes"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/fxamacker/cbor/v2"
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

func goldenContentHashes(t *testing.T, values ...[]byte) []byte {
	t.Helper()
	raw, err := bitfs.EncodeContentHashes(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGoldenWireBytes003(t *testing.T) {
	quoteHash, err := bitfs.FileQuoteTermsHash(goldenQuote(t).TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := bytes.Repeat([]byte{5}, 32)
	terms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:       quoteHash[:],
		RefundTemplateTxID:   bytes.Repeat([]byte{9}, 32),
		PaymentSequence:      3,
		SellerAmountAfterSat: 1100,
		ContentHashesCBOR:    goldenContentHashes(t, contentHash),
		DeliveryDeadlineUnix: 1999999000,
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
	const want = "8304587386582096f04221834fb5f0fd57eef01d2ec1463cc363960b3fbd49d5faf0a1b60282d4582009090909090909090909090909090909090909090909090909090909090909090319044c582381582005050505050505050505050505050505050505050505050505050505050505051a7735901858473045022100dd13ad289dfc0f41c7817c5808d647114af1a695682a8f5ead3b6ba472badaab022032c69f4f0f4b3858b03c7ef9c268ee5045e0cb0972291ec06a13ab61d9de1cb2"
	if got != want {
		t.Fatalf("golden 003 mismatch:\n got %s\nwant %s", got, want)
	}
	decoded, err := UnmarshalContentRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalContentRequest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("003 decode/encode round trip changed bytes")
	}
}

func TestGoldenWireBytes004(t *testing.T) {
	quoteHash, err := bitfs.FileQuoteTermsHash(goldenQuote(t).TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:       quoteHash[:],
		RefundTemplateTxID:   bytes.Repeat([]byte{9}, 32),
		PaymentSequence:      3,
		SellerAmountAfterSat: 100,
		ContentHashesCBOR:    goldenContentHashes(t, bytes.Repeat([]byte{6}, 32)),
		DeliveryDeadlineUnix: 1999999000,
	}
	request, err := bitfs.NewSignedContentRequest(terms, mustGoldenKey(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := bitfs.NewSignedContentDelivery(authHash[:], [][]byte{[]byte("seed-payload")}, mustGoldenKey(t, "22"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "8404582025c7b4b292d34033fdd4e8f9ebe3ea91d0fb17c808eece35a7ca414612bd2bf25846304402206772cc6f65f82e5b0a9c6baba6a7a53ab645125331f3dc91859d7993db91511f022046a4705175c322c5825a2aaeb5519119efe949f688a98169d4ad06342775a2074e814c736565642d7061796c6f6164"
	if got != want {
		t.Fatalf("golden 004 mismatch:\n got %s\nwant %s", got, want)
	}
	decoded, err := UnmarshalContentDelivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalContentDelivery(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("004 decode/encode round trip changed bytes")
	}
}

// Pre-switch v4 bytes must be rejected outright: the old thirteen-element
// terms, the old three-element 003 shell, the old three-element 004 shell, and
// the old five-element 005 payment container all carry removed fields or
// signatures over removed structures. No length-based legacy decoder exists.
func canonicalGoldenMarshal(values []any) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(values)
}

func goldenBstr(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}
func TestGoldenWireBytesRejectPreSwitchShapes(t *testing.T) {
	hash32 := bytes.Repeat([]byte{1}, 32)
	signature := bytes.Repeat([]byte{7}, 70)
	legacyTerms, err := canonicalGoldenMarshal([]any{
		uint64(4), goldenBstr(hash32), goldenBstr(hash32), uint64(2), uint64(3), uint64(10),
		uint64(1), goldenBstr(mustGoldenKey(t, "44").PubKey().Compressed()), goldenBstr(mustGoldenKey(t, "22").PubKey().Compressed()),
		goldenBstr(mustGoldenKey(t, "33").PubKey().Compressed()), uint64(0), goldenBstr(hash32), int64(1999999000)})
	if err != nil {
		t.Fatal(err)
	}
	legacyRequestShell, err := canonicalGoldenMarshal([]any{uint64(4), goldenBstr(legacyTerms), goldenBstr(signature)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalContentRequest(legacyRequestShell); err == nil {
		t.Fatal("legacy thirteen-element 003 terms were accepted")
	}
	legacyDeliveryShell, err := canonicalGoldenMarshal([]any{uint64(4), goldenBstr(hash32), goldenBstr(signature)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalContentDelivery(legacyDeliveryShell); err == nil {
		t.Fatal("legacy three-element 004 shell was accepted")
	}
	legacyUpdate, err := canonicalGoldenMarshal([]any{
		uint64(4), goldenBstr(hash32), goldenBstr(hash32),
		goldenBstr([]byte{2, 3, 4}), goldenBstr(signature)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPaymentUpdate(legacyUpdate); err == nil {
		t.Fatal("pre-switch five-element v4 005 was accepted")
	}
}

func TestGoldenWireBytes005(t *testing.T) {
	// The minimal 005 credential carries only the authorization hash and the
	// buyer transaction signature; pool ID and raw state tx are rebuilt
	// locally by both roles and never transmitted.
	update := &pool.PaymentUpdate{
		Version:                   pool.MajorVersion,
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, 32),
		BuyerTransactionSignature: []byte{5, 6},
	}
	raw, err := MarshalPaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "830458200101010101010101010101010101010101010101010101010101010101010101420506"
	if got != want {
		t.Fatalf("golden 005 mismatch:\n got %s\nwant %s", got, want)
	}
	if len(raw) == 0 || raw[0] != 0x83 {
		t.Fatalf("minimal 005 must be a three-element array: %x", raw)
	}
	decoded, err := UnmarshalPaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PaymentAuthorizationHash, update.PaymentAuthorizationHash) || !bytes.Equal(decoded.BuyerTransactionSignature, update.BuyerTransactionSignature) {
		t.Fatal("005 round trip changed fields")
	}
	again, err := MarshalPaymentUpdate(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("005 decode/encode round trip changed bytes")
	}
}

func TestGoldenWireBytes007(t *testing.T) {
	request, arbiter := wireArbitrationEvidence(t)
	claim, err := arbitration.UnmarshalClaim(request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimDomain, err := arbitration.SellerClaimSigningCBOR(request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := MarshalArbitrationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := arbiter.PreparePayment(nil, request, 900000)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbiter.SignPreparedPayment(nil, prepared)
	if err != nil {
		t.Fatal(err)
	}
	resultDomain, err := arbitration.ArbiterResultSigningCBOR(response.ResultCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse, err := MarshalArbitrationResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := prepared.UnsignedPayment()
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	sellerKey := mustGoldenKey(t, "22")
	sellerSig, err := engine.SignArbitrationSellerPayment(nil, unsigned, sellerKey)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSig, err := engine.SignArbitrationArbiterPayment(nil, unsigned, mustGoldenKey(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := engine.MergeArbitratedPoolSellerArbiterSignatures(unsigned, sellerSig, arbiterSig)
	if err != nil {
		t.Fatal(err)
	}
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	state.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: unsigned.PoolOutputSatoshis, LockingScript: script.NewFromBytes(unsigned.PoolLockingScript)})
	preimage, err := state.CalcInputPreimage(0, sighash.Flag(sighash.ForkID|sighash.All))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := state.CalcInputSignatureHash(0, sighash.Flag(sighash.ForkID|sighash.All))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"claim":        "851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402201da8f281734183760083ef98a3e841c9e630b5f29e12c5ffd166d748d1d94a1c02203995171e0d5b76c7b6c51d029df05815c2e19406d4fcc2531f3c567f6cb703fe",
		"claimDomain":  "8304085901c8851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402201da8f281734183760083ef98a3e841c9e630b5f29e12c5ffd166d748d1d94a1c02203995171e0d5b76c7b6c51d029df05815c2e19406d4fcc2531f3c567f6cb703fe",
		"request":      "8504085901c8851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402201da8f281734183760083ef98a3e841c9e630b5f29e12c5ffd166d748d1d94a1c02203995171e0d5b76c7b6c51d029df05815c2e19406d4fcc2531f3c567f6cb703fe58463044022003172b7f261668c5a5f6128dbc5c1439dd4725ca1ff8ab585cb4b42d15fdf76702202e4db4ef869671ddb6718907a098e24125e36106e79cf1a5ba475233eb773e584981477061796c6f6164",
		"result":       "83582021d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c92582011f5cab5a47ef4d0d5d66a546ca2ee5cfc18bddf84164f343fb1efaa5c7acf855820d8c972fedaa6cff44bd7e2f59f0dd515958378a5a02edbe7e567e266b2c3c18d",
		"resultDomain": "830409586783582021d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c92582011f5cab5a47ef4d0d5d66a546ca2ee5cfc18bddf84164f343fb1efaa5c7acf855820d8c972fedaa6cff44bd7e2f59f0dd515958378a5a02edbe7e567e266b2c3c18d",
		"response":     "850409586783582021d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c92582011f5cab5a47ef4d0d5d66a546ca2ee5cfc18bddf84164f343fb1efaa5c7acf855820d8c972fedaa6cff44bd7e2f59f0dd515958378a5a02edbe7e567e266b2c3c18d5846304402203845cff3f9398f8ccb72e3dd75cf7029ae6af8c87e4db1d43eeec840e54c229202205c620a3edb57698b83ffd0a0b91a38fb9de35463162c3318875cf67518e604a058483045022100fd427976aaa40e34fe04b686943c651efa93da00788c0fd9f2ddc8a389da2b3102201f2b24c150e259b1630dd18189a88b4d41923cd19f081698cc400df00a04896f41",
		"unsigned":     "0100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000003000000033b860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac64000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac00943577",
		"preimage":     "01000000e3405dabffa47e3af49a520b10556b69ecd981f4f9523e32ee158fc6615a00e29953051d0daf36399447027f1ff4ceee27161c808c610b3f961ea3805ab3e793d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df00000000695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153aea08601000000000003000000ac7b58088b80c22cb95eedfe17cc7b723fc1632156fd92f3980170a6b3c020af0094357741000000",
		"digest":       "4612676d46372eaa5b83988dd028a5ab16275353c860dec6c2ed72910e40b20f",
		"sellerSig":    "3044022003654de9a48433d3519b7a06d32dbb7336605e2ef85006d682ca252dc43a1bda022032d56edcf78c22294b81b19544bc26dfa0ca0941770b32a72ea8236cd1c8388141",
		"arbiterSig":   "3045022100fd427976aaa40e34fe04b686943c651efa93da00788c0fd9f2ddc8a389da2b3102201f2b24c150e259b1630dd18189a88b4d41923cd19f081698cc400df00a04896f41",
		"merged":       "0100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000009200473044022003654de9a48433d3519b7a06d32dbb7336605e2ef85006d682ca252dc43a1bda022032d56edcf78c22294b81b19544bc26dfa0ca0941770b32a72ea8236cd1c8388141483045022100fd427976aaa40e34fe04b686943c651efa93da00788c0fd9f2ddc8a389da2b3102201f2b24c150e259b1630dd18189a88b4d41923cd19f081698cc400df00a04896f4103000000033b860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac64000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac00943577",
	}
	got := map[string][]byte{
		"claim": request.ClaimCBOR, "claimDomain": claimDomain, "request": rawRequest,
		"result": response.ResultCBOR, "resultDomain": resultDomain, "response": rawResponse,
		"unsigned": unsigned.RawTx, "preimage": preimage, "digest": digest,
		"sellerSig": sellerSig, "arbiterSig": arbiterSig, "merged": merged.RawTx,
	}
	for name, value := range got {
		if hex.EncodeToString(value) != want[name] {
			t.Fatalf("golden 007 %s mismatch:\n got %s\nwant %s", name, hex.EncodeToString(value), want[name])
		}
	}
}
