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
	claimID, err := arbitration.ArbitrationClaimID(request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := MarshalArbitrationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	const arbitrationFeeSat = uint64(500)
	prepared, err := arbiter.PreparePayment(nil, request, 900000, arbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbiter.SignPreparedPayment(nil, prepared)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	receiptDomain, err := arbitration.ArbiterReceiptSigningCBOR(response.ReceiptCBOR)
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
		"claim":         "851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402201da8f281734183760083ef98a3e841c9e630b5f29e12c5ffd166d748d1d94a1c02203995171e0d5b76c7b6c51d029df05815c2e19406d4fcc2531f3c567f6cb703fe",
		"claimDomain":   "8304085901c8851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402201da8f281734183760083ef98a3e841c9e630b5f29e12c5ffd166d748d1d94a1c02203995171e0d5b76c7b6c51d029df05815c2e19406d4fcc2531f3c567f6cb703fe",
		"request":       "8504085901c8851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402201da8f281734183760083ef98a3e841c9e630b5f29e12c5ffd166d748d1d94a1c02203995171e0d5b76c7b6c51d029df05815c2e19406d4fcc2531f3c567f6cb703fe58463044022003172b7f261668c5a5f6128dbc5c1439dd4725ca1ff8ab585cb4b42d15fdf76702202e4db4ef869671ddb6718907a098e24125e36106e79cf1a5ba475233eb773e584981477061796c6f6164",
		"claimID":       "21d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c92",
		"unsigned":      "0100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df0000000000030000000347840100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac64000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88acf4010000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac00943577",
		"receipt":       "83582021d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c921901f458483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41",
		"receiptDomain": "830409587083582021d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c921901f458483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41",
		"receiptSig":    "3045022100e4e045fdab4682d2f2265a28680c95a09f1b2e067ba432595b5becef96e008dd02205c81121a0ea01de3479871a3a1b7fad3771f81632c0372642583d1e2fc453bcf",
		"response":      "840409587083582021d2abc826024bdd797c620fd99e159107c8ba331b43c9c6682da968ef069c921901f458483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc4158473045022100e4e045fdab4682d2f2265a28680c95a09f1b2e067ba432595b5becef96e008dd02205c81121a0ea01de3479871a3a1b7fad3771f81632c0372642583d1e2fc453bcf",
		"preimage":      "01000000e3405dabffa47e3af49a520b10556b69ecd981f4f9523e32ee158fc6615a00e29953051d0daf36399447027f1ff4ceee27161c808c610b3f961ea3805ab3e793d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df00000000695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153aea08601000000000003000000edc160877ce4f5ed0255cd24686fd8735c7ab293596242cb88eb82be757e18530094357741000000",
		"digest":        "817e3c9ef6fa9e0d5d58f993d4e77c514d6e856596111c567240ea5c0a5c7712",
		"sellerSig":     "304402205f12246a3007711102e3cfc1bea0d3a47f0ff0f2e47893780a8ef2e37a9eded10220358125b2478f0b9498884d43fc7db4c69d46f9274d12bee837a980391a2a875741",
		"arbiterSig":    "3045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41",
		"merged":        "0100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df00000000920047304402205f12246a3007711102e3cfc1bea0d3a47f0ff0f2e47893780a8ef2e37a9eded10220358125b2478f0b9498884d43fc7db4c69d46f9274d12bee837a980391a2a875741483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41030000000347840100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac64000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88acf4010000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac00943577",
	}
	got := map[string][]byte{
		"claim": request.ClaimCBOR, "claimDomain": claimDomain, "request": rawRequest,
		"claimID":  claimID,
		"unsigned": unsigned.RawTx, "preimage": preimage, "digest": digest,
		"receipt": response.ReceiptCBOR, "receiptDomain": receiptDomain, "receiptSig": response.ArbiterReceiptSignature, "response": rawResponse,
		"sellerSig": sellerSig, "arbiterSig": arbiterSig, "merged": merged.RawTx,
	}
	for name, value := range got {
		if hex.EncodeToString(value) != want[name] {
			t.Fatalf("golden 007 %s mismatch:\n got %s\nwant %s", name, hex.EncodeToString(value), want[name])
		}
	}
	// 回执金额必须等于 golden candidate 的第三输出金额，且 Seller 输出保持
	// Buyer 授权的绝对金额。
	if receipt.ArbiterAmountSat != arbitrationFeeSat || unsigned.ArbiterAmountSat != arbitrationFeeSat {
		t.Fatalf("paid fee drifted: receipt %d unsigned %d want %d", receipt.ArbiterAmountSat, unsigned.ArbiterAmountSat, arbitrationFeeSat)
	}
}
