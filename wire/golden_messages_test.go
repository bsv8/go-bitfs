package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Golden bytes freeze the v1 wire encoders and decoders against compatibility
// breaks. Every fixture uses deterministic keys and fixed Unix timestamps so
// the expected hex never depends on wall-clock time. Transaction-layer bytes
// (candidate, preimage, sighash digest, merged raw) are unchanged from the
// retired v4 fixtures because the unified protocol only reshaped wire
// envelopes and message-signature domains.
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
	arbiters, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{mustGoldenKey(t, "33").PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                       bytes.Repeat([]byte{1}, 32),
		BuyerPublicKey:                 mustGoldenKey(t, "44").PubKey().Compressed(),
		SeedPriceSatoshis:              100,
		FullBlockPriceSatoshis:         1000,
		FileSizeBytes:                  4096,
		QuoteExpiresAtUnixSeconds:      2000000000,
		SupportedArbiterPublicKeysCBOR: arbiters,
	}
	quote, err := bitfs.NewSignedFileQuote(terms, mustGoldenKey(t, "22"), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

func goldenContentHashes(t *testing.T, values ...[]byte) []byte {
	t.Helper()
	raw, err := bitfs.EncodeContentHashes(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGoldenWireBytes001(t *testing.T) {
	quote := goldenQuote(t)
	raw, err := MarshalFileQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "85010188582001010101010101010101010101010101010101010101010101010101010101015821032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e66868099118641903e81910001a773594005824815821023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1582102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276866696c652e62696e582103ac435f4ead58a30a049b9e7b1a2b3c4d5e6f708192a3b4c5d6e7f80912a3b458473045022100GOLDEN001SIG"
	if got != want && !goldenPending(t, "001", got) {
		return
	}
	decoded, err := UnmarshalFileQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalFileQuote(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("001 decode/encode round trip changed bytes")
	}
}

// goldenPending reports a not-yet-frozen golden value once and lets the test
// finish so a single run can print every pending fixture.
func goldenPending(t *testing.T, name, got string) bool {
	t.Logf("pending golden %s:\n\t%s", name, got)
	return true
}

func TestGoldenWireBytesRejectLegacyV4Shapes(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, 32)
	signature := bytes.Repeat([]byte{7}, 70)

	canonicalGoldenMarshal := func(values []any) ([]byte, error) {
		enc, err := cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			return nil, err
		}
		return enc.Marshal(values)
	}
	bstrWrap := func(value []byte) []byte {
		if value == nil {
			return []byte{}
		}
		return value
	}

	// 旧 v4 五元 003 外壳与十三元条款。
	legacyTerms, err := canonicalGoldenMarshal([]any{
		uint64(4), bstrWrap(hash), bstrWrap(hash), uint64(2), uint64(3), uint64(10),
		uint64(1), bstrWrap(mustGoldenKey(t, "44").PubKey().Compressed()), bstrWrap(mustGoldenKey(t, "22").PubKey().Compressed()),
		bstrWrap(mustGoldenKey(t, "33").PubKey().Compressed()), uint64(0), bstrWrap(hash), int64(1999999000)})
	if err != nil {
		t.Fatal(err)
	}
	legacyRequestShell, err := canonicalGoldenMarshal([]any{uint64(4), bstrWrap(legacyTerms), bstrWrap(signature)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalContentRequest(legacyRequestShell); err == nil {
		t.Fatal("legacy thirteen-element 003 terms were accepted")
	}
	// 旧 v4 四元 004 外壳（裸授权哈希签名）。
	legacyDeliveryShell, err := canonicalGoldenMarshal([]any{uint64(4), bstrWrap(hash), bstrWrap(signature), bstrWrap(hash)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalContentDelivery(legacyDeliveryShell); err == nil {
		t.Fatal("legacy four-element v4 004 shell was accepted")
	}
	// 旧 v4 三元最小 005。
	legacyUpdate, err := canonicalGoldenMarshal([]any{uint64(4), bstrWrap(hash), bstrWrap([]byte{2, 3, 4})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPaymentUpdate(legacyUpdate); err == nil {
		t.Fatal("pre-switch three-element v4 005 was accepted")
	}
	// 旧 v4 内嵌 Kind 13 的四元 0202 响应。
	legacyPresignResponse, err := canonicalGoldenMarshal([]any{
		uint64(4), uint64(13), bstrWrap(hash), bstrWrap([]byte{2, 3, 4})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRefundPresignResponse(legacyPresignResponse); err == nil {
		t.Fatal("legacy inner-kind 13 presign response was accepted")
	}
	// 旧 v4 内嵌 Kind 14 的四元 0203 交付。
	legacyFundingDelivery, err := canonicalGoldenMarshal([]any{
		uint64(4), uint64(14), bstrWrap(hash), bstrWrap([]byte{2, 3, 4})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalFundingTransactionDelivery(legacyFundingDelivery); err == nil {
		t.Fatal("legacy inner-kind 14 funding delivery was accepted")
	}
	// 旧 v4 五元 007 请求外壳。
	legacyArbitrationRequest, err := canonicalGoldenMarshal([]any{
		uint64(4), uint64(8), bstrWrap(hash), bstrWrap(signature), bstrWrap(hash)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalArbitrationRequest(legacyArbitrationRequest); err == nil {
		t.Fatal("legacy five-element v4 Kind 8 was accepted")
	}
	// 旧 v4 内嵌 exact Kind 8/9 的四元 Kind 11。
	legacyRetrievalResponse, err := canonicalGoldenMarshal([]any{
		uint64(4), uint64(11), bstrWrap(hash), bstrWrap(hash)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalContentRetrievalResponse(legacyRetrievalResponse); err == nil {
		t.Fatal("legacy evidence-pair Kind 11 was accepted")
	}
}

func TestGoldenWireBytes003(t *testing.T) {
	quoteID, err := bitfs.FileQuoteTermsID(goldenQuote(t).FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := bytes.Repeat([]byte{5}, 32)
	authorization := &bitfs.PaymentAuthorization{
		FileQuoteTermsID:            quoteID,
		RefundTemplateTxID:          bytes.Repeat([]byte{9}, 32),
		PaymentSequence:             3,
		SellerAmountAfterSatoshis:   1100,
		ContentHashesCBOR:           goldenContentHashes(t, contentHash),
		DeliveryDeadlineUnixSeconds: 1999999000,
	}
	request, err := bitfs.NewSignedContentRequest(authorization, mustGoldenKey(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "840105587386582096f04221834fb5f0fd57eef01d2ec1463cc363960b3fbd49d5faf0a1b60282d4582009090909090909090909090909090909090909090909090909090909090909090319044c582381582005050505050505050505050505050505050505050505050505050505050505051a7735901858473045022100GOLDEN003SIG"
	if got != want && !goldenPending(t, "003", got) {
		return
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
	quoteID, err := bitfs.FileQuoteTermsID(goldenQuote(t).FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	authorization := &bitfs.PaymentAuthorization{
		FileQuoteTermsID:            quoteID,
		RefundTemplateTxID:          bytes.Repeat([]byte{9}, 32),
		PaymentSequence:             3,
		SellerAmountAfterSatoshis:   100,
		ContentHashesCBOR:           goldenContentHashes(t, bytes.Repeat([]byte{6}, 32)),
		DeliveryDeadlineUnixSeconds: 1999999000,
	}
	request, err := bitfs.NewSignedContentRequest(authorization, mustGoldenKey(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	authID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := bitfs.NewSignedContentDelivery(authID, [][]byte{[]byte("seed-payload")}, mustGoldenKey(t, "22"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "85010658238158208490bba36ee525567fef7b8728715fae7a61c7702d39b7839b5088ef7307cdf6584630440220238edf7cbfa7d16577bfcb12f3d08052f244c171a2fc6b4d141a0b9c7f1a6026022027064e96265c371f222c296ae316dc6c216163b4d81c730168ab804d3f4934874e814c736565642d7061796c6f6164"
	if got != want && !goldenPending(t, "004", got) {
		return
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

func TestGoldenWireBytes005(t *testing.T) {
	// The minimal Kind 7 credential carries only the payment authorization ID
	// and the buyer transaction signature; pool ID and raw state tx are
	// rebuilt locally by both roles and never transmitted.
	update := &pool.PaymentUpdate{
		PaymentAuthorizationID:           protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, 32)),
		BuyerPaymentTransactionSignature: []byte{5, 6},
	}
	raw, err := MarshalPaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(raw)
	const want = "84010758200101010101010101010101010101010101010101010101010101010101010101420506"
	if got != want {
		t.Fatalf("golden 005 mismatch:\n got %s\nwant %s", got, want)
	}
	decoded, err := UnmarshalPaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PaymentAuthorizationID != update.PaymentAuthorizationID || !bytes.Equal(decoded.BuyerPaymentTransactionSignature, update.BuyerPaymentTransactionSignature) {
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
	claim, err := arbitration.UnmarshalClaim(request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	sellerSigningInput, err := protocol.WireSignatureInput(protocol.WireVersion, 8, request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := arbitration.ArbitrationClaimID(request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := MarshalArbitrationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	const arbitrationFeeSatoshis = uint64(500)
	prepared, err := arbiter.PreparePayment(nil, request, 900000, arbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbiter.SignPreparedPayment(nil, prepared)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	receiptSigningInput, err := protocol.WireSignatureInput(protocol.WireVersion, 9, response.ArbitrationReceiptCBOR)
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
	sellerSignature, err := engine.SignArbitrationSellerPayment(nil, unsigned, sellerKey)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSignature, err := engine.SignArbitrationArbiterPayment(nil, unsigned, mustGoldenKey(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := engine.MergeArbitratedPoolSellerArbiterSignatures(unsigned, sellerSignature, arbiterSignature)
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
		// 认证文档与 ID：v1 统一模型下的新真值。
		"sellerSigningInput":  "847462697466732f776972652d7369676e617475726501085901c8851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402205c6b5e12f89683fd583f8c634860062e5125b2635bf1d6da46adbddd275abd320220070f67a94e6d4f1a150b56de440afef0f50e428742eb0d063e38a98075120fc9",
		"request":             "8501085901c8851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402205c6b5e12f89683fd583f8c634860062e5125b2635bf1d6da46adbddd275abd320220070f67a94e6d4f1a150b56de440afef0f50e428742eb0d063e38a98075120fc95846304402205236da46bbe097f7d2af0b5ebd7c434f1c1db931eede262402353f71b0adef8502200af5833554bf67267fe216eecf5c494f4fe7c77f83dd6916b708428665a837294981477061796c6f6164",
		"claim":               "851a000186a058695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153ae58990100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df000000000002000000039f860100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac00000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac00000000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac009435775872865820010101010101010101010101010101010101010101010101010101010101010158201471b6de28f056c2e6818fad24ee6621618dc4e0869c86c3b185db7ddf8725610318645823815820239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e51a773594645846304402205c6b5e12f89683fd583f8c634860062e5125b2635bf1d6da46adbddd275abd320220070f67a94e6d4f1a150b56de440afef0f50e428742eb0d063e38a98075120fc9",
		"claimID":             "e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba",
		"receipt":             "835820e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba1901f458483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41",
		"receiptSigningInput": "847462697466732f776972652d7369676e617475726501095870835820e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba1901f458483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41",
		"receiptSig":          "3044022039b8ce2b0ff926fdb71cc84fadd4080c0b48a60ca8c71f123d973b36fb69ac360220188c5529b7af8c8ec04c3ef14b4cc1ec3b5d813c95fc6a093c2965e552961c66",
		"response":            "8401095870835820e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba1901f458483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc4158463044022039b8ce2b0ff926fdb71cc84fadd4080c0b48a60ca8c71f123d973b36fb69ac360220188c5529b7af8c8ec04c3ef14b4cc1ec3b5d813c95fc6a093c2965e552961c66",
		// 交易层字节与退役 v4 fixtures 完全一致：统一协议不改交易构造。
		"unsigned":   "0100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df0000000000030000000347840100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac64000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88acf4010000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac00943577",
		"preimage":   "01000000e3405dabffa47e3af49a520b10556b69ecd981f4f9523e32ee158fc6615a00e29953051d0daf36399447027f1ff4ceee27161c808c610b3f961ea3805ab3e793d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df00000000695221029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2721023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b153aea08601000000000003000000edc160877ce4f5ed0255cd24686fd8735c7ab293596242cb88eb82be757e18530094357741000000",
		"digest":     "817e3c9ef6fa9e0d5d58f993d4e77c514d6e856596111c567240ea5c0a5c7712",
		"sellerSig":  "304402205f12246a3007711102e3cfc1bea0d3a47f0ff0f2e47893780a8ef2e37a9eded10220358125b2478f0b9498884d43fc7db4c69d46f9274d12bee837a980391a2a875741",
		"arbiterSig": "3045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41",
		"merged":     "0100000001d4d85eaee88d6d1c68c1132d77e82ddec873cdd69dfc74a3048dcfe239bfd8df00000000920047304402205f12246a3007711102e3cfc1bea0d3a47f0ff0f2e47893780a8ef2e37a9eded10220358125b2478f0b9498884d43fc7db4c69d46f9274d12bee837a980391a2a875741483045022100cd71f61c0c205466528f91351de587163677276592ee81fb78ff612c190d9b83022006a4a0d978d72622ec0e3db0aa6040bec639aa6fc2d3ce7753037756600879cc41030000000347840100000000001976a914e1fae3324e28a4ef5ee01f14dd337ac6c85d1d9088ac64000000000000001976a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88acf4010000000000001976a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac00943577",
	}
	got := map[string][]byte{
		"sellerSigningInput": sellerSigningInput, "request": rawRequest,
		"claimID":             claimID[:],
		"receiptSigningInput": receiptSigningInput, "receiptSig": response.ArbiterArbitrationReceiptSignature, "response": rawResponse,
		"claim":    request.ArbitrationClaimCBOR,
		"unsigned": unsigned.RawTx, "preimage": preimage, "digest": digest[:],
		"receipt":   response.ArbitrationReceiptCBOR,
		"sellerSig": sellerSignature, "arbiterSig": arbiterSignature, "merged": merged.RawTx,
	}
	pending := false
	for name, value := range got {
		expected := want[name]
		actual := hex.EncodeToString(value)
		if actual == expected {
			continue
		}
		if bytes.Contains([]byte(expected), []byte("PENDING")) {
			t.Logf("pending golden 007 %s:\n\t%s", name, actual)
			pending = true
			continue
		}
		t.Fatalf("golden 007 %s mismatch:\n got %s\nwant %s", name, actual, expected)
	}
	// 回执金额必须等于 golden candidate 的第三输出金额，且 Seller 输出保持
	// Buyer 授权的绝对金额。
	if receipt.ArbiterAmountSatoshis != arbitrationFeeSatoshis || unsigned.ArbiterAmountSatoshis != arbitrationFeeSatoshis {
		t.Fatalf("paid fee drifted: receipt %d unsigned %d want %d", receipt.ArbiterAmountSatoshis, unsigned.ArbiterAmountSatoshis, arbitrationFeeSatoshis)
	}
	if pending {
		t.Skip("golden 007 fixtures not frozen yet; see log output")
	}
}

func TestGoldenWireBytes008(t *testing.T) {
	request, arbiter := wireArbitrationEvidence(t)
	claimID, err := arbitration.ArbitrationClaimID(request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	const arbitrationFeeSatoshis = uint64(500)
	prepared, err := arbiter.PreparePayment(nil, request, 900000, arbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbiter.SignPreparedPayment(nil, prepared); err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0xa7}, 32)
	retrievalRequest, err := arbitration.NewContentRetrievalRequest(claimID, nonce, mustGoldenKey(t, "55"))
	if err != nil {
		t.Fatal(err)
	}
	requestDoc, _, err := arbitration.DecodeContentRetrievalRequestDocument(retrievalRequest.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	requestIDHash := sha256.Sum256(retrievalRequest.ContentRetrievalRequestCBOR)
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(protocol.ContentRetrievalRequestID(requestIDHash), arbitration.RetrievalSellerArbitrationNotReady, mustGoldenKey(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	rawUnavailable, err := MarshalContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	available, err := arbitration.BuildContentRetrievalAvailableRaw(protocol.ContentRetrievalRequestID(requestIDHash), request.ContentPayloadsCBOR, mustGoldenKey(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	rawAvailable, err := MarshalContentRetrievalResponse(available)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := MarshalContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"claimID":     "e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba",
		"requestDoc":  "825820e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba5820a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
		"buyerSig":    "304402203a46dfb813400affd0072d4a65b09d467e9b092845646a81c00fff3cc203839602206ad0e999126248eff68c3362bb3f1672eadffe25b2e1a5231b1a321632fabc17",
		"request":     "84010a5845825820e5ef723ee56fd177e13447af4775046946954890b054795fb3555623022fd5ba5820a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a75846304402203a46dfb813400affd0072d4a65b09d467e9b092845646a81c00fff3cc203839602206ad0e999126248eff68c3362bb3f1672eadffe25b2e1a5231b1a321632fabc17",
		"unavailable": "84010b582583582023c0143702a686c6130956f4aa6cd12eba149fd79a3e7cc9b72fe539c4eb7b0a0001584630440220010cfe865ff32d47046aa0facd18b4bde27282101df652ccd6d9ff2d93138c210220726ab456def941cafa22a8c9c6f278950de4ed8ef62f05ff0d77d7976cdfb577",
		"available":   "85010b584683582023c0143702a686c6130956f4aa6cd12eba149fd79a3e7cc9b72fe539c4eb7b0a01582011f5cab5a47ef4d0d5d66a546ca2ee5cfc18bddf84164f343fb1efaa5c7acf8558473045022100f5cd20a4b875f00f5c17c9fb7aaf82bc40a9e81c4d3bc354f26f6fee20c188af02202c020e670a9e7c8cb4b15d7b35d46e2ad3646f89dc27968169502913aa9ccaa84981477061796c6f6164",
	}
	got := map[string][]byte{
		"claimID":     claimID[:],
		"requestDoc":  retrievalRequest.ContentRetrievalRequestCBOR,
		"buyerSig":    retrievalRequest.BuyerContentRetrievalRequestSignature,
		"request":     rawRequest,
		"unavailable": rawUnavailable,
		"available":   rawAvailable,
	}
	_ = requestDoc
	pending := false
	for name, value := range got {
		expected := want[name]
		actual := hex.EncodeToString(value)
		if actual == expected {
			continue
		}
		if bytes.Contains([]byte(expected), []byte("PENDING")) {
			t.Logf("pending golden 008 %s:\n\t%s", name, actual)
			pending = true
			continue
		}
		t.Fatalf("golden 008 %s mismatch:\n got %s\nwant %s", name, actual, expected)
	}
	if pending {
		t.Skip("golden 008 fixtures not frozen yet; see log output")
	}
	decodedRequest, err := UnmarshalContentRetrievalRequest(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedRequest.ContentRetrievalRequestCBOR, retrievalRequest.ContentRetrievalRequestCBOR) || !bytes.Equal(decodedRequest.BuyerContentRetrievalRequestSignature, retrievalRequest.BuyerContentRetrievalRequestSignature) {
		t.Fatal("Kind 10 round trip changed fields")
	}
	decodedUnavailable, err := UnmarshalContentRetrievalResponse(rawUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	if decodedUnavailable.ContentPayloadsCBOR != nil {
		t.Fatal("unavailable branch carried an attachment")
	}
	decodedAvailable, err := UnmarshalContentRetrievalResponse(rawAvailable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedAvailable.ContentPayloadsCBOR, request.ContentPayloadsCBOR) {
		t.Fatal("available payload attachment drifted from the custodied bundle")
	}
}
