package pool

import (
	"bytes"
	"context"
	"errors"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"testing"
)

type permissivePoolBackend struct {
	final       Hash32
	update      *UpdateAcceptance
	height      uint32
	heightError error
	updates     int
	finals      int
	fundings    int
}

type advancingHeightBackend struct {
	permissivePoolBackend
	heights []uint32
	reads   int
}

func (backend *advancingHeightBackend) BlockHeight(context.Context) (uint32, error) {
	if backend.heightError != nil {
		return 0, backend.heightError
	}
	if len(backend.heights) == 0 {
		return 0, errors.New("height sequence exhausted")
	}
	index := backend.reads
	if index >= len(backend.heights) {
		index = len(backend.heights) - 1
	}
	backend.reads++
	return backend.heights[index], nil
}

type fixedOpeningStore struct{ proof *OpeningProof }

type idempotentFundingBackend struct {
	accepted map[Hash32][]byte
}

func (backend *idempotentFundingBackend) SubmitTransaction(_ context.Context, raw []byte) (Hash32, error) {
	id, err := fixedTransactionID(raw)
	if err != nil {
		return Hash32{}, err
	}
	if backend.accepted == nil {
		backend.accepted = make(map[Hash32][]byte)
	}
	if existing, ok := backend.accepted[id]; ok && !bytes.Equal(existing, raw) {
		return Hash32{}, errors.New("same canonical txid had different raw bytes")
	}
	backend.accepted[id] = append([]byte(nil), raw...)
	return id, nil
}

func (store fixedOpeningStore) LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error) {
	return CloneOpeningProof(store.proof), nil
}

func (backend *permissivePoolBackend) SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error) {
	backend.updates++
	return backend.update, nil
}

func (backend *permissivePoolBackend) SubmitFinal(context.Context, []byte) (Hash32, error) {
	backend.finals++
	return backend.final, nil
}

func (backend *permissivePoolBackend) SubmitTransaction(context.Context, []byte) (Hash32, error) {
	backend.fundings++
	return backend.final, nil
}

func (backend *permissivePoolBackend) BlockHeight(context.Context) (uint32, error) {
	return backend.height, backend.heightError
}

func TestVerifiedNodeRejectsMalformedEvidenceBeforePermissiveBackend(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	backend := &permissivePoolBackend{}
	node, err := NewVerifiedNonFinalPoolNode(store, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.SubmitFunding(ctx, []byte{1, 2, 3}); err == nil {
		t.Fatal("malformed funding was accepted")
	}
	if _, err := node.SubmitUpdate(ctx, []byte{1, 2, 3}); err == nil {
		t.Fatal("malformed update was accepted")
	}
	if _, err := node.SubmitFinal(ctx, []byte{1, 2, 3}); err == nil {
		t.Fatal("malformed final was accepted")
	}
	if backend.fundings != 0 || backend.updates != 0 || backend.finals != 0 {
		t.Fatalf("malformed evidence reached backend: funding=%d update=%d final=%d", backend.fundings, backend.updates, backend.finals)
	}
}

func TestVerifiedNodeRejectsCorruptOpeningSignaturesBeforeFundingBackend(t *testing.T) {
	ctx := context.Background()
	_, proof := mustRefundExpiryFixture(t, 4102444800, nil)
	for name, mutate := range map[string]func(*OpeningProof){
		"buyer":  func(value *OpeningProof) { value.BuyerRefundSignature = []byte{1, 2, 3} },
		"seller": func(value *OpeningProof) { value.SellerRefundSignature = []byte{1, 2, 3} },
	} {
		backend := &permissivePoolBackend{final: Hash32{1}}
		corrupt := CloneOpeningProof(proof)
		mutate(corrupt)
		node, err := NewVerifiedNonFinalPoolNode(fixedOpeningStore{proof: corrupt}, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := node.SubmitFunding(ctx, proof.FundingTx); err == nil {
			t.Fatalf("%s-corrupt opening proof reached funding backend", name)
		}
		if backend.fundings != 0 {
			t.Fatalf("%s-corrupt funding backend calls = %d, want 0", name, backend.fundings)
		}
	}
}

func TestFundingBackendRetryIsCanonicalTransactionIDempotent(t *testing.T) {
	backend := &idempotentFundingBackend{}
	raw := validTestTxWithMarker(9)
	first, err := backend.SubmitTransaction(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := backend.SubmitTransaction(context.Background(), append([]byte(nil), raw...))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("retry txid = %x, want %x", second, first)
	}
}

func TestVerifiedNodeRejectsForgedOpeningSpendAnchorBeforeEveryBackend(t *testing.T) {
	ctx := context.Background()
	engine, proof := mustRefundExpiryFixture(t, 4102444800, nil)
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: initial, SellerAmountAfterSat: initial.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	buyerSig, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	final, err := NewSellerPoolAdapter(engine, testSigner{seller}).MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, submit := range map[string]func(*VerifiedNonFinalPoolNode) error{
		"funding": func(node *VerifiedNonFinalPoolNode) error {
			_, err := node.SubmitFunding(ctx, proof.FundingTx)
			return err
		},
		"update": func(node *VerifiedNonFinalPoolNode) error {
			_, err := node.SubmitUpdate(ctx, initialRaw)
			return err
		},
		"final": func(node *VerifiedNonFinalPoolNode) error {
			_, err := node.SubmitFinal(ctx, final.RawTx)
			return err
		},
	} {
		backend := &permissivePoolBackend{}
		forged := CloneOpeningProof(proof)
		forged.SpendTxID[0] ^= 0xff
		node, err := NewVerifiedNonFinalPoolNode(fixedOpeningStore{proof: forged}, backend)
		if err != nil {
			t.Fatal(err)
		}
		if err := submit(node); err == nil {
			t.Fatalf("%s accepted forged opening anchor", name)
		}
		if backend.fundings != 0 || backend.updates != 0 || backend.finals != 0 {
			t.Fatalf("%s forged anchor reached backend: funding=%d update=%d final=%d", name, backend.fundings, backend.updates, backend.finals)
		}
	}
}

func TestPoolWireIdentityKeysRequireCompressedEncoding(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 4102444800, nil)
	request := &RefundPresignRequest{
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx: proof.RefundTx, FundingTxID: proof.FundingTxID, PoolOutputIndex: proof.PoolOutputIndex,
		PoolOutputSatoshis: proof.PoolOutputSatoshis, PoolLockingScript: proof.PoolLockingScript,
		BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey,
		MinerFeeRateSatPerKB: proof.MinerFeeRateSatPerKB, BuyerRefundSignature: proof.BuyerRefundSignature,
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		t.Fatal(err)
	}
	key := mustPoolTestKey(t, "22")
	request.SellerPubKey = key.PubKey().Uncompressed()
	if err := ValidateRefundPresignRequest(request); err == nil {
		t.Fatal("uncompressed pool request seller key was accepted")
	}
}

func TestVerifiedNodeChecksBackendIdentityAndSequence(t *testing.T) {
	ctx := context.Background()
	engine, proof := mustRefundExpiryFixture(t, 4102444800, nil)
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	backend := &permissivePoolBackend{}
	node, err := NewVerifiedNonFinalPoolNode(store, backend)
	if err != nil {
		t.Fatal(err)
	}
	refund, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(ctx, refund, proof)
	if err != nil {
		t.Fatal(err)
	}
	closeUnsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: initial, SellerAmountAfterSat: initial.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	closeBuyerSig, err := NewBuyerPoolAdapter(engine, testSigner{mustPoolTestKey(t, "11")}).SignBuyerPayment(ctx, closeUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	closeSellerSig, err := NewSellerPoolAdapter(engine, testSigner{mustPoolTestKey(t, "22")}).SignSellerPayment(ctx, closeUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	close, err := NewSellerPoolAdapter(engine, testSigner{mustPoolTestKey(t, "22")}).MergeBuyerSellerPayment(closeUnsigned, closeBuyerSig, closeSellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	backend.final = Hash32{99}
	if _, err := node.SubmitFinal(ctx, close.RawTx); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("inconsistent final txid error = %v", err)
	}
	if backend.finals != 1 {
		t.Fatalf("final backend calls = %d, want 1", backend.finals)
	}

	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	previous, err := engine.ParsePaymentState(ctx, refund, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: 1})
	if err != nil {
		t.Fatal(err)
	}
	buyerSig, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := NewSellerPoolAdapter(engine, testSigner{seller}).MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	backend.update = &UpdateAcceptance{}
	if _, err := node.SubmitUpdate(ctx, accepted.RawTx); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("inconsistent update response error = %v", err)
	}
	if backend.updates != 1 {
		t.Fatalf("update backend calls = %d, want 1", backend.updates)
	}
}

func TestVerifiedNodeRejectsImmediateFinalFromUpdateBackend(t *testing.T) {
	ctx := context.Background()
	engine, proof := mustRefundExpiryFixture(t, 4102444800, nil)
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: initial, SellerAmountAfterSat: initial.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	buyerSig, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	final, err := NewSellerPoolAdapter(engine, testSigner{seller}).MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	backend := &permissivePoolBackend{}
	node, err := NewVerifiedNonFinalPoolNode(store, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.SubmitUpdate(ctx, final.RawTx); err == nil {
		t.Fatal("immediate final transaction was accepted as a non-final update")
	}
	if backend.updates != 0 {
		t.Fatalf("final transaction reached update backend %d times", backend.updates)
	}
}

func TestVerifiedNodeUsesBackendHeightOnlyForHeightRefund(t *testing.T) {
	ctx := context.Background()
	_, proof := mustRefundExpiryFixture(t, 900000, nil)
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	refundEngine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := refundEngine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	backend := &permissivePoolBackend{final: Hash32{1}, height: 900000, heightError: errors.New("height unavailable")}
	node, err := NewVerifiedNonFinalPoolNode(store, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.SubmitFinal(ctx, raw); err == nil {
		t.Fatal("height refund succeeded without a height source")
	}
	if backend.finals != 0 {
		t.Fatal("height refund reached backend without height")
	}
	backend.heightError = nil
	backend.final, err = fixedTransactionID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.SubmitFinal(ctx, raw); err != nil {
		t.Fatalf("height refund with backend height failed: %v", err)
	}
	if backend.finals != 1 {
		t.Fatalf("final backend calls = %d, want 1", backend.finals)
	}
}

func TestVerifiedNodeRejectsExpiredUpdateAndImmediateCloseBeforeBackend(t *testing.T) {
	ctx := context.Background()
	engine, proof := mustRefundExpiryFixture(t, 500000100, nil)
	previousRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(ctx, previousRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: previous.SellerAmountSat + 1})
	if err != nil {
		t.Fatal(err)
	}
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	buyerSig, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := engine.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	closeUnsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: &accepted.State, SellerAmountAfterSat: accepted.State.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	closeBuyer, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, closeUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	closeSeller, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, closeUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	close, err := engine.MergeBuyerSellerPayment(closeUnsigned, closeBuyer, closeSeller, proof)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	backend := &permissivePoolBackend{update: &UpdateAcceptance{}, final: Hash32{1}}
	node, err := NewVerifiedNonFinalPoolNode(store, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.SubmitUpdate(ctx, accepted.RawTx); err == nil {
		t.Fatal("expired update unexpectedly reached backend")
	}
	if backend.updates != 0 {
		t.Fatalf("expired update backend calls = %d", backend.updates)
	}
	if _, err := node.SubmitFinal(ctx, close.RawTx); err == nil {
		t.Fatal("expired immediate close unexpectedly reached backend")
	}
	if backend.finals != 0 {
		t.Fatalf("expired immediate-close backend calls = %d", backend.finals)
	}
}

func TestVerifiedNodeUpdateFetchesLatestBlockHeightImmediatelyBeforeBackend(t *testing.T) {
	ctx := context.Background()
	engine, proof := mustRefundExpiryFixture(t, 900000, nil)
	previousRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(ctx, previousRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: previous.SellerAmountSat + 1})
	if err != nil {
		t.Fatal(err)
	}
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	buyerSig, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := engine.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	backend := &advancingHeightBackend{heights: []uint32{900000}, permissivePoolBackend: permissivePoolBackend{update: &UpdateAcceptance{TxID: Hash32{1}, SpendTxID: accepted.State.SpendTxID, PaymentSequence: accepted.State.PaymentSequence}}}
	node, err := NewVerifiedNonFinalPoolNode(store, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.SubmitUpdate(ctx, accepted.RawTx); err == nil {
		t.Fatal("update at newly reached refund height was accepted")
	}
	if backend.reads != 1 {
		t.Fatalf("height reads = %d, want one final read", backend.reads)
	}
	if backend.updates != 0 {
		t.Fatalf("expired update reached backend %d times", backend.updates)
	}
	backend.heightError = errors.New("height unavailable")
	if _, err := node.SubmitUpdate(ctx, accepted.RawTx); err == nil {
		t.Fatal("update succeeded without height")
	}
	if backend.updates != 0 {
		t.Fatalf("height-error update reached backend %d times", backend.updates)
	}
}

func TestRefundUsesBlockHeightRejectsMalformedBytes(t *testing.T) {
	if _, err := RefundUsesBlockHeight([]byte{1, 2, 3}); err == nil {
		t.Fatal("malformed refund bytes were classified")
	}
	refundValue, err := transaction.NewTransactionFromBytes(validTestTxWithMarker(1))
	if err != nil {
		t.Fatal(err)
	}
	refundValue.LockTime = lockTimeTimestampThreshold
	refund := refundValue.Bytes()
	usesHeight, err := RefundUsesBlockHeight(refund)
	if err != nil {
		t.Fatal(err)
	}
	if usesHeight {
		t.Fatal("timestamp refund was classified as block-height refund")
	}
}

func TestParseCanonicalTransactionRejectsNonMinimalInputCount(t *testing.T) {
	raw := validTestTxWithMarker(1)
	if len(raw) < 8 || raw[6] != 1 {
		t.Fatalf("test transaction does not use a one-byte input count: %x", raw)
	}
	nonCanonical := append([]byte(nil), raw[:6]...)
	nonCanonical = append(nonCanonical, 0xfd, 0x01, 0x00)
	nonCanonical = append(nonCanonical, raw[7:]...)
	if _, err := ParseCanonicalTransaction(nonCanonical); err == nil {
		t.Fatal("non-minimal CompactSize transaction was accepted")
	}
}
