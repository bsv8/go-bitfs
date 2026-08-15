package pool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
)

func validTestTx() []byte { return tx.NewTransaction().Bytes() }

func validTestTxWithMarker(marker byte) []byte {
	value := tx.NewTransaction()
	value.AddOutput(&tx.TransactionOutput{Satoshis: uint64(marker), LockingScript: script.NewFromBytes([]byte{marker})})
	return value.Bytes()
}

func TestCloseIssuedPersistsAcrossFileStoreRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "close-state.json")
	spend := Hash32{7}
	first, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.MarkPoolClosing(ctx, spend); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.EnsurePoolOpen(ctx, spend); !errors.Is(err, ErrPoolStateUncertain) {
		t.Fatalf("reloaded close guard=%v", err)
	}
	if err := second.ReconcilePoolClosing(ctx, spend); err != nil {
		t.Fatal(err)
	}
	if err := second.EnsurePoolOpen(ctx, spend); err != nil {
		t.Fatalf("reconciled close guard=%v", err)
	}
}

func poolTestPubkeys(t *testing.T) (buyer, seller, arbiter []byte) {
	t.Helper()
	return mustPoolTestKey(t, "11").PubKey().Compressed(), mustPoolTestKey(t, "22").PubKey().Compressed(), mustPoolTestKey(t, "33").PubKey().Compressed()
}

func TestFileStoreRejectsPreviousSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	if err := os.WriteFile(path, []byte(`{"version":3,"openings":[],"accepted":[],"pending":[],"uncertain":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path); err == nil || !strings.Contains(err.Error(), "unsupported pool store snapshot version 3") {
		t.Fatalf("NewFileStore() error = %v, want schema rejection", err)
	}
}

func TestPoolStateUncertaintyStopsFurtherUseAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	spend := Hash32{1}
	txID := Hash32{2}
	if err := first.MarkExternalStateUncertain(ctx, spend, txID); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsurePoolHealthy(ctx, spend); !errors.Is(err, ErrPoolStateUncertain) {
		t.Fatalf("EnsurePoolHealthy() = %v, want ErrPoolStateUncertain", err)
	}
	second, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.EnsurePoolHealthy(ctx, spend); !errors.Is(err, ErrPoolStateUncertain) {
		t.Fatalf("reloaded EnsurePoolHealthy() = %v, want ErrPoolStateUncertain", err)
	}
	state := &PaymentState{SpendTxID: spend, RawTx: validTestTx(), PaymentSequence: 4}
	reconciledID, err := fixedTransactionID(state.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.MarkExternalStateUncertain(ctx, spend, reconciledID); err != nil {
		t.Fatal(err)
	}
	if err := second.ReconcileExternalState(ctx, spend, state); err != nil {
		t.Fatalf("ReconcileExternalState() = %v", err)
	}
	if err := second.EnsurePoolHealthy(ctx, spend); err != nil {
		t.Fatalf("EnsurePoolHealthy() after reconciliation = %v", err)
	}
}

func TestMemoryStoreUpgradesPendingOpeningAndSerializesRequests(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx:           validTestTx(),
		SpendTxID:          make([]byte, 32),
		FundingTxID:        make([]byte, 32),
		PoolOutputSatoshis: 100,
		PoolLockingScript:  []byte("script"),
		SellerPubKey:       nil, BuyerPubKey: nil, ArbiterPubKey: nil,
		BuyerRefundSignature:  []byte("buyer"),
		SellerRefundSignature: []byte("seller"),
	}
	proof.BuyerPubKey, proof.SellerPubKey, proof.ArbiterPubKey = poolTestPubkeys(t)
	spendID, err := fixedTransactionID(proof.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	proof.SpendTxID = append([]byte(nil), spendID[:]...)
	if err := store.SaveOpeningProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	proof.FundingTx = validTestTx()
	if err := store.SaveOpeningProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	spend, err := SpendTxID(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadOpeningProof(context.Background(), spend)
	if err != nil || loaded == nil || len(loaded.FundingTx) == 0 {
		t.Fatalf("loaded proof = %#v, err = %v", loaded, err)
	}
	request := PendingRequest{SpendTxID: spend, BasePaymentSequence: 1, ContentRequestHash: Hash32{1}}
	result, err := store.TryAcquire(context.Background(), request)
	if err != nil || result != PendingAcquired {
		t.Fatalf("first acquire = %v, %v", result, err)
	}
	result, err = store.TryAcquire(context.Background(), request)
	if err != nil || result != PendingAlreadyHeld {
		t.Fatalf("same-request acquire = %v, %v", result, err)
	}
	other := request
	other.ContentRequestHash = Hash32{2}
	result, err = store.TryAcquire(context.Background(), other)
	if err != nil || result != PendingConflict {
		t.Fatalf("conflicting acquire = %v, %v", result, err)
	}
	if err := store.Release(context.Background(), spend, request.ContentRequestHash); err != nil {
		t.Fatal(err)
	}
}

func TestStoresRequireCorrectSuppliedSpendTxID(t *testing.T) {
	ctx := context.Background()
	_, proof := mustRefundExpiryFixture(t, 500000100, nil)
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	missing := CloneOpeningProof(proof)
	missing.SpendTxID = nil
	if err := store.SaveOpeningProof(ctx, missing); err == nil {
		t.Fatal("memory store accepted missing SpendTxID")
	}
	mismatch := CloneOpeningProof(proof)
	mismatch.SpendTxID[0] ^= 0xff
	if err := store.SaveOpeningProof(ctx, mismatch); err == nil {
		t.Fatal("memory store accepted mismatched SpendTxID")
	}
	path := filepath.Join(t.TempDir(), "pool-state.json")
	file, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.SaveOpeningProof(ctx, missing); err == nil {
		t.Fatal("file store accepted missing SpendTxID")
	}
}

func TestSpendTxIDRejectsForgedAnchor(t *testing.T) {
	proof := &OpeningProof{RefundTx: validTestTx(), SpendTxID: bytes32(0xaa)}
	if _, err := SpendTxID(context.Background(), proof); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("SpendTxID forged anchor error = %v, want ErrInvalidEvidence", err)
	}
}

func TestFileStoreRehydratesPoolPaymentAndPendingState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx:           validTestTx(),
		SpendTxID:          make([]byte, 32),
		FundingTxID:        make([]byte, 32),
		PoolOutputSatoshis: 100,
		PoolLockingScript:  []byte("script"),
		SellerPubKey:       nil, BuyerPubKey: nil, ArbiterPubKey: nil,
		BuyerRefundSignature:  []byte("buyer"),
		SellerRefundSignature: []byte("seller"),
		FundingTx:             validTestTx(),
	}
	proof.BuyerPubKey, proof.SellerPubKey, proof.ArbiterPubKey = poolTestPubkeys(t)
	spendID, err := fixedTransactionID(proof.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	proof.SpendTxID = append([]byte(nil), spendID[:]...)
	if err := first.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	spend, err := SpendTxID(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	state := &PaymentState{
		SpendTxID:                spend,
		RawTx:                    validTestTx(),
		PaymentSequence:          2,
		SellerAmountSat:          20,
		BuyerAmountSat:           92,
		PaymentAuthorizationHash: Hash32{3},
	}
	if err := first.SaveAcceptedPayment(ctx, state); err != nil {
		t.Fatal(err)
	}
	pending := PendingRequest{
		SpendTxID:               spend,
		BasePaymentSequence:     2,
		BaseSellerAmountSat:     13,
		ContentRequestHash:      Hash32{4},
		ExpectedSellerAmountSat: 7,
	}
	if result, err := first.TryAcquire(ctx, pending); err != nil || result != PendingAcquired {
		t.Fatalf("TryAcquire() = %v, %v", result, err)
	}

	second, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loadedProof, err := second.LoadOpeningProof(ctx, spend)
	if err != nil || loadedProof == nil || len(loadedProof.FundingTx) == 0 {
		t.Fatalf("loaded proof = %#v, err = %v", loadedProof, err)
	}
	loadedState, err := second.LoadAcceptedPayment(ctx, spend)
	if err != nil || loadedState == nil || loadedState.PaymentSequence != 2 || loadedState.SellerAmountSat != 20 {
		t.Fatalf("loaded state = %#v, err = %v", loadedState, err)
	}
	loadedPending, err := second.Load(ctx, spend)
	if err != nil || loadedPending == nil || loadedPending.SpendTxID != pending.SpendTxID || loadedPending.BasePaymentSequence != pending.BasePaymentSequence || loadedPending.BaseSellerAmountSat != 13 || loadedPending.ContentRequestHash != pending.ContentRequestHash || loadedPending.ExpectedSellerAmountSat != 7 {
		t.Fatalf("loaded pending = %#v, err = %v", loadedPending, err)
	}
	if result, err := second.TryAcquire(ctx, pending); err != nil || result != PendingAlreadyHeld {
		t.Fatalf("rehydrated TryAcquire() = %v, %v", result, err)
	}
}

func TestReconcileExternalStateValidatesEveryPendingLeaseField(t *testing.T) {
	ctx := context.Background()
	spend := Hash32{41}
	auth := Hash32{42}
	raw := validTestTxWithMarker(43)
	txID, err := fixedTransactionID(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PendingRequest, *PaymentState){
		"spend":           func(p *PendingRequest, _ *PaymentState) { p.SpendTxID = Hash32{99} },
		"hash":            func(p *PendingRequest, _ *PaymentState) { p.ContentRequestHash = Hash32{99} },
		"base sequence":   func(p *PendingRequest, _ *PaymentState) { p.BasePaymentSequence = 3 },
		"base amount":     func(p *PendingRequest, _ *PaymentState) { p.BaseSellerAmountSat = 12 },
		"expected amount": func(p *PendingRequest, _ *PaymentState) { p.ExpectedSellerAmountSat = 8 },
		"state sequence":  func(_ *PendingRequest, s *PaymentState) { s.PaymentSequence = 6 },
		"state amount":    func(_ *PendingRequest, s *PaymentState) { s.SellerAmountSat = 21 },
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewMemoryStore()
			if err != nil {
				t.Fatal(err)
			}
			pending := PendingRequest{SpendTxID: spend, BasePaymentSequence: 4, BaseSellerAmountSat: 13, ContentRequestHash: auth, ExpectedSellerAmountSat: 7}
			if result, err := store.TryAcquire(ctx, pending); err != nil || result != PendingAcquired {
				t.Fatalf("acquire = %v, %v", result, err)
			}
			state := &PaymentState{SpendTxID: spend, RawTx: raw, PaymentSequence: 5, SellerAmountSat: 20, PaymentAuthorizationHash: auth}
			if err := store.MarkExternalStateUncertain(ctx, spend, txID); err != nil {
				t.Fatal(err)
			}
			mutate(&pending, state)
			store.mu.Lock()
			store.pending[spend] = pending
			store.mu.Unlock()
			if err := store.ReconcileExternalState(ctx, spend, state); err == nil {
				t.Fatal("mismatched pending lease reconciled")
			}
			if err := store.EnsurePoolHealthy(ctx, spend); !errors.Is(err, ErrPoolStateUncertain) {
				t.Fatalf("uncertainty was cleared after rejection: %v", err)
			}
			loaded, err := store.Load(ctx, spend)
			if err != nil || loaded == nil {
				t.Fatalf("pending lease was removed after rejection: %#v, %v", loaded, err)
			}
		})
	}
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	pending := PendingRequest{SpendTxID: spend, BasePaymentSequence: 4, BaseSellerAmountSat: 13, ContentRequestHash: auth, ExpectedSellerAmountSat: 7}
	if result, err := store.TryAcquire(ctx, pending); err != nil || result != PendingAcquired {
		t.Fatalf("matching acquire = %v, %v", result, err)
	}
	state := &PaymentState{SpendTxID: spend, RawTx: raw, PaymentSequence: 5, SellerAmountSat: 20, PaymentAuthorizationHash: auth}
	if err := store.MarkExternalStateUncertain(ctx, spend, txID); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileExternalState(ctx, spend, state); err != nil {
		t.Fatalf("matching reconciliation failed: %v", err)
	}
	loadedState, err := store.LoadAcceptedPayment(ctx, spend)
	if err != nil || !paymentStateEqual(loadedState, state) {
		t.Fatalf("reconciled state = %#v, want %#v (err=%v)", loadedState, state, err)
	}
	if err := store.EnsurePoolHealthy(ctx, spend); err != nil {
		t.Fatalf("uncertainty remained after matching reconciliation: %v", err)
	}
	if loadedPending, err := store.Load(ctx, spend); err != nil || loadedPending != nil {
		t.Fatalf("matching pending lease remained: %#v, err=%v", loadedPending, err)
	}
}

func TestFileStoreInstancesReloadBeforeMutating(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	proof := func(marker byte) *OpeningProof {
		result := &OpeningProof{
			Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
			RefundTx:           validTestTxWithMarker(marker),
			SpendTxID:          make([]byte, 32),
			FundingTxID:        bytes32(marker),
			PoolOutputSatoshis: 100,
			PoolLockingScript:  []byte("script"),
			SellerPubKey:       nil, BuyerPubKey: nil, ArbiterPubKey: nil,
			BuyerRefundSignature:  []byte("buyer"),
			SellerRefundSignature: []byte("seller"),
			FundingTx:             []byte{marker, 0xff},
		}
		result.BuyerPubKey, result.SellerPubKey, result.ArbiterPubKey = poolTestPubkeys(t)
		spendID, err := fixedTransactionID(result.RefundTx)
		if err != nil {
			t.Fatal(err)
		}
		result.SpendTxID = append([]byte(nil), spendID[:]...)
		return result
	}
	firstProof, secondProof := proof(1), proof(2)
	if err := first.SaveOpeningProof(ctx, firstProof); err != nil {
		t.Fatal(err)
	}
	if err := second.SaveOpeningProof(ctx, secondProof); err != nil {
		t.Fatal(err)
	}
	firstSpend, err := SpendTxID(ctx, firstProof)
	if err != nil {
		t.Fatal(err)
	}
	secondSpend, err := SpendTxID(ctx, secondProof)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := first.LoadOpeningProof(ctx, secondSpend); err != nil || loaded == nil {
		t.Fatalf("first instance did not observe second instance write: proof=%#v err=%v", loaded, err)
	}
	request := PendingRequest{SpendTxID: firstSpend, BasePaymentSequence: 1, ContentRequestHash: Hash32{9}}
	if result, err := first.TryAcquire(ctx, request); err != nil || result != PendingAcquired {
		t.Fatalf("first TryAcquire() = %v, %v", result, err)
	}
	if result, err := second.TryAcquire(ctx, request); err != nil || result != PendingAlreadyHeld {
		t.Fatalf("second TryAcquire() did not see persisted latch = %v, %v", result, err)
	}
}

func TestMemoryStoreTryAcquireHasOneWinnerUnderConcurrency(t *testing.T) {
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 32
	results := make(chan PendingAcquireResult, attempts)
	request := PendingRequest{SpendTxID: Hash32{9}, BasePaymentSequence: 4, ContentRequestHash: Hash32{8}, ExpectedSellerAmountSat: 11}
	var group sync.WaitGroup
	group.Add(attempts)
	for index := 0; index < attempts; index++ {
		go func() {
			defer group.Done()
			result, err := store.TryAcquire(context.Background(), request)
			if err != nil {
				t.Errorf("TryAcquire() error = %v", err)
				return
			}
			results <- result
		}()
	}
	group.Wait()
	close(results)
	var acquired, alreadyHeld int
	for result := range results {
		switch result {
		case PendingAcquired:
			acquired++
		case PendingAlreadyHeld:
			alreadyHeld++
		default:
			t.Fatalf("unexpected same-request result %v", result)
		}
	}
	if acquired != 1 || alreadyHeld != attempts-1 {
		t.Fatalf("concurrent latch results: acquired=%d already-held=%d", acquired, alreadyHeld)
	}
}
