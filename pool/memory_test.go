package pool

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"sync"
	"testing"
)

type testIDCalculator struct{}

func (testIDCalculator) TransactionID(_ context.Context, rawTx []byte) (Hash32, error) {
	return Hash32(sha256.Sum256(rawTx)), nil
}

func TestMemoryStoreUpgradesPendingOpeningAndSerializesRequests(t *testing.T) {
	store, err := NewMemoryStore(testIDCalculator{})
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{
		Version:               MajorVersion,
		RefundTx:              []byte("refund"),
		FundingTxID:           make([]byte, 32),
		PoolOutputSatoshis:    100,
		PoolLockingScript:     []byte("script"),
		BuyerRefundSignature:  []byte("buyer"),
		SellerRefundSignature: []byte("seller"),
	}
	if err := store.SaveOpeningProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	proof.FundingTx = []byte("funding")
	if err := store.SaveOpeningProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	spend, err := SpendTxID(context.Background(), proof, testIDCalculator{})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadOpeningProof(context.Background(), spend)
	if err != nil || loaded == nil || string(loaded.FundingTx) != "funding" {
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

func TestFileStoreRehydratesPoolPaymentAndPendingState(t *testing.T) {
	ctx := context.Background()
	calculator := testIDCalculator{}
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first, err := NewFileStore(path, calculator)
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{
		Version:               MajorVersion,
		RefundTx:              []byte("refund"),
		FundingTxID:           make([]byte, 32),
		PoolOutputSatoshis:    100,
		PoolLockingScript:     []byte("script"),
		BuyerRefundSignature:  []byte("buyer"),
		SellerRefundSignature: []byte("seller"),
		FundingTx:             []byte("funding"),
	}
	if err := first.SaveOpeningProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	spend, err := SpendTxID(ctx, proof, calculator)
	if err != nil {
		t.Fatal(err)
	}
	state := &PaymentState{
		SpendTxID:               spend,
		RawTx:                   []byte("accepted-payment"),
		PaymentSequence:         2,
		SellerAmountSat:         7,
		ClientAmountSat:         92,
		ContentRequestTermsHash: Hash32{3},
	}
	if err := first.SaveAcceptedPayment(ctx, state); err != nil {
		t.Fatal(err)
	}
	pending := PendingRequest{
		SpendTxID:               spend,
		BasePaymentSequence:     2,
		ContentRequestHash:      Hash32{4},
		ExpectedSellerAmountSat: 7,
	}
	if result, err := first.TryAcquire(ctx, pending); err != nil || result != PendingAcquired {
		t.Fatalf("TryAcquire() = %v, %v", result, err)
	}

	second, err := NewFileStore(path, calculator)
	if err != nil {
		t.Fatal(err)
	}
	loadedProof, err := second.LoadOpeningProof(ctx, spend)
	if err != nil || loadedProof == nil || string(loadedProof.FundingTx) != "funding" {
		t.Fatalf("loaded proof = %#v, err = %v", loadedProof, err)
	}
	loadedState, err := second.LoadAcceptedPayment(ctx, spend)
	if err != nil || loadedState == nil || loadedState.PaymentSequence != 2 || loadedState.SellerAmountSat != 7 {
		t.Fatalf("loaded state = %#v, err = %v", loadedState, err)
	}
	loadedPending, err := second.Load(ctx, spend)
	if err != nil || loadedPending == nil || loadedPending.ExpectedSellerAmountSat != 7 {
		t.Fatalf("loaded pending = %#v, err = %v", loadedPending, err)
	}
	if result, err := second.TryAcquire(ctx, pending); err != nil || result != PendingAlreadyHeld {
		t.Fatalf("rehydrated TryAcquire() = %v, %v", result, err)
	}
}

func TestFileStoreInstancesReloadBeforeMutating(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first, err := NewFileStore(path, testIDCalculator{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStore(path, testIDCalculator{})
	if err != nil {
		t.Fatal(err)
	}
	proof := func(marker byte) *OpeningProof {
		return &OpeningProof{
			Version:               MajorVersion,
			RefundTx:              []byte{marker},
			FundingTxID:           bytes32(marker),
			PoolOutputSatoshis:    100,
			PoolLockingScript:     []byte("script"),
			BuyerRefundSignature:  []byte("buyer"),
			SellerRefundSignature: []byte("seller"),
			FundingTx:             []byte{marker, 0xff},
		}
	}
	firstProof, secondProof := proof(1), proof(2)
	if err := first.SaveOpeningProof(ctx, firstProof); err != nil {
		t.Fatal(err)
	}
	if err := second.SaveOpeningProof(ctx, secondProof); err != nil {
		t.Fatal(err)
	}
	firstSpend, err := SpendTxID(ctx, firstProof, testIDCalculator{})
	if err != nil {
		t.Fatal(err)
	}
	secondSpend, err := SpendTxID(ctx, secondProof, testIDCalculator{})
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
	store, err := NewMemoryStore(testIDCalculator{})
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
