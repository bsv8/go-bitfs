package pool

import (
	"context"
	"fmt"
	"sync"
)

// BSVTransactionIDCalculator adapts the synchronous reference engine to the
// context-aware opening workflow port.  Production applications can replace
// it with a database-backed calculator or a node/SDK implementation.
type BSVTransactionIDCalculator struct {
	Engine *MultisigPoolEngine
}

// TransactionID computes the canonical transaction identifier from raw transaction bytes.
func (calculator BSVTransactionIDCalculator) TransactionID(_ context.Context, rawTx []byte) (Hash32, error) {
	if calculator.Engine == nil {
		return Hash32{}, fmt.Errorf("%w: MultisigPool engine is required", ErrInvalidEvidence)
	}
	return calculator.Engine.TransactionID(rawTx)
}

// MemoryStore is a concurrency-safe reference implementation of the pool
// persistence ports.  It is useful for integration tests and small embedded
// deployments; replacing it does not change protocol semantics.
type MemoryStore struct {
	mu                sync.Mutex
	calculator        TransactionIDCalculator
	openingsBySpend   map[Hash32]*OpeningProof
	openingsByFunding map[Hash32]*OpeningProof
	accepted          map[Hash32]*PaymentState
	pending           map[Hash32]PendingRequest
	uncertain         map[Hash32]Hash32
}

// NewMemoryStore requires a transaction ID calculator and returns a concurrency-safe in-memory pool store.
func NewMemoryStore(calculator TransactionIDCalculator) (*MemoryStore, error) {
	if calculator == nil {
		return nil, fmt.Errorf("%w: transaction ID calculator is required", ErrInvalidEvidence)
	}
	return &MemoryStore{
		calculator:        calculator,
		openingsBySpend:   make(map[Hash32]*OpeningProof),
		openingsByFunding: make(map[Hash32]*OpeningProof),
		accepted:          make(map[Hash32]*PaymentState),
		pending:           make(map[Hash32]PendingRequest),
		uncertain:         make(map[Hash32]Hash32),
	}, nil
}

// SaveOpeningProof validates and persists the opening proof keyed by its spend transaction ID.
func (store *MemoryStore) SaveOpeningProof(ctx context.Context, proof *OpeningProof) error {
	if store == nil {
		return fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	cloned := cloneOpeningProof(proof)
	if cloned != nil && len(cloned.SpendTxID) == 0 {
		spendTxID, err := store.calculator.TransactionID(ctx, append([]byte(nil), cloned.RefundTx...))
		if err != nil {
			return fmt.Errorf("calculate opening spend transaction ID: %w", err)
		}
		cloned.SpendTxID = append([]byte(nil), spendTxID[:]...)
	}
	if err := ValidateOpeningProof(cloned); err != nil {
		return err
	}
	spendTxID, err := SpendTxID(ctx, cloned, store.calculator)
	if err != nil {
		return err
	}
	cloned.Version = MajorVersion
	cloned.MultisigProtocol = MultisigProtocol
	cloned.MultisigVersion = MultisigVersion
	store.mu.Lock()
	defer store.mu.Unlock()
	if old := store.openingsBySpend[spendTxID]; old != nil && !openingProofCompatible(old, cloned) {
		return fmt.Errorf("%w: spend transaction ID already maps to different opening proof", ErrInvalidEvidence)
	}
	store.openingsBySpend[spendTxID] = cloned
	if len(cloned.FundingTxID) == 32 {
		fundingID := hash32FromBytes(cloned.FundingTxID)
		if old := store.openingsByFunding[fundingID]; old != nil && !openingProofCompatible(old, cloned) {
			return fmt.Errorf("%w: funding transaction ID already maps to different opening proof", ErrInvalidEvidence)
		}
		store.openingsByFunding[fundingID] = cloneOpeningProof(cloned)
	}
	return nil
}

// LoadOpeningProof loads the opening proof keyed by spend transaction ID.
func (store *MemoryStore) LoadOpeningProof(_ context.Context, spendTxID Hash32) (*OpeningProof, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneOpeningProof(store.openingsBySpend[spendTxID]), nil
}

// LoadOpeningProofByFundingTxID finds an opening proof by its funding transaction ID.
func (store *MemoryStore) LoadOpeningProofByFundingTxID(_ context.Context, fundingTxID Hash32) (*OpeningProof, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneOpeningProof(store.openingsByFunding[fundingTxID]), nil
}

// SaveAcceptedPayment stores a payment by spend transaction ID and rejects sequence rollback or conflicting same-sequence state.
func (store *MemoryStore) SaveAcceptedPayment(_ context.Context, state *PaymentState) error {
	if store == nil {
		return fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	if state == nil || len(state.RawTx) == 0 {
		return fmt.Errorf("%w: payment state is incomplete", ErrInvalidEvidence)
	}
	if state.ArbiterAmountSat != 0 {
		return fmt.Errorf("%w: arbiter amount must be zero", ErrInvalidEvidence)
	}
	cloned := clonePaymentState(state)
	store.mu.Lock()
	defer store.mu.Unlock()
	if old := store.accepted[state.SpendTxID]; old != nil {
		if state.PaymentSequence < old.PaymentSequence {
			return ErrStalePaymentSequence
		}
		if state.PaymentSequence == old.PaymentSequence && !paymentStateEqual(old, cloned) {
			return fmt.Errorf("%w: payment sequence already maps to different state", ErrInvalidEvidence)
		}
	}
	store.accepted[state.SpendTxID] = cloned
	return nil
}

// LoadAcceptedPayment returns the accepted payment state for a spend transaction ID.
func (store *MemoryStore) LoadAcceptedPayment(_ context.Context, spendTxID Hash32) (*PaymentState, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return clonePaymentState(store.accepted[spendTxID]), nil
}

// EnsurePoolHealthy rejects operations after an uncertain external submission is recorded.
func (store *MemoryStore) EnsurePoolHealthy(_ context.Context, spendTxID Hash32) error {
	if store == nil {
		return fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if txID, ok := store.uncertain[spendTxID]; ok {
		return fmt.Errorf("%w: accepted transaction %x requires external reconciliation", ErrPoolStateUncertain, txID[:])
	}
	return nil
}

// MarkExternalStateUncertain records a transaction ID whose node outcome must be reconciled.
func (store *MemoryStore) MarkExternalStateUncertain(_ context.Context, spendTxID, txID Hash32) error {
	if store == nil {
		return fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.uncertain[spendTxID] = txID
	return nil
}

// ReconcileExternalState clears uncertainty after the caller supplies the accepted payment state.
func (store *MemoryStore) ReconcileExternalState(ctx context.Context, spendTxID Hash32, state *PaymentState) error {
	if store == nil {
		return fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	if state == nil || state.SpendTxID != spendTxID || len(state.RawTx) == 0 {
		return fmt.Errorf("%w: reconciled payment state is incomplete", ErrInvalidEvidence)
	}
	txID, err := store.calculator.TransactionID(ctx, append([]byte(nil), state.RawTx...))
	if err != nil {
		return fmt.Errorf("calculate reconciled transaction ID: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	expected, ok := store.uncertain[spendTxID]
	if !ok || expected != txID {
		return fmt.Errorf("%w: reconciled transaction does not match the uncertain state", ErrInvalidEvidence)
	}
	if old := store.accepted[spendTxID]; old != nil && state.PaymentSequence < old.PaymentSequence {
		return ErrStalePaymentSequence
	}
	store.accepted[spendTxID] = clonePaymentState(state)
	delete(store.uncertain, spendTxID)
	return nil
}

// TryAcquire atomically claims a pending request lease unless another owner or hash conflict exists.
func (store *MemoryStore) TryAcquire(_ context.Context, request PendingRequest) (PendingAcquireResult, error) {
	if store == nil {
		return 0, fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if old, ok := store.pending[request.SpendTxID]; ok {
		if old == request {
			return PendingAlreadyHeld, nil
		}
		return PendingConflict, nil
	}
	store.pending[request.SpendTxID] = request
	return PendingAcquired, nil
}

// Load returns a copy of the pending delivery request for spendTxID.
func (store *MemoryStore) Load(_ context.Context, spendTxID Hash32) (*PendingRequest, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	request, ok := store.pending[spendTxID]
	if !ok {
		return nil, nil
	}
	return &request, nil
}

// Release removes a pending request lease only when the caller supplies the matching request hash.
func (store *MemoryStore) Release(_ context.Context, spendTxID, requestHash Hash32) error {
	if store == nil {
		return fmt.Errorf("%w: pool store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	request, ok := store.pending[spendTxID]
	if !ok {
		return nil
	}
	if request.ContentRequestHash != requestHash {
		return ErrStalePaymentSequence
	}
	delete(store.pending, spendTxID)
	return nil
}

func paymentStateEqual(left, right *PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.SpendTxID == right.SpendTxID && left.PaymentSequence == right.PaymentSequence && left.BuyerAmountSat == right.BuyerAmountSat && left.SellerAmountSat == right.SellerAmountSat && left.ArbiterAmountSat == right.ArbiterAmountSat && left.PaymentAuthorizationHash == right.PaymentAuthorizationHash && string(left.RawTx) == string(right.RawTx) && string(left.PoolLockingScript) == string(right.PoolLockingScript)
}

func openingProofEqual(left, right *OpeningProof) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Version == right.Version && left.MultisigProtocol == right.MultisigProtocol && left.MultisigVersion == right.MultisigVersion && left.PoolOutputIndex == right.PoolOutputIndex && left.PoolOutputSatoshis == right.PoolOutputSatoshis && left.MinerFeeRateSatPerKB == right.MinerFeeRateSatPerKB && string(left.RefundTx) == string(right.RefundTx) && string(left.SpendTxID) == string(right.SpendTxID) && string(left.FundingTxID) == string(right.FundingTxID) && string(left.PoolLockingScript) == string(right.PoolLockingScript) && string(left.BuyerPubKey) == string(right.BuyerPubKey) && string(left.SellerPubKey) == string(right.SellerPubKey) && string(left.ArbiterPubKey) == string(right.ArbiterPubKey) && string(left.BuyerRefundSignature) == string(right.BuyerRefundSignature) && string(left.SellerRefundSignature) == string(right.SellerRefundSignature) && string(left.FundingTx) == string(right.FundingTx)
}

func openingProofCompatible(left, right *OpeningProof) bool {
	if !openingProofEqual(left, right) {
		if left == nil || right == nil || left.Version != right.Version || left.MultisigProtocol != right.MultisigProtocol || left.MultisigVersion != right.MultisigVersion || left.PoolOutputIndex != right.PoolOutputIndex || left.PoolOutputSatoshis != right.PoolOutputSatoshis || left.MinerFeeRateSatPerKB != right.MinerFeeRateSatPerKB || string(left.RefundTx) != string(right.RefundTx) || string(left.SpendTxID) != string(right.SpendTxID) || string(left.FundingTxID) != string(right.FundingTxID) || string(left.PoolLockingScript) != string(right.PoolLockingScript) || string(left.BuyerPubKey) != string(right.BuyerPubKey) || string(left.SellerPubKey) != string(right.SellerPubKey) || string(left.ArbiterPubKey) != string(right.ArbiterPubKey) || string(left.BuyerRefundSignature) != string(right.BuyerRefundSignature) || string(left.SellerRefundSignature) != string(right.SellerRefundSignature) {
			return false
		}
		// A proof may be upgraded exactly once from the presign form to the
		// complete form after FundingTx is delivered.
		return len(left.FundingTx) == 0 && len(right.FundingTx) != 0
	}
	return true
}
