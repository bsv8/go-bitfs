package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore is a small durable reference implementation of the pool storage
// ports. It uses an advisory process lock and reloads the current snapshot for
// every operation, so cooperating Unix processes do not overwrite each
// other's updates. A transactional database is still preferable when the
// deployment needs indexed queries, crash-recovery guarantees beyond atomic
// rename, or an authoritative lock service.
//
// Each mutation writes a complete snapshot through a temporary file and an
// atomic rename. Raw transactions, signatures and pending price commitments
// therefore survive a process restart without changing their protocol bytes.
type FileStore struct {
	mu     sync.Mutex
	path   string
	memory *MemoryStore
}

const fileStoreSchemaVersion uint8 = 4

type fileStoreSnapshot struct {
	Version   uint8                   `json:"version"`
	Openings  []fileOpeningSnapshot   `json:"openings"`
	Accepted  []filePaymentSnapshot   `json:"accepted"`
	Pending   []filePendingSnapshot   `json:"pending"`
	Uncertain []fileUncertainSnapshot `json:"uncertain"`
}

type fileOpeningSnapshot struct {
	SpendTxID Hash32        `json:"spend_txid"`
	Proof     *OpeningProof `json:"proof"`
}

type filePaymentSnapshot struct {
	SpendTxID Hash32        `json:"spend_txid"`
	State     *PaymentState `json:"state"`
}

type filePendingSnapshot struct {
	SpendTxID Hash32         `json:"spend_txid"`
	Request   PendingRequest `json:"request"`
}

type fileUncertainSnapshot struct {
	SpendTxID Hash32 `json:"spend_txid"`
	TxID      Hash32 `json:"txid"`
}

// NewFileStore opens path and rehydrates all pool, payment and delivery-latch
// state. A missing file is treated as an empty store.
func NewFileStore(path string, calculator TransactionIDCalculator) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: file store path is required", ErrInvalidEvidence)
	}
	memory, err := NewMemoryStore(calculator)
	if err != nil {
		return nil, err
	}
	store := &FileStore{path: path, memory: memory}
	if err := withProcessFileLock(path, false, store.reloadFromDiskLocked); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *FileStore) SaveOpeningProof(ctx context.Context, proof *OpeningProof) error {
	return store.mutate(func() error { return store.memory.SaveOpeningProof(ctx, CloneOpeningProof(proof)) })
}

func (store *FileStore) LoadOpeningProof(ctx context.Context, spendTxID Hash32) (*OpeningProof, error) {
	return store.loadOpening(func() (*OpeningProof, error) { return store.memory.LoadOpeningProof(ctx, spendTxID) })
}

func (store *FileStore) LoadOpeningProofByFundingTxID(ctx context.Context, fundingTxID Hash32) (*OpeningProof, error) {
	return store.loadOpening(func() (*OpeningProof, error) {
		return store.memory.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	})
}

func (store *FileStore) SaveAcceptedPayment(ctx context.Context, state *PaymentState) error {
	return store.mutate(func() error { return store.memory.SaveAcceptedPayment(ctx, ClonePaymentState(state)) })
}

func (store *FileStore) LoadAcceptedPayment(ctx context.Context, spendTxID Hash32) (*PaymentState, error) {
	return store.loadPayment(func() (*PaymentState, error) { return store.memory.LoadAcceptedPayment(ctx, spendTxID) })
}

func (store *FileStore) EnsurePoolHealthy(ctx context.Context, spendTxID Hash32) error {
	if store == nil || store.memory == nil {
		return fmt.Errorf("%w: file store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return withProcessFileLock(store.path, false, func() error {
		if err := store.reloadFromDiskLocked(); err != nil {
			return err
		}
		return store.memory.EnsurePoolHealthy(ctx, spendTxID)
	})
}

func (store *FileStore) MarkExternalStateUncertain(ctx context.Context, spendTxID, txID Hash32) error {
	return store.mutate(func() error { return store.memory.MarkExternalStateUncertain(ctx, spendTxID, txID) })
}

func (store *FileStore) ReconcileExternalState(ctx context.Context, spendTxID Hash32, state *PaymentState) error {
	return store.mutate(func() error { return store.memory.ReconcileExternalState(ctx, spendTxID, ClonePaymentState(state)) })
}

func (store *FileStore) TryAcquire(ctx context.Context, request PendingRequest) (PendingAcquireResult, error) {
	if store == nil || store.memory == nil {
		return 0, fmt.Errorf("%w: file store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var result PendingAcquireResult
	err := withProcessFileLock(store.path, true, func() error {
		if err := store.reloadFromDiskLocked(); err != nil {
			return err
		}
		before := store.memory.snapshot()
		var err error
		result, err = store.memory.TryAcquire(ctx, request)
		if err != nil || result != PendingAcquired {
			return err
		}
		if err := store.flushLocked(); err != nil {
			store.memory.replaceSnapshot(before)
			return err
		}
		return nil
	})
	return result, err
}

func (store *FileStore) Load(ctx context.Context, spendTxID Hash32) (*PendingRequest, error) {
	if store == nil || store.memory == nil {
		return nil, fmt.Errorf("%w: file store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var result *PendingRequest
	err := withProcessFileLock(store.path, false, func() error {
		if err := store.reloadFromDiskLocked(); err != nil {
			return err
		}
		var err error
		result, err = store.memory.Load(ctx, spendTxID)
		return err
	})
	return result, err
}

func (store *FileStore) Release(ctx context.Context, spendTxID, requestHash Hash32) error {
	return store.mutate(func() error { return store.memory.Release(ctx, spendTxID, requestHash) })
}

func (store *FileStore) mutate(operation func() error) error {
	if store == nil || store.memory == nil {
		return fmt.Errorf("%w: file store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return withProcessFileLock(store.path, true, func() error {
		if err := store.reloadFromDiskLocked(); err != nil {
			return err
		}
		before := store.memory.snapshot()
		if err := operation(); err != nil {
			return err
		}
		if err := store.flushLocked(); err != nil {
			store.memory.replaceSnapshot(before)
			return err
		}
		return nil
	})
}

func (store *FileStore) loadOpening(operation func() (*OpeningProof, error)) (*OpeningProof, error) {
	if store == nil || store.memory == nil {
		return nil, fmt.Errorf("%w: file store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var result *OpeningProof
	err := withProcessFileLock(store.path, false, func() error {
		if err := store.reloadFromDiskLocked(); err != nil {
			return err
		}
		var err error
		result, err = operation()
		return err
	})
	return result, err
}

func (store *FileStore) loadPayment(operation func() (*PaymentState, error)) (*PaymentState, error) {
	if store == nil || store.memory == nil {
		return nil, fmt.Errorf("%w: file store is required", ErrInvalidEvidence)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var result *PaymentState
	err := withProcessFileLock(store.path, false, func() error {
		if err := store.reloadFromDiskLocked(); err != nil {
			return err
		}
		var err error
		result, err = operation()
		return err
	})
	return result, err
}

func (store *FileStore) reloadFromDiskLocked() error {
	fresh, err := NewMemoryStore(store.memory.calculator)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(store.path)
	if os.IsNotExist(err) {
		store.memory = fresh
		return nil
	}
	if err != nil {
		return fmt.Errorf("read pool store: %w", err)
	}
	var snapshot fileStoreSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("decode pool store: %w", err)
	}
	if snapshot.Version != fileStoreSchemaVersion {
		return fmt.Errorf("unsupported pool store snapshot version %d", snapshot.Version)
	}
	if err := fresh.restore(snapshot); err != nil {
		return fmt.Errorf("restore pool store: %w", err)
	}
	store.memory = fresh
	return nil
}

func (store *FileStore) flushLocked() error {
	snapshot := store.memory.snapshot()
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create pool store directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(store.path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create pool store snapshot: %w", err)
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect pool store snapshot: %w", err)
	}
	if err := json.NewEncoder(temporary).Encode(snapshot); err != nil {
		return fmt.Errorf("encode pool store snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync pool store snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close pool store snapshot: %w", err)
	}
	if err := os.Rename(temporaryName, store.path); err != nil {
		return fmt.Errorf("replace pool store snapshot: %w", err)
	}
	keep = true
	return nil
}

func (store *MemoryStore) snapshot() fileStoreSnapshot {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot := fileStoreSnapshot{Version: fileStoreSchemaVersion}
	for spendTxID, proof := range store.openingsBySpend {
		snapshot.Openings = append(snapshot.Openings, fileOpeningSnapshot{SpendTxID: spendTxID, Proof: cloneOpeningProof(proof)})
	}
	for spendTxID, state := range store.accepted {
		snapshot.Accepted = append(snapshot.Accepted, filePaymentSnapshot{SpendTxID: spendTxID, State: clonePaymentState(state)})
	}
	for spendTxID, request := range store.pending {
		snapshot.Pending = append(snapshot.Pending, filePendingSnapshot{SpendTxID: spendTxID, Request: request})
	}
	for spendTxID, txID := range store.uncertain {
		snapshot.Uncertain = append(snapshot.Uncertain, fileUncertainSnapshot{SpendTxID: spendTxID, TxID: txID})
	}
	return snapshot
}

func (store *MemoryStore) replaceSnapshot(snapshot fileStoreSnapshot) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.openingsBySpend = make(map[Hash32]*OpeningProof, len(snapshot.Openings))
	store.openingsByFunding = make(map[Hash32]*OpeningProof, len(snapshot.Openings))
	store.accepted = make(map[Hash32]*PaymentState, len(snapshot.Accepted))
	store.pending = make(map[Hash32]PendingRequest, len(snapshot.Pending))
	store.uncertain = make(map[Hash32]Hash32, len(snapshot.Uncertain))
	for _, entry := range snapshot.Openings {
		store.openingsBySpend[entry.SpendTxID] = cloneOpeningProof(entry.Proof)
		if entry.Proof != nil && len(entry.Proof.FundingTxID) == 32 {
			store.openingsByFunding[hash32FromBytes(entry.Proof.FundingTxID)] = cloneOpeningProof(entry.Proof)
		}
	}
	for _, entry := range snapshot.Accepted {
		store.accepted[entry.SpendTxID] = clonePaymentState(entry.State)
	}
	for _, entry := range snapshot.Pending {
		store.pending[entry.SpendTxID] = entry.Request
	}
	for _, entry := range snapshot.Uncertain {
		store.uncertain[entry.SpendTxID] = entry.TxID
	}
}

func (store *MemoryStore) restore(snapshot fileStoreSnapshot) error {
	for _, entry := range snapshot.Openings {
		if entry.Proof == nil {
			return fmt.Errorf("%w: nil opening proof in snapshot", ErrInvalidEvidence)
		}
		spendTxID, err := SpendTxID(context.Background(), entry.Proof, store.calculator)
		if err != nil {
			return err
		}
		if spendTxID != entry.SpendTxID {
			return fmt.Errorf("%w: opening proof spend transaction ID mismatch in snapshot", ErrInvalidEvidence)
		}
		if err := store.SaveOpeningProof(context.Background(), entry.Proof); err != nil {
			return err
		}
	}
	for _, entry := range snapshot.Accepted {
		if entry.State == nil || entry.State.SpendTxID != entry.SpendTxID {
			return fmt.Errorf("%w: accepted payment key mismatch in snapshot", ErrInvalidEvidence)
		}
		if err := store.SaveAcceptedPayment(context.Background(), entry.State); err != nil {
			return err
		}
	}
	for _, entry := range snapshot.Pending {
		if entry.Request.SpendTxID != entry.SpendTxID {
			return fmt.Errorf("%w: pending request key mismatch in snapshot", ErrInvalidEvidence)
		}
		result, err := store.TryAcquire(context.Background(), entry.Request)
		if err != nil {
			return err
		}
		if result != PendingAcquired {
			return fmt.Errorf("%w: duplicate pending request in snapshot", ErrInvalidEvidence)
		}
	}
	for _, entry := range snapshot.Uncertain {
		if entry.SpendTxID == (Hash32{}) || entry.TxID == (Hash32{}) {
			return fmt.Errorf("%w: invalid uncertain pool state in snapshot", ErrInvalidEvidence)
		}
		if err := store.MarkExternalStateUncertain(context.Background(), entry.SpendTxID, entry.TxID); err != nil {
			return err
		}
	}
	return nil
}

var _ PoolStore = (*FileStore)(nil)
var _ PendingRequestStore = (*FileStore)(nil)
var _ PendingOpeningProofStore = (*FileStore)(nil)
