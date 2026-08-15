package buyer

import (
	"context"
	"errors"
	"testing"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

type nilOpeningPoolStore struct{ pool.PoolStore }

func (nilOpeningPoolStore) LoadOpeningProof(context.Context, pool.Hash32) (*pool.OpeningProof, error) {
	return nil, nil
}

type emptyBuyerQuoteStore struct{}

func (emptyBuyerQuoteStore) SaveQuote(context.Context, *bitfs.SignedFileQuote) error { return nil }
func (emptyBuyerQuoteStore) LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error) {
	return nil, errors.New("quote not found")
}

type emptyBuyerSigner struct{}

func (emptyBuyerSigner) PublicKey(context.Context) ([]byte, error)    { return nil, nil }
func (emptyBuyerSigner) Sign(context.Context, []byte) ([]byte, error) { return nil, nil }

type emptyBuyerBackend struct{}

func (emptyBuyerBackend) SubmitUpdate(context.Context, []byte) (*pool.UpdateAcceptance, error) {
	return nil, errors.New("unexpected update submission")
}
func (emptyBuyerBackend) SubmitFinal(context.Context, []byte) (pool.Hash32, error) {
	return pool.Hash32{}, errors.New("unexpected final submission")
}

func TestRefundAfterExpiryRejectsNilOpeningProof(t *testing.T) {
	store, err := pool.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := NewWorkflow(WorkflowConfig{
		Signer:  emptyBuyerSigner{},
		Quotes:  emptyBuyerQuoteStore{},
		Pools:   nilOpeningPoolStore{PoolStore: store},
		Backend: emptyBuyerBackend{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.RefundAfterExpiry(context.Background(), pool.Hash32{}); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("RefundAfterExpiry() error = %v, want ErrInvalidEvidence", err)
	}
}
