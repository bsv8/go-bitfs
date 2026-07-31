// Package buyer implements the buyer-side BitFS workflow. Network adapters
// feed it asynchronous CBOR messages; it does not implement a transport service.
//go:build legacy

package buyer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
	pool "github.com/bsv8/go-bitfs/settlement"
)

// SellerClient is a local workflow port. A queue, WebSocket, or gRPC adapter may implement it.
type SellerClient interface {
	Deliver(context.Context, *core.HashGetTicket) (*core.HashDelivery, error)
}

type PoolClient interface {
	PrepareTicketPayment(context.Context, *pool.PaymentPrepare) (*pool.PaymentPrepared, error)
	CommitTicketPayment(context.Context, *pool.PaymentCommit) (*pool.PaymentCommitted, error)
}

type Config struct{ Now func() time.Time }

// Runtime is the legacy HashGetTicket session workflow. New integrations
// should use Client, which binds quotes, pool references and signed content
// credentials to the protocol 001-007 state model.
type Runtime struct {
	seller SellerClient
	pool   PoolClient
	now    func() time.Time

	mu     sync.RWMutex
	quotes []*core.FileQuote
}

// New constructs the legacy HashGetTicket runtime.
// Deprecated: use NewClient with protocol 001-007 ports.
func New(config Config, seller SellerClient, pool PoolClient) (*Runtime, error) {
	if seller == nil {
		return nil, errors.New("seller client is required")
	}
	if pool == nil {
		return nil, errors.New("pool client is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Runtime{seller: seller, pool: pool, now: config.Now}, nil
}

// ReceiveQuote records a valid asynchronous FileQuote packet.
func (runtime *Runtime) ReceiveQuote(quote *core.FileQuote) error {
	if runtime == nil {
		return errors.New("buyer runtime is required")
	}
	if err := core.ValidateFileQuoteAt(quote, runtime.now()); err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.quotes = append(runtime.quotes, core.CloneFileQuote(quote))
	runtime.mu.Unlock()
	return nil
}

func (runtime *Runtime) Quotes() []*core.FileQuote {
	if runtime == nil {
		return nil
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	quotes := make([]*core.FileQuote, len(runtime.quotes))
	for index, quote := range runtime.quotes {
		quotes[index] = core.CloneFileQuote(quote)
	}
	return quotes
}

// Purchase is a local orchestration helper. It is not a wire-level BitFS RPC.
func (runtime *Runtime) Purchase(ctx context.Context, spendTxID []byte, ticket *core.HashGetTicket) (*core.HashDelivery, error) {
	if runtime == nil {
		return nil, errors.New("buyer runtime is required")
	}
	if len(spendTxID) != 32 {
		return nil, errors.New("spend_txid is required")
	}
	if err := core.ValidateHashGetTicketAt(ticket, runtime.now()); err != nil {
		return nil, err
	}
	ticket = core.CloneHashGetTicket(ticket)
	delivery, err := runtime.seller.Deliver(ctx, ticket)
	if err != nil {
		return nil, fmt.Errorf("seller delivery: %w", err)
	}
	if err := core.ValidateDelivery(ticket, delivery); err != nil {
		return nil, err
	}
	ticketID, err := core.TicketID(ticket)
	if err != nil {
		return nil, err
	}
	poolTicket := pool.TicketRef{SpendTxID: spendTxID, Sequence: ticket.Sequence, ContentHash: ticket.ContentHash, PriceSat: ticket.PriceSat, TicketID: ticketID[:]}
	prepared, err := runtime.pool.PrepareTicketPayment(ctx, pool.NewPaymentPrepare(poolTicket))
	if err != nil {
		return nil, fmt.Errorf("prepare ticket payment: %w", err)
	}
	if prepared == nil {
		return nil, errors.New("prepare ticket payment was rejected")
	}
	if !bytes.Equal(prepared.TicketID, ticketID[:]) {
		return nil, errors.New("prepare ticket payment returned an unexpected ticket")
	}
	if len(prepared.ProposalID) == 0 {
		return nil, errors.New("prepare ticket payment was rejected")
	}
	committed, err := runtime.pool.CommitTicketPayment(ctx, pool.NewPaymentCommit(poolTicket, prepared.ProposalID))
	if err != nil {
		return nil, fmt.Errorf("commit ticket payment: %w", err)
	}
	if committed == nil || !bytes.Equal(committed.TicketID, ticketID[:]) {
		return nil, errors.New("commit ticket payment was rejected")
	}
	return delivery, nil
}
