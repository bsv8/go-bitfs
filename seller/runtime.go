// Package seller implements seller-side BitFS validation and delivery without binding it to a wire transport.
//go:build legacy

package seller

import (
	"context"
	"errors"
	"fmt"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
)

// QuoteReceiver is a local workflow port implemented by an asynchronous transport adapter.
type QuoteReceiver interface{ ReceiveQuote(*core.FileQuote) error }

type PayloadProvider interface {
	PayloadForTicket(context.Context, *core.HashGetTicket) ([]byte, error)
}

type Config struct {
	Now      func() time.Time
	Verifier core.TicketSignatureVerifier
}

// Runtime is the legacy HashGetTicket session workflow. New integrations
// should use Service, which uses quote/content credentials and pool-backed
// payment state instead of proposal/session identifiers.
type Runtime struct {
	buyer    QuoteReceiver
	provider PayloadProvider
	now      func() time.Time
	verifier core.TicketSignatureVerifier
}

// New constructs the legacy HashGetTicket runtime.
// Deprecated: use NewService with protocol 001-007 ports.
func New(config Config, buyer QuoteReceiver, provider PayloadProvider) (*Runtime, error) {
	if buyer == nil {
		return nil, errors.New("buyer quote receiver is required")
	}
	if provider == nil {
		return nil, errors.New("payload provider is required")
	}
	if config.Verifier == nil {
		return nil, errors.New("ticket signature verifier is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Runtime{buyer: buyer, provider: provider, now: config.Now, verifier: config.Verifier}, nil
}

// Offer validates a quote before handing it to the selected local transport adapter.
func (runtime *Runtime) Offer(_ context.Context, quote *core.FileQuote) error {
	if runtime == nil {
		return errors.New("seller runtime is required")
	}
	if err := core.ValidateFileQuoteAt(quote, runtime.now()); err != nil {
		return err
	}
	if err := runtime.buyer.ReceiveQuote(quote); err != nil {
		return fmt.Errorf("receive file quote: %w", err)
	}
	return nil
}

// Deliver validates a ticket and creates the corresponding HashDelivery business message.
func (runtime *Runtime) Deliver(ctx context.Context, ticket *core.HashGetTicket) (*core.HashDelivery, error) {
	if runtime == nil {
		return nil, errors.New("seller runtime is required")
	}
	if err := core.ValidateHashGetTicketAt(ticket, runtime.now()); err != nil {
		return nil, err
	}
	if err := core.VerifyHashGetTicket(ticket, runtime.verifier); err != nil {
		return nil, err
	}
	payload, err := runtime.provider.PayloadForTicket(ctx, ticket)
	if err != nil {
		return nil, fmt.Errorf("load payload: %w", err)
	}
	delivery := &core.HashDelivery{SessionID: ticket.SessionID, Sequence: ticket.Sequence, ContentHash: ticket.ContentHash, Payload: payload}
	if err := core.ValidateDelivery(ticket, delivery); err != nil {
		return nil, err
	}
	return delivery, nil
}
