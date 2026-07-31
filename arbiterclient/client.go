// Package arbiterclient is a legacy transport-neutral client helper for the
// HashGetTicket arbitration model.
// Deprecated: use arbiter.Service with wire.ArbitrationRequest/Response.
//go:build legacy

package arbiterclient

import (
	"context"
	"errors"

	core "github.com/bsv8/go-bitfs/bitfs"
)

type Service interface {
	SubmitClaim(context.Context, *core.ArbitrationClaim) (*core.ArbitrationDecision, error)
	GetArbitration(string, uint64) (*core.ArbitrationRecord, error)
	ListArbitrations(string) ([]*core.ArbitrationRecord, error)
}

type Client struct{ service Service }

func New(service Service) (*Client, error) {
	if service == nil {
		return nil, errors.New("arbitration service is required")
	}
	return &Client{service: service}, nil
}

func (client *Client) SubmitBuyerClaim(ctx context.Context, ticket *core.HashGetTicket, payload []byte) (*core.ArbitrationDecision, error) {
	return client.submit(ctx, ticket, payload, core.ArbitrationClaimantRoleBuyer)
}

func (client *Client) SubmitSellerClaim(ctx context.Context, ticket *core.HashGetTicket, payload []byte) (*core.ArbitrationDecision, error) {
	return client.submit(ctx, ticket, payload, core.ArbitrationClaimantRoleSeller)
}

func (client *Client) GetArbitration(_ context.Context, sessionID string, sequence uint64) (*core.ArbitrationRecord, error) {
	if client == nil || client.service == nil {
		return nil, errors.New("arbitration client is required")
	}
	return client.service.GetArbitration(sessionID, sequence)
}

func (client *Client) ListArbitrations(_ context.Context, sessionID string) ([]*core.ArbitrationRecord, error) {
	if client == nil || client.service == nil {
		return nil, errors.New("arbitration client is required")
	}
	return client.service.ListArbitrations(sessionID)
}

func (client *Client) submit(ctx context.Context, ticket *core.HashGetTicket, payload []byte, role core.ArbitrationClaimantRole) (*core.ArbitrationDecision, error) {
	if client == nil || client.service == nil {
		return nil, errors.New("arbitration client is required")
	}
	return client.service.SubmitClaim(ctx, &core.ArbitrationClaim{Ticket: ticket, Payload: payload, ClaimantRole: role})
}
