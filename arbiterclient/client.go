// Package arbiterclient 提供买方和卖方使用的 BitFS 仲裁服务客户端。
package arbiterclient

import (
	"context"
	"errors"

	bitfspb "github.com/bsv8/go-bitfs/proto/bitfspb"
)

// Client 封装正式 BitfsArbitrationServiceClient，避免买卖双方各自拼装申诉对象。
type Client struct {
	service bitfspb.BitfsArbitrationServiceClient
}

// New 构造仲裁客户端。
func New(service bitfspb.BitfsArbitrationServiceClient) (*Client, error) {
	if service == nil {
		return nil, errors.New("arbitration service client is required")
	}
	return &Client{service: service}, nil
}

// SubmitBuyerClaim 提交买方仲裁申诉。payload 可为空，以请求仲裁方恢复交付。
func (client *Client) SubmitBuyerClaim(ctx context.Context, ticket *bitfspb.HashGetTicketV1, payload []byte) (*bitfspb.SubmitArbitrationClaimResponseV1, error) {
	return client.submit(ctx, ticket, payload, bitfspb.ArbitrationClaimantRoleV1_ARBITRATION_CLAIMANT_ROLE_BUYER)
}

// SubmitSellerClaim 提交卖方仲裁申诉。payload 必须是卖方实际可交付的二进制。
func (client *Client) SubmitSellerClaim(ctx context.Context, ticket *bitfspb.HashGetTicketV1, payload []byte) (*bitfspb.SubmitArbitrationClaimResponseV1, error) {
	return client.submit(ctx, ticket, payload, bitfspb.ArbitrationClaimantRoleV1_ARBITRATION_CLAIMANT_ROLE_SELLER)
}

// GetArbitration 查询一张票据对应的仲裁记录。
func (client *Client) GetArbitration(ctx context.Context, sessionID string, sequence uint64) (*bitfspb.GetArbitrationResponseV1, error) {
	if client == nil {
		return nil, errors.New("arbitration client is required")
	}
	return client.service.GetArbitration(ctx, &bitfspb.GetArbitrationRequestV1{SessionId: sessionID, Sequence: sequence})
}

// ListArbitrations 查询一个 BitFS 会话下的全部仲裁记录。
func (client *Client) ListArbitrations(ctx context.Context, sessionID string) (*bitfspb.ListArbitrationsResponseV1, error) {
	if client == nil {
		return nil, errors.New("arbitration client is required")
	}
	return client.service.ListArbitrations(ctx, &bitfspb.ListArbitrationsRequestV1{SessionId: sessionID})
}

// submit 构造并发送统一申诉请求。
func (client *Client) submit(ctx context.Context, ticket *bitfspb.HashGetTicketV1, payload []byte, role bitfspb.ArbitrationClaimantRoleV1) (*bitfspb.SubmitArbitrationClaimResponseV1, error) {
	if client == nil {
		return nil, errors.New("arbitration client is required")
	}
	return client.service.SubmitClaim(ctx, &bitfspb.SubmitArbitrationClaimRequestV1{
		Claim: &bitfspb.ArbitrationClaimV1{Ticket: ticket, Payload: payload, ClaimantRole: role},
	})
}
