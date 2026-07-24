// Package seller 实现 BitFS 卖方的最小标准交易流程。
package seller

import (
	"context"
	"errors"
	"fmt"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
	bitfspb "github.com/bsv8/go-bitfs/proto/bitfspb"
)

// BuyerClient 是卖方向 buyer 主动提交报价的最小客户端抽象。
type BuyerClient interface {
	SubmitFileQuote(context.Context, *bitfspb.FileQuoteV1) (*bitfspb.SubmitFileQuoteResponseV1, error)
}

// PayloadProvider 是 seller 从本地内容系统读取真实二进制的抽象。
type PayloadProvider interface {
	PayloadForTicket(context.Context, *bitfspb.HashGetTicketV1) ([]byte, error)
}

// Config 是 seller Runtime 的可测试运行配置。
type Config struct {
	Now      func() time.Time
	Verifier core.TicketSignatureVerifier
}

// Runtime 同时承担 seller 的报价客户端和交付服务端。
type Runtime struct {
	bitfspb.UnimplementedBitfsSellerServiceServer

	buyer    BuyerClient
	provider PayloadProvider
	now      func() time.Time
	verifier core.TicketSignatureVerifier
}

// New 构造 seller Runtime。buyer 与 provider 分别提供报价目标和文件真值。
func New(config Config, buyer BuyerClient, provider PayloadProvider) (*Runtime, error) {
	if buyer == nil {
		return nil, errors.New("buyer client is required")
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

// Offer 主动向 buyer 服务端提交一份有效的文件级报价。
func (runtime *Runtime) Offer(ctx context.Context, quote *bitfspb.FileQuoteV1) error {
	if runtime == nil {
		return errors.New("seller runtime is required")
	}
	if err := core.ValidateFileQuoteAt(quote, runtime.now()); err != nil {
		return err
	}
	response, err := runtime.buyer.SubmitFileQuote(ctx, quote)
	if err != nil {
		return fmt.Errorf("submit file quote: %w", err)
	}
	if !response.GetAccepted() || response.GetError() != nil {
		return errors.New("buyer rejected file quote")
	}
	return nil
}

// Deliver 实现 seller 服务端：验票后从内容系统读取并返回真实 payload。
func (runtime *Runtime) Deliver(ctx context.Context, ticket *bitfspb.HashGetTicketV1) (*bitfspb.HashDeliveryV1, error) {
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
	delivery := &bitfspb.HashDeliveryV1{
		SessionId:   ticket.GetSessionId(),
		Sequence:    ticket.GetSequence(),
		ContentHash: ticket.GetContentHash(),
		Payload:     payload,
	}
	if err := core.ValidateDelivery(ticket, delivery); err != nil {
		return nil, err
	}
	return delivery, nil
}
