// Package buyer 实现 BitFS 买方的最小标准交易流程。
package buyer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
	bitfspb "github.com/bsv8/go-bitfs/proto/bitfspb"
	pool2of3pb "github.com/bsv8/go-bitfs/proto/pool2of3pb"
)

// SellerClient 是买方对 seller 交付服务的最小客户端抽象。
type SellerClient interface {
	Deliver(context.Context, *bitfspb.HashGetTicketV1) (*bitfspb.HashDeliveryV1, error)
}

// PoolClient 是买方在验货成功后推进付款的最小客户端抽象。
type PoolClient interface {
	PrepareTicketPayment(context.Context, *pool2of3pb.PrepareTicketPaymentRequestV1) (*pool2of3pb.PrepareTicketPaymentResponseV1, error)
	CommitTicketPayment(context.Context, *pool2of3pb.CommitTicketPaymentRequestV1) (*pool2of3pb.CommitTicketPaymentResponseV1, error)
}

// Config 是 buyer Runtime 的可测试运行配置。
type Config struct {
	Now func() time.Time
}

// Runtime 同时承担 buyer 的报价服务端和取货付款客户端。
type Runtime struct {
	bitfspb.UnimplementedBitfsBuyerServiceServer

	seller SellerClient
	pool   PoolClient
	now    func() time.Time

	mu     sync.RWMutex
	quotes []*bitfspb.FileQuoteV1
}

// New 构造 buyer Runtime。seller 与 pool 分别是交易和结算的正式依赖。
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

// SubmitFileQuote 实现 buyer 服务端：接收并保存仍有效的卖方文件级报价。
func (runtime *Runtime) SubmitFileQuote(_ context.Context, quote *bitfspb.FileQuoteV1) (*bitfspb.SubmitFileQuoteResponseV1, error) {
	if runtime == nil {
		return nil, errors.New("buyer runtime is required")
	}
	if err := core.ValidateFileQuoteAt(quote, runtime.now()); err != nil {
		return &bitfspb.SubmitFileQuoteResponseV1{
			Accepted: false,
			Error:    &bitfspb.BitfsErrorV1{Code: "invalid_quote", Message: err.Error()},
		}, nil
	}
	runtime.mu.Lock()
	runtime.quotes = append(runtime.quotes, quote)
	runtime.mu.Unlock()
	return &bitfspb.SubmitFileQuoteResponseV1{Accepted: true}, nil
}

// Quotes 返回当前 Runtime 收到的报价快照。
func (runtime *Runtime) Quotes() []*bitfspb.FileQuoteV1 {
	if runtime == nil {
		return nil
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return append([]*bitfspb.FileQuoteV1(nil), runtime.quotes...)
}

// Purchase 执行买方的最小闭环：取货、哈希验收、prepare、commit。
func (runtime *Runtime) Purchase(ctx context.Context, spendTxID string, ticket *bitfspb.HashGetTicketV1) (*bitfspb.HashDeliveryV1, error) {
	if runtime == nil {
		return nil, errors.New("buyer runtime is required")
	}
	if spendTxID == "" {
		return nil, errors.New("spend_txid is required")
	}
	if err := core.ValidateHashGetTicketAt(ticket, runtime.now()); err != nil {
		return nil, err
	}
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
	poolTicket := &pool2of3pb.PoolTicketRefV1{
		SpendTxid:   spendTxID,
		Sequence:    ticket.GetSequence(),
		ContentHash: ticket.GetContentHash(),
		PriceSat:    ticket.GetPriceSat(),
		TicketId:    fmt.Sprintf("%x", ticketID),
	}
	prepared, err := runtime.pool.PrepareTicketPayment(ctx, &pool2of3pb.PrepareTicketPaymentRequestV1{
		SpendTxid: spendTxID,
		Ticket:    poolTicket,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare ticket payment: %w", err)
	}
	if prepared.GetError() != nil || prepared.GetProposalId() == "" {
		return nil, errors.New("prepare ticket payment was rejected")
	}
	committed, err := runtime.pool.CommitTicketPayment(ctx, &pool2of3pb.CommitTicketPaymentRequestV1{
		SpendTxid:  spendTxID,
		ProposalId: prepared.GetProposalId(),
		Ticket:     poolTicket,
	})
	if err != nil {
		return nil, fmt.Errorf("commit ticket payment: %w", err)
	}
	if !committed.GetSuccess() || committed.GetError() != nil {
		return nil, errors.New("commit ticket payment was rejected")
	}
	return delivery, nil
}
