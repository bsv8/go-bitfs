// Package integration_test 验证公开 buyer、seller 与仲裁 demo 的最小闭环。
package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/arbiter"
	"github.com/bsv8/go-bitfs/seller"
	settlement "github.com/bsv8/go-bitfs/settlement"
)

// TestBuyerSellerTransaction 验证报价、验票、交付、验货和付款顺序。
func TestBuyerSellerTransaction(t *testing.T) {
	clock := func() time.Time { return time.Unix(100, 0) }
	payload := []byte("file block")
	contentHash := sha256.Sum256(payload)
	pools := &transactionPool{}
	sellerProxy := &sellerDeliveryProxy{}
	buyerRuntime, err := buyer.New(buyer.Config{Now: clock}, sellerProxy, pools)
	if err != nil {
		t.Fatalf("buyer.New() error = %v", err)
	}
	sellerRuntime, err := seller.New(seller.Config{Now: clock, Verifier: acceptTestSignature}, buyerRuntime, staticPayloadProvider{payload: payload})
	if err != nil {
		t.Fatalf("seller.New() error = %v", err)
	}
	sellerProxy.runtime = sellerRuntime
	quote := &core.FileQuote{
		SeedHash:            bytes.Repeat([]byte{0x01}, sha256.Size),
		SeedPriceSat:        1,
		BlockPriceSat:       2,
		EndblockPriceSat:    3,
		FileSize:            uint64(len(payload)),
		RecommendedFilename: "file.bin",
		QuoteExpiresAtUnix:  200,
		BlockCount:          1,
		SellerPubkey:        []byte{0x03},
	}
	if err := sellerRuntime.Offer(context.Background(), quote); err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if len(buyerRuntime.Quotes()) != 1 {
		t.Fatal("buyer did not retain seller quote")
	}
	ticket := transactionTicket(contentHash[:], uint64(len(payload)))
	delivery, err := buyerRuntime.Purchase(context.Background(), bytes.Repeat([]byte{0x09}, sha256.Size), ticket)
	if err != nil {
		t.Fatalf("Purchase() error = %v", err)
	}
	if !bytes.Equal(delivery.Payload, payload) {
		t.Fatal("buyer received an unexpected payload")
	}
	if !pools.prepared || !pools.committed {
		t.Fatal("buyer did not prepare and commit payment after successful delivery")
	}
}

// TestArbiterDemoSellerClaim 验证卖方票据加 payload 经过验证后会完成两阶段 pool 收尾。
func TestArbiterDemoSellerClaim(t *testing.T) {
	clock := func() time.Time { return time.Unix(100, 0) }
	payload := []byte("arbitration payload")
	contentHash := sha256.Sum256(payload)
	pools := &arbitrationPool{}
	service, err := arbiter.New(arbiter.Config{
		Now:            clock,
		TicketVerifier: acceptTestSignature,
		DecisionSigner: testDecisionSigner,
		CloseTxSigner:  testCloseTxSigner,
	}, arbiter.Dependencies{
		Pool:            pools,
		SessionResolver: staticSessionResolver{},
	})
	if err != nil {
		t.Fatalf("arbiter.New() error = %v", err)
	}
	ticket := transactionTicket(contentHash[:], uint64(len(payload)))
	decision, err := service.SubmitClaim(context.Background(), &core.ArbitrationClaim{
		Ticket:       ticket,
		Payload:      payload,
		ClaimantRole: core.ArbitrationClaimantRoleSeller,
	})
	if err != nil {
		t.Fatalf("SubmitClaim() error = %v", err)
	}
	if !decision.Approved {
		t.Fatalf("seller claim was not approved: %#v", decision)
	}
	if decision.FinalPayoutSat != 12 {
		t.Fatalf("final payout = %d, want 12", decision.FinalPayoutSat)
	}
	if pools.calls != 2 || !pools.closed {
		t.Fatal("arbiter demo did not complete two-phase pool close")
	}
	record, err := service.GetArbitration(ticket.SessionID, ticket.Sequence)
	if err != nil {
		t.Fatalf("GetArbitration() error = %v", err)
	}
	if record.State != core.ArbitrationStateClosed {
		t.Fatalf("arbitration state = %v, want closed", record.State)
	}
}

// staticPayloadProvider 返回固定的卖方内容真值。
type staticPayloadProvider struct{ payload []byte }

// PayloadForTicket 实现 seller.PayloadProvider。
func (provider staticPayloadProvider) PayloadForTicket(_ context.Context, _ *core.HashGetTicket) ([]byte, error) {
	return provider.payload, nil
}

// sellerDeliveryProxy 打破测试中 buyer 与 seller 的构造环。
type sellerDeliveryProxy struct{ runtime *seller.Runtime }

// Deliver 把 buyer 请求转发到实际 seller 服务端。
func (proxy *sellerDeliveryProxy) Deliver(ctx context.Context, ticket *core.HashGetTicket) (*core.HashDelivery, error) {
	if proxy.runtime == nil {
		return nil, errors.New("seller runtime is not configured")
	}
	return proxy.runtime.Deliver(ctx, ticket)
}

// transactionPool 是正常交易的最小费用池测试替身。
type transactionPool struct {
	prepared  bool
	committed bool
}

// PrepareTicketPayment 实现 buyer.PoolClient。
func (pool *transactionPool) PrepareTicketPayment(_ context.Context, request *settlement.PaymentPrepare) (*settlement.PaymentPrepared, error) {
	if request == nil || len(request.Ticket.SpendTxID) != sha256.Size {
		return nil, errors.New("invalid prepare request")
	}
	pool.prepared = true
	return &settlement.PaymentPrepared{Version: settlement.MajorVersion, MessageKind: settlement.KindPaymentPrepared, TicketID: request.Ticket.TicketID, ProposalID: bytes.Repeat([]byte{5}, sha256.Size)}, nil
}

// CommitTicketPayment 实现 buyer.PoolClient。
func (pool *transactionPool) CommitTicketPayment(_ context.Context, request *settlement.PaymentCommit) (*settlement.PaymentCommitted, error) {
	if request == nil || len(request.ProposalID) != sha256.Size {
		return nil, errors.New("unexpected proposal")
	}
	pool.committed = true
	return &settlement.PaymentCommitted{Version: settlement.MajorVersion, MessageKind: settlement.KindPaymentCommitted, TicketID: request.Ticket.TicketID}, nil
}

// staticSessionResolver 返回仲裁 demo 的固定业务会话映射。
type staticSessionResolver struct{}

// ResolveSessionPool 实现 arbiter.SessionResolver。
func (staticSessionResolver) ResolveSessionPool(_ context.Context, _ string, _ []byte) (arbiter.SessionPoolRef, error) {
	return arbiter.SessionPoolRef{SpendTxID: bytes.Repeat([]byte{9}, sha256.Size), CurrentSellerAmountSat: 7}, nil
}

// arbitrationPool 是两阶段仲裁收尾的费用池测试替身。
type arbitrationPool struct {
	calls  int
	closed bool
}

// ArbitrateSessionPool 实现 arbiter.PoolClient。
func (pool *arbitrationPool) StartArbitration(_ context.Context, request *settlement.ArbitrationRequest) (*settlement.CloseSignatureRequest, error) {
	pool.calls++
	if request == nil || len(request.SpendTxID) != sha256.Size || !request.Approved || request.FinalPayoutSat != 12 {
		return nil, errors.New("unexpected arbitration request")
	}
	return &settlement.CloseSignatureRequest{Version: settlement.MajorVersion, MessageKind: settlement.KindCloseSignatureRequest, SpendTxID: request.SpendTxID, ArbitrationID: bytes.Repeat([]byte{8}, sha256.Size), UnsignedCloseTransaction: []byte{0xde, 0xad}, CloseSighash: bytes.Repeat([]byte{9}, sha256.Size)}, nil
}

func (pool *arbitrationPool) CompleteArbitration(_ context.Context, request *settlement.CloseSignature) (*settlement.PoolArbitrated, error) {
	pool.calls++
	if request == nil || len(request.ArbiterSignatureOnCloseTransaction) == 0 {
		return nil, errors.New("close signature is required")
	}
	pool.closed = true
	return &settlement.PoolArbitrated{Version: settlement.MajorVersion, MessageKind: settlement.KindPoolArbitrated, SpendTxID: request.SpendTxID, ArbitrationID: request.ArbitrationID, ClosingTransactionID: bytes.Repeat([]byte{7}, sha256.Size), ClosingTransaction: []byte{0xde, 0xad, 0xbe, 0xef}}, nil
}

// transactionTicket 构造可被卖方与仲裁 demo 验证的 block 票据。
func transactionTicket(contentHash []byte, expectedSize uint64) *core.HashGetTicket {
	return &core.HashGetTicket{
		SessionID:      "session-1",
		Sequence:       1,
		RootSeedHash:   bytes.Repeat([]byte{0x01}, sha256.Size),
		ContentHash:    contentHash,
		ContentIndex:   0,
		ExpectedSize:   expectedSize,
		PriceSat:       5,
		BuyerPubkey:    []byte{0x02},
		SellerPubkey:   []byte{0x03},
		ExpiresAtUnix:  200,
		BuyerSignature: []byte{0x01},
	}
}

// acceptTestSignature 提供固定成功的测试验签器。
func acceptTestSignature(_ []byte, _ [sha256.Size]byte, signature []byte) error {
	if len(signature) == 1 && signature[0] == 0x01 {
		return nil
	}
	return errors.New("invalid test signature")
}

// testDecisionSigner 返回固定的 pool 决策签名。
func testDecisionSigner(_ context.Context, _ [32]byte) ([]byte, error) {
	return []byte{0x02}, nil
}

// testCloseTxSigner 返回固定的 close 交易签名。
func testCloseTxSigner(_ context.Context, _ [32]byte) ([]byte, error) {
	return []byte{0x03}, nil
}

// TestProtocolImportKeepsCorePackageReferenced 防止集成测试失去核心协议依赖。
func TestProtocolImportKeepsCorePackageReferenced(t *testing.T) {
	if core.BlockSize != 262144 {
		t.Fatalf("BlockSize = %d", core.BlockSize)
	}
}
