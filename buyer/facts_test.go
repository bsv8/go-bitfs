package buyer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/protocol"
)

// 本文件锁定显式事实的按需读取契约：refund 门禁只读取锁定类型对应的那一份
// 事实——timestamp 锁定绝不要求区块高度，height 锁定绝不要求时间。

// TestForwardGateTimestampLockNeedsOnlyNow timestamp 锁定池的正向操作在
// Facts 只含 Now（无高度）时必须成功。
func TestForwardGateTimestampLockNeedsOnlyNow(t *testing.T) {
	f := newBuyerFixture(t)
	p := f.openDefaultPool(t) // fixture 默认为时间戳型退款锁
	ctx := context.Background()

	quote, signedQuote := f.defaultQuote(t)
	result, err := f.Buyer.RequestContent(ctx, protocol.Facts{Now: testBaseTime}, RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Add(30 * time.Minute).Unix()),
	})
	if err != nil {
		t.Fatalf("timestamp-lock forward op demanded block height: %v", err)
	}
	if result.Outbound.IsZero() {
		t.Fatal("forward op produced no artifact")
	}
	_ = signedQuote
}

// TestMaturedRefundHeightLockNeedsOnlyHeight height 锁定池的到期退款：
// Facts 只含 BlockHeight（无时间）时必须成功；只有 Now 时必须以
// facts-missing 拒绝，绝不猜测高度。
func TestMaturedRefundHeightLockNeedsOnlyHeight(t *testing.T) {
	f := newBuyerFixture(t)
	heightLock := uint32(800321)
	quote, _ := f.defaultQuote(t)
	prepared, err := f.Buyer.PreparePoolOpening(context.Background(), testFacts(testBaseTime), PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(heightLock),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := f.Seller.PreparePoolOpening(context.Background(), testFacts(testBaseTime), prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(context.Background(), prepared.Checkpoint, presign.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// 只有 BlockHeight：成功（timestamp 侧完全不需要）。
	refund, err := f.Buyer.BuildMaturedRefund(protocol.Facts{BlockHeight: protocol.BlockHeight(heightLock)}, completed.InitialPool)
	if err != nil {
		t.Fatalf("height-lock refund with only block height failed: %v", err)
	}
	if len(refund.RawTx()) == 0 {
		t.Fatal("matured refund produced empty raw tx")
	}

	// 只有 Now：缺高度必须拒绝，且分类为 facts 缺失而不是 expired/not-matured。
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime.Add(10 * 365 * 24 * time.Hour)}, completed.InitialPool)
	if !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("height-lock refund without height error = %v, want facts missing", err)
	}
}

// TestZeroFactsNeverAccepted 零值事实在任何时间敏感入口都被拒绝，
// 绝不回退系统时钟或猜测高度。
func TestZeroFactsNeverAccepted(t *testing.T) {
	f := newBuyerFixture(t)
	p := f.openDefaultPool(t)
	quote, _ := f.defaultQuote(t)

	if _, err := f.Buyer.AcceptQuote(protocol.Facts{}, f.createQuoteRaw(t, nil)); err == nil {
		t.Fatal("zero-time AcceptQuote accepted")
	}
	if _, err := f.Buyer.RequestContent(context.Background(), protocol.Facts{}, RequestContentCommand{
		Quote: quote, Pool: p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Add(30 * time.Minute).Unix()),
	}); !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("zero-facts RequestContent error = %v", err)
	}
}
