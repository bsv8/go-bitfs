package buyer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
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
	ctx := context.Background()
	prepared, err := f.Buyer.PreparePoolOpening(ctx, PrepareOpeningCommand{
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
	presign, err := f.Seller.PreparePoolOpening(context.Background(), prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, presign.Outbound.Bytes())
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

	// 只有 Now：缺高度必须拒绝，且分类保持事实缺失的 invalid_evidence，
	// 绝不能被调用层包装误报成 expired/not_matured（应用只依据 Code 分支）。
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime.Add(10 * 365 * 24 * time.Hour)}, completed.InitialPool)
	if !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("height-lock refund without height error = %v, want facts missing", err)
	}
	requireExactCode(t, err, protocol.CodeInvalidEvidence)
}

// requireExactCode 断言 CodeOf 精确命中 want：比 errors.Is 更严格——任何
// 调用层包装覆盖稳定分类都会在此失败。
func requireExactCode(t *testing.T, err error, want protocol.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	code, ok := protocol.CodeOf(err)
	if !ok || code != want {
		t.Fatalf("error code = %v (err=%v), want exactly %s", code, err, want)
	}
}

// TestRefundGateClassificationAtEntryPoints 锁定退款门禁在对外入口上的稳定
// 分类矩阵：事实缺失 → invalid_evidence；正向门禁撞上已成熟锁 → expired；
// 成熟判定未到 → not_matured。timestamp/height 两种锁定都要覆盖。
func TestRefundGateClassificationAtEntryPoints(t *testing.T) {
	f := newBuyerFixture(t)
	p := f.openDefaultPool(t) // 时间戳型退款锁：base + 1h
	ctx := context.Background()

	// 正向门禁真正成熟 → expired：refund 门禁先于报价过期判断触发。
	maturity := time.Unix(int64(f.Expiry), 0)
	quote, _ := f.defaultQuote(t)
	_, err := f.Buyer.RequestContent(ctx, protocol.Facts{Now: maturity}, RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(maturity.Add(30 * time.Minute).Unix()),
	})
	requireExactCode(t, err, protocol.CodeExpired)

	// 成熟判定真正未到 → not_matured（时间戳锁）。
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime}, p.buyerPool)
	requireExactCode(t, err, protocol.CodeNotMatured)

	// 时间戳锁缺少 Now → invalid_evidence（不是 expired），哨兵仍可穿透。
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{}, p.buyerPool)
	requireExactCode(t, err, protocol.CodeInvalidEvidence)
	if !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("missing-fact error lost ErrFactsMissing sentinel: %v", err)
	}

	// 高度锁池：正向入口只有 Now（缺 BlockHeight）→ invalid_evidence。
	heightQuoteRaw := f.createQuoteRaw(t, func(draft *seller.QuoteDraft) { draft.SeedPriceSatoshis += 2 })
	heightQuote := mustAcceptQuote(t, f.Buyer, testBaseTime, heightQuoteRaw)
	heightPool := f.openPoolWith(t, heightQuote, testHeightLockRefundLockTime, testMinerFeeRateSatPerKB, f.FundingTransactionRaw)
	_, err = f.Buyer.RequestContent(ctx, protocol.Facts{Now: testBaseTime}, RequestContentCommand{
		Quote:            heightQuote,
		Pool:             heightPool.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Add(30 * time.Minute).Unix()),
	})
	requireExactCode(t, err, protocol.CodeInvalidEvidence)
	if !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("missing-height error lost ErrFactsMissing sentinel: %v", err)
	}

	// 高度锁退款执行真正未成熟 → not_matured。
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime, BlockHeight: testBlockHeight - 1}, heightPool.buyerPool)
	requireExactCode(t, err, protocol.CodeNotMatured)
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
