package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/pool"
)

// blockHeight 是调用方认可并提供的当前区块高度；SDK 不查询节点。
const blockHeight uint32 = 900000

func main() {
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	f, err := fixture.New(ctx)
	if err != nil {
		fail(err)
	}
	now := time.Now().UTC()
	debug("=== Step 006: Immediate Pool Close ===")
	_, _, deliveryState, verified, err := f.DeliverAndBuildPayment(ctx, now)
	if err != nil {
		fail(fmt.Errorf("build prerequisite payment: %w", err))
	}
	// 005 最小凭证只携带授权哈希与买方签名；应用先按哈希取回原始签名 003
	// 再交给卖方验收。
	authorization, err := f.LookupPaymentAuthorization(verified.Update.PaymentAuthorizationHash)
	if err != nil {
		fail(err)
	}
	// 卖方本地重建状态交易、合并签名后得到完整付款交易；demo 作为调用方把
	// 它当作新的最新状态保存（真实应用在此处广播并记录结果）。
	signedPayment, err := f.Seller.AcceptPayment(ctx, f.Opening, f.LatestPayment, authorization, deliveryState, verified.Update, blockHeight)
	if err != nil {
		fail(fmt.Errorf("accept prerequisite payment: %w", err))
	}
	latest := &signedPayment.State
	debug("[state] latest non-final payment has been merged and saved by the caller")
	debug("[buyer] buyer.BuildImmediateClose creates final unsigned transaction and buyer signature from explicit state")
	unsigned, buyerSignature, err := f.Buyer.BuildImmediateClose(ctx, f.Opening, latest, latest.SellerAmountSat, blockHeight)
	if err != nil {
		fail(fmt.Errorf("buyer.BuildImmediateClose: %w", err))
	}
	debug("[close] unsigned transaction bytes: %d", len(unsigned.RawTx))
	debug("[close] buyer signature: %s", hex.EncodeToString(buyerSignature))
	debug("[seller] seller.SignImmediateClose adds seller signature without broadcasting")
	closed, err := f.Seller.SignImmediateClose(ctx, f.Opening, unsigned, buyerSignature, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.SignImmediateClose: %w", err))
	}
	debug("[close] seller signature: %s", hex.EncodeToString(closed.State.SellerTransactionSignature))
	debug("[buyer] buyer.CompleteImmediateClose verifies the fully signed final transaction; the caller broadcasts it")
	completed, err := f.Buyer.CompleteImmediateClose(ctx, f.Opening, closed)
	if err != nil {
		fail(fmt.Errorf("buyer.CompleteImmediateClose: %w", err))
	}
	finalTransaction, err := pool.ParseCanonicalTransaction(completed.RawTx)
	if err != nil {
		fail(fmt.Errorf("parse final close transaction: %w", err))
	}
	txID := finalTransaction.TxID().CloneBytes()
	debug("[close] final transaction ready for caller broadcast")
	debug("[close] final transaction ID: %s", hex.EncodeToString(txID))
	fmt.Printf("FINAL_CLOSE_TX_HEX=%s\n", hex.EncodeToString(completed.RawTx))
	fmt.Printf("FINAL_CLOSE_TX_ID_HEX=%s\n", hex.EncodeToString(txID))
	debug("=== Immediate pool close complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
