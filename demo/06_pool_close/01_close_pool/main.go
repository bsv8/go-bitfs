// Command buyer and seller perform an immediate pool close (BitFS 006).
//
// fixture 先完成一轮付款得到共享的“节点已确认”最新状态；随后买方角色 API
// 从调用方选定的基准状态构造未签名关闭 candidate 与买方签名（不广播），
// 卖方补签合并，最后买方验证完整关闭交易。是否广播由应用决定。
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
)

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
	if _, err := f.RunSeedPurchase(ctx, now); err != nil {
		fail(fmt.Errorf("build prerequisite payment: %w", err))
	}
	latest := f.LatestPayment
	debug("[state] latest non-final payment has been merged and saved by the caller")
	debug("[buyer] buyer.PrepareClose creates final unsigned transaction and buyer signature from explicit state")
	unsignedRaw, buyerSignature, err := buyer.PrepareClose(ctx, f.Facts(now), buyer.PrepareCloseInput{
		Pool:                       f.BuyerPool,
		TargetSellerAmountSatoshis: protocol.Satoshis(latest.SellerAmountSatoshis),
	}, f.BuyerSigner)
	if err != nil {
		fail(fmt.Errorf("buyer.PrepareClose: %w", err))
	}
	debug("[close] unsigned transaction bytes: %d", len(unsignedRaw))
	debug("[close] buyer signature produced (detached; persisted before sending)")
	debug("[seller] seller.CompleteClose adds seller signature without broadcasting")
	closedRaw, err := seller.CompleteClose(ctx, f.Facts(now), seller.CompleteCloseInput{
		Pool:           f.SellerPool,
		UnsignedRaw:    unsignedRaw,
		BuyerSignature: buyerSignature,
	}, f.SellerSigner)
	if err != nil {
		fail(fmt.Errorf("seller.CompleteClose: %w", err))
	}
	debug("[close] seller signature produced and merged")
	debug("[buyer] buyer.VerifyCompletedClose verifies the fully signed final transaction; the caller broadcasts it")
	verifiedClose, err := buyer.VerifyCompletedClose(buyer.VerifyCompletedCloseInput{
		Pool:     f.BuyerPool,
		CloseRaw: closedRaw,
	})
	if err != nil {
		fail(fmt.Errorf("buyer.VerifyCompletedClose: %w", err))
	}
	finalTransaction := verifiedClose.RawTx()
	txID := hex.EncodeToString(finalTransactionTxID(finalTransaction))
	debug("[close] final transaction ready for caller broadcast")
	debug("[close] final transaction ID: %s", txID)
	fmt.Printf("FINAL_CLOSE_TX_HEX=%s\n", hex.EncodeToString(finalTransaction))
	fmt.Printf("FINAL_CLOSE_TX_ID_HEX=%s\n", txID)
	debug("=== Immediate pool close complete ===")
}

// finalTransactionTxID 用库的规范交易解析器计算交易 ID，保证与后续广播使用
// 的序列化一致。
func finalTransactionTxID(raw []byte) []byte {
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		fail(fmt.Errorf("parse final close transaction: %w", err))
	}
	return transaction.TxID().CloneBytes()
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
