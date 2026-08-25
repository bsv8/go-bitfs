// Command buyer and seller complete one cumulative payment (BitFS 003→004→005).
//
// fixture 作为调用方应用串起完整一轮：买方请求 seed、卖方交付并保存
// DeliveryCheckpoint、买方验收 payload 并构造整批唯一的最小 Kind 7 凭证，
// 最后卖方按 PaymentAuthorizationID 取回原始签名 003 并合并签名得到完整付款
// 交易。双方本地 checkpoint 随后推进到同一确认状态。
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
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
	debug("=== Step 005: Cumulative Payment ===")
	debug("[buyer] VerifyDeliveryAndPreparePayment verifies 004 against caller-held state, prices content, rebuilds the unsigned state locally, and signs the buyer payment")
	round, err := f.RunSeedPurchase(ctx, now)
	if err != nil {
		fail(err)
	}
	debug("[payment] PaymentAuthorizationID (application lookup key): %s", round.PaymentID.String())
	debug("[payment] wire carries no pool ID and no raw transaction; both sides rebuild the exact state transaction locally")
	debug("[app] PaymentAuthorizationID lookup retrieves the exact original signed 003 for the minimal credential")
	if _, err := f.LookupPaymentAuthorization(round.PaymentID); err != nil {
		fail(err)
	}
	debug("[seller] seller.CompletePayment re-verifies the original 003, rebuilds the same unsigned transaction, verifies the buyer signature over it, then co-signs and merges")
	accepted := round.AcceptedTx.State()
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] buyer amount: %d satoshis", accepted.BuyerAmountSatoshis)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSatoshis)
	fmt.Printf("PAYMENT_UPDATE_HEX=%x\n", round.Kind7Raw)
	fmt.Printf("ACCEPTED_TX_HEX=%x\n", round.AcceptedTx.RawTx())
	debug("=== Cumulative payment complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
