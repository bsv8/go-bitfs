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
	debug("=== Step 005: Cumulative Payment ===")
	debug("[buyer] AcceptDelivery verifies 004 against caller-held state, prices content, rebuilds the unsigned state locally, and signs the buyer payment")
	request, delivery, deliveryState, verified, err := f.DeliverAndBuildPayment(ctx, now)
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptDelivery: %w", err))
	}
	update := verified.Update
	debug("[payment] PaymentAuthorizationID (application lookup key): %s", hex.EncodeToString(update.PaymentAuthorizationID[:]))
	debug("[payment] buyer transaction signature: %s", hex.EncodeToString(update.BuyerPaymentTransactionSignature))
	debug("[payment] wire carries no pool ID and no raw transaction; both sides rebuild the exact state transaction locally")
	// 应用先用 005 携带的 PaymentAuthorizationID 取回保存的精确原始签名 003；
	// 它是内容
	// 寻址键，不可解码出池 ID、金额或交易字节。
	debug("[app] PaymentAuthorizationID lookup retrieves the exact original signed 003 for the minimal credential")
	authorization, err := f.LookupPaymentAuthorization(update.PaymentAuthorizationID)
	if err != nil {
		fail(err)
	}
	debug("[seller] seller.AcceptPayment re-verifies the original 003, rebuilds the same unsigned transaction via BuildPaymentUpdate, verifies the buyer signature over it, then co-signs and merges")
	signed, err := f.Seller.AcceptPayment(ctx, f.Opening, f.LatestPayment, authorization, deliveryState, update, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.AcceptPayment: %w", err))
	}
	accepted := signed.State
	if update.PaymentAuthorizationID != accepted.PaymentAuthorizationID || update.PaymentAuthorizationID != deliveryState.PaymentAuthorizationID {
		fail(fmt.Errorf("PaymentAuthorizationID changed across seller acceptance"))
	}
	debug("[payment] PaymentAuthorizationID consistent across 003/004/005 and accepted state: true")
	rawUpdate, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		fail(err)
	}
	debug("[payment] request terms bytes: %d", len(request.PaymentAuthorizationCBOR))
	debug("[payment] delivery payload batch bytes: %d", len(delivery.ContentPayloadsCBOR))
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] buyer amount: %d satoshis", accepted.BuyerAmountSatoshis)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSatoshis)
	fmt.Printf("PAYMENT_UPDATE_HEX=%s\n", hex.EncodeToString(rawUpdate))
	fmt.Printf("ACCEPTED_TX_HEX=%s\n", hex.EncodeToString(signed.RawTx))
	debug("=== Cumulative payment complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
