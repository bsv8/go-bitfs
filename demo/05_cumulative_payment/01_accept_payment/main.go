package main

import (
	"bytes"
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
	debug("[buyer] AcceptDelivery verifies 004 against caller-held state, prices content, builds next unsigned state, and signs buyer payment")
	request, delivery, deliveryState, verified, err := f.DeliverAndBuildPayment(ctx, now)
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptDelivery: %w", err))
	}
	update := verified.Update
	debug("[payment] refund tx hash (pool correlation ID): %s", hex.EncodeToString(update.RefundTemplateTxID[:]))
	debug("[payment] authorization hash: %s", hex.EncodeToString(update.PaymentAuthorizationHash))
	debug("[payment] unsigned state tx bytes: %d", len(update.UnsignedStateTxRaw))
	debug("[payment] buyer transaction signature: %s", hex.EncodeToString(update.BuyerTransactionSignature))
	debug("[seller] seller.AcceptPayment verifies the buyer update against the saved ContentDeliveryState and merges signatures without submitting")
	signed, err := f.Seller.AcceptPayment(ctx, f.Opening, f.LatestPayment, deliveryState, update, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.AcceptPayment: %w", err))
	}
	accepted := signed.State
	if !bytes.Equal(update.RefundTemplateTxID[:], accepted.RefundTemplateTxID[:]) {
		fail(fmt.Errorf("refund tx hash changed across seller acceptance"))
	}
	debug("[payment] refund tx hash unchanged across seller acceptance: true")
	rawUpdate, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		fail(err)
	}
	debug("[payment] request terms bytes: %d", len(request.TermsCBOR))
	debug("[payment] delivery payload batch bytes: %d", len(delivery.ContentPayloadsCBOR))
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] buyer amount: %d satoshis", accepted.BuyerAmountSat)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSat)
	fmt.Printf("PAYMENT_UPDATE_HEX=%s\n", hex.EncodeToString(rawUpdate))
	fmt.Printf("ACCEPTED_TX_HEX=%s\n", hex.EncodeToString(signed.RawTx))
	debug("=== Cumulative payment complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
