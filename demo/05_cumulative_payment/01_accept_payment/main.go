package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/pool"
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
	debug("=== Step 005: Cumulative Payment ===")
	debug("[buyer] AcceptDelivery verifies 004, prices content, builds next unsigned state, and signs buyer payment")
	request, delivery, update, err := f.DeliverAndBuildPayment(ctx)
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptDelivery: %w", err))
	}
	debug("[payment] authorization hash: %s", hex.EncodeToString(update.PaymentAuthorizationHash))
	debug("[payment] unsigned state tx bytes: %d", len(update.UnsignedStateTxRaw))
	debug("[payment] buyer transaction signature: %s", hex.EncodeToString(update.BuyerTransactionSignature))
	debug("[seller] seller.AcceptPayment verifies the buyer update, adds seller signature, and submits it")
	accepted, err := f.Seller.AcceptPayment(ctx, update)
	if err != nil {
		fail(fmt.Errorf("seller.AcceptPayment: %w", err))
	}
	rawUpdate, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		fail(err)
	}
	debug("[payment] request terms bytes: %d", len(request.TermsCBOR))
	debug("[payment] delivery terms bytes: %d", len(delivery.TermsCBOR))
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] buyer amount: %d satoshis", accepted.BuyerAmountSat)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSat)
	debug("[accepted] backend update submissions: %d", f.Backend.Updates)
	fmt.Printf("PAYMENT_UPDATE_HEX=%s\n", hex.EncodeToString(rawUpdate))
	fmt.Printf("ACCEPTED_TX_HEX=%s\n", hex.EncodeToString(accepted.RawTx))
	debug("=== Cumulative payment complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
