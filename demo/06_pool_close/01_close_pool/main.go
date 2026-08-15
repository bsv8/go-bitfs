package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

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
	debug("=== Step 006: Immediate Pool Close ===")
	_, _, update, err := f.DeliverAndBuildPayment(ctx)
	if err != nil {
		fail(fmt.Errorf("build prerequisite payment: %w", err))
	}
	if _, err := f.Seller.AcceptPayment(ctx, update); err != nil {
		fail(fmt.Errorf("accept prerequisite payment: %w", err))
	}
	debug("[state] latest non-final payment has been accepted")
	debug("[buyer] buyer.BuildImmediateClose creates final unsigned transaction and buyer signature")
	unsigned, buyerSignature, err := f.Buyer.BuildImmediateClose(ctx, f.Reference.SpendTxID)
	if err != nil {
		fail(fmt.Errorf("buyer.BuildImmediateClose: %w", err))
	}
	debug("[close] unsigned transaction bytes: %d", len(unsigned.RawTx))
	debug("[close] buyer signature: %s", hex.EncodeToString(buyerSignature))
	debug("[seller] seller.SignImmediateClose adds seller signature without broadcasting")
	closed, err := f.Seller.SignImmediateClose(ctx, unsigned, buyerSignature)
	if err != nil {
		fail(fmt.Errorf("seller.SignImmediateClose: %w", err))
	}
	debug("[close] seller signature: %s", hex.EncodeToString(closed.State.SellerTransactionSignature))
	debug("[buyer] buyer.SubmitImmediateClose submits the fully signed final transaction")
	txID, err := f.Buyer.SubmitImmediateClose(ctx, closed)
	if err != nil {
		fail(fmt.Errorf("buyer.SubmitImmediateClose: %w", err))
	}
	debug("[close] final transaction accepted by demo backend")
	debug("[close] final transaction ID: %s", hex.EncodeToString(txID[:]))
	fmt.Printf("FINAL_CLOSE_TX_HEX=%s\n", hex.EncodeToString(closed.RawTx))
	fmt.Printf("FINAL_CLOSE_TX_ID_HEX=%s\n", hex.EncodeToString(txID[:]))
	debug("=== Immediate pool close complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
