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
	f, err := fixture.New(context.Background())
	if err != nil {
		fail(err)
	}

	debug("=== Step 002: Pool Opening ===")
	debug("[1] buyer.PreparePoolOpening: buyer builds and signs RefundPresignRequest")
	debug("[2] seller.PresignPoolOpening: seller verifies and signs the refund")
	debug("[3] buyer.AcceptRefundPresign: buyer stores the complete OpeningProof")
	debug("[4] buyer.BuildFundingTxDelivery: buyer reveals FundingTx only after step 3")
	debug("[5] seller.AcceptPoolFunding: seller verifies and submits FundingTx")
	debug("[state] funding submissions accepted by demo backend: %d", f.Backend.Fundings)
	debug("[state] initial payment sequence: %d", f.Reference.BasePaymentSequence)
	debug("[state] SpendTxID: %s", hex.EncodeToString(f.Reference.SpendTxID[:]))
	debug("[state] FundingTxID: %s", hex.EncodeToString(f.Opening.FundingTxID))
	debug("[state] pool output satoshis: %d", f.Opening.PoolOutputSatoshis)
	debug("[state] pool locking script: %s", hex.EncodeToString(f.Opening.PoolLockingScript))
	debug("[state] refund tx bytes: %d", len(f.Opening.RefundTx))
	debug("[state] buyer refund signature: %s", hex.EncodeToString(f.Opening.BuyerRefundSignature))
	debug("[state] seller refund signature: %s", hex.EncodeToString(f.Opening.SellerRefundSignature))

	rawProof, err := pool.EncodeOpeningProof(f.Opening)
	if err != nil {
		fail(fmt.Errorf("encode OpeningProof: %w", err))
	}
	fmt.Printf("OPENING_PROOF_HEX=%s\n", hex.EncodeToString(rawProof))
	fmt.Printf("FUNDING_TX_HEX=%s\n", hex.EncodeToString(f.FundingTx))
	fmt.Printf("SPEND_TX_ID_HEX=%s\n", hex.EncodeToString(f.Reference.SpendTxID[:]))
	debug("=== Pool opening complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
