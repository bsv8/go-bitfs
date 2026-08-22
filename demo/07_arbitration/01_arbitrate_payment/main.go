package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
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
	debug("=== Step 007: Arbitration ===")
	request, err := f.BuildSeedRequest(ctx, now)
	if err != nil {
		fail(err)
	}
	debug("[seller] buyer has not produced 005; seller builds evidence from the signed 003 authorization and caller-held state")
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, f.Opening, request, f.LatestPayment, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.BuildArbitrationRequest: %w", err))
	}
	rawRequest, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		fail(err)
	}
	debug("[007 request] opening proof CBOR bytes: %d", len(arbitrationRequest.PoolOpeningProofCBOR))
	debug("[007 request] authorization CBOR bytes: %d", len(arbitrationRequest.PaymentAuthorizationCBOR))
	debug("[007 request] unsigned candidate tx bytes: %d", len(arbitrationRequest.UnsignedStateTxRaw))
	debug("[007 request] seller candidate signature: %s", hex.EncodeToString(arbitrationRequest.SellerTransactionSignature))
	debug("[arbiter] arbitration.SignPayment verifies evidence and adds only arbiter signature")
	arbitrationResponse, err := f.Arbiter.SignPayment(ctx, arbitrationRequest)
	if err != nil {
		fail(fmt.Errorf("arbitration.SignPayment: %w", err))
	}
	rawResponse, err := arbitration.MarshalResponse(arbitrationResponse)
	if err != nil {
		fail(err)
	}
	debug("[007 request/response] refund tx hash (pool correlation ID): request=%s response=%s", hex.EncodeToString(arbitrationRequest.RefundTemplateTxID[:]), hex.EncodeToString(arbitrationResponse.RefundTemplateTxID[:]))
	debug("[007 response] authorization hash: %s", hex.EncodeToString(arbitrationResponse.PaymentAuthorizationHash))
	debug("[007 response] candidate tx hash: %s", hex.EncodeToString(arbitrationResponse.UnsignedStateTxHash))
	debug("[007 response] arbiter signature: %s", hex.EncodeToString(arbitrationResponse.ArbiterTransactionSignature))
	debug("[seller] seller.CompleteArbitratedPayment merges the same candidate without broadcasting")
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, f.Opening, f.LatestPayment, arbitrationRequest, arbitrationResponse, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.CompleteArbitratedPayment: %w", err))
	}
	accepted := signed.State
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSat)
	fmt.Printf("ARBITRATION_REQUEST_HEX=%s\n", hex.EncodeToString(rawRequest))
	fmt.Printf("ARBITRATION_RESPONSE_HEX=%s\n", hex.EncodeToString(rawResponse))
	fmt.Printf("ARBITRATED_TX_HEX=%s\n", hex.EncodeToString(signed.RawTx))
	debug("=== Arbitration complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
