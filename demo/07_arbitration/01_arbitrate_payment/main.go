package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bsv8/go-bitfs/arbitration"
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
	debug("=== Step 007: Arbitration ===")
	request, err := f.BuildSeedRequest(ctx)
	if err != nil {
		fail(err)
	}
	debug("[seller] seller.DeliverRequestedContent delivers 004 first")
	if _, err := f.Seller.DeliverRequestedContent(ctx, request); err != nil {
		fail(fmt.Errorf("deliver prerequisite content: %w", err))
	}
	debug("[seller] buyer has not produced 005; seller builds evidence from the signed 003 authorization")
	arbitrationRequest, err := f.Seller.BuildArbitrationRequestFromAuthorization(ctx, request)
	if err != nil {
		fail(fmt.Errorf("seller.BuildArbitrationRequestFromAuthorization: %w", err))
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
	debug("[007 response] authorization hash: %s", hex.EncodeToString(arbitrationResponse.PaymentAuthorizationHash))
	debug("[007 response] candidate tx hash: %s", hex.EncodeToString(arbitrationResponse.UnsignedStateTxHash))
	debug("[007 response] arbiter signature: %s", hex.EncodeToString(arbitrationResponse.ArbiterTransactionSignature))
	debug("[seller] seller.SubmitArbitratedPayment merges the same candidate and submits it")
	accepted, err := f.Seller.SubmitArbitratedPayment(ctx, arbitrationRequest, arbitrationResponse)
	if err != nil {
		fail(fmt.Errorf("seller.SubmitArbitratedPayment: %w", err))
	}
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSat)
	fmt.Printf("ARBITRATION_REQUEST_HEX=%s\n", hex.EncodeToString(rawRequest))
	fmt.Printf("ARBITRATION_RESPONSE_HEX=%s\n", hex.EncodeToString(rawResponse))
	debug("=== Arbitration complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
