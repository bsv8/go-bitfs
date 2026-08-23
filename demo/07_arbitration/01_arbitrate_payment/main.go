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

type custodyRecord struct {
	Request             *arbitration.ArbitrationRequest
	ContentPayloadsCBOR []byte
	RequestCommitment   []byte
	UnsignedStateTxHash []byte
}

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
	request, delivery, _, _, err := f.DeliverAndBuildPayment(ctx, now)
	if err != nil {
		fail(err)
	}
	debug("[seller] seller builds Claim evidence from signed 003 and the validated 004 payload bundle")
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, f.Opening, request, delivery, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.BuildArbitrationRequest: %w", err))
	}
	rawRequest, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		fail(err)
	}
	debug("[007 request] Claim CBOR bytes: %d", len(arbitrationRequest.ClaimCBOR))
	debug("[007 request] payload bundle CBOR bytes: %d", len(arbitrationRequest.ContentPayloadsCBOR))
	debug("[007 request] Seller Claim signature: %s", hex.EncodeToString(arbitrationRequest.SellerClaimSignature))
	debug("[arbiter] PreparePayment verifies and holds custody evidence; application persistence occurs here")
	prepared, err := f.Arbiter.PreparePayment(ctx, arbitrationRequest, blockHeight)
	if err != nil {
		fail(fmt.Errorf("arbitration.PreparePayment: %w", err))
	}
	custody := make(map[string]custodyRecord)
	custodyKey := hex.EncodeToString(prepared.RequestCommitment())
	custody[custodyKey] = custodyRecord{
		Request:             prepared.Request(),
		ContentPayloadsCBOR: prepared.ContentPayloadsCBOR(),
		RequestCommitment:   prepared.RequestCommitment(),
		UnsignedStateTxHash: prepared.UnsignedStateTxHash(),
	}
	if saved, ok := custody[custodyKey]; !ok || saved.Request == nil || len(saved.ContentPayloadsCBOR) == 0 {
		fail(fmt.Errorf("persist arbitration custody: record missing"))
	}
	debug("[arbiter] persisted exact request and payload bundle; SignPreparedPayment independently rebuilds and signs")
	arbitrationResponse, err := f.Arbiter.SignPreparedPayment(ctx, prepared)
	if err != nil {
		fail(fmt.Errorf("arbitration.SignPreparedPayment: %w", err))
	}
	rawResponse, err := arbitration.MarshalResponse(arbitrationResponse)
	if err != nil {
		fail(err)
	}
	result, err := arbitration.UnmarshalResult(arbitrationResponse.ResultCBOR)
	if err != nil {
		fail(err)
	}
	debug("[007 result] request commitment: %s", hex.EncodeToString(result.RequestCommitment))
	debug("[007 result] payload bundle hash: %s", hex.EncodeToString(result.ContentPayloadsHash))
	debug("[007 result] unsigned candidate hash: %s", hex.EncodeToString(result.UnsignedStateTxHash))
	debug("[007 response] arbiter signature: %s", hex.EncodeToString(arbitrationResponse.ArbiterTransactionSignature))
	debug("[seller] seller independently rebuilds, verifies both Arbiter signatures, then signs and merges")
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, arbitrationResponse, blockHeight)
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
