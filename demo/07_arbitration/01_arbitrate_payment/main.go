package main

import (
	"bytes"
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

// demoFeePolicy 是应用层的确定性演示计费策略：按仲裁方收到的 exact
// ContentPayloadsCBOR 长度阶梯计费（整数运算，无浮点）。它只属于本 demo
// 应用，不是 SDK 的自动费率；生产应用应替换为自己的报价服务或价目表。
//
//	fee = baseFeeSat + ceil(payloadCBORBytes / 1024) * satPerKiB
func demoFeePolicy(payloadCBORBytes int) uint64 {
	const baseFeeSat = 100
	const satPerKiB = 50
	kib := (payloadCBORBytes + 1023) / 1024
	if kib < 1 {
		kib = 1
	}
	return baseFeeSat + uint64(kib)*satPerKiB
}

// custodyRecord 是应用侧 007 托管记录：exact Kind 8 原始字节、payload、
// Claim ID 与冻结费用。真实应用应在 PreparePayment 之后、SignPreparedPayment
// 之前原子持久化；签名完成后把 exact canonical 响应字节附加到同一记录（只
// 追加，不覆盖既有字段），供审计、恢复与 exact Kind 8 相同时的幂等重发使用。
type custodyRecord struct {
	RequestBytes        []byte
	ContentPayloadsCBOR []byte
	ClaimID             []byte
	ArbiterAmountSat    uint64
	ResponseBytes       []byte
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
	// 应用先按 exact payload CBOR 长度计费，再把明确金额交给 SDK。
	billedBytes := len(arbitrationRequest.ContentPayloadsCBOR)
	arbiterAmountSat := demoFeePolicy(billedBytes)
	debug("[arbiter] fee policy: %d payload-CBOR bytes -> %d satoshis", billedBytes, arbiterAmountSat)
	debug("[arbiter] PreparePayment verifies and holds custody evidence; application persistence occurs here")
	prepared, err := f.Arbiter.PreparePayment(ctx, arbitrationRequest, blockHeight, arbiterAmountSat)
	if err != nil {
		fail(fmt.Errorf("arbitration.PreparePayment: %w", err))
	}
	custodyKey := hex.EncodeToString(prepared.ClaimID())
	custody := make(map[string]custodyRecord)
	custody[custodyKey] = custodyRecord{
		RequestBytes:        append([]byte(nil), rawRequest...),
		ContentPayloadsCBOR: prepared.ContentPayloadsCBOR(),
		ClaimID:             prepared.ClaimID(),
		ArbiterAmountSat:    prepared.ArbiterAmountSat(),
	}
	saved, ok := custody[custodyKey]
	if !ok || len(saved.RequestBytes) == 0 || len(saved.ClaimID) != 32 || saved.ArbiterAmountSat == 0 {
		fail(fmt.Errorf("persist arbitration custody: record missing"))
	}
	debug("[arbiter] persisted exact Kind 8 bytes, Claim ID %s and frozen fee; SignPreparedPayment independently rebuilds and signs", custodyKey[:16])
	response, err := f.Arbiter.SignPreparedPayment(ctx, prepared)
	if err != nil {
		fail(fmt.Errorf("arbitration.SignPreparedPayment: %w", err))
	}
	rawResponse, err := arbitration.MarshalResponse(response)
	if err != nil {
		fail(err)
	}
	// 签名后只更新原记录的响应字段，绝不整体覆盖：请求、payload、Claim ID
	// 与冻结费用必须保持原样，供审计、恢复和 exact Kind 8 相同时的幂等重发使用。
	saved.ResponseBytes = append([]byte(nil), rawResponse...)
	custody[custodyKey] = saved
	persisted := custody[custodyKey]
	if len(persisted.ResponseBytes) != len(rawResponse) || !bytes.Equal(persisted.ResponseBytes, rawResponse) {
		fail(fmt.Errorf("custody update lost the exact canonical response bytes"))
	}
	if !bytes.Equal(persisted.RequestBytes, rawRequest) {
		fail(fmt.Errorf("custody update dropped or altered the exact Kind 8 bytes"))
	}
	if _, err := arbitration.UnmarshalRequest(persisted.RequestBytes); err != nil {
		fail(fmt.Errorf("persisted Kind 8 bytes no longer strict-decode: %w", err))
	}
	if !bytes.Equal(persisted.ContentPayloadsCBOR, prepared.ContentPayloadsCBOR()) {
		fail(fmt.Errorf("custody update dropped the exact payload bundle"))
	}
	if !bytes.Equal(persisted.ClaimID, prepared.ClaimID()) || persisted.ArbiterAmountSat != prepared.ArbiterAmountSat() {
		fail(fmt.Errorf("custody update changed the Claim ID or the frozen fee"))
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		fail(err)
	}
	debug("[007 receipt] claim id: %s", hex.EncodeToString(receipt.ClaimID))
	debug("[007 receipt] arbiter amount: %d satoshis", receipt.ArbiterAmountSat)
	debug("[007 receipt] receipt cbor (%d bytes): %s", len(response.ReceiptCBOR), hex.EncodeToString(response.ReceiptCBOR))
	debug("[007 response] arbiter transaction signature: %s", hex.EncodeToString(receipt.ArbiterTransactionSignature))
	debug("[007 response] arbiter receipt signature: %s", hex.EncodeToString(response.ArbiterReceiptSignature))
	debug("[seller] seller independently rebuilds, verifies both Arbiter signatures, then signs and merges")
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, response, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.CompleteArbitratedPayment: %w", err))
	}
	accepted := signed.State
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] buyer amount: %d satoshis", accepted.BuyerAmountSat)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSat)
	debug("[accepted] arbiter amount: %d satoshis", accepted.ArbiterAmountSat)
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
