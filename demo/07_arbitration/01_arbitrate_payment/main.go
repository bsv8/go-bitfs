// Command seller, arbiter complete an arbitrated payment (BitFS 007).
//
// fixture 先完成一轮交付（003→004，不执行普通付款）；卖方纯函数 API 从本地
// 开池证据、买方授权与本方已发交付构造 exact Kind 8 Artifact；仲裁方纯函数
// API 先 PrepareArbitration 完整验证（应用在此持久化托管证据），再独立重建并
// 签署 Kind 9；最后卖方 CompleteArbitratedPayment 验证回执、补签并合并完整
// 交易。是否广播由应用决定。
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

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
	round, err := f.RequestSeed(ctx, now)
	if err != nil {
		fail(err)
	}
	if err := f.DeliverRound(ctx, now, round, [][]byte{append([]byte(nil), f.Seed...)}); err != nil {
		fail(err)
	}
	debug("[seller] seller.PrepareArbitration builds Claim evidence from the signed 003 and the validated 004 payload bundle")
	kind8Artifact, sellerClaimID, err := seller.PrepareArbitration(ctx, f.Facts(now), seller.PrepareArbitrationInput{
		Pool:        f.SellerPool,
		RequestRaw:  round.Authorization.RawKind5,
		DeliveryRaw: round.Kind6Raw,
	}, f.SellerSigner)
	if err != nil {
		fail(fmt.Errorf("seller.PrepareArbitration: %w", err))
	}
	rawKind8 := kind8Artifact.Bytes() // 应用先持久化 exact Kind 8 再发送

	// 展示层解码 payload bundle 长度用于计费与字节比对演示。
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, round.Kind6Raw)
	if err != nil {
		fail(err)
	}
	deliveryDTO, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		fail(err)
	}

	debug("[arbiter] fee policy: %d payload-CBOR bytes -> %d satoshis", len(deliveryDTO.ContentPayloadsCBOR), demoFeePolicy(len(deliveryDTO.ContentPayloadsCBOR)))
	fee := protocol.Satoshis(demoFeePolicy(len(deliveryDTO.ContentPayloadsCBOR)))
	// PrepareArbitration 完整验证但绝不签名；应用必须在 Sign 之前先持久化
	// exact 托管证据（Kind 8 原始字节、Claim ID、冻结费用与 payload bundle）。
	prepared, err := arbiter.PrepareArbitration(f.Facts(now), rawKind8, fee)
	if err != nil {
		fail(fmt.Errorf("arbiter.PrepareArbitration: %w", err))
	}
	if prepared.ArbitrationClaimID != sellerClaimID {
		fail(fmt.Errorf("arbiter claim id does not match seller-derived claim id"))
	}
	custodyClaimID := prepared.ArbitrationClaimID
	// 演示应用侧托管记录：真实实现应在数据库唯一键下原子写入这些字段。
	type custodyRecord struct {
		RequestBytes          []byte
		ArbitrationClaimID    protocol.ArbitrationClaimID
		ArbiterAmountSatoshis uint64
		ResponseBytes         []byte // 签名后追加，只追加不覆盖
	}
	custodyKey := hex.EncodeToString(custodyClaimID[:])
	custody := map[string]*custodyRecord{custodyKey: {
		RequestBytes:          append([]byte(nil), prepared.RawKind8...),
		ArbitrationClaimID:    custodyClaimID,
		ArbiterAmountSatoshis: uint64(prepared.FeeSatoshis),
	}}
	saved := custody[custodyKey]
	if saved == nil || len(saved.RequestBytes) == 0 || saved.ArbiterAmountSatoshis == 0 {
		fail(fmt.Errorf("persist arbitration custody: record missing"))
	}
	debug("[arbiter] persisted exact Kind 8 bytes under claim id %s with frozen fee %d; SignPreparedArbitration independently rebuilds and signs", custodyClaimID.String(), saved.ArbiterAmountSatoshis)

	signed, err := arbiter.SignPreparedArbitration(ctx, f.Facts(now), *prepared, f.ArbiterSigner)
	if err != nil {
		fail(fmt.Errorf("arbiter.SignPreparedArbitration: %w", err))
	}
	rawKind9 := signed.Outbound.Bytes()
	// 签名后只把 exact canonical Kind 9 追加到原记录，绝不整体覆盖。
	saved.ResponseBytes = append([]byte(nil), rawKind9...)
	persisted := custody[custodyKey]
	if string(persisted.ResponseBytes) != string(rawKind9) || string(persisted.RequestBytes) != string(prepared.RawKind8) {
		fail(fmt.Errorf("custody update lost the exact evidence bytes"))
	}

	debug("[seller] seller.CompleteArbitratedPayment independently rebuilds, verifies both arbiter signatures, then signs and merges")
	arbitratedRaw, err := seller.CompleteArbitratedPayment(ctx, f.Facts(now), seller.CompleteArbitratedPaymentInput{
		RequestRaw:           rawKind8,
		ResponseRaw:          rawKind9,
		DeliveryPayloadsCBOR: deliveryDTO.ContentPayloadsCBOR,
	}, f.SellerSigner)
	if err != nil {
		fail(fmt.Errorf("seller.CompleteArbitratedPayment: %w", err))
	}
	arbitratedTx, err := pool.VerifySignedTransaction(arbitratedRaw, f.SellerPool.Opening)
	if err != nil {
		fail(fmt.Errorf("pool.VerifySignedTransaction: %w", err))
	}
	accepted := arbitratedTx.State()
	debug("[accepted] sequence: %d", accepted.PaymentSequence)
	debug("[accepted] buyer amount: %d satoshis", accepted.BuyerAmountSatoshis)
	debug("[accepted] seller amount: %d satoshis", accepted.SellerAmountSatoshis)
	debug("[accepted] arbiter amount: %d satoshis", accepted.ArbiterAmountSatoshis)
	fmt.Printf("ARBITRATION_REQUEST_HEX=%s\n", hex.EncodeToString(rawKind8))
	fmt.Printf("ARBITRATION_RESPONSE_HEX=%s\n", hex.EncodeToString(rawKind9))
	fmt.Printf("ARBITRATED_TX_HEX=%s\n", hex.EncodeToString(arbitratedTx.RawTx()))
	fmt.Printf("ARBITRATION_CLAIM_ID=%s\n", custodyClaimID.String())
	debug("=== Arbitration complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
