// 008 买方仲裁托管内容取回演示：Seller 与 Buyer 无法直连，但二者均能连接
// Arbiter。完整顺序为 001–007（Seller 托管、Arbiter 签署 Kind 9）之后，
// Buyer 用角色 API 构造 exact Kind 10（SDK 生成安全随机 nonce），Arbiter 验
// 签并按结果返回由自己签名的 Kind 11：可交付分支绑定 exact payload，不可交付
// 分支携带结构化原因。
//
// 本 demo 演示两个分支：先在 Kind 9 落库前请求一次得到签名 not_ready（typed
// 结果，不是 error），随后用新 nonce 重试得到 available。验收不产生 Kind 7、
// 不改 previous、不关池、不广播任何交易；Claim ID 不是下载密码，nonce 不代替
// TLS，Kind 11 不声称 Seller 交易已上链结算。
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

// demoFeePolicy 是应用层计费策略示例：按 exact ContentPayloadsCBOR 长度阶梯
// 计费。SDK 只验证正数与余额，不注入费率策略。
func demoFeePolicy(payloadCBORBytes int) uint64 {
	const baseFeeSat = 100
	const satPerKiB = 50
	kib := (payloadCBORBytes + 1023) / 1024
	if kib < 1 {
		kib = 1
	}
	return baseFeeSat + uint64(kib)*satPerKiB
}

// custodyRecord 是应用侧 007 托管记录：exact Kind 8 原始字节与 exact canonical
// Kind 9。真实应用应在 PrepareArbitration 之后、SignPreparedArbitration 之前
// 原子持久化；签名完成后把响应字节追加到同一记录。
type custodyRecord struct {
	requestBytes  []byte // exact received raw Kind 8, deep-copied on save
	responseBytes []byte // exact canonical saved Kind 9；payload 无第二份存储真值
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
	debug("=== Steps 001-007: seller submits custody while buyer is offline ===")
	round, err := f.RequestSeed(ctx, now)
	if err != nil {
		fail(err)
	}
	if err := f.DeliverRound(ctx, now, round, [][]byte{append([]byte(nil), f.Seed...)}); err != nil {
		fail(err)
	}
	rawKind8Artifact, err := f.Seller.PrepareArbitration(ctx, f.Facts(now), seller.ArbitrationCommand{
		Pool:        f.SellerPool,
		Request:     round.Request.Checkpoint.Request(),
		DeliveryRaw: round.Kind6Raw,
	})
	if err != nil {
		fail(fmt.Errorf("seller.PrepareArbitration: %w", err))
	}
	rawKind8 := rawKind8Artifact.Bytes()

	// 展示层解码 payload bundle 长度用于计费。
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, round.Kind6Raw)
	if err != nil {
		fail(err)
	}
	deliveryDTO, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		fail(err)
	}

	// 应用侧托管：先原子持久化 exact Kind 8（此时还没有 Kind 9）。
	store := &custodyRecord{requestBytes: append([]byte(nil), rawKind8...)}
	debug("[arbiter] exact Kind 8 persisted; record is CustodyPrepared (no Kind 9 yet)")

	prepared, err := f.Arbiter.PrepareArbitration(f.Facts(now), rawKind8, protocol.Satoshis(demoFeePolicy(len(deliveryDTO.ContentPayloadsCBOR))))
	if err != nil {
		fail(fmt.Errorf("arbiter.PrepareArbitration: %w", err))
	}
	custodyClaimID := prepared.ArbitrationClaimID()

	debug("=== Step 008a: buyer asks before Kind 9 exists -> signed not_ready ===")
	// Buyer 只需要池 checkpoint + exact 已签 003 就能构造 Kind 10；
	// SDK 默认入口生成安全随机 nonce，重试必须原样重放已持久化的 Artifact。
	k10FirstArtifact, err := f.Buyer.RequestArbitratedContent(ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          f.BuyerPool,
		Authorization: round.Request.Checkpoint,
	})
	if err != nil {
		fail(fmt.Errorf("buyer.RequestArbitratedContent: %w", err))
	}
	k10First := k10FirstArtifact.Bytes() // 应用先持久化 exact Kind 10 再发送
	requestID := retrievalRequestIDOf(k10First)

	notReadyArtifact, err := f.Arbiter.BuildUnavailableRetrieval(ctx, requestID, arbitration.RetrievalSellerArbitrationNotReady)
	if err != nil {
		fail(fmt.Errorf("arbiter.BuildUnavailableRetrieval(not_ready): %w", err))
	}
	outcomeNotReady, err := f.Buyer.VerifyArbitratedContent(ctx, buyer.ArbitratedContentCommand{
		Quote:                f.VerifiedQuote,
		Pool:                 f.BuyerPool,
		Request:              round.Request.Checkpoint,
		RetrievalRequestRaw:  k10First,
		RetrievalResponseRaw: notReadyArtifact.Bytes(),
	})
	if err != nil {
		fail(fmt.Errorf("buyer.VerifyArbitratedContent(not_ready): %w", err))
	}
	if outcomeNotReady.Available || outcomeNotReady.UnavailableReason != arbitration.RetrievalSellerArbitrationNotReady {
		fail(fmt.Errorf("not_ready branch mismatch: %+v", outcomeNotReady))
	}
	debug("[arbiter] answered signed not_ready; buyer must retry with a NEW nonce")

	// Kind 9 落库：记录进入 Retrievable。
	response9Artifact, err := f.Arbiter.SignPreparedArbitration(ctx, f.Facts(now), prepared)
	if err != nil {
		fail(fmt.Errorf("arbiter.SignPreparedArbitration: %w", err))
	}
	store.responseBytes = append([]byte(nil), response9Artifact.Bytes()...)
	debug("[arbiter] exact canonical Kind 9 appended; record is now Retrievable")

	debug("=== Step 008b: fresh-nonce retry -> available with bound payloads ===")
	k10RetryArtifact, err := f.Buyer.RequestArbitratedContent(ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          f.BuyerPool,
		Authorization: round.Request.Checkpoint,
	})
	if err != nil {
		fail(fmt.Errorf("buyer.RequestArbitratedContent(retry): %w", err))
	}
	k10Retry := k10RetryArtifact.Bytes() // 新 nonce = 新请求；旧 nonce 永远不会升级
	retryRequestID := retrievalRequestIDOf(k10Retry)

	custodyVerified, err := f.Arbiter.VerifyRetrievableCustody(k10Retry, store.requestBytes, store.responseBytes)
	if err != nil {
		fail(fmt.Errorf("arbiter.VerifyRetrievableCustody: %w", err))
	}
	availableArtifact, err := f.Arbiter.BuildAvailableRetrieval(ctx, retryRequestID, custodyVerified)
	if err != nil {
		fail(fmt.Errorf("arbiter.BuildAvailableRetrieval: %w", err))
	}
	result, err := f.Buyer.VerifyArbitratedContent(ctx, buyer.ArbitratedContentCommand{
		Quote:                f.VerifiedQuote,
		Pool:                 f.BuyerPool,
		Request:              round.Request.Checkpoint,
		RetrievalRequestRaw:  k10Retry,
		RetrievalResponseRaw: availableArtifact.Bytes(),
	})
	if err != nil {
		fail(fmt.Errorf("buyer.VerifyArbitratedContent(available): %w", err))
	}
	if !result.Available || len(result.Payloads) == 0 {
		fail(fmt.Errorf("available branch mismatch: %+v", result))
	}
	// 验收只返回 deep-copy payload 与审计数据；不构造、不签名、不发送 Kind 7。
	debug("[buyer] accepted %d payload(s) bound to request ID %s", len(result.Payloads), result.ContentRetrievalRequestID.String())
	fmt.Printf("ARBITRATION_CLAIM_ID=%s\n", custodyClaimID.String())
	fmt.Printf("NOT_READY_REASON=%d\n", int(outcomeNotReady.UnavailableReason))
	fmt.Printf("KIND10_BYTES=%d\n", len(k10Retry))
	fmt.Printf("KIND11_BYTES=%d\n", len(availableArtifact.Bytes()))
	fmt.Printf("PAYLOAD_COUNT=%d\n", len(result.Payloads))
	fmt.Printf("VERIFIED=true\n")
	debug("=== Retrieval complete: no payment credential, no pool close, no broadcast ===")
}

// retrievalRequestIDOf 从 exact Kind 10 bytes 派生请求 ID：
// SHA-256(exact content_retrieval_request_cbor)。展示层允许 wire.Decode。
func retrievalRequestIDOf(rawKind10 []byte) protocol.ContentRetrievalRequestID {
	artifact, err := wire.ParseAs(wire.ContentRetrievalRequest, rawKind10)
	if err != nil {
		fail(err)
	}
	dto, err := wire.DecodeContentRetrievalRequest(artifact)
	if err != nil {
		fail(err)
	}
	digest := sha256.Sum256(dto.ContentRetrievalRequestCBOR)
	return protocol.ContentRetrievalRequestID(digest)
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
