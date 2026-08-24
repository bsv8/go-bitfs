// 008 买方仲裁托管内容取回演示：Seller 与 Buyer 无法直连，但二者均能连接
// Arbiter。完整顺序为 001–007（Seller 托管、Arbiter 签署 Kind 9）之后，
// Buyer 用自己可独立计算的 Claim ID 构造 Kind 10，Arbiter 验签并原子占用
// nonce 后按结果返回由自己签名的 Kind 11：可交付分支绑定 exact payload，
// 不可交付分支携带结构化原因（本 demo 存储只会遇到可交付路径）。
//
// 本 demo 不产生 005、不关池、不广播任何交易；Claim ID 不是下载密码，
// nonce 不代替 TLS，Kind 11 不声称 Seller 交易已上链结算。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/protocol"
)

// blockHeight 是调用方认可并提供的当前区块高度；SDK 不查询节点。
const blockHeight uint32 = 900000

// retrievalError 是应用层错误通道：not_received / not_ready / available 三种
// 正常结果全部是签名的 Kind 11；并发相同请求由原子提交裁决唯一胜者，败者
// 重放胜者已提交的字节——对 Buyer 与首次响应完全一致。其余走这里。
var (
	errUnauthorized   = fmt.Errorf("Unauthorized")
	errCustodyCorrupt = fmt.Errorf("CustodyCorrupt: stored custody bytes failed verification; isolate and alarm")
)

// custodyStore 是应用侧托管库 + nonce 占用表。真实实现应使用数据库唯一键
// (hex(ClaimID), hex(Nonce)) 与事务保证原子性；demo 用互斥锁模拟唯一键的
// 并发语义。先验签，再占用 nonce——验签失败的请求绝不污染 nonce 表。
// answers 保存每个请求首次持久化的 Kind 11：同一 content_retrieval_request_id
// 重放原样重发，状态变化后不升级；not_received 是不写任何状态的明确例外。
type custodyStore struct {
	mu      sync.Mutex
	record  *arbitrationCustodyRecord
	nonces  map[string]bool
	answers map[string][]byte
}

type arbitrationCustodyRecord struct {
	requestBytes  []byte // exact received raw Kind 8, deep-copied on save
	responseBytes []byte // exact canonical saved Kind 9
	// payload 不再单独保存第二份真值：响应一律使用
	// VerifyCustodiedContent 返回并验证过的 PayloadsCBOR。
}

func newCustodyStore() *custodyStore {
	return &custodyStore{nonces: make(map[string]bool), answers: make(map[string][]byte)}
}

// handleArbitrationRequest 固定顺序：strict decode -> 派生 Claim ID ->
// 原子持久化 exact Kind 8/Claim ID/payload/费用 -> 签署 -> 追加 exact Kind 9。
func (store *custodyStore) handleArbitrationRequest(rawKind8 []byte, arbiter *arbitration.Workflow) error {
	decoded, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		return err
	}
	feeSat := demoFeePolicy(len(decoded.ContentPayloadsCBOR))
	prepared, err := arbiter.PreparePayment(context.Background(), decoded, blockHeight, feeSat)
	if err != nil {
		return err
	}
	custodyClaimID := prepared.ArbitrationClaimID()
	claimID := hex.EncodeToString(custodyClaimID[:])
	store.mu.Lock()
	if store.record != nil {
		store.mu.Unlock()
		return fmt.Errorf("duplicate claim %s under demo single-record store", claimID[:16])
	}
	// 原子持久化点：此后才允许 SignPreparedPayment。
	store.record = &arbitrationCustodyRecord{requestBytes: append([]byte(nil), rawKind8...)}
	store.mu.Unlock()

	debug("[arbiter] frozen fee %d satoshis; exact Kind 8 persisted under Claim ID %s", feeSat, claimID[:16])
	response, err := arbiter.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		return err
	}
	rawResponse, err := arbitration.MarshalResponse(response)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.record.responseBytes = append([]byte(nil), rawResponse...)
	debug("[arbiter] exact canonical Kind 9 appended; record is now Retrievable")
	return nil
}

// handleContentRetrieval 固定顺序：strict decode -> 幂等重放检查 -> lookup ->
// 分支判定 -> Buyer 鉴权 -> nonce CAS -> 持久化首次响应 -> 返回 Arbiter
// 签名的 Kind 11。
//
// nonce 一次性语义（与主规范 §14.3 一致）：
//
//	没有 Kind 8             -> not_received（无法鉴权 Buyer 的明确例外：不占用
//	                           nonce、不持久化响应；生产实现必须限流）
//	有 Kind 8、没有 Kind 9  -> not_ready（先凭已验证 Kind 8 完成 Buyer 鉴权，
//	                           再原子占用并持久化——Buyer 必须换新 nonce 重试，
//	                           旧 nonce 永远不会再变成下载授权）
//	完整记录                -> available（payload 经 content_payloads_id 绑定）
//	同一请求重放            -> 原样返回第一次持久化的 Kind 11，状态变化后
//	                           不升级为 available
//
// Malformed / CustodyCorrupt / Unauthorized 仍走应用错误通道。
func (store *custodyStore) handleContentRetrieval(rawKind10 []byte, arbiter *arbitration.Workflow, arbiterPrivateKey *ec.PrivateKey) ([]byte, error) {
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return nil, err
	}
	requestID := protocol.ContentRetrievalRequestID(sha256.Sum256(retrievalRequest.ContentRetrievalRequestCBOR))
	buildUnavailable := func(reason arbitration.ContentRetrievalUnavailableReason) ([]byte, error) {
		signed, buildErr := arbitration.BuildContentRetrievalUnavailable(requestID, reason, arbiterPrivateKey)
		if buildErr != nil {
			return nil, buildErr
		}
		return arbitration.MarshalContentRetrievalResponse(signed)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	routingClaimID0, retrievalNonce0, err := arbitration.DecodeContentRetrievalRequestDocument(retrievalRequest.ContentRetrievalRequestCBOR)
	if err != nil {
		return nil, err
	}
	answerKey := hex.EncodeToString(routingClaimID0[:]) + ":" + hex.EncodeToString(retrievalNonce0)
	if served, ok := store.answers[answerKey]; ok {
		debug("[arbiter] replay of a persisted request; resending the first signed answer verbatim")
		return append([]byte(nil), served...), nil
	}

	if store.record == nil || len(store.record.requestBytes) == 0 {
		// 不返回任何 Claim、角色公钥、payload 或记录元数据；不占用 nonce。
		// 生产实现还应限流，防止把 Arbiter 变成签名服务。
		debug("[arbiter] no custody record; answering signed not_received without buyer authentication")
		return buildUnavailable(arbitration.RetrievalSellerArbitrationNotReceived)
	}
	storedRequest, err := arbitration.UnmarshalRequest(store.record.requestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: stored Kind 8 failed strict decode; isolate and alarm: %v", errCustodyCorrupt, err)
	}

	// occupyAndAnswer 在同一临界区内完成 "(Claim ID, Nonce) 唯一键占用 +
	// exact 首次响应插入"：数据库里每个请求只有一行首次应答；并发相同请求
	// 的后来者命中 answers 重放胜者字节——对 Buyer 与首次响应完全一致。
	occupyAndAnswer := func(raw []byte) ([]byte, error) {
		store.nonces[answerKey] = true
		store.answers[answerKey] = append([]byte(nil), raw...)
		return append([]byte(nil), raw...), nil
	}

	if len(store.record.responseBytes) == 0 {
		if authErr := arbiter.AuthenticateContentRetrievalRequest(retrievalRequest, storedRequest); authErr != nil {
			return nil, fmt.Errorf("%w: %v", errUnauthorized, authErr)
		}
		rawNotReady, buildErr := buildUnavailable(arbitration.RetrievalSellerArbitrationNotReady)
		if buildErr != nil {
			return nil, buildErr
		}
		debug("[arbiter] buyer authenticated against the stored Kind 8; nonce occupied atomically")
		return occupyAndAnswer(rawNotReady)
	}
	storedResponse, err := arbitration.UnmarshalResponse(store.record.responseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: stored Kind 9 failed strict decode; isolate and alarm: %v", errCustodyCorrupt, err)
	}
	verified, evidenceErr := arbitration.VerifyCustodiedContent(storedRequest, storedResponse)
	if evidenceErr != nil {
		return nil, fmt.Errorf("%w: stored evidence failed verification; isolate and alarm: %v", errCustodyCorrupt, evidenceErr)
	}
	if _, verifyErr := arbiter.VerifyContentRetrievalRequest(retrievalRequest, storedRequest, storedResponse); verifyErr != nil {
		return nil, fmt.Errorf("%w: %v", errUnauthorized, verifyErr)
	}
	debug("[arbiter] buyer signature verified over %d payloads; nonce occupied atomically", len(verified.Payloads))
	// 唯一真值：payload 来自 VerifyCustodiedContent 验证过的证据字节。
	result, err := arbitration.BuildContentRetrievalAvailableRaw(requestID, verified.PayloadsCBOR, arbiterPrivateKey)
	if err != nil {
		return nil, err
	}
	rawAvailable, err := arbitration.MarshalContentRetrievalResponse(result)
	if err != nil {
		return nil, err
	}
	return occupyAndAnswer(rawAvailable)
}

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

func main() {
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	f, err := fixture.New(ctx)
	if err != nil {
		fail(err)
	}
	debug("=== Steps 001-007: seller submits custody while buyer is offline ===")
	request003, delivery004, _, _, err := f.DeliverAndBuildPayment(ctx, time.Now().UTC())
	if err != nil {
		fail(err)
	}
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, f.Opening, request003, delivery004, blockHeight)
	if err != nil {
		fail(fmt.Errorf("seller.BuildArbitrationRequest: %w", err))
	}
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		fail(err)
	}
	store := newCustodyStore()
	if err := store.handleArbitrationRequest(rawKind8, f.Arbiter); err != nil {
		fail(fmt.Errorf("arbiter custody: %w", err))
	}
	claimID, err := arbitration.ArbitrationClaimID(arbitrationRequest.ArbitrationClaimCBOR)
	if err != nil {
		fail(err)
	}

	debug("=== Step 008: buyer retrieves custodied content without the seller ===")
	// Buyer 只需要 OpeningProof + 精确签名 003 就能独立得到同一 Claim ID；
	// 不需要 Seller Claim 签名、payload 或 Kind 9。
	independentBuilt, err := arbitration.BuildClaimFromAuthorization(f.Opening, request003)
	if err != nil {
		fail(err)
	}
	if independentBuilt.ArbitrationClaimID != claimID {
		fail(fmt.Errorf("buyer-derived Claim ID differs from the custody record"))
	}
	debug("[buyer] independently rebuilt Claim ID %s from opening + signed 003", hex.EncodeToString(claimID[:]))
	// 应用用密码学安全随机源生成 32 字节 nonce，再显式传入 SDK。
	nonce := make([]byte, arbitration.RetrievalNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		fail(err)
	}
	retrievalRequest, err := f.Buyer.BuildArbitrationContentRequest(ctx, f.Opening, request003, nonce)
	if err != nil {
		fail(fmt.Errorf("buyer.BuildArbitrationContentRequest: %w", err))
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrievalRequest)
	if err != nil {
		fail(err)
	}
	debug("[buyer] persisted exact Kind 10 before sending (%d bytes); nonce %s", len(rawKind10), hex.EncodeToString(nonce))

	rawKind11, err := store.handleContentRetrieval(rawKind10, f.Arbiter, f.ArbiterKey)
	if err != nil {
		fail(err)
	}
	retrievalResponse, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		fail(err)
	}
	decodedResult, err := arbitration.DecodeContentRetrievalResultDocument(retrievalResponse.ContentRetrievalResultCBOR)
	if err != nil {
		fail(err)
	}
	if decodedResult.Result != arbitration.ContentRetrievalAvailable {
		fail(fmt.Errorf("arbiter answered unavailable reason %d for a complete custody record", decodedResult.UnavailableReason))
	}
	debug("[arbiter] returned signed Kind 11 (%d bytes); content_payloads_id binds the exact attachment (%d bytes)",
		len(rawKind11), len(retrievalResponse.ContentPayloadsCBOR))

	result, err := f.Buyer.AcceptArbitratedContent(ctx, f.Quote, f.Opening, f.LatestPayment, request003, retrievalRequest, retrievalResponse, buyer.ArbitratedContentInput{})
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptArbitratedContent: %w", err))
	}
	// 验收只返回 deep-copy payload 与审计数据；不构造、不签名、不发送 005。
	debug("[buyer] accepted %d payload(s) bound to request ID %s", len(result.Payloads), hex.EncodeToString(result.ContentRetrievalRequestID[:])[:16])
	fmt.Printf("ARBITRATION_CLAIM_ID_HEX=%s\n", hex.EncodeToString(claimID[:]))
	fmt.Printf("RETRIEVAL_NONCE_HEX=%s\n", hex.EncodeToString(nonce))
	fmt.Printf("KIND10_BYTES=%d\n", len(rawKind10))
	fmt.Printf("KIND11_BYTES=%d\n", len(rawKind11))
	fmt.Printf("PAYLOAD_COUNT=%d\n", len(result.Payloads))
	fmt.Printf("VERIFIED=true\n")
	debug("=== Retrieval complete: no 005, no pool close, no broadcast ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
