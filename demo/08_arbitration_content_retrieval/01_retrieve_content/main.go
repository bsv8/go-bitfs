// 008 买方仲裁托管内容取回演示：Seller 与 Buyer 无法直连，但二者均能连接
// Arbiter。完整顺序为 001–007（Seller 托管、Arbiter 签署 Kind 9）之后，
// Buyer 用自己可独立计算的 Claim ID 构造 Kind 10，Arbiter 验签并原子占用
// nonce 后返回内嵌 exact Kind 8/9 的 Kind 11，Buyer 完整验收并保存 payload。
//
// 本 demo 不产生 005、不关池、不广播任何交易；Claim ID 不是下载密码，
// nonce 不代替 TLS，Kind 11 不声称 Seller 交易已上链结算。
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
)

// blockHeight 是调用方认可并提供的当前区块高度；SDK 不查询节点。
const blockHeight uint32 = 900000

// retrievalError 是应用层错误通道：Kind 11 只表达成功取回，其余全部走这里。
var (
	errNotFound       = fmt.Errorf("NotFound: custody record not found")
	errNotReady       = fmt.Errorf("NotReady: Kind 9 not persisted yet")
	errUnauthorized   = fmt.Errorf("Unauthorized")
	errNonceReused    = fmt.Errorf("NonceReused: (claim id, nonce) already used")
	errCustodyCorrupt = fmt.Errorf("CustodyCorrupt: stored custody bytes failed verification; isolate and alarm")
)

// custodyStore 是应用侧托管库 + nonce 占用表。真实实现应使用数据库唯一键
// (hex(ClaimID), hex(Nonce)) 与事务保证原子性；demo 用互斥锁模拟唯一键的
// 并发语义。先验签，再占用 nonce——验签失败的请求绝不污染 nonce 表。
type custodyStore struct {
	mu     sync.Mutex
	record *arbitrationCustodyRecord
	nonces map[string]bool
}

type arbitrationCustodyRecord struct {
	requestBytes  []byte // exact received raw Kind 8, deep-copied on save
	responseBytes []byte // exact canonical saved Kind 9, embedded verbatim in Kind 11
}

func newCustodyStore() *custodyStore { return &custodyStore{nonces: make(map[string]bool)} }

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
	claimID := hex.EncodeToString(prepared.ClaimID())
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

// handleContentRetrieval 固定顺序：strict decode -> lookup -> 要求 Retrievable
// -> SDK 完整验证存储证据与 Buyer 签名 -> nonce CAS -> 内嵌 exact bytes 返回。
func (store *custodyStore) handleContentRetrieval(rawKind10 []byte, arbiter *arbitration.Workflow) ([]byte, error) {
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	// 错误分类固定顺序：
	//   没有 Kind 8             -> NotFound
	//   有 Kind 8、没有 Kind 9  -> NotReady（Buyer 可稍后用新 nonce 重试）
	//   Kind 8/9 无法解码       -> CustodyCorrupt + 隔离告警
	//   完整证据验证失败         -> CustodyCorrupt + 隔离告警（持久化冲突/攻击）
	//   Buyer 验签失败          -> Unauthorized（统一语义，不泄露细节）
	if store.record == nil || len(store.record.requestBytes) == 0 {
		return nil, errNotFound
	}
	storedRequest, err := arbitration.UnmarshalRequest(store.record.requestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: stored Kind 8 failed strict decode; isolate and alarm: %v", errCustodyCorrupt, err)
	}
	if len(store.record.responseBytes) == 0 {
		return nil, errNotReady
	}
	storedResponse, err := arbitration.UnmarshalResponse(store.record.responseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: stored Kind 9 failed strict decode; isolate and alarm: %v", errCustodyCorrupt, err)
	}
	if _, err := arbitration.VerifyCustodiedContent(storedRequest, storedResponse); err != nil {
		return nil, fmt.Errorf("%w: stored evidence failed verification; isolate and alarm: %v", errCustodyCorrupt, err)
	}
	// 先验签（SDK 完整验证托管证据链 + Buyer 对 [4,10,claim_id,nonce] 的签名），
	// 后原子占用 nonce。
	verified, verifyErr := arbiter.VerifyContentRetrievalRequest(retrievalRequest, storedRequest, storedResponse)
	if verifyErr != nil {
		// 统一 Unauthorized：不泄露 Claim 是否存在或哪个字段失败。
		return nil, fmt.Errorf("%w: %v", errUnauthorized, verifyErr)
	}
	nonceKey := hex.EncodeToString(retrievalRequest.ClaimID) + ":" + hex.EncodeToString(retrievalRequest.Nonce)
	if store.nonces[nonceKey] {
		return nil, errNonceReused
	}
	store.nonces[nonceKey] = true
	debug("[arbiter] buyer signature verified over %d payloads; nonce occupied atomically", len(verified.Payloads))
	response, err := arbitration.BuildContentRetrievalResponse(store.record.requestBytes, store.record.responseBytes)
	if err != nil {
		return nil, err
	}
	return arbitration.MarshalContentRetrievalResponse(response)
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
	claimID, err := arbitration.ArbitrationClaimID(arbitrationRequest.ClaimCBOR)
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
	if !bytes.Equal(independentBuilt.ClaimID, claimID) {
		fail(fmt.Errorf("buyer-derived Claim ID differs from the custody record"))
	}
	debug("[buyer] independently rebuilt Claim ID %s from opening + signed 003", hex.EncodeToString(claimID))
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

	rawKind11, err := store.handleContentRetrieval(rawKind10, f.Arbiter)
	if err != nil {
		fail(err)
	}
	retrievalResponse, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		fail(err)
	}
	debug("[arbiter] returned exact Kind 11 (%d bytes) embedding exact Kind 8 (%d bytes) and Kind 9 (%d bytes)",
		len(rawKind11), len(retrievalResponse.ArbitrationRequestCBOR), len(retrievalResponse.ArbitrationResponseCBOR))

	result, err := f.Buyer.AcceptArbitratedContent(ctx, f.Quote, f.Opening, f.LatestPayment, request003, retrievalRequest, retrievalResponse, buyer.ArbitratedContentInput{})
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptArbitratedContent: %w", err))
	}
	// 验收只返回 deep-copy payload 与审计数据；不构造、不签名、不发送 005。
	debug("[buyer] accepted %d payload(s); receipt fee %d satoshis", len(result.Payloads), result.Receipt.ArbiterAmountSat)
	fmt.Printf("ARBITRATION_CLAIM_ID_HEX=%s\n", hex.EncodeToString(claimID))
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
