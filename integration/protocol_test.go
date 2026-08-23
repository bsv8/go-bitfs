// Package integration exercises the complete BitFS v4 protocol lifecycle
// 001–008 with the test acting as the calling application. Every quote,
// opening state, proof, payment state, and delivery context is held in local
// variables and passed explicitly into each SDK call. The 007 arbitration
// path additionally runs an application-level custody store and request
// handler (memoryArbitrationCustodyStore) that models production persistence,
// crash recovery after save but before signing, and Claim-ID-indexed
// idempotent replay — the SDK itself still holds no stores; there are no node
// adapters or broadcast/reconciliation assertions.
package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/rand"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

type integrationSigner struct{ key *ec.PrivateKey }

// arbitrationCustodyRecord is one application custody record, indexed by
// Claim ID. It persists the exact received Kind 8 raw bytes (not a decoded
// struct), the payload bundle, the derived Claim ID, and the frozen fee; after
// signing the exact canonical Kind 9 bytes are appended to the same record.
type arbitrationCustodyRecord struct {
	requestBytes     []byte // exact received raw Kind 8 CBOR, deep-copied on save
	payloadsCBOR     []byte
	claimID          []byte
	arbiterAmountSat uint64
	responseBytes    []byte // exact canonical saved Kind 9, resent verbatim on retry
}

// memoryArbitrationCustodyStore is the application's 007/008 store plus the
// application-level request handlers implementing the mandated idempotency
// order: strict-decode first, derive the Claim ID, look up the record by that
// ID, compare the saved exact request bytes, then either replay the saved
// response verbatim, recover an unsigned record from saved bytes + saved fee,
// or create a new record. A same-ID/different-bytes input is first fully
// re-validated with the frozen fee; validation failure rejects it as invalid
// evidence, while a fully valid variant is a duplicate-evidence conflict alarm
// that never overwrites the stored evidence. Concurrency on one Claim ID and
// on (ClaimID, Nonce) occupancy is serialized by mutexes standing in for the
// production database unique keys.
type memoryArbitrationCustodyStore struct {
	fail       bool
	records    map[string]*arbitrationCustodyRecord // key: hex(Claim ID)
	conflicts  int
	priceCalls int
	signCalls  int

	// nonceRecords 是应用侧 (ClaimID, Nonce) 原子占用表：先验签成功后才占用，
	// 唯一键由数据库保证；这里用互斥锁模拟唯一键的并发语义。旧 nonce 记录
	// 至少保留到对应 custody record 删除（本测试中永久保留）。
	mu           sync.Mutex
	nonceRecords map[string]bool // key: hex(ClaimID) + ":" + hex(Nonce)
	goneClaims   map[string]bool // retention 结束并已安全删除的 Claim ID
}

func newMemoryArbitrationCustodyStore() *memoryArbitrationCustodyStore {
	return &memoryArbitrationCustodyStore{records: make(map[string]*arbitrationCustodyRecord), nonceRecords: make(map[string]bool), goneClaims: make(map[string]bool)}
}

// priceArbitrationFee is this application's fee policy entry point; production
// services would consult their own price book here.
func (store *memoryArbitrationCustodyStore) priceArbitrationFee(decoded *arbitration.ArbitrationRequest) (uint64, error) {
	store.priceCalls++
	return arbitrationFeeSat, nil
}

// handleArbitrationRequest implements the mandated application flow:
//
//	strict decode Kind 8 -> derive Claim ID -> index by Claim ID
//	  -> saved record with different exact bytes: conflict, alarm, no overwrite
//	  -> saved record with response: return its copy (no pricing, no signing)
//	  -> saved record without response: recover via PreparePayment(saved
//	     requestBytes, blockHeight, savedFee) — the fee policy is not re-run
//	  -> unknown Claim ID: price once, PreparePayment, atomic custody persistence,
//	     SignPreparedPayment, append the exact canonical response to the record
func (store *memoryArbitrationCustodyStore) handleArbitrationRequest(rawKind8 []byte, arbiter *arbitration.Workflow, blockHeight uint32) ([]byte, error) {
	decoded, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		return nil, err
	}
	claimID, err := arbitration.ArbitrationClaimID(decoded.ClaimCBOR)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(claimID)

	// 阶段一：锁内一次性取得记录状态深拷贝；密码学验证在锁外执行。
	store.mu.Lock()
	saved := store.snapshotLocked(key)
	store.mu.Unlock()

	if saved != nil && !bytes.Equal(saved.requestBytes, rawKind8) {
		// 相同 Claim ID、不同外层字节：施工单要求先对完整证据链重新验证
		// （Seller Claim 签名、Buyer terms 签名、payload 数量/顺序/hash、
		// deadline/refund、Arbiter 身份与按已冻结费用重建交易），再判定是
		// 否构成重复证据冲突。PreparePayment 不产生签名，也不重新调用费用
		// 策略——直接复用记录中冻结的费用。
		if _, err := arbiter.PreparePayment(context.Background(), decoded, blockHeight, saved.arbiterAmountSat); err != nil {
			// 完整验证失败 = 无效请求（攻击者拼接的假 bundle、篡改的签名、
			// 过期证据等），按 invalid evidence 拒绝；这绝不是 collision。
			return nil, err
		}
		store.mu.Lock()
		store.conflicts++
		store.mu.Unlock()
		return nil, fmt.Errorf("arbitration claim id %s arrived with different but fully valid request bytes; recording duplicate-evidence conflict and stopping automation", key[:16])
	}
	if saved != nil && saved.responseBytes != nil {
		// 已有响应：原样重发保存的 canonical bytes，不重新计价、不重新签名。
		return append([]byte(nil), saved.responseBytes...), nil
	}

	var prepared *arbitration.PreparedPayment
	if saved != nil {
		// 只有托管、尚未签名：从保存的 exact bytes 与保存的费用恢复，
		// 绝不重新调用费用策略。
		savedDecoded, err := arbitration.UnmarshalRequest(saved.requestBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, err)
		}
		prepared, err = arbiter.PreparePayment(context.Background(), savedDecoded, blockHeight, saved.arbiterAmountSat)
		if err != nil {
			return nil, err
		}
	} else {
		fee, err := store.priceArbitrationFee(decoded)
		if err != nil {
			return nil, err
		}
		prepared, err = arbiter.PreparePayment(context.Background(), decoded, blockHeight, fee)
		if err != nil {
			return nil, err
		}
		if store.fail {
			return nil, errors.New("custody store unavailable")
		}
	}

	// 阶段二：重新加锁提交。若并发请求已为同一 Claim 建立记录（数据库唯一
	// 键语义下只有一个胜者），放弃自己的 prepared，复用已存在记录。
	store.mu.Lock()
	defer store.mu.Unlock()
	current := store.snapshotLocked(key)
	if current == nil {
		if saved != nil {
			// 记录在间隙中被 retention 删除：不复活已删除内容。
			return nil, errRetentionGone
		}
		store.records[key] = &arbitrationCustodyRecord{
			requestBytes:     append([]byte(nil), rawKind8...),
			payloadsCBOR:     prepared.ContentPayloadsCBOR(),
			claimID:          append([]byte(nil), prepared.ClaimID()...),
			arbiterAmountSat: prepared.ArbiterAmountSat(),
		}
		current = store.snapshotLocked(key)
	} else if !bytes.Equal(current.requestBytes, rawKind8) {
		return nil, fmt.Errorf("concurrent custody request for claim id %s arrived with different bytes", key[:16])
	}
	if current.responseBytes != nil {
		return append([]byte(nil), current.responseBytes...), nil
	}

	store.signCalls++
	response, err := arbiter.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		return nil, err
	}
	raw, err := arbitration.MarshalResponse(response)
	if err != nil {
		return nil, err
	}
	store.records[key].responseBytes = append([]byte(nil), raw...)
	return append([]byte(nil), raw...), nil
}

// 应用级错误通道：Kind 11 只表达成功取回，NotFound/NotReady/Unauthorized/
// NonceReused/Gone 全部走这些哨兵错误，绝不编码为结构合法的 Kind 11。
var (
	errRetrievalNotFound     = errors.New("custody record not found")
	errRetrievalNotReady     = errors.New("custody record is not retrievable yet")
	errRetrievalUnauthorized = errors.New("buyer retrieval unauthorized")
	errNonceReused           = errors.New("(claim id, nonce) already used")
	errRetentionGone         = errors.New("custody content deleted after retention")
	errCustodyCorrupt        = errors.New("stored custody bytes failed strict decode")
)

// snapshotLocked 返回 key 对应记录的深拷贝快照；必须在持有 store.mu 时调用。
func (store *memoryArbitrationCustodyStore) snapshotLocked(key string) *arbitrationCustodyRecord {
	record, exists := store.records[key]
	if !exists || record == nil {
		return nil
	}
	snapshot := &arbitrationCustodyRecord{
		requestBytes:     append([]byte(nil), record.requestBytes...),
		payloadsCBOR:     append([]byte(nil), record.payloadsCBOR...),
		claimID:          append([]byte(nil), record.claimID...),
		arbiterAmountSat: record.arbiterAmountSat,
	}
	if record.responseBytes != nil {
		snapshot.responseBytes = append([]byte(nil), record.responseBytes...)
	}
	return snapshot
}

// putRecord 原子写入一条托管记录（供测试模拟 PreparePayment 后的持久化点）。
func (store *memoryArbitrationCustodyStore) putRecord(record *arbitrationCustodyRecord) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[hex.EncodeToString(record.claimID)] = record
}

// recordOf 返回 key 对应记录的深拷贝快照（测试用只读访问）。
func (store *memoryArbitrationCustodyStore) recordOf(key string) *arbitrationCustodyRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.snapshotLocked(key)
}

// appendResponse 在锁内把 exact canonical Kind 9 追加到已有记录；这是
// CustodyPrepared -> Retrievable 的唯一状态迁移入口。
func (store *memoryArbitrationCustodyStore) appendResponse(key string, raw []byte) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if record := store.records[key]; record != nil && record.responseBytes == nil {
		record.responseBytes = append([]byte(nil), raw...)
	}
}

// retrievable 判定：只有 exact Kind 8 与 exact Kind 9 同时已持久化的记录才
// 进入 Retrievable 状态；PreparePayment 成功但 Kind 9 未产生的记录只是
// CustodyPrepared，不得向 Buyer 返回 payload。
func (store *memoryArbitrationCustodyStore) retrievable(key string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.retrievableLocked(key)
}

func (store *memoryArbitrationCustodyStore) retrievableLocked(key string) bool {
	record, exists := store.records[key]
	return exists && record != nil && record.responseBytes != nil
}

// occupyNonce 模拟数据库唯一键/CAS：同一 (ClaimID, Nonce) 只允许一个胜者。
// 调用方必须已经通过 SDK 验签；未通过签名的请求不会到达这里。
func (store *memoryArbitrationCustodyStore) occupyNonce(claimID, nonce []byte) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := hex.EncodeToString(claimID) + ":" + hex.EncodeToString(nonce)
	if store.nonceRecords[key] {
		return false
	}
	store.nonceRecords[key] = true
	return true
}

// expireRetention 模拟留存期结束并安全删除内容，但保留 nonce 去重记录。
func (store *memoryArbitrationCustodyStore) expireRetention(claimID []byte) {
	key := hex.EncodeToString(claimID)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.goneClaims[key] = true
	delete(store.records, key)
}

// handleContentRetrieval 实现施工单固定的应用级顺序：
//
//	strict decode Kind 10 -> 按 Claim ID 查 custody record
//	  -> 锁内一次性深拷贝 exact Kind 8/9 快照
//	  -> 锁外执行存储损坏检查与 SDK 完整验证（先验签）
//	  -> CAS 前重新加锁确认记录版本未变，再原子占用 nonce
//	  -> 构造 Kind 11，内嵌已验证的 exact Kind 8/9 副本
func (store *memoryArbitrationCustodyStore) handleContentRetrieval(rawKind10 []byte, arbiter *arbitration.Workflow) ([]byte, error) {
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(retrievalRequest.ClaimID)

	// 阶段一：锁内取得快照。
	store.mu.Lock()
	gone := store.goneClaims[key]
	record := store.snapshotLocked(key)
	store.mu.Unlock()
	if gone && record == nil {
		return nil, errRetentionGone
	}
	if record == nil {
		return nil, errRetrievalNotFound
	}
	requestBytes, responseBytes := record.requestBytes, record.responseBytes

	// 锁外：失败关闭的损坏检查。有 Kind 8、没有 Kind 9 是合法 NotReady，
	// 不是损坏；无法 strict decode 才是损坏。
	storedRequest, err := arbitration.UnmarshalRequest(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, err)
	}
	if responseBytes == nil {
		return nil, errRetrievalNotReady
	}
	storedResponse, err := arbitration.UnmarshalResponse(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, err)
	}
	// 先验签：SDK 完整验证托管证据链 + Buyer 对 [4,10,claim_id,nonce] 的签名。
	// 存储证据本身验证失败属于持久化冲突/攻击：按损坏隔离告警。
	if _, err := arbitration.VerifyCustodiedContent(storedRequest, storedResponse); err != nil {
		return nil, fmt.Errorf("%w: stored evidence failed verification; isolate and alarm: %v", errCustodyCorrupt, err)
	}
	if _, err := arbiter.VerifyContentRetrievalRequest(retrievalRequest, storedRequest, storedResponse); err != nil {
		// 统一 Unauthorized 语义：不泄露 Claim 是否存在或哪个字段失败。
		return nil, fmt.Errorf("%w: %v", errRetrievalUnauthorized, err)
	}

	// 阶段二：CAS 前重新加锁，确认记录版本/状态没有变化，再原子占用 nonce；
	// CAS 成功即释放锁——真实实现应在事务提交后结束数据库占用，
	// 再用已验证的快照构造响应，绝不在持锁状态下做 CBOR 构造。
	store.mu.Lock()
	fresh := store.snapshotLocked(key)
	if fresh == nil || !bytes.Equal(fresh.requestBytes, requestBytes) {
		store.mu.Unlock()
		return nil, errRetentionGone
	}
	if fresh.responseBytes == nil || !bytes.Equal(fresh.responseBytes, responseBytes) {
		store.mu.Unlock()
		return nil, errRetrievalNotReady
	}
	nonceKey := key + ":" + hex.EncodeToString(retrievalRequest.Nonce)
	if store.nonceRecords[nonceKey] {
		store.mu.Unlock()
		return nil, errNonceReused
	}
	store.nonceRecords[nonceKey] = true
	store.mu.Unlock()

	// 锁外：用已验证的快照构造 Kind 11。
	response, err := arbitration.BuildContentRetrievalResponse(requestBytes, responseBytes)
	if err != nil {
		return nil, err
	}
	return arbitration.MarshalContentRetrievalResponse(response)
}

func (s integrationSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}

func (s integrationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	sig, err := s.key.Sign(payload)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func integrationKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// protocolFixture is the application-side state holder for one pool across
// the full 001–008 lifecycle. Every field would live in an application
// database in production; here it lives in test variables.
type protocolFixture struct {
	ctx        context.Context
	buyerKey   *ec.PrivateKey
	sellerKey  *ec.PrivateKey
	arbiterKey *ec.PrivateKey
	buyer      *buyer.Workflow
	seller     *seller.Workflow
	arbiter    *arbitration.Workflow
	quote      *bitfs.SignedFileQuote
	seed       []byte
	source     []byte

	// Pool A (main lifecycle).
	fundingTx    []byte
	openingState *buyer.BuyerOpeningState
	presignProof *pool.OpeningProof
	acceptance   *buyer.RefundPresignAcceptance
	completed    *seller.PoolFundingAcceptance
	now          time.Time
	expiry       uint32
}

func newProtocolFixture(t *testing.T) *protocolFixture {
	return newProtocolFixtureWithExpiry(t, uint32(time.Now().UTC().Add(time.Hour).Unix()))
}

func newProtocolFixtureWithExpiry(t *testing.T, expiry uint32) *protocolFixture {
	f := &protocolFixture{
		ctx:        context.Background(),
		buyerKey:   integrationKey(t, "11"),
		sellerKey:  integrationKey(t, "22"),
		arbiterKey: integrationKey(t, "33"),
		now:        time.Now().UTC(),
		expiry:     expiry,
	}
	var err error
	f.buyer, err = buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: f.buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.seller, err = seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: f.sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.arbiter, err = arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: f.arbiterKey})
	if err != nil {
		t.Fatal(err)
	}
	f.seedContent(t)

	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	// 001: seller creates the quote, buyer verifies and accepts it; both sides
	// keep their own copy as application state.
	quote, err := f.seller.CreateQuote(f.ctx, bitfs.FileQuoteTerms{SeedHash: masterseed.Sum256(f.seed).Bytes(), BuyerPubkey: f.buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: uint64(len(f.source)), QuoteExpiresAtUnix: f.now.Add(time.Hour).Unix(), SupportedArbiterPubkeysCBOR: arbiters}, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.quote = quote
	if _, err := f.buyer.AcceptQuote(f.ctx, quote); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *protocolFixture) seedContent(t *testing.T) {
	t.Helper()
	f.source = bytes.Repeat([]byte{7}, 4096)
	var buffer bytes.Buffer
	if _, err := masterseed.CreateSeed(f.ctx, bytes.NewReader(f.source), &buffer); err != nil {
		t.Fatal(err)
	}
	f.seed = buffer.Bytes()
}

func (f *protocolFixture) buildFunding(t *testing.T, satoshis uint64) []byte {
	t.Helper()
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPubKey: f.buyerKey.PubKey().Compressed(), SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	zero, err := chainhash.NewHash(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: satoshis, LockingScript: script.NewFromBytes(lock)})
	return funding.Bytes()
}

// preparePool runs 0201+0202+0203+0204+0205 for a fresh funding transaction
// and returns every intermediate value explicitly.
func (f *protocolFixture) openPool(t *testing.T, fundingTx []byte) (*buyer.RefundPresignAcceptance, *seller.PoolFundingAcceptance, *pool.OpeningProof) {
	t.Helper()
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTx: fundingTx, ExpiryLockTime: f.expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.seller.PresignPoolOpening(f.ctx, preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := f.buyer.AcceptRefundPresign(f.ctx, preparation.State, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.buyer.BuildFundingTxDelivery(f.ctx, acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.seller.AcceptPoolFunding(f.ctx, result.Opening, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return acceptance, completed, result.Opening
}

// openMainPool opens the fixture's primary pool and stores its state on the
// fixture, mirroring how an application would persist these values.
func (f *protocolFixture) openMainPool(t *testing.T) {
	t.Helper()
	f.fundingTx = f.buildFunding(t, 100000)
	acceptance, completed, presignProof := f.openPool(t, f.fundingTx)
	f.acceptance = acceptance
	f.completed = completed
	f.presignProof = presignProof
}

func (f *protocolFixture) facts() uint32 { return 900000 }

// arbitrationFeeSat 是集成测试中应用层固定、可审计的正仲裁费：调用方先计价，
// 再把明确金额交给 SDK；SDK 不注入任何费率策略。
const arbitrationFeeSat uint64 = 777

func TestFullLifecycleWithExplicitStatePassing(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.completed.Opening.BuyerPubKey, SellerPubKey: f.completed.Opening.SellerPubKey, ArbiterPubKey: f.completed.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(f.completed.InitialPayment, f.completed.Opening); err != nil {
		t.Fatalf("initial payment invalid: %v", err)
	}

	// 003: buyer builds the content request from explicit state.
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	// 004: seller delivers from caller-provided content bytes.
	delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	// Buyer accepts delivery; verified payload is data the app must save.
	verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], f.seed) {
		t.Fatal("verified payload mismatch")
	}
	// 005: the application routes the minimal credential by its authorization
	// hash back to the exact original signed 003, then the seller merges
	// signatures over the locally rebuilt transaction.
	signedPayment, err := f.seller.AcceptPayment(f.ctx, f.completed.Opening, f.completed.InitialPayment, request, deliveryState, verified.Update, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	latest := &signedPayment.State
	if err := engine.VerifyAcceptedPayment(latest, f.completed.Opening); err != nil {
		t.Fatalf("accepted payment invalid: %v", err)
	}
	if latest.SellerAmountSat != 100 {
		t.Fatalf("seller amount = %d, want seed price 100", latest.SellerAmountSat)
	}

	// 006: immediate close from explicit latest state.
	unsigned, buyerSig, err := f.buyer.BuildImmediateClose(f.ctx, f.completed.Opening, latest, latest.SellerAmountSat, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.seller.SignImmediateClose(f.ctx, f.completed.Opening, unsigned, buyerSig, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	final, err := f.buyer.CompleteImmediateClose(f.ctx, f.completed.Opening, closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyFinalPayment(&final.State, f.completed.Opening); err != nil {
		t.Fatalf("final payment invalid: %v", err)
	}
}

func TestArbitrationLifecycleWithExplicitStatePassing(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.arbiter.PreparePayment(f.ctx, arbitrationRequest, f.facts(), arbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.arbiter.SignPreparedPayment(f.ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.seller.CompleteArbitratedPayment(f.ctx, arbitrationRequest, response, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.completed.Opening.BuyerPubKey, SellerPubKey: f.completed.Opening.SellerPubKey, ArbiterPubKey: f.completed.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&signed.State, f.completed.Opening); err != nil {
		t.Fatalf("arbitrated payment invalid: %v", err)
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawState, err := tx.NewTransactionFromBytes(signed.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbiterAmountSat != arbitrationFeeSat || signed.State.ArbiterAmountSat != arbitrationFeeSat || rawState.Outputs[2].Satoshis != arbitrationFeeSat {
		t.Fatalf("paid fee mismatch: receipt %d state %d raw %d want %d", receipt.ArbiterAmountSat, signed.State.ArbiterAmountSat, rawState.Outputs[2].Satoshis, arbitrationFeeSat)
	}
}

func TestArbitrationCustodyPersistenceGatesSigning(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := arbitration.ArbitrationClaimID(arbitrationRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	recordKey := hex.EncodeToString(claimID)

	// 托管保存失败：处理器必须在任何签名之前失败，且不产生响应。
	failingStore := newMemoryArbitrationCustodyStore()
	failingStore.fail = true
	if responseBytes, err := failingStore.handleArbitrationRequest(rawKind8, f.arbiter, f.facts()); err == nil || responseBytes != nil || failingStore.signCalls != 0 || len(failingStore.records) != 0 {
		t.Fatal("signing proceeded after custody persistence failure")
	}

	// 正常路径：首次处理恰好计价一次、签名一次，并原子持久化。
	workingStore := newMemoryArbitrationCustodyStore()
	// 深拷贝证明：传入独立的调用方缓冲区并在保存后原地篡改它，仓储中的
	// 字节必须保持与原始 Kind 8 一致。
	inputBuffer := append([]byte(nil), rawKind8...)
	firstResponse, err := workingStore.handleArbitrationRequest(inputBuffer, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	record := workingStore.recordOf(recordKey)
	if record == nil {
		t.Fatal("first handling did not create a custody record under the Claim ID")
	}
	if workingStore.priceCalls != 1 || workingStore.signCalls != 1 {
		t.Fatalf("first handling counters = price %d sign %d, want exactly one each", workingStore.priceCalls, workingStore.signCalls)
	}
	for index := range inputBuffer {
		inputBuffer[index] ^= 0xff
	}
	if !bytes.Equal(record.requestBytes, rawKind8) {
		t.Fatal("custody store did not retain the exact received Kind 8 bytes, or save shares memory with the caller's buffer")
	}

	// 持久化的是原始 Kind 8 字节：服务重启后可严格解码；派生 Claim ID 与
	// 冻结费用必须与保存值一致，解码出的 Claim 与原始请求逐字节相同。
	recovered, err := arbitration.UnmarshalRequest(record.requestBytes)
	if err != nil {
		t.Fatalf("saved raw Kind 8 failed strict re-decode: %v", err)
	}
	if !bytes.Equal(recovered.ClaimCBOR, arbitrationRequest.ClaimCBOR) || !bytes.Equal(recovered.ContentPayloadsCBOR, arbitrationRequest.ContentPayloadsCBOR) {
		t.Fatal("recovered request does not round-trip to the original evidence")
	}
	localClaimID, err := arbitration.ArbitrationClaimID(recovered.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(localClaimID, record.claimID) {
		t.Fatal("custody record retained a Claim ID inconsistent with the saved raw request")
	}
	if record.arbiterAmountSat != arbitrationFeeSat {
		t.Fatalf("custody fee = %d, want the frozen %d", record.arbiterAmountSat, arbitrationFeeSat)
	}
	if len(record.payloadsCBOR) == 0 || !bytes.Equal(record.payloadsCBOR, arbitrationRequest.ContentPayloadsCBOR) {
		t.Fatal("custody record did not retain the exact payload bundle")
	}

	// 同一 Claim 重试：直接重发已保存 canonical bytes；计价器与签名器计数
	// 不再增加；重发字节与首次响应逐字节一致；返回的是副本而非内部引用。
	resentResponse, err := workingStore.handleArbitrationRequest(rawKind8, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	if workingStore.priceCalls != 1 || workingStore.signCalls != 1 {
		t.Fatalf("retry re-priced or re-signed: counters = price %d sign %d", workingStore.priceCalls, workingStore.signCalls)
	}
	if !bytes.Equal(firstResponse, resentResponse) {
		t.Fatal("resent response differs from the first signed response")
	}
	resentResponse[0] ^= 1
	if !bytes.Equal(record.responseBytes, firstResponse) {
		t.Fatal("retry returned an internal reference instead of a copy of the saved bytes")
	}
}

// TestArbitrationCustodyIdempotencyConflicts pins the Claim-ID-indexed replay
// rules: hostile bytes are rejected before any lookup, a different valid Claim
// gets its own record and never the old response, a same-ID/different-bytes
// input is a conflict alarm that overwrites nothing, and an exact retry keeps
// every counter flat.
func TestArbitrationCustodyIdempotencyConflicts(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	buildDelivery := func(deadline time.Time) (*bitfs.SignedContentRequest, *bitfs.SignedContentDelivery) {
		input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(deadline.Unix())}
		request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
		if err != nil {
			t.Fatal(err)
		}
		delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
		if err != nil {
			t.Fatal(err)
		}
		return request, delivery
	}
	requestA, deliveryA := buildDelivery(f.now.Add(30 * time.Minute))
	arbitrationA, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, requestA, deliveryA, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	rawA, err := arbitration.MarshalRequest(arbitrationA)
	if err != nil {
		t.Fatal(err)
	}

	store := newMemoryArbitrationCustodyStore()
	responseA, err := store.handleArbitrationRequest(rawA, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}

	// 1. 已有响应后传入非法 CBOR：必须在任何查询或重放之前拒绝。
	if resent, err := store.handleArbitrationRequest([]byte{0x85, 0x04}, f.arbiter, f.facts()); err == nil || resent != nil {
		t.Fatal("malformed Kind 8 was served the saved response")
	}

	// 2. 不同有效 Claim（不同截止时间 → 不同 Claim ID）：必须建立新记录并
	//    得到自己的响应，绝不能拿到 A 的旧响应；A 的记录不受影响。
	requestB, deliveryB := buildDelivery(f.now.Add(20 * time.Minute))
	arbitrationB, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, requestB, deliveryB, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := arbitration.MarshalRequest(arbitrationB)
	if err != nil {
		t.Fatal(err)
	}
	claimIDA, err := arbitration.ArbitrationClaimID(arbitrationA.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimIDB, err := arbitration.ArbitrationClaimID(arbitrationB.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(claimIDA, claimIDB) {
		t.Fatal("test premise broken: the two Claims share one Claim ID")
	}
	responseB, err := store.handleArbitrationRequest(rawB, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(responseA, responseB) {
		t.Fatal("a different valid Claim received the first Claim's saved response")
	}
	recordB := store.recordOf(hex.EncodeToString(claimIDB))
	if recordB == nil || !bytes.Equal(recordB.requestBytes, rawB) {
		t.Fatal("the second Claim did not get its own custody record")
	}
	if store.conflicts != 0 {
		t.Fatalf("legitimate distinct Claims were counted as conflicts: %d", store.conflicts)
	}

	// 3. 同 Claim ID、不同 exact bytes 且证据无效（换掉 payload bundle）：
	//    必须先执行完整验证——这里 payload/hash 校验失败——因此按
	//    invalid evidence 拒绝，绝不能记为 collision/conflict 报警。
	sameClaimOtherBundle := cloneArbitrationRequestForTest(arbitrationA)
	otherPayloads, err := bitfs.EncodeContentPayloads([][]byte{[]byte("conflicting-payload")})
	if err != nil {
		t.Fatal(err)
	}
	sameClaimOtherBundle.ContentPayloadsCBOR = otherPayloads
	rawInvalidPayload, err := arbitration.MarshalRequest(sameClaimOtherBundle)
	if err != nil {
		t.Fatal(err)
	}
	conflictClaimID, err := arbitration.ArbitrationClaimID(sameClaimOtherBundle.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conflictClaimID, claimIDA) {
		t.Fatal("test premise broken: swapping payloads changed the Claim ID")
	}
	if _, err := store.handleArbitrationRequest(rawInvalidPayload, f.arbiter, f.facts()); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("invalid same-claim-id variant error = %v, want pool.ErrInvalidEvidence", err)
	}

	// 4. 同 Claim ID、Seller Claim signature 被篡改：同样必须先完整验签，
	//    验签失败按 invalid evidence 拒绝，不计冲突。
	badSignature := cloneArbitrationRequestForTest(arbitrationA)
	badSignature.SellerClaimSignature[len(badSignature.SellerClaimSignature)-1] ^= 1
	rawBadSignature, err := arbitration.MarshalRequest(badSignature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.handleArbitrationRequest(rawBadSignature, f.arbiter, f.facts()); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("tampered seller signature on a known claim error = %v, want pool.ErrInvalidEvidence", err)
	}

	// 5. 同 Claim ID、外层 Seller 签名不同但密码学有效（ECDSA high-S 可延展
	//    变体，通过完整 Seller/Buyer/payload/余额验证）：这才是真正的重复
	//    证据冲突——报警并停止自动流程，且绝不覆盖原记录。
	baseSig, err := ec.ParseDERSignature(arbitrationA.SellerClaimSignature)
	if err != nil {
		t.Fatal(err)
	}
	malleated := &ec.Signature{R: baseSig.R, S: new(big.Int).Sub(ec.S256().N, baseSig.S)}
	variantSignature, err := malleated.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(variantSignature, arbitrationA.SellerClaimSignature) {
		t.Fatal("test premise broken: the malleated signature is byte-identical")
	}
	validVariant := cloneArbitrationRequestForTest(arbitrationA)
	validVariant.SellerClaimSignature = variantSignature
	rawValidVariant, err := arbitration.MarshalRequest(validVariant)
	if err != nil {
		t.Fatal(err)
	}
	// 变体签名本身必须能通过协议固定验证器，证明它确实是"有效但不同"。
	domain, err := arbitration.SellerClaimSigningCBOR(validVariant.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(mustClaimForTest(t, validVariant.ClaimCBOR).PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(keys.SellerPubKey, domain, validVariant.SellerClaimSignature); err != nil {
		t.Fatalf("test premise broken: the malleated signature does not verify: %v", err)
	}
	recordA := store.recordOf(hex.EncodeToString(claimIDA))
	if _, err := store.handleArbitrationRequest(rawValidVariant, f.arbiter, f.facts()); err == nil {
		t.Fatal("a fully valid different-bytes variant was accepted instead of conflicted")
	}
	if !bytes.Equal(recordA.requestBytes, rawA) || !bytes.Equal(recordA.responseBytes, responseA) || recordA.arbiterAmountSat != arbitrationFeeSat {
		t.Fatal("the conflict path mutated the stored evidence or response")
	}
	if store.conflicts != 1 {
		t.Fatalf("conflict counter = %d, want exactly 1 (only the fully valid variant)", store.conflicts)
	}

	// 4. exact 同一请求重试：计价与签名计数保持不变。
	priceBefore, signBefore := store.priceCalls, store.signCalls
	retry, err := store.handleArbitrationRequest(rawA, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	if store.priceCalls != priceBefore || store.signCalls != signBefore {
		t.Fatalf("exact retry moved counters: price %d->%d sign %d->%d", priceBefore, store.priceCalls, signBefore, store.signCalls)
	}
	if !bytes.Equal(retry, responseA) {
		t.Fatal("exact retry did not resend the saved response bytes")
	}
}

// TestArbitrationCrashRecoverySignsFromSavedEvidenceOnly simulates a crash
// after atomic custody persistence but before signing: recovery must rebuild
// via PreparePayment(savedRequestBytes, blockHeight, savedFee) without ever
// re-running the fee policy, then sign once and persist a byte-identical
// response.
func TestArbitrationCrashRecoverySignsFromSavedEvidenceOnly(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}

	// 参考实现：完整走完一次，得到"应当产出"的 canonical 响应。
	referenceStore := newMemoryArbitrationCustodyStore()
	expected, err := referenceStore.handleArbitrationRequest(rawKind8, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}

	// 崩溃模拟：只完成托管持久化，尚未生成 Kind 9。
	crashedStore := newMemoryArbitrationCustodyStore()
	decoded, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		t.Fatal(err)
	}
	fee, err := crashedStore.priceArbitrationFee(decoded)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.arbiter.PreparePayment(f.ctx, decoded, f.facts(), fee)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := arbitration.ArbitrationClaimID(decoded.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(claimID)
	crashedStore.putRecord(&arbitrationCustodyRecord{
		requestBytes:     append([]byte(nil), rawKind8...),
		payloadsCBOR:     prepared.ContentPayloadsCBOR(),
		claimID:          prepared.ClaimID(),
		arbiterAmountSat: prepared.ArbiterAmountSat(),
	})

	// 恢复：处理器发现"只有托管、没有响应"，从保存的 exact bytes 与保存的
	// 费用重建——费用策略绝不再次运行——然后签名一次并持久化响应。
	recovered, err := crashedStore.handleArbitrationRequest(rawKind8, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	if crashedStore.priceCalls != 1 || crashedStore.signCalls != 1 {
		t.Fatalf("recovery counters = price %d sign %d; the fee policy must run exactly once across crash and recovery", crashedStore.priceCalls, crashedStore.signCalls)
	}
	if !bytes.Equal(recovered, expected) {
		t.Fatal("recovery produced different response bytes than a clean single pass")
	}
	if recoveredRecord := crashedStore.recordOf(key); !bytes.Equal(recoveredRecord.responseBytes, expected) {
		t.Fatal("recovery did not persist the exact canonical response onto the saved record")
	}
}

func cloneArbitrationRequestForTest(request *arbitration.ArbitrationRequest) *arbitration.ArbitrationRequest {
	return &arbitration.ArbitrationRequest{Version: request.Version, ClaimCBOR: append([]byte(nil), request.ClaimCBOR...), SellerClaimSignature: append([]byte(nil), request.SellerClaimSignature...), ContentPayloadsCBOR: append([]byte(nil), request.ContentPayloadsCBOR...)}
}

func mustClaimForTest(t *testing.T, claimCBOR []byte) *arbitration.ArbitrationClaim {
	t.Helper()
	claim, err := arbitration.UnmarshalClaim(claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func TestWrongBuyerCannotActOnAnotherBuyersPool(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	wrongBuyer, err := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: integrationKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongBuyer.BuildFundingTxDelivery(f.ctx, f.acceptance.Opening); err == nil {
		t.Fatal("wrong buyer delivered another buyer's funding transaction")
	}
	if _, _, err := wrongBuyer.BuildImmediateClose(f.ctx, f.completed.Opening, f.completed.InitialPayment, f.completed.InitialPayment.SellerAmountSat, f.facts()); err == nil {
		t.Fatal("wrong buyer signed an immediate close")
	}
}

func TestWrongSellerCannotPresignOrDeliverForAnotherSellersPool(t *testing.T) {
	f := newProtocolFixture(t)
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTx: f.buildFunding(t, 100000), ExpiryLockTime: f.expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	wrongSeller, err := seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: integrationKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongSeller.PresignPoolOpening(f.ctx, preparation.Request); err == nil {
		t.Fatal("wrong seller presigned another seller's opening")
	}
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongSeller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("wrong seller delivered content")
	}
}

func TestExpiredFactsRejectForwardOperationsButEnableRefundBuild(t *testing.T) {
	expiry := uint32(time.Now().UTC().Add(-time.Hour).Unix())
	f := newProtocolFixtureWithExpiry(t, expiry)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	if _, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input); err == nil {
		t.Fatal("content request accepted after refund expiry")
	}
	// With the refund expired the template becomes computable from stored
	// evidence; whether to broadcast remains the application's decision. The
	// fixture's timestamp-lock refund only needs a trusted height placeholder.
	raw, state, err := f.buyer.BuildRefundAfterExpiry(f.ctx, f.completed.Opening, f.facts())
	if err != nil {
		t.Fatalf("refund build after expiry failed: %v", err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.completed.Opening.BuyerPubKey, SellerPubKey: f.completed.Opening.SellerPubKey, ArbiterPubKey: f.completed.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := engine.ParsePaymentState(f.ctx, raw, f.completed.Opening)
	if err != nil || parsed.PaymentSequence != 2 || state.PaymentSequence != 2 {
		t.Fatalf("refund state parse = %v", err)
	}
}

func TestStaleSequenceAndTamperedEvidenceAreRejected(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	stalePrevious := &pool.PaymentState{}
	*stalePrevious = *f.completed.InitialPayment
	stalePrevious.PaymentSequence--
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, stalePrevious, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("stale previous state accepted for delivery")
	}
	// Tampered authorization hash must not be accepted at payment time.
	delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	tampered := &pool.PaymentUpdate{Version: verified.Update.Version, PaymentAuthorizationHash: append([]byte(nil), verified.Update.PaymentAuthorizationHash...), BuyerTransactionSignature: append([]byte(nil), verified.Update.BuyerTransactionSignature...)}
	tampered.PaymentAuthorizationHash[0] ^= 0xff
	if _, err := f.seller.AcceptPayment(f.ctx, f.completed.Opening, f.completed.InitialPayment, request, deliveryState, tampered, f.facts()); err == nil {
		t.Fatal("tampered authorization hash was accepted")
	}
}

// TestConsecutiveCumulativePaymentRoundsShareConfirmedState runs two full
// 003→004→005 rounds. After each round the application verifies the complete
// dual-signed payment (the "node confirmed" candidate) and saves the SAME
// confirmed state on both the buyer and seller sides; the second round must
// consume the first round's state so sequence and cumulative amount keep
// advancing. Using a stale buyer-side previous in round two must fail.
func TestConsecutiveCumulativePaymentRoundsShareConfirmedState(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	opening := f.completed.Opening
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: opening.BuyerPubKey, SellerPubKey: opening.SellerPubKey, ArbiterPubKey: opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}

	input := func(deadline time.Time) buyer.ContentRequestInput {
		return buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(deadline.Add(30 * time.Minute).Unix())}
	}
	runRound := func(previous *pool.PaymentState, deadline time.Time) (*pool.SignedPayment, *bitfs.SignedContentRequest) {
		request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, opening, previous, input(deadline))
		if err != nil {
			t.Fatal(err)
		}
		delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, opening, previous, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
		if err != nil {
			t.Fatal(err)
		}
		verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, opening, previous, request, delivery, buyer.ContentDeliveryInput{})
		if err != nil {
			t.Fatal(err)
		}
		signedPayment, err := f.seller.AcceptPayment(f.ctx, opening, previous, request, deliveryState, verified.Update, f.facts())
		if err != nil {
			t.Fatal(err)
		}
		return signedPayment, request
	}

	// Round one.
	confirmed := f.completed.InitialPayment
	signed1, _ := runRound(confirmed, f.now)
	if err := engine.VerifyAcceptedPayment(&signed1.State, opening); err != nil {
		t.Fatalf("round-one confirmed payment invalid: %v", err)
	}
	// Node policy accepted the candidate: BOTH roles now persist the same
	// complete dual-signed state as their latest.
	buyerLatest := &signed1.State
	sellerLatest := &signed1.State
	if buyerLatest.PaymentSequence != sellerLatest.PaymentSequence || buyerLatest.SellerAmountSat != sellerLatest.SellerAmountSat {
		t.Fatal("buyer and seller persisted different confirmed states")
	}
	if buyerLatest.PaymentSequence != confirmed.PaymentSequence+1 || buyerLatest.SellerAmountSat != 100 {
		t.Fatalf("round-one state = seq %d amount %d, want seq %d amount 100", buyerLatest.PaymentSequence, buyerLatest.SellerAmountSat, confirmed.PaymentSequence+1)
	}

	// Round two must consume round one's confirmed state.
	signed2, _ := runRound(buyerLatest, f.now.Add(time.Minute))
	if err := engine.VerifyAcceptedPayment(&signed2.State, opening); err != nil {
		t.Fatalf("round-two confirmed payment invalid: %v", err)
	}
	if signed2.State.PaymentSequence != buyerLatest.PaymentSequence+1 {
		t.Fatalf("round-two sequence = %d, want %d", signed2.State.PaymentSequence, buyerLatest.PaymentSequence+1)
	}
	if signed2.State.SellerAmountSat != buyerLatest.SellerAmountSat+100 {
		t.Fatalf("round-two cumulative amount = %d, want %d", signed2.State.SellerAmountSat, buyerLatest.SellerAmountSat+100)
	}
	if !bytes.Equal(signed2.RawTx, signed2.State.RawTx) {
		t.Fatal("round-two merged transaction does not match its parsed state")
	}
	// Round two's confirmed state replaces the shared record on both sides.
	buyerLatest = &signed2.State
	sellerLatest = &signed2.State

	// A buyer whose journal still holds the round-one previous cannot start
	// the next round against the advanced seller state: the request it signs
	// targets an already-consumed sequence and must be refused.
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, opening, sellerLatest, mustStaleRoundRequest(t, f, opening, &signed1.State), seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("stale previous state was accepted for the next round's delivery")
	}
}

func mustStaleRoundRequest(t *testing.T, f *protocolFixture, opening *pool.OpeningProof, stale *pool.PaymentState) *bitfs.SignedContentRequest {
	t.Helper()
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, opening, stale, input)
	if err != nil {
		t.Fatalf("build stale next-round request: %v", err)
	}
	return request
}

// runCustodyThroughKind9 完成 001–007 的托管侧：Seller 提交 Kind 8、Arbiter
// 原子持久化并签署 exact Kind 9，全部字节保存在应用 store 中。
func (store *memoryArbitrationCustodyStore) runCustodyThroughKind9(t *testing.T, f *protocolFixture, request003 *bitfs.SignedContentRequest) ([]byte, []byte) {
	t.Helper()
	input := seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request003, input)
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request003, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.handleArbitrationRequest(rawKind8, f.arbiter, f.facts()); err != nil {
		t.Fatal(err)
	}
	custodyKey := mustHex(t, mustClaimIDOf(t, rawKind8))
	record := store.recordOf(custodyKey)
	if record == nil || record.responseBytes == nil || !store.retrievable(custodyKey) {
		t.Fatal("custody record did not reach the Retrievable state")
	}
	return rawKind8, record.responseBytes
}

func mustClaimIDOf(t *testing.T, rawKind8 []byte) []byte {
	t.Helper()
	request, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := arbitration.ArbitrationClaimID(request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return claimID
}

func mustHex(t *testing.T, value []byte) string {
	t.Helper()
	return hex.EncodeToString(value)
}

// TestBuyerArbitratedContentRetrievalLifecycle walks 001–008 end to end:
// Seller submits 007, the arbiter persists Kind 8/9, the buyer independently
// rebuilds its Claim ID and Kind 10 from opening + signed 003 only, the
// arbiter verifies, atomically occupies the nonce, returns exact Kind 11,
// and the buyer accepts and saves the payloads. The path has no 005, no
// buyer+arbiter close, and no node broadcast.
func TestBuyerArbitratedContentRetrievalLifecycle(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	store := newMemoryArbitrationCustodyStore()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, storedRawKind9 := store.runCustodyThroughKind9(t, f, request003)
	claimID := mustClaimIDOf(t, rawKind8)

	// Buyer：应用生成密码学安全随机 nonce（此处用 crypto/rand 演示），发送前
	// 持久化 exact Kind 10。
	nonce := make([]byte, arbitration.RetrievalNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	retrievalRequest, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonce)
	if err != nil {
		t.Fatal(err)
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rawKind10, claimID) {
		t.Fatal("Kind 10 does not route by the independently rebuilt Claim ID")
	}
	rawKind11, err := store.handleContentRetrieval(rawKind10, f.arbiter)
	if err != nil {
		t.Fatal(err)
	}
	retrievalResponse, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retrievalResponse.ArbitrationRequestCBOR, rawKind8) || !bytes.Equal(retrievalResponse.ArbitrationResponseCBOR, storedRawKind9) {
		t.Fatal("Kind 11 did not return the exact persisted custody bytes")
	}
	// Buyer 验收并保存 payload；验收不产生 005、不改 previous、不关池。
	previousSnapshot := pool.ClonePaymentState(f.completed.InitialPayment)
	verified, err := f.buyer.AcceptArbitratedContent(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request003, retrievalRequest, retrievalResponse, buyer.ArbitratedContentInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], f.seed) {
		t.Fatal("retrieved payloads do not match the custodied content")
	}
	if !bytes.Equal(verified.ClaimID, claimID) || verified.Receipt == nil || !bytes.Equal(verified.Receipt.ClaimID, claimID) {
		t.Fatal("verified audit data does not bind the Claim ID")
	}
	if !samePaymentStateForIntegration(previousSnapshot, f.completed.InitialPayment) {
		t.Fatal("acceptance changed the previous payment state")
	}
}

func samePaymentStateForIntegration(left, right *pool.PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID && left.PaymentSequence == right.PaymentSequence && left.SellerAmountSat == right.SellerAmountSat && bytes.Equal(left.RawTx, right.RawTx)
}

// TestBuyerRetrievalApplicationErrorChannels pins every application-level
// failure path: NotFound, NotReady (custody prepared but Kind 9 unsigned),
// Unauthorized, NonceReused including concurrent CAS, new-nonce retry,
// retention Gone, and corrupted storage.
func TestBuyerRetrievalApplicationErrorChannels(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)

	mustMarshalKind8ForRetrieval := func(t *testing.T, f *protocolFixture, request003 *bitfs.SignedContentRequest) []byte {
		t.Helper()
		delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
		if err != nil {
			t.Fatal(err)
		}
		arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request003, delivery, f.facts())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := arbitration.MarshalRequest(arbitrationRequest)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	buildChain := func(deadline time.Time) (*bitfs.SignedContentRequest, []byte) {
		input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(deadline.Unix())}
		request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
		if err != nil {
			t.Fatal(err)
		}
		return request003, mustClaimIDOf(t, mustMarshalKind8ForRetrieval(t, f, request003))
	}

	requestA, claimIDA := buildChain(f.now.Add(30 * time.Minute))
	store := newMemoryArbitrationCustodyStore()

	// NotReady：只有托管、尚未签署 Kind 9 的记录不得返回 payload。
	preparedOnly, err := f.arbiter.PreparePayment(f.ctx, mustDecodeKind8(t, mustMarshalKind8ForRetrieval(t, f, requestA)), f.facts(), arbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	store.putRecord(&arbitrationCustodyRecord{
		requestBytes:     append([]byte(nil), mustMarshalKind8ForRetrieval(t, f, requestA)...),
		payloadsCBOR:     preparedOnly.ContentPayloadsCBOR(),
		claimID:          preparedOnly.ClaimID(),
		arbiterAmountSat: preparedOnly.ArbiterAmountSat(),
	})
	nonceA := bytes.Repeat([]byte{0x11}, 32)
	kind10A, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, requestA, nonceA)
	if err != nil {
		t.Fatal(err)
	}
	raw10A, err := arbitration.MarshalContentRetrievalRequest(kind10A)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.handleContentRetrieval(raw10A, f.arbiter); !errors.Is(err, errRetrievalNotReady) {
		t.Fatalf("NotReady error = %v", err)
	}

	// 完成签署后同一请求可以取回；同时证明验签失败不污染 nonce 表。
	if _, err := store.handleArbitrationRequest(mustMarshalKind8ForRetrieval(t, f, requestA), f.arbiter, f.facts()); err != nil {
		t.Fatal(err)
	}
	wrongBuyer, err := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: integrationKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	forgeNonce := bytes.Repeat([]byte{0x22}, 32)
	// 另一个买家的 workflow key 与 opening 不匹配，无法通过 SDK 伪造 Kind 10：
	// 手工构造一个签名错误的请求，并必须真正调用 handler。
	forgeRequest, err := wrongBuyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, requestA, forgeNonce)
	if err == nil {
		t.Fatal("wrong buyer unexpectedly built a valid Kind 10 for another buyer's opening")
	}
	signing, signingErr := arbitration.BuyerRetrievalSigningCBOR(kind10A.ClaimID, forgeNonce)
	if signingErr != nil {
		t.Fatal(signingErr)
	}
	badSig, sigErr := bitfs.SignMessage(integrationKey(t, "44"), signing)
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	forgeRequest = &arbitration.ContentRetrievalRequest{Version: arbitration.MajorVersion, ClaimID: append([]byte(nil), kind10A.ClaimID...), Nonce: append([]byte(nil), forgeNonce...), BuyerSignature: badSig}
	if _, err := store.handleContentRetrieval(mustMarshalKind10(t, forgeRequest), f.arbiter); !errors.Is(err, errRetrievalUnauthorized) {
		t.Fatalf("Unauthorized error = %v", err)
	}
	store.mu.Lock()
	polluted := len(store.nonceRecords) != 0
	store.mu.Unlock()
	if polluted {
		t.Fatal("a failed-signature request polluted the nonce table")
	}

	first11, err := store.handleContentRetrieval(raw10A, f.arbiter)
	if err != nil {
		t.Fatal(err)
	}
	// NonceReused：同 (ClaimID, Nonce) 第二次必须失败。
	if replay, err := store.handleContentRetrieval(raw10A, f.arbiter); !errors.Is(err, errNonceReused) || replay != nil {
		t.Fatalf("NonceReused error = %v result %v", err, replay)
	}
	// 新 nonce 重试：retention 期内合法重复下载，内容一致。
	retryNonce := bytes.Repeat([]byte{0x33}, 32)
	kind10Retry, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, requestA, retryNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw10Retry, err := arbitration.MarshalContentRetrievalRequest(kind10Retry)
	if err != nil {
		t.Fatal(err)
	}
	second11, err := store.handleContentRetrieval(raw10Retry, f.arbiter)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first11, second11) {
		t.Fatal("retry with a fresh nonce returned different custody bytes")
	}

	// NotFound：未知 Claim ID。
	unknownClaimID := bytes.Repeat([]byte{0x7f}, 32)
	signingUnknown, err := arbitration.BuyerRetrievalSigningCBOR(unknownClaimID, nonceA)
	if err != nil {
		t.Fatal(err)
	}
	sigUnknown, err := bitfs.SignMessage(f.buyerKey, signingUnknown)
	if err != nil {
		t.Fatal(err)
	}
	unknownRequest := &arbitration.ContentRetrievalRequest{Version: arbitration.MajorVersion, ClaimID: unknownClaimID, Nonce: append([]byte(nil), nonceA...), BuyerSignature: sigUnknown}
	if _, err := store.handleContentRetrieval(mustMarshalKind10(t, unknownRequest), f.arbiter); !errors.Is(err, errRetrievalNotFound) {
		t.Fatalf("NotFound error = %v", err)
	}

	// Gone：留存期结束并安全删除后返回 Gone，nonce 记录保留。
	store.expireRetention(claimIDA)
	if _, err := store.handleContentRetrieval(raw10Retry, f.arbiter); !errors.Is(err, errRetentionGone) {
		t.Fatalf("Gone error = %v", err)
	}

	// 存储损坏：exact Kind 8 字节损坏时失败关闭，隔离记录。
	store2 := newMemoryArbitrationCustodyStore()
	raw8B, _ := store2.runCustodyThroughKind9(t, f, requestA)
	claimIDB := mustClaimIDOf(t, raw8B)
	recordB := store2.recordOf(hex.EncodeToString(claimIDB))
	savedCopy := append([]byte(nil), recordB.requestBytes...)
	// 破坏 CBOR 结构头，使 strict decode 直接失败（失败关闭，隔离记录）。
	recordB.requestBytes[0] ^= 0xff
	store2.putRecord(recordB)
	kind10B, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, requestA, bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	raw10B, err := arbitration.MarshalContentRetrievalRequest(kind10B)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store2.handleContentRetrieval(raw10B, f.arbiter); !errors.Is(err, errCustodyCorrupt) {
		t.Fatalf("corruption error = %v", err)
	}
	recordB.requestBytes = savedCopy
	store2.putRecord(recordB)
	if _, err := store2.handleContentRetrieval(raw10B, f.arbiter); err != nil {
		t.Fatalf("restored record still failed: %v", err)
	}

	// 并发 nonce CAS：两个相同 nonce 的并发请求只有一个成功。
	store3 := newMemoryArbitrationCustodyStore()
	raw8C, _ := store3.runCustodyThroughKind9(t, f, requestA)
	_ = raw8C
	concurrentNonce := bytes.Repeat([]byte{0x66}, 32)
	kind10C, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, requestA, concurrentNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw10C, err := arbitration.MarshalContentRetrievalRequest(kind10C)
	if err != nil {
		t.Fatal(err)
	}
	const racers = 4
	results := make(chan error, racers)
	for index := 0; index < racers; index++ {
		go func() {
			_, err := store3.handleContentRetrieval(raw10C, f.arbiter)
			results <- err
		}()
	}
	successes := 0
	for index := 0; index < racers; index++ {
		err := <-results
		if err == nil {
			successes++
		} else if !errors.Is(err, errNonceReused) {
			t.Fatalf("concurrent racer failed with %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent nonce CAS winners = %d, want exactly 1", successes)
	}
}

func mustMarshalKind10(t *testing.T, request *arbitration.ContentRetrievalRequest) []byte {
	t.Helper()
	raw, err := arbitration.MarshalContentRetrievalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustDecodeKind8(t *testing.T, raw []byte) *arbitration.ArbitrationRequest {
	t.Helper()
	request, err := arbitration.UnmarshalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// TestRetrievalRacesWithKind9AppendAndRetentionDelete runs retrieval against
// concurrent custody-state transitions under -race: appending Kind 9 turns a
// CustodyPrepared record into Retrievable, retention deletion turns everything
// into Gone. Every outcome must stay inside the declared error channels, the
// nonce table must never be polluted by failed attempts, and the record must
// be retrievable exactly once per nonce after it becomes ready.
func TestRetrievalRacesWithKind9AppendAndRetentionDelete(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request003, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	claimID := mustClaimIDOf(t, rawKind8)

	// ---- 阶段 A：并发取件 vs Kind 9 追加。----
	storeA := newMemoryArbitrationCustodyStore()
	decoded, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.arbiter.PreparePayment(f.ctx, decoded, f.facts(), arbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	storeA.putRecord(&arbitrationCustodyRecord{
		requestBytes:     append([]byte(nil), rawKind8...),
		payloadsCBOR:     prepared.ContentPayloadsCBOR(),
		claimID:          prepared.ClaimID(),
		arbiterAmountSat: prepared.ArbiterAmountSat(),
	})
	nonceA := bytes.Repeat([]byte{0x91}, 32)
	kind10A, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonceA)
	if err != nil {
		t.Fatal(err)
	}
	raw10A, err := arbitration.MarshalContentRetrievalRequest(kind10A)
	if err != nil {
		t.Fatal(err)
	}

	raceResult := make(chan error, 1)
	go func() {
		var lastErr error
		for attempt := 0; attempt < 200; attempt++ {
			_, err := storeA.handleContentRetrieval(raw10A, f.arbiter)
			if err == nil {
				raceResult <- nil
				return
			}
			if !errors.Is(err, errRetrievalNotReady) {
				raceResult <- err
				return
			}
			lastErr = err
		}
		raceResult <- lastErr
	}()
	response, err := f.arbiter.SignPreparedPayment(f.ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	rawKind9, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	storeA.appendResponse(hex.EncodeToString(claimID), rawKind9)
	if err := <-raceResult; err != nil {
		t.Fatalf("retrieval racing with Kind 9 append failed outside the declared channels: %v", err)
	}
	// 记录就绪后：同一 nonce 已被竞速胜者占用（NonceReused），新 nonce 必须成功。
	if _, err := storeA.handleContentRetrieval(raw10A, f.arbiter); !errors.Is(err, errNonceReused) {
		t.Fatalf("same-nonce replay after success error = %v", err)
	}
	retryNonce := bytes.Repeat([]byte{0x92}, 32)
	kind10Retry, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, retryNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw10Retry, err := arbitration.MarshalContentRetrievalRequest(kind10Retry)
	if err != nil {
		t.Fatal(err)
	}
	raw11, err := storeA.handleContentRetrieval(raw10Retry, f.arbiter)
	if err != nil {
		t.Fatalf("fresh-nonce retrieval after readiness failed: %v", err)
	}
	storedKind8 := storeA.recordOf(hex.EncodeToString(claimID)).requestBytes
	storedKind9 := storeA.recordOf(hex.EncodeToString(claimID)).responseBytes
	if !bytes.Contains(raw11, storedKind8) || !bytes.Contains(raw11, storedKind9) {
		t.Fatal("Kind 11 does not embed the exact persisted bytes")
	}

	// ---- 阶段 B：并发取件 vs retention 删除。----
	storeB := newMemoryArbitrationCustodyStore()
	storeB.putRecord(&arbitrationCustodyRecord{
		requestBytes:     append([]byte(nil), rawKind8...),
		payloadsCBOR:     prepared.ContentPayloadsCBOR(),
		claimID:          prepared.ClaimID(),
		arbiterAmountSat: prepared.ArbiterAmountSat(),
	})
	storeB.appendResponse(hex.EncodeToString(claimID), rawKind9)
	nonceB := bytes.Repeat([]byte{0x93}, 32)
	kind10B, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonceB)
	if err != nil {
		t.Fatal(err)
	}
	raw10B, err := arbitration.MarshalContentRetrievalRequest(kind10B)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				storeB.expireRetention(claimID)
			}
		}
	}()
	successes := 0
	for attempt := 0; attempt < 100; attempt++ {
		_, err := storeB.handleContentRetrieval(raw10B, f.arbiter)
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errRetentionGone):
			// 竞争失败方必须得到 Gone，绝不能是其他错误通道。
		case errors.Is(err, errNonceReused):
			// 删除尚未落地时同 nonce 重试：合法重放拒绝，不占用新表项。
		default:
			close(stop)
			t.Fatalf("retrieval racing with retention delete returned %v", err)
		}
	}
	close(stop)
	if successes > 1 {
		t.Fatalf("deleted content was served %d times", successes)
	}
	storeB.mu.Lock()
	polluted := len(storeB.nonceRecords) != successes
	storeB.mu.Unlock()
	if polluted {
		t.Fatal("nonce table does not match successful occupations during retention race")
	}
}
