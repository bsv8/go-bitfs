// Package integration exercises the complete BitFS v1 protocol lifecycle
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
	"crypto/sha256"
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
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
)

type integrationSigner struct{ key *ec.PrivateKey }

// arbitrationCustodyRecord is one application custody record, indexed by
// Claim ID. It persists the exact received Kind 8 raw bytes (not a decoded
// struct) and the frozen fee; the payload bundle has no second stored truth —
// it lives only inside the exact Kind 8 bytes and is re-derived through strict
// decoding and full verification. After signing the exact canonical Kind 9
// bytes are appended to the same record.
type arbitrationCustodyRecord struct {
	requestBytes          []byte // exact received raw Kind 8 CBOR, deep-copied on save
	claimID               protocol.ArbitrationClaimID
	arbiterAmountSatoshis uint64
	responseBytes         []byte // exact canonical saved Kind 9, resent verbatim on retry
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

	// servedResponses 是应用侧 (ClaimID, Nonce) 原子占用表 + 首次持久化 Kind 11：
	// 验签成功后由唯一的原子提交入口写入（数据库唯一键语义）；旧 nonce 记录
	// 至少保留到对应 custody record 删除（本测试中永久保留）。同一
	// content_retrieval_request_id 重放时原样重发，状态变化后不升级。
	// hookBeforeCommit 是确定性测试屏障：模拟"候选应答构造完成"与"事务提交"
	// 之间的调度暂停；生产实现没有对应物。
	mu               sync.Mutex
	servedResponses  map[string][]byte            // key: hex(ClaimID)+":"+hex(Nonce) -> 首次持久化的 exact Kind 11
	goneClaims       map[string]*custodyTombstone // retention 结束后的最小可验证墓碑
	hookBeforeCommit func()
}

func newMemoryArbitrationCustodyStore() *memoryArbitrationCustodyStore {
	return &memoryArbitrationCustodyStore{records: make(map[string]*arbitrationCustodyRecord), servedResponses: make(map[string][]byte), goneClaims: make(map[string]*custodyTombstone)}
}

// priceArbitrationFee is this application's fee policy entry point; production
// services would consult their own price book here.
func (store *memoryArbitrationCustodyStore) priceArbitrationFee(decoded *arbitration.ArbitrationRequest) (uint64, error) {
	store.priceCalls++
	return arbitrationFeeSatoshis, nil
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
	claimID, err := arbitration.ArbitrationClaimID(decoded.ArbitrationClaimCBOR)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(claimID[:])

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
		if _, err := arbiter.PreparePayment(context.Background(), decoded, blockHeight, saved.arbiterAmountSatoshis); err != nil {
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
		prepared, err = arbiter.PreparePayment(context.Background(), savedDecoded, blockHeight, saved.arbiterAmountSatoshis)
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
			requestBytes:          append([]byte(nil), rawKind8...),
			claimID:               prepared.ArbitrationClaimID(),
			arbiterAmountSatoshis: prepared.ArbiterAmountSatoshis(),
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

// 应用级错误通道：Kind 11 的 available 与 unavailable 都是仲裁方签名的 wire
// 响应（§15），同一 exact Kind 10 的并发重复请求经原子提交入口重放首次提交
// 的相同 Kind 11；只有 Unauthorized、Malformed、RateLimited 与内部存储损坏/
// 冲突走这些哨兵错误，绝不伪装成结构合法的 Kind 11。
var (
	errRetrievalUnauthorized = errors.New("buyer retrieval unauthorized")
	errRetentionGone         = errors.New("custody content deleted after retention")
	errCustodyCorrupt        = errors.New("stored custody bytes failed strict decode")
	// errCustodyConflict：同一 Claim ID 下持久化的 request 字节与验证时的
	// 快照不一致——这是存储冲突/证据冲突，必须停止自动处理并报警；绝不能
	// 降级成 custody_gone，也不占用 nonce、不落任何 Kind 11。
	errCustodyConflict = errors.New("custody evidence conflict: stored request bytes changed under one claim id; stop automation and alarm")
	// errInternalStorage：记录消失且没有任何 tombstone——retention 流程不会
	// 产生这种状态，属于内部存储错误；不得凭空签署 custody_gone。
	errInternalStorage = errors.New("internal storage error: custody record vanished without a tombstone")
)

// snapshotLocked 返回 key 对应记录的深拷贝快照；必须在持有 store.mu 时调用。
func (store *memoryArbitrationCustodyStore) snapshotLocked(key string) *arbitrationCustodyRecord {
	record, exists := store.records[key]
	if !exists || record == nil {
		return nil
	}
	snapshot := &arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), record.requestBytes...),
		claimID:               record.claimID,
		arbiterAmountSatoshis: record.arbiterAmountSatoshis,
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
	store.records[hex.EncodeToString(record.claimID[:])] = record
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

// commitFirstAnswer 用于状态不可变（tombstone-gone）路径的提交入口：调用方先
// 在锁外构造好候选应答，这里在同一个互斥临界区内完成"重放检查 + (Claim ID,
// Nonce) 唯一键占用 + exact 首次响应插入"。并发败者的未提交签名在此被直接
// 丢弃，重放已提交胜者的字节——数据库里永远只有一份。
func (store *memoryArbitrationCustodyStore) commitFirstAnswer(nonceKey string, raw []byte) []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	if served, ok := store.servedResponses[nonceKey]; ok {
		return append([]byte(nil), served...)
	}
	store.servedResponses[nonceKey] = append([]byte(nil), raw...)
	return append([]byte(nil), raw...)
}

// commitOutcome 是状态感知原子提交的裁决结果。
type commitOutcome int

const (
	// commitServed：已有首次响应，raw 为已提交字节（并发胜者或重放）。
	commitServed commitOutcome = iota
	// commitCommitted：本调用提交的候选成为协议答案，raw 即该候选字节。
	commitCommitted
	// commitBecameComplete：Kind 9 在候选构造期间落地。NotReady 候选作废；
	// fresh 携带最新完整快照，调用方必须在锁外重建 Available 后走
	// commitAvailableAnswer 完成最终的原子插入。
	commitBecameComplete
)

// beforeCommit 是确定性测试屏障：模拟候选应答构造完成与事务提交之间的调度
// 暂停；生产实现没有对应物。
func (store *memoryArbitrationCustodyStore) beforeCommit() {
	if store.hookBeforeCommit != nil {
		store.hookBeforeCommit()
	}
}

// commitUnavailableAnswer 在单一互斥临界区内完成 "custody 状态复核 + nonce
// 唯一键 + exact 首次响应插入"。snapshotRequestBytes 是调用方验证证据时使用
// 的快照字节；rawNotReady/rawGone 是锁外预先签署好的候选。
//
// 裁决规则（custody_gone 只属于"曾有记录、已按 retention 删除"这一种事实）：
//
//	已有首次响应                      -> commitServed（原样重发）
//	记录已删除且存在 tombstone        -> 提交 rawGone
//	记录消失且没有 tombstone          -> errInternalStorage（不签署任何 Kind 11）
//	requestBytes 与验证快照不一致     -> errCustodyConflict（不占用 nonce、不落 Kind 11）
//	仍是 Prepared                     -> 提交 rawNotReady
//	Kind 9 已落地                     -> commitBecameComplete（NotReady 作废，需重建 Available）
func (store *memoryArbitrationCustodyStore) commitUnavailableAnswer(claimKey, nonceKey string, snapshotRequestBytes, rawNotReady, rawGone []byte) (commitOutcome, []byte, *arbitrationCustodyRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if served, ok := store.servedResponses[nonceKey]; ok {
		return commitServed, append([]byte(nil), served...), nil, nil
	}
	fresh := store.snapshotLocked(claimKey)
	tombstone := store.goneClaims[claimKey]
	switch {
	case fresh == nil && tombstone != nil:
		store.servedResponses[nonceKey] = append([]byte(nil), rawGone...)
		return commitCommitted, append([]byte(nil), rawGone...), nil, nil
	case fresh == nil:
		return commitServed, nil, nil, errInternalStorage
	case !bytes.Equal(fresh.requestBytes, snapshotRequestBytes):
		return commitServed, nil, nil, errCustodyConflict
	case fresh.responseBytes == nil:
		store.servedResponses[nonceKey] = append([]byte(nil), rawNotReady...)
		return commitCommitted, append([]byte(nil), rawNotReady...), nil, nil
	default:
		return commitBecameComplete, nil, fresh, nil
	}
}

// commitAvailableAnswer 在 custody 状态确认为 Complete 的前提下原子插入
// Available。裁决规则与 commitUnavailableAnswer 一致：
//
//	已有首次响应                    -> 原样重发
//	记录已删除且存在 tombstone      -> 提交 rawGone
//	记录消失且没有 tombstone        -> errInternalStorage
//	requestBytes 与验证快照不一致   -> errCustodyConflict
//	responseBytes 与验证快照不一致  -> errCustodyCorrupt（不落任何 Kind 11）
//	状态未变                        -> 提交 rawAvailable
func (store *memoryArbitrationCustodyStore) commitAvailableAnswer(claimKey, nonceKey string, expect *arbitrationCustodyRecord, rawAvailable, rawGone []byte) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if served, ok := store.servedResponses[nonceKey]; ok {
		return append([]byte(nil), served...), nil
	}
	fresh := store.snapshotLocked(claimKey)
	tombstone := store.goneClaims[claimKey]
	switch {
	case fresh == nil && tombstone != nil:
		store.servedResponses[nonceKey] = append([]byte(nil), rawGone...)
		return append([]byte(nil), rawGone...), nil
	case fresh == nil:
		return nil, errInternalStorage
	case !bytes.Equal(fresh.requestBytes, expect.requestBytes):
		return nil, errCustodyConflict
	case fresh.responseBytes == nil || !bytes.Equal(fresh.responseBytes, expect.responseBytes):
		return nil, fmt.Errorf("%w: stored response bytes changed under one claim id", errCustodyCorrupt)
	}
	store.servedResponses[nonceKey] = append([]byte(nil), rawAvailable...)
	return append([]byte(nil), rawAvailable...), nil
}

// custodyTombstone 是 retention 删除后的最小墓碑：保留资金池锁定脚本，
// 使 Arbiter 仍能从 Claim 关联恢复 Buyer 公钥完成 Kind 10 鉴权（§15.1）。
type custodyTombstone struct {
	poolLockingScript []byte
}

// expireRetention 模拟留存期结束并安全删除内容，但保留可验证的 tombstone
// 与 nonce 去重记录；tombstone 不足以重建 payload，只支持鉴权与 gone 判定。
// 已持久化的首次响应与内容一起删除：删除后同请求重放不再泄露 payload，
// 而是由 tombstone 鉴权路径回答签名的 gone。重复执行 retention 是幂等的：
// 记录已不存在时不触碰 tombstone 与已提交的 Gone 应答，幂等重放继续生效。
func (store *memoryArbitrationCustodyStore) expireRetention(claimID protocol.ArbitrationClaimID) {
	key := hex.EncodeToString(claimID[:])
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.records[key]
	existed := record != nil && len(record.requestBytes) > 0
	if existed {
		decoded, err := arbitration.UnmarshalRequest(record.requestBytes)
		if err == nil {
			claim, claimErr := arbitration.UnmarshalClaim(decoded.ArbitrationClaimCBOR)
			if claimErr == nil {
				store.goneClaims[key] = &custodyTombstone{poolLockingScript: append([]byte(nil), claim.PoolOutputLockingScript...)}
			}
		}
	}
	delete(store.records, key)
	if !existed {
		return
	}
	for nonceKey := range store.servedResponses {
		if strings.HasPrefix(nonceKey, key+":") {
			delete(store.servedResponses, nonceKey)
		}
	}
}

// handleContentRetrieval 实现施工单固定的应用级顺序：
//
//	strict decode Kind 10 -> 派生 request ID（SHA-256(exact request cbor)，
//	  与 (ClaimID, Nonce) 一一对应）
//	  -> 阶段〇 锁内查首次持久化响应：命中则原样重发——同一
//	     content_retrieval_request_id 的重放永远得到第一份 Kind 11，
//	     状态变化后绝不升级为 available
//	  -> 快照 tombstone / custody record
//	  -> not_received：无法鉴权的明确例外——不占用 nonce、不持久化响应；
//	     生产实现必须限流且不得返回敏感状态（§15.6）
//	  -> gone：tombstone 恢复 Buyer 公钥完成鉴权后，提交签名的四元 gone Kind 11
//	  -> 锁外损坏检查（失败关闭）+ SDK 完整验证（先验签）
//	  -> not_ready：鉴权通过后锁外构造 NotReady/Gone 候选，再进入状态感知
//	     原子提交：期间 Kind 9 落地则放弃 NotReady、基于新快照重建 Available；
//	     期间内容被 retention 删除则改答 Gone——旧 nonce 永远不会再变成下载
//	     授权，Buyer 必须换新 nonce 重试
//	  -> available：锁外构造候选 Available；随后在单一原子事务内完成
//	     "custody 版本/retention 状态复核 + nonce 唯一键 + exact 响应插入"。
//	     验证期间内容被 retention 删除时，候选 payload 签名直接作废，改答
//	     并持久化签名的 gone——绝不复活已删除内容。并发产生的未提交签名
//	     一律丢弃，最终只返回已成功提交的那一份响应字节。
func (store *memoryArbitrationCustodyStore) handleContentRetrieval(rawKind10 []byte, arbiter *arbitration.Workflow, arbiterKey *ec.PrivateKey) ([]byte, error) {
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return nil, err
	}
	claimID, retrievalNonce, err := arbitration.DecodeContentRetrievalRequestDocument(retrievalRequest.ContentRetrievalRequestCBOR)
	if err != nil {
		return nil, err
	}
	requestIDHash := sha256.Sum256(retrievalRequest.ContentRetrievalRequestCBOR)
	requestID := protocol.ContentRetrievalRequestID(requestIDHash)
	key := hex.EncodeToString(claimID[:])
	nonceKey := key + ":" + hex.EncodeToString(retrievalNonce)

	buildUnavailable := func(reason arbitration.ContentRetrievalUnavailableReason) ([]byte, error) {
		response, buildErr := arbitration.BuildContentRetrievalUnavailable(requestID, reason, arbiterKey)
		if buildErr != nil {
			return nil, buildErr
		}
		return arbitration.MarshalContentRetrievalResponse(response)
	}

	// 阶段〇：幂等重放。
	store.mu.Lock()
	if served, ok := store.servedResponses[nonceKey]; ok {
		store.mu.Unlock()
		return append([]byte(nil), served...), nil
	}
	tombstone := store.goneClaims[key]
	record := store.snapshotLocked(key)
	store.mu.Unlock()

	if record == nil && tombstone == nil {
		// not_received：没有 Claim 就无法恢复 Buyer 公钥完成鉴权。这是唯一
		// 不占用 nonce、不持久化响应的例外分支；生产实现必须对随机 Claim ID
		// 查询限流，防止把 Arbiter 变成无限签名服务（§15.6）。
		return buildUnavailable(arbitration.RetrievalSellerArbitrationNotReceived)
	}
	if record == nil {
		// gone：墓碑保留了资金池锁定脚本，可恢复 Buyer 公钥完成鉴权；内容
		// 已按 retention policy 删除，构造并原子提交签名的四元 gone Kind 11。
		keys, keysErr := pool.ParseArbitratedPoolLockingScript(tombstone.poolLockingScript)
		if keysErr != nil {
			return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, keysErr)
		}
		if protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 10, retrievalRequest.ContentRetrievalRequestCBOR, retrievalRequest.BuyerContentRetrievalRequestSignature) != nil {
			return nil, fmt.Errorf("%w: %v", errRetrievalUnauthorized, errors.New("tombstone buyer authentication failed"))
		}
		rawGone, buildErr := buildUnavailable(arbitration.RetrievalCustodyGone)
		if buildErr != nil {
			return nil, buildErr
		}
		return store.commitFirstAnswer(nonceKey, rawGone), nil
	}

	// 锁外：失败关闭的损坏检查。有 Kind 8、没有 Kind 9 是合法 NotReady，
	// 不是损坏；无法 strict decode 才是损坏。
	storedRequest, err := arbitration.UnmarshalRequest(record.requestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, err)
	}
	if record.responseBytes == nil {
		// not_ready：已有持久化 Kind 8，但 Kind 9 尚未签署完成。先用已验证
		// Kind 8 的 Claim 关联完成 Buyer 鉴权；随后锁外构造 NotReady 与 Gone
		// 两个候选，再进入状态感知的原子提交——提交临界区会复核 custody
		// 状态：期间 Kind 9 落地则放弃 NotReady 并重建 Available，期间内容被
		// retention 删除则改答 Gone。绝不在删除后应答 not_ready，也绝不让
		// 已 ready 的记录继续回答 not_ready。
		if authErr := arbiter.AuthenticateContentRetrievalRequest(retrievalRequest, storedRequest); authErr != nil {
			return nil, fmt.Errorf("%w: %v", errRetrievalUnauthorized, authErr)
		}
		rawNotReady, buildErr := buildUnavailable(arbitration.RetrievalSellerArbitrationNotReady)
		if buildErr != nil {
			return nil, buildErr
		}
		rawGone, buildErr := buildUnavailable(arbitration.RetrievalCustodyGone)
		if buildErr != nil {
			return nil, buildErr
		}
		store.beforeCommit()
		outcome, raw, fresh, commitErr := store.commitUnavailableAnswer(key, nonceKey, record.requestBytes, rawNotReady, rawGone)
		if commitErr != nil {
			return nil, commitErr
		}
		if outcome == commitBecameComplete {
			// Kind 9 在窗口内落地：NotReady 候选作废。基于最新完整快照重新
			// 执行锁外损坏检查与完整验证，构造 Available 后走状态感知插入。
			rebuiltRequest, rebuildErr := arbitration.UnmarshalRequest(fresh.requestBytes)
			if rebuildErr != nil {
				return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, rebuildErr)
			}
			rebuiltResponse, rebuildErr := arbitration.UnmarshalResponse(fresh.responseBytes)
			if rebuildErr != nil {
				return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, rebuildErr)
			}
			if _, err := arbitration.VerifyCustodiedContent(rebuiltRequest, rebuiltResponse); err != nil {
				return nil, fmt.Errorf("%w: stored evidence failed verification; isolate and alarm: %v", errCustodyCorrupt, err)
			}
			reverified, err := arbiter.VerifyContentRetrievalRequest(retrievalRequest, rebuiltRequest, rebuiltResponse)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", errRetrievalUnauthorized, err)
			}
			rebuiltAvailable, err := arbitration.BuildContentRetrievalAvailableRaw(requestID, reverified.PayloadsCBOR, arbiterKey)
			if err != nil {
				return nil, err
			}
			rawAvailable, err := arbitration.MarshalContentRetrievalResponse(rebuiltAvailable)
			if err != nil {
				return nil, err
			}
			store.beforeCommit()
			raw, commitErr = store.commitAvailableAnswer(key, nonceKey, fresh, rawAvailable, rawGone)
			if commitErr != nil {
				return nil, commitErr
			}
		}
		return raw, nil
	}
	storedResponse, err := arbitration.UnmarshalResponse(record.responseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCustodyCorrupt, err)
	}
	// 先验签：存储证据本身验证失败属于持久化冲突/攻击，按损坏隔离告警。
	if _, err := arbitration.VerifyCustodiedContent(storedRequest, storedResponse); err != nil {
		return nil, fmt.Errorf("%w: stored evidence failed verification; isolate and alarm: %v", errCustodyCorrupt, err)
	}
	// Buyer 对精确 content_retrieval_request_cbor 的统一签名验证；统一
	// Unauthorized 语义：不泄露 Claim 是否存在或哪个字段失败。
	verified, err := arbiter.VerifyContentRetrievalRequest(retrievalRequest, storedRequest, storedResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRetrievalUnauthorized, err)
	}

	// 锁外构造两个候选应答：content_payloads_id 绑定 VerifyCustodiedContent
	// 返回并验证过的 exact payload bundle——托管证据链是 payload 的唯一真值；
	// gone 兜底用于验证期间内容被 retention 删除的竞争窗口。签名可以在
	// 事务外完成；未提交的签名之后会被直接丢弃。
	response, err := arbitration.BuildContentRetrievalAvailableRaw(requestID, verified.PayloadsCBOR, arbiterKey)
	if err != nil {
		return nil, err
	}
	rawAvailable, err := arbitration.MarshalContentRetrievalResponse(response)
	if err != nil {
		return nil, err
	}
	rawGoneFallback, err := buildUnavailable(arbitration.RetrievalCustodyGone)
	if err != nil {
		return nil, err
	}
	store.beforeCommit()

	// 状态感知的单一原子事务：custody 版本/retention 复核 + nonce 唯一键 +
	// exact 响应插入在同一临界区完成；并发产生的未提交签名直接丢弃。
	return store.commitAvailableAnswer(key, nonceKey, record, rawAvailable, rawGoneFallback)
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

	arbiters, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	// 001: seller creates the quote, buyer verifies and accepts it; both sides
	// keep their own copy as application state.
	quote, err := f.seller.CreateQuote(f.ctx, bitfs.FileQuoteTerms{SeedHash: masterseed.Sum256(f.seed).Bytes(), BuyerPublicKey: f.buyerKey.PubKey().Compressed(), SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: uint64(len(f.source)), QuoteExpiresAtUnixSeconds: f.now.Add(time.Hour).Unix(), SupportedArbiterPublicKeysCBOR: arbiters}, "file.bin")
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
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerKey.PubKey().Compressed(), SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
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
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTransactionRaw: fundingTx, ExpiryLockTime: f.expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
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
	delivery, err := f.buyer.BuildFundingTransactionDelivery(f.ctx, acceptance.Opening)
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

// arbitrationFeeSatoshis 是集成测试中应用层固定、可审计的正仲裁费：调用方先计价，
// 再把明确金额交给 SDK；SDK 不注入任何费率策略。
const arbitrationFeeSatoshis uint64 = 777

func TestFullLifecycleWithExplicitStatePassing(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: f.completed.Opening.BuyerPublicKey, SellerPublicKey: f.completed.Opening.SellerPublicKey, ArbiterPublicKey: f.completed.Opening.ArbiterPublicKey})
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
	if latest.SellerAmountSatoshis != 100 {
		t.Fatalf("seller amount = %d, want seed price 100", latest.SellerAmountSatoshis)
	}

	// 006: immediate close from explicit latest state.
	unsigned, buyerSignature, err := f.buyer.BuildImmediateClose(f.ctx, f.completed.Opening, latest, latest.SellerAmountSatoshis, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.seller.SignImmediateClose(f.ctx, f.completed.Opening, unsigned, buyerSignature, f.facts())
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
	prepared, err := f.arbiter.PreparePayment(f.ctx, arbitrationRequest, f.facts(), arbitrationFeeSatoshis)
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
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: f.completed.Opening.BuyerPublicKey, SellerPublicKey: f.completed.Opening.SellerPublicKey, ArbiterPublicKey: f.completed.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&signed.State, f.completed.Opening); err != nil {
		t.Fatalf("arbitrated payment invalid: %v", err)
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawState, err := tx.NewTransactionFromBytes(signed.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbiterAmountSatoshis != arbitrationFeeSatoshis || signed.State.ArbiterAmountSatoshis != arbitrationFeeSatoshis || rawState.Outputs[2].Satoshis != arbitrationFeeSatoshis {
		t.Fatalf("paid fee mismatch: receipt %d state %d raw %d want %d", receipt.ArbiterAmountSatoshis, signed.State.ArbiterAmountSatoshis, rawState.Outputs[2].Satoshis, arbitrationFeeSatoshis)
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
	claimID, err := arbitration.ArbitrationClaimID(arbitrationRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	recordKey := hex.EncodeToString(claimID[:])

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
	if !bytes.Equal(recovered.ArbitrationClaimCBOR, arbitrationRequest.ArbitrationClaimCBOR) || !bytes.Equal(recovered.ContentPayloadsCBOR, arbitrationRequest.ContentPayloadsCBOR) {
		t.Fatal("recovered request does not round-trip to the original evidence")
	}
	localClaimID, err := arbitration.ArbitrationClaimID(recovered.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if localClaimID != record.claimID {
		t.Fatal("custody record retained a Claim ID inconsistent with the saved raw request")
	}
	if record.arbiterAmountSatoshis != arbitrationFeeSatoshis {
		t.Fatalf("custody fee = %d, want the frozen %d", record.arbiterAmountSatoshis, arbitrationFeeSatoshis)
	}
	// payload 没有第二份存储真值：它只存在于 exact Kind 8 字节内，由严格
	// 解码重新派生并与授权哈希链绑定（上方 recovered.ContentPayloadsCBOR）。

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
	claimIDA, err := arbitration.ArbitrationClaimID(arbitrationA.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimIDB, err := arbitration.ArbitrationClaimID(arbitrationB.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if claimIDA == claimIDB {
		t.Fatal("test premise broken: the two Claims share one Claim ID")
	}
	responseB, err := store.handleArbitrationRequest(rawB, f.arbiter, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(responseA, responseB) {
		t.Fatal("a different valid Claim received the first Claim's saved response")
	}
	recordB := store.recordOf(hex.EncodeToString(claimIDB[:]))
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
	conflictClaimID, err := arbitration.ArbitrationClaimID(sameClaimOtherBundle.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if conflictClaimID != claimIDA {
		t.Fatal("test premise broken: swapping payloads changed the Claim ID")
	}
	if _, err := store.handleArbitrationRequest(rawInvalidPayload, f.arbiter, f.facts()); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("invalid same-claim-id variant error = %v, want pool.ErrInvalidEvidence", err)
	}

	// 4. 同 Claim ID、Seller Claim signature 被篡改：同样必须先完整验签，
	//    验签失败按 invalid evidence 拒绝，不计冲突。
	badSignature := cloneArbitrationRequestForTest(arbitrationA)
	badSignature.SellerArbitrationClaimSignature[len(badSignature.SellerArbitrationClaimSignature)-1] ^= 1
	rawBadSignature, err := arbitration.MarshalRequest(badSignature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.handleArbitrationRequest(rawBadSignature, f.arbiter, f.facts()); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("tampered seller signature on a known claim error = %v, want pool.ErrInvalidEvidence", err)
	}

	// 5. 同 Claim ID、ECDSA high-S 可延展变体：协议统一强制 low-S，
	//    high-S 变体必须作为 invalid evidence 拒绝——同一认证文档只存在
	//    一份有效 wire 签名，绝不进入重复证据冲突通道。
	baseSig, err := ec.ParseDERSignature(arbitrationA.SellerArbitrationClaimSignature)
	if err != nil {
		t.Fatal(err)
	}
	malleated := &ec.Signature{R: baseSig.R, S: new(big.Int).Sub(ec.S256().N, baseSig.S)}
	variantSignature, err := malleated.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(variantSignature, arbitrationA.SellerArbitrationClaimSignature) {
		t.Fatal("test premise broken: the malleated signature is byte-identical")
	}
	highSVariant := cloneArbitrationRequestForTest(arbitrationA)
	highSVariant.SellerArbitrationClaimSignature = variantSignature
	rawHighSVariant, err := arbitration.MarshalRequest(highSVariant)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(mustClaimForTest(t, highSVariant.ArbitrationClaimCBOR).PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyWireDocument(keys.SellerPublicKey, protocol.WireVersion, 8, highSVariant.ArbitrationClaimCBOR, highSVariant.SellerArbitrationClaimSignature); !errors.Is(err, protocol.ErrHighSSignature) {
		t.Fatalf("high-S seller signature error = %v, want protocol.ErrHighSSignature", err)
	}
	recordA := store.recordOf(hex.EncodeToString(claimIDA[:]))
	if _, err := store.handleArbitrationRequest(rawHighSVariant, f.arbiter, f.facts()); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("high-S same-claim variant error = %v, want pool.ErrInvalidEvidence", err)
	}
	if !bytes.Equal(recordA.requestBytes, rawA) || !bytes.Equal(recordA.responseBytes, responseA) || recordA.arbiterAmountSatoshis != arbitrationFeeSatoshis {
		t.Fatal("the high-S rejection path mutated the stored evidence or response")
	}
	if store.conflicts != 0 {
		t.Fatalf("conflict counter = %d, want 0: a high-S variant is invalid evidence, not a conflict", store.conflicts)
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
	claimID, err := arbitration.ArbitrationClaimID(decoded.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(claimID[:])
	crashedStore.putRecord(&arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), rawKind8...),
		claimID:               prepared.ArbitrationClaimID(),
		arbiterAmountSatoshis: prepared.ArbiterAmountSatoshis(),
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
	return &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: append([]byte(nil), request.ArbitrationClaimCBOR...), SellerArbitrationClaimSignature: append([]byte(nil), request.SellerArbitrationClaimSignature...), ContentPayloadsCBOR: append([]byte(nil), request.ContentPayloadsCBOR...)}
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
	if _, err := wrongBuyer.BuildFundingTransactionDelivery(f.ctx, f.acceptance.Opening); err == nil {
		t.Fatal("wrong buyer delivered another buyer's funding transaction")
	}
	if _, _, err := wrongBuyer.BuildImmediateClose(f.ctx, f.completed.Opening, f.completed.InitialPayment, f.completed.InitialPayment.SellerAmountSatoshis, f.facts()); err == nil {
		t.Fatal("wrong buyer signed an immediate close")
	}
}

func TestWrongSellerCannotPresignOrDeliverForAnotherSellersPool(t *testing.T) {
	f := newProtocolFixture(t)
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTransactionRaw: f.buildFunding(t, 100000), ExpiryLockTime: f.expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
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
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: f.completed.Opening.BuyerPublicKey, SellerPublicKey: f.completed.Opening.SellerPublicKey, ArbiterPublicKey: f.completed.Opening.ArbiterPublicKey})
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
	tampered := &pool.PaymentUpdate{PaymentAuthorizationID: verified.Update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: append([]byte(nil), verified.Update.BuyerPaymentTransactionSignature...)}
	tampered.PaymentAuthorizationID[0] ^= 0xff
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
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
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
	if buyerLatest.PaymentSequence != sellerLatest.PaymentSequence || buyerLatest.SellerAmountSatoshis != sellerLatest.SellerAmountSatoshis {
		t.Fatal("buyer and seller persisted different confirmed states")
	}
	if buyerLatest.PaymentSequence != confirmed.PaymentSequence+1 || buyerLatest.SellerAmountSatoshis != 100 {
		t.Fatalf("round-one state = seq %d amount %d, want seq %d amount 100", buyerLatest.PaymentSequence, buyerLatest.SellerAmountSatoshis, confirmed.PaymentSequence+1)
	}

	// Round two must consume round one's confirmed state.
	signed2, _ := runRound(buyerLatest, f.now.Add(time.Minute))
	if err := engine.VerifyAcceptedPayment(&signed2.State, opening); err != nil {
		t.Fatalf("round-two confirmed payment invalid: %v", err)
	}
	if signed2.State.PaymentSequence != buyerLatest.PaymentSequence+1 {
		t.Fatalf("round-two sequence = %d, want %d", signed2.State.PaymentSequence, buyerLatest.PaymentSequence+1)
	}
	if signed2.State.SellerAmountSatoshis != buyerLatest.SellerAmountSatoshis+100 {
		t.Fatalf("round-two cumulative amount = %d, want %d", signed2.State.SellerAmountSatoshis, buyerLatest.SellerAmountSatoshis+100)
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
	runClaimID := mustClaimIDOf(t, rawKind8)
	custodyKey := mustHex(t, runClaimID[:])
	record := store.recordOf(custodyKey)
	if record == nil || record.responseBytes == nil || !store.retrievable(custodyKey) {
		t.Fatal("custody record did not reach the Retrievable state")
	}
	return rawKind8, record.responseBytes
}

// assertSignedUnavailable 校验 not_received/not_ready 分支的协议真值：
// 四元 [1,11,...] 外壳、Arbiter 统一签名、请求 ID 绑定、无附件、原因正确。
func assertSignedUnavailable(t *testing.T, f *protocolFixture, request10A *arbitration.ContentRetrievalRequest, rawKind11 []byte, wantReason arbitration.ContentRetrievalUnavailableReason) {
	t.Helper()
	if len(rawKind11) < 3 || rawKind11[0] != 0x84 || rawKind11[1] != 0x01 || rawKind11[2] != 0x0b {
		t.Fatalf("unavailable Kind 11 must be a four-element [1,11,...] array: %x", rawKind11)
	}
	response, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	if response.ContentPayloadsCBOR != nil {
		t.Fatal("unavailable Kind 11 carried an attachment")
	}
	result, err := arbitration.VerifyContentRetrievalResponse(request10A, f.completed.Opening.ArbiterPublicKey, response)
	if err != nil {
		t.Fatalf("unavailable Kind 11 failed verification: %v", err)
	}
	if result.Available {
		t.Fatal("unavailable branch verified as available")
	}
	decoded, err := arbitration.DecodeContentRetrievalResultDocument(response.ContentRetrievalResultCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.UnavailableReason != wantReason {
		t.Fatalf("unavailable reason = %d, want %d", decoded.UnavailableReason, wantReason)
	}
}

func mustClaimIDBytes(t *testing.T, prepared *arbitration.PreparedPayment) []byte {
	t.Helper()
	id := prepared.ArbitrationClaimID()
	return append([]byte(nil), id[:]...)
}

func mustClaimIDOf(t *testing.T, rawKind8 []byte) protocol.ArbitrationClaimID {
	t.Helper()
	request, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := arbitration.ArbitrationClaimID(request.ArbitrationClaimCBOR)
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
	rawKind8, _ := store.runCustodyThroughKind9(t, f, request003)
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
	if !bytes.Contains(rawKind10, claimID[:]) {
		t.Fatal("Kind 10 does not route by the independently rebuilt Claim ID")
	}
	rawKind11, err := store.handleContentRetrieval(rawKind10, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	retrievalResponse, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	verifiedResult, err := arbitration.VerifyContentRetrievalResponse(retrievalRequest, f.completed.Opening.ArbiterPublicKey, retrievalResponse)
	if err != nil {
		t.Fatalf("Kind 11 failed verification against the buyer request: %v", err)
	}
	if !verifiedResult.Available || !bytes.Equal(verifiedResult.PayloadsCBOR, mustDecodeKind8(t, rawKind8).ContentPayloadsCBOR) {
		t.Fatal("Kind 11 payload attachment does not bind the custodied bundle")
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
	if verified.ArbitrationClaimID != claimID || verified.ContentRetrievalRequestID != protocol.ContentRetrievalRequestID(requestIDOf(t, retrievalRequest)) {
		t.Fatal("verified audit data does not bind the Claim ID and request ID")
	}
	if !samePaymentStateForIntegration(previousSnapshot, f.completed.InitialPayment) {
		t.Fatal("acceptance changed the previous payment state")
	}
}

func requestIDOf(t *testing.T, request *arbitration.ContentRetrievalRequest) []byte {
	t.Helper()
	digest := sha256.Sum256(request.ContentRetrievalRequestCBOR)
	return digest[:]
}

func samePaymentStateForIntegration(left, right *pool.PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID && left.PaymentSequence == right.PaymentSequence && left.SellerAmountSatoshis == right.SellerAmountSatoshis && bytes.Equal(left.RawTx, right.RawTx)
}

// TestBuyerRetrievalResponsesAndApplicationErrorChannels pins every
// response branch and application-level failure path: the three signed Kind 11
// answers (not_received / not_ready / available), replay of the first
// persisted answer, Unauthorized, concurrent identical requests resolving to
// one committed response, new-nonce retry after an explicit not_ready,
// retention Gone, and corrupted storage.
func TestBuyerRetrievalResponsesAndApplicationErrorChannels(t *testing.T) {
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
	buildChain := func(deadline time.Time) (*bitfs.SignedContentRequest, protocol.ArbitrationClaimID) {
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
	preparedOnly, err := f.arbiter.PreparePayment(f.ctx, mustDecodeKind8(t, mustMarshalKind8ForRetrieval(t, f, requestA)), f.facts(), arbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	store.putRecord(&arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), mustMarshalKind8ForRetrieval(t, f, requestA)...),
		claimID:               preparedOnly.ArbitrationClaimID(),
		arbiterAmountSatoshis: preparedOnly.ArbiterAmountSatoshis(),
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
	// not_ready 现在是 Arbiter 签名的四元 Kind 11：可验签、绑定请求 ID、无附件。
	// 该回答同时原子占用了 (ClaimID, NonceA) 并持久化为该请求的唯一答案。
	notReadyRaw, err := store.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatalf("NotReady path returned an application error: %v", err)
	}
	assertSignedUnavailable(t, f, kind10A, notReadyRaw, arbitration.RetrievalSellerArbitrationNotReady)

	// 同一 content_retrieval_request_id 立即重放：原样返回第一次持久化的
	// not_ready，而不是重新评估或返回瞬态占用错误。
	replayedNotReady, err := store.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayedNotReady, notReadyRaw) {
		t.Fatal("not_ready replay did not return the first persisted response")
	}

	// 完成签署后同一请求仍必须得到同一份 not_ready：曾经捕获的 Kind 10 永远
	// 不能在状态变化后升级为下载授权；Buyer 必须换新 nonce。
	if _, err := store.handleArbitrationRequest(mustMarshalKind8ForRetrieval(t, f, requestA), f.arbiter, f.facts()); err != nil {
		t.Fatal(err)
	}
	if !store.retrievable(hex.EncodeToString(claimIDA[:])) {
		t.Fatal("custody record did not become retrievable after Kind 9 signing")
	}
	upgraded, err := store.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(upgraded, notReadyRaw) {
		t.Fatal("a captured not_ready request became a download authorization after the record turned ready")
	}
	assertSignedUnavailable(t, f, kind10A, upgraded, arbitration.RetrievalSellerArbitrationNotReady)

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
	kind10AClaimID, _, decodeErr := arbitration.DecodeContentRetrievalRequestDocument(kind10A.ContentRetrievalRequestCBOR)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	forgeDoc, forgeDocErr := arbitration.EncodeContentRetrievalRequestDocument(kind10AClaimID, forgeNonce)
	if forgeDocErr != nil {
		t.Fatal(forgeDocErr)
	}
	badSig, sigErr := protocol.SignWireDocument(integrationKey(t, "44"), protocol.WireVersion, 10, forgeDoc)
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	forgeRequest = &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: forgeDoc, BuyerContentRetrievalRequestSignature: badSig}
	if _, err := store.handleContentRetrieval(mustMarshalKind10(t, forgeRequest), f.arbiter, f.arbiterKey); !errors.Is(err, errRetrievalUnauthorized) {
		t.Fatalf("Unauthorized error = %v", err)
	}
	store.mu.Lock()
	polluted := false
	for nonceKey := range store.servedResponses {
		if strings.HasSuffix(nonceKey, ":"+hex.EncodeToString(forgeNonce)) {
			polluted = true
		}
	}
	store.mu.Unlock()
	if polluted {
		t.Fatal("a failed-signature request polluted the nonce table")
	}

	// 新 nonce 重试：retention 期内唯一合法的再次取回路径。
	retryNonce := bytes.Repeat([]byte{0x33}, 32)
	kind10Retry, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, requestA, retryNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw10Retry, err := arbitration.MarshalContentRetrievalRequest(kind10Retry)
	if err != nil {
		t.Fatal(err)
	}
	first11, err := store.handleContentRetrieval(raw10Retry, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	firstParsed, parsedErr := arbitration.UnmarshalContentRetrievalResponse(first11)
	if parsedErr != nil {
		t.Fatal(parsedErr)
	}
	if len(firstParsed.ContentPayloadsCBOR) == 0 {
		t.Fatal("fresh-nonce retrieval did not deliver payloads")
	}
	// Available 重放：同样原样重发第一次持久化的响应字节。
	replayAvailable, err := store.handleContentRetrieval(raw10Retry, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayAvailable, first11) {
		t.Fatal("available replay did not return the first persisted response verbatim")
	}

	// NotFound：未知 Claim ID。
	unknownClaimID := bytes.Repeat([]byte{0x7f}, 32)
	var typedUnknownID protocol.ArbitrationClaimID
	copy(typedUnknownID[:], unknownClaimID)
	unknownDoc, err := arbitration.EncodeContentRetrievalRequestDocument(typedUnknownID, nonceA)
	if err != nil {
		t.Fatal(err)
	}
	sigUnknown, err := protocol.SignWireDocument(f.buyerKey, protocol.WireVersion, 10, unknownDoc)
	if err != nil {
		t.Fatal(err)
	}
	unknownRequest := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: unknownDoc, BuyerContentRetrievalRequestSignature: sigUnknown}
	// not_received：没有 Claim，无法鉴权 Buyer；仍返回签名的最小四元 Kind 11。
	// 明确例外：不占用 nonce、不持久化响应；生产实现必须限流。
	notFoundRaw, nfErr := store.handleContentRetrieval(mustMarshalKind10(t, unknownRequest), f.arbiter, f.arbiterKey)
	if nfErr != nil {
		t.Fatalf("NotFound path returned an application error: %v", nfErr)
	}
	assertSignedUnavailable(t, f, unknownRequest, notFoundRaw, arbitration.RetrievalSellerArbitrationNotReceived)
	store.mu.Lock()
	if len(store.servedResponses) != 2 {
		store.mu.Unlock()
		t.Fatalf("not_received must not write any state: served=%d", len(store.servedResponses))
	}
	store.mu.Unlock()

	// Gone：留存期结束并安全删除后返回 Gone；nonce 记录保留，已持久化的
	// 首次响应随内容一起删除——删除后重放不再泄露 payload。tombstone 保留
	// Claim/角色公钥关联；先完成 Buyer 鉴权再返回签名的四元 Kind 11，
	// 绝不泄露任何 payload 或记录元数据。
	store.expireRetention(claimIDA)
	goneRaw, goneErr := store.handleContentRetrieval(raw10Retry, f.arbiter, f.arbiterKey)
	if goneErr != nil {
		t.Fatalf("Gone path returned an application error: %v", goneErr)
	}
	assertSignedUnavailable(t, f, kind10Retry, goneRaw, arbitration.RetrievalCustodyGone)
	goneReplay, goneReplayErr := store.handleContentRetrieval(raw10Retry, f.arbiter, f.arbiterKey)
	if goneReplayErr != nil {
		t.Fatal(goneReplayErr)
	}
	if !bytes.Equal(goneReplay, goneRaw) {
		t.Fatal("gone replay did not return the first persisted response verbatim")
	}

	// 存储损坏：exact Kind 8 字节损坏时失败关闭，隔离记录。
	store2 := newMemoryArbitrationCustodyStore()
	raw8B, _ := store2.runCustodyThroughKind9(t, f, requestA)
	claimIDB := mustClaimIDOf(t, raw8B)
	recordB := store2.recordOf(hex.EncodeToString(claimIDB[:]))
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
	if _, err := store2.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey); !errors.Is(err, errCustodyCorrupt) {
		t.Fatalf("corruption error = %v", err)
	}
	recordB.requestBytes = savedCopy
	store2.putRecord(recordB)
	if _, err := store2.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey); err != nil {
		t.Fatalf("restored record still failed: %v", err)
	}

	// 并发相同 exact Kind 10：原子提交裁决唯一胜者；其余竞争者全部读取并
	// 返回首次提交的同一份 Kind 11 字节——绝不允许出现第二份不同的成功响应，
	// 也绝不向 Buyer 暴露瞬态占用错误。
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
	const racers = 8
	type raceOutcome struct {
		raw []byte
		err error
	}
	results := make(chan raceOutcome, racers)
	for index := 0; index < racers; index++ {
		go func() {
			raw, err := store3.handleContentRetrieval(raw10C, f.arbiter, f.arbiterKey)
			results <- raceOutcome{raw: raw, err: err}
		}()
	}
	var committedResponse []byte
	for index := 0; index < racers; index++ {
		outcome := <-results
		if outcome.err != nil {
			t.Fatalf("concurrent racer failed with %v", outcome.err)
		}
		if committedResponse == nil {
			committedResponse = outcome.raw
		}
		if !bytes.Equal(outcome.raw, committedResponse) {
			t.Fatal("concurrent identical requests observed more than one stored response")
		}
	}
	if committedResponse == nil {
		t.Fatal("no concurrent racer produced a response")
	}
	parsedC, parseCErr := arbitration.UnmarshalContentRetrievalResponse(committedResponse)
	if parseCErr != nil {
		t.Fatal(parseCErr)
	}
	if len(parsedC.ContentPayloadsCBOR) == 0 {
		t.Fatal("committed response did not deliver payloads")
	}
	store3.mu.Lock()
	servedCount := len(store3.servedResponses)
	store3.mu.Unlock()
	if servedCount != 1 {
		t.Fatalf("stored responses = %d, want exactly 1", servedCount)
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
// CustodyPrepared record into Retrievable (state-aware commit rebuilds the
// Available answer), retention deletion turns every answer into signed Gone.
// Every outcome must stay inside the declared error channels, the
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
	prepared, err := f.arbiter.PreparePayment(f.ctx, decoded, f.facts(), arbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	storeA.putRecord(&arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), rawKind8...),
		claimID:               prepared.ArbitrationClaimID(),
		arbiterAmountSatoshis: prepared.ArbiterAmountSatoshis(),
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
	// 记录就绪前的第一次询问：not_ready 被签名并持久化为该请求的唯一答案。
	notReadyAnswer, err := storeA.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	assertSignedUnavailable(t, f, kind10A, notReadyAnswer, arbitration.RetrievalSellerArbitrationNotReady)

	raceResult := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 200; attempt++ {
			// not_ready 之后必须换新 nonce：旧 nonce 的答案已持久化，永远
			// 不会再升级为可交付授权。
			attemptNonce := make([]byte, arbitration.RetrievalNonceBytes)
			if _, err := rand.Read(attemptNonce); err != nil {
				raceResult <- err
				return
			}
			attemptKind10, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, attemptNonce)
			if err != nil {
				raceResult <- err
				return
			}
			attemptRaw, err := arbitration.MarshalContentRetrievalRequest(attemptKind10)
			if err != nil {
				raceResult <- err
				return
			}
			raw11Race, err := storeA.handleContentRetrieval(attemptRaw, f.arbiter, f.arbiterKey)
			if err != nil {
				raceResult <- err
				return
			}
			// not_ready 分支返回无附件的签名 Kind 11；可交付分支带 payload。
			raceParsed, parseErr := arbitration.UnmarshalContentRetrievalResponse(raw11Race)
			if parseErr != nil {
				raceResult <- parseErr
				return
			}
			if raceParsed.ContentPayloadsCBOR != nil {
				raceResult <- nil
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		raceResult <- errors.New("custody record never became retrievable")
	}()
	response, err := f.arbiter.SignPreparedPayment(f.ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	rawKind9, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	storeA.appendResponse(hex.EncodeToString(claimID[:]), rawKind9)
	if err := <-raceResult; err != nil {
		t.Fatalf("retrieval racing with Kind 9 append failed outside the declared channels: %v", err)
	}
	// 记录就绪后重放就绪前的 Kind 10：仍必须得到同一份 not_ready——状态
	// 变化绝不把已应答的请求升级为 available。
	upgradedAnswer, err := storeA.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(upgradedAnswer, notReadyAnswer) {
		t.Fatal("a captured not_ready request was upgraded after the record became retrievable")
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
	raw11, err := storeA.handleContentRetrieval(raw10Retry, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatalf("fresh-nonce retrieval after readiness failed: %v", err)
	}
	// payload 唯一真值：附件必须逐字节等于托管 exact Kind 8 内的 bundle。
	storedRequest := mustDecodeKind8(t, storeA.recordOf(hex.EncodeToString(claimID[:])).requestBytes)
	parsed11, parseErr := arbitration.UnmarshalContentRetrievalResponse(raw11)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if !bytes.Equal(parsed11.ContentPayloadsCBOR, storedRequest.ContentPayloadsCBOR) {
		t.Fatal("Kind 11 attachment is not the exact persisted payload bundle")
	}

	// ---- 阶段 B：并发取件 vs retention 删除。----
	storeB := newMemoryArbitrationCustodyStore()
	storeB.putRecord(&arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), rawKind8...),
		claimID:               prepared.ArbitrationClaimID(),
		arbiterAmountSatoshis: prepared.ArbiterAmountSatoshis(),
	})
	storeB.appendResponse(hex.EncodeToString(claimID[:]), rawKind9)
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
	servedGone := 0
	var firstAvailable []byte
	for attempt := 0; attempt < 100; attempt++ {
		raw11B, err := storeB.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
		switch {
		case err == nil:
			parsed, parseErr := arbitration.UnmarshalContentRetrievalResponse(raw11B)
			if parseErr != nil {
				close(stop)
				t.Fatalf("race response failed strict decode: %v", parseErr)
			}
			if parsed.ContentPayloadsCBOR != nil {
				// 删除落地前的成功应答（含幂等重放）：同一请求永远只对应
				// 第一份持久化的 available 字节，绝不允许出现第二份。
				if firstAvailable == nil {
					firstAvailable = append([]byte(nil), raw11B...)
				} else if !bytes.Equal(raw11B, firstAvailable) {
					close(stop)
					t.Fatal("retention race produced a second distinct available response")
				}
			} else {
				// 删除落地后的竞争方得到签名的四元 gone Kind 11（nil error）。
				assertSignedUnavailable(t, f, kind10B, raw11B, arbitration.RetrievalCustodyGone)
				servedGone++
			}
		default:
			close(stop)
			t.Fatalf("retrieval racing with retention delete returned %v", err)
		}
	}
	close(stop)
	if servedGone == 0 {
		t.Log("retention delete landed after all race attempts; no signed-gone answer observed")
	}
	// 删除已落地时的最终安全属性：同请求重放绝不再泄露 payload，只能得到
	// 签名的四元 gone Kind 11（首次持久化响应已随内容一起删除）。
	storeB.mu.Lock()
	_, deleted := storeB.goneClaims[hex.EncodeToString(claimID[:])]
	storeB.mu.Unlock()
	if deleted {
		postRaw, postErr := storeB.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
		if postErr != nil {
			t.Fatalf("post-deletion replay error = %v", postErr)
		}
		postParsed, postParseErr := arbitration.UnmarshalContentRetrievalResponse(postRaw)
		if postParseErr != nil {
			t.Fatal(postParseErr)
		}
		if postParsed.ContentPayloadsCBOR != nil {
			t.Fatal("post-deletion replay leaked the cached available payload")
		}
		assertSignedUnavailable(t, f, kind10B, postRaw, arbitration.RetrievalCustodyGone)
	}
}

// TestAvailableServesOnlyEvidenceChainPayloads pins the single-truth rule for
// the 008 available branch: the attached bundle is byte-identical to the
// payload bundle inside the custodied exact Kind 8 evidence. A poisoned
// duplicate cache holding another valid-but-unrelated payload CBOR must never
// be signed — any divergence between stored bytes and the verified evidence
// chain fails closed before the arbiter produces a Kind 11 signature.
func TestAvailableServesOnlyEvidenceChainPayloads(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	store := newMemoryArbitrationCustodyStore()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, _ := store.runCustodyThroughKind9(t, f, request003)
	claimID := mustClaimIDOf(t, rawKind8)
	recordKey := hex.EncodeToString(claimID[:])

	// 模拟应用侧遗留的"第二份 payload 缓存"：一份与证据链无关、但自身完全
	// 合法（可严格解码、数量与块长合规）的 bundle。参考 handler 不存在任何
	// 会读取它的字段；签发来源只能是验证过的证据链字节。
	poisonCache, err := bitfs.EncodeContentPayloads([][]byte{[]byte("poisoned-duplicate-cache-payload")})
	if err != nil {
		t.Fatal(err)
	}

	nonce := bytes.Repeat([]byte{0x71}, 32)
	kind10, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonce)
	if err != nil {
		t.Fatal(err)
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(kind10)
	if err != nil {
		t.Fatal(err)
	}
	rawKind11, err := store.handleContentRetrieval(rawKind10, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	evidenceBundle := mustDecodeKind8(t, store.recordOf(recordKey).requestBytes).ContentPayloadsCBOR
	if !bytes.Equal(parsed.ContentPayloadsCBOR, evidenceBundle) {
		t.Fatal("available attachment is not the exact custodied evidence bundle")
	}
	if bytes.Equal(parsed.ContentPayloadsCBOR, poisonCache) {
		t.Fatal("handler served the poisoned duplicate cache instead of the verified evidence")
	}

	// 反向证明唯一防线：即使攻击者把持久化 Kind 8 内的 bundle 篡改成上述另
	// 一份合法 CBOR，证据链验证（payload hash ≠ Buyer 授权哈希）也必须在任何
	// Arbiter 签名之前失败关闭——错误内容永远得不到有效 Kind 11。
	tamperedRecord := store.recordOf(recordKey)
	tamperedRequest := mustDecodeKind8(t, tamperedRecord.requestBytes)
	tamperedRequest.ContentPayloadsCBOR = append([]byte(nil), poisonCache...)
	tamperedRecord.requestBytes, err = arbitration.MarshalRequest(tamperedRequest)
	if err != nil {
		t.Fatal(err)
	}
	store.putRecord(tamperedRecord)
	retryNonce := bytes.Repeat([]byte{0x72}, 32)
	kind10Retry, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, retryNonce)
	if err != nil {
		t.Fatal(err)
	}
	rawKind10Retry, err := arbitration.MarshalContentRetrievalRequest(kind10Retry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.handleContentRetrieval(rawKind10Retry, f.arbiter, f.arbiterKey); !errors.Is(err, errCustodyCorrupt) {
		t.Fatalf("tampered custody bundle error = %v, want errCustodyCorrupt before any signing", err)
	}
}

// TestKind11CommitAtomicityBarriers pins the atomic commit contract of the
// 008 available branch with deterministic barriers:
//
//  1. a candidate that fails to build/sign leaves zero residue — the nonce
//     stays free and the retry succeeds;
//  2. retention landing after the Available candidate was built but before
//     the transaction commits must discard the candidate signature and answer
//     (and persist) a signed Gone — deleted content never comes back;
//  3. N concurrent identical requests each building their own signature end
//     with exactly one stored response and byte-identical answers for all.
func TestKind11CommitAtomicityBarriers(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}

	buildKind10 := func(t *testing.T, nonce []byte) []byte {
		t.Helper()
		kind10, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonce)
		if err != nil {
			t.Fatal(err)
		}
		return mustMarshalKind10(t, kind10)
	}

	// ---- Barrier 1：候选构造失败不残留任何占用状态。----
	barrierStore := newMemoryArbitrationCustodyStore()
	preparedOnly, err := f.arbiter.PreparePayment(f.ctx, mustDecodeKind8(t, mustMarshalKind8ForRetrievalTest(t, f, request003)), f.facts(), arbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	barrierStore.putRecord(&arbitrationCustodyRecord{
		requestBytes:          mustMarshalKind8ForRetrievalTest(t, f, request003),
		claimID:               preparedOnly.ArbitrationClaimID(),
		arbiterAmountSatoshis: preparedOnly.ArbiterAmountSatoshis(),
	})
	nonceA := bytes.Repeat([]byte{0x21}, 32)
	raw10A := buildKind10(t, nonceA)
	// arbiterKey = nil 使锁外的签名构造必然失败（模拟签名服务不可用）。
	if _, err := barrierStore.handleContentRetrieval(raw10A, f.arbiter, nil); err == nil {
		t.Fatal("candidate construction unexpectedly succeeded without an arbiter key")
	}
	barrierStore.mu.Lock()
	residue := len(barrierStore.servedResponses)
	barrierStore.mu.Unlock()
	if residue != 0 {
		t.Fatalf("failed candidate left %d residue entries; the nonce would be permanently stuck", residue)
	}
	notReadyAnswer, err := barrierStore.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatalf("retry after failed candidate failed: %v", err)
	}
	kind10A := mustDecodeKind10ForBarrier(t, raw10A)
	assertSignedUnavailable(t, f, kind10A, notReadyAnswer, arbitration.RetrievalSellerArbitrationNotReady)

	// ---- Barrier 2：Available 构造完成、提交前触发 retention → 绝不返回 payload。----
	fullStore := newMemoryArbitrationCustodyStore()
	rawKind8, _ := fullStore.runCustodyThroughKind9(t, f, request003)
	claimID := mustClaimIDOf(t, rawKind8)
	nonceB := bytes.Repeat([]byte{0x22}, 32)
	raw10B := buildKind10(t, nonceB)
	fullStore.hookBeforeCommit = func() {
		// 确定性屏障：模拟候选签名完成后、事务提交前 retention 删除落地。
		fullStore.expireRetention(claimID)
	}
	rawKind11, err := fullStore.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatalf("post-retention commit returned an error: %v", err)
	}
	parsed, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ContentPayloadsCBOR != nil {
		t.Fatal("content was resurrected after retention deletion")
	}
	assertSignedUnavailable(t, f, mustDecodeKind10ForBarrier(t, raw10B), rawKind11, arbitration.RetrievalCustodyGone)
	nonceKey := hex.EncodeToString(claimID[:]) + ":" + hex.EncodeToString(nonceB)
	fullStore.mu.Lock()
	committed := append([]byte(nil), fullStore.servedResponses[nonceKey]...)
	fullStore.mu.Unlock()
	if !bytes.Equal(committed, rawKind11) {
		t.Fatal("the committed first answer is not the served gone response")
	}
	replayAfterDeletion, err := fullStore.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayAfterDeletion, committed) {
		t.Fatal("post-deletion replay diverged from the committed gone answer")
	}
	fullStore.hookBeforeCommit = nil

	// ---- Barrier 3：并发相同请求各自构造签名，只保存一份且逐字节一致。----
	concurrentStore := newMemoryArbitrationCustodyStore()
	_, _ = concurrentStore.runCustodyThroughKind9(t, f, request003)
	nonceC := bytes.Repeat([]byte{0x23}, 32)
	raw10C := buildKind10(t, nonceC)
	const racers = 12
	results := make(chan []byte, racers)
	errCh := make(chan error, racers)
	for index := 0; index < racers; index++ {
		go func() {
			raw, err := concurrentStore.handleContentRetrieval(raw10C, f.arbiter, f.arbiterKey)
			if err != nil {
				errCh <- err
				return
			}
			results <- raw
		}()
	}
	var committedResponse []byte
	for index := 0; index < racers; index++ {
		select {
		case err := <-errCh:
			t.Fatalf("concurrent racer failed: %v", err)
		case raw := <-results:
			if committedResponse == nil {
				committedResponse = raw
			}
			if !bytes.Equal(raw, committedResponse) {
				t.Fatal("racers observed different stored responses")
			}
		}
	}
	parsedCommitted, err := arbitration.UnmarshalContentRetrievalResponse(committedResponse)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedCommitted.ContentPayloadsCBOR) == 0 {
		t.Fatal("committed response did not deliver payloads")
	}
	concurrentStore.mu.Lock()
	storedCount := len(concurrentStore.servedResponses)
	concurrentStore.mu.Unlock()
	if storedCount != 1 {
		t.Fatalf("stored responses = %d, want exactly 1", storedCount)
	}

	// ---- Barrier 4：NotReady 候选构造完成后、提交前 Kind 9 落地。----
	// 状态感知提交必须放弃 NotReady 候选，基于新快照重建 Available——
	// 已 ready 的记录绝不允许继续回答 not_ready。
	nrStore := newMemoryArbitrationCustodyStore()
	rawKind8Prepared := mustMarshalKind8ForRetrievalTest(t, f, request003)
	preparedOnly, prepErr := f.arbiter.PreparePayment(f.ctx, mustDecodeKind8(t, rawKind8Prepared), f.facts(), arbitrationFeeSatoshis)
	if prepErr != nil {
		t.Fatal(prepErr)
	}
	nrStore.putRecord(&arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), rawKind8Prepared...),
		claimID:               preparedOnly.ArbitrationClaimID(),
		arbiterAmountSatoshis: preparedOnly.ArbiterAmountSatoshis(),
	})
	signedResponse, err := f.arbiter.SignPreparedPayment(f.ctx, preparedOnly)
	if err != nil {
		t.Fatal(err)
	}
	rawKind9Signed, err := arbitration.MarshalResponse(signedResponse)
	if err != nil {
		t.Fatal(err)
	}
	preparedClaimID := preparedOnly.ArbitrationClaimID()
	preparedClaimKey := hex.EncodeToString(preparedClaimID[:])
	nonceD := bytes.Repeat([]byte{0x24}, 32)
	kind10D, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonceD)
	if err != nil {
		t.Fatal(err)
	}
	raw10D := mustMarshalKind10(t, kind10D)
	nrStore.hookBeforeCommit = func() {
		// 确定性屏障：NotReady 候选已构造，事务提交前 Kind 9 落库。
		nrStore.appendResponse(preparedClaimKey, rawKind9Signed)
	}
	upgradedAnswer, err := nrStore.handleContentRetrieval(raw10D, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatalf("post-Kind9 commit returned an error: %v", err)
	}
	parsedUpgraded, err := arbitration.UnmarshalContentRetrievalResponse(upgradedAnswer)
	if err != nil {
		t.Fatal(err)
	}
	if parsedUpgraded.ContentPayloadsCBOR == nil {
		t.Fatal("a record that became complete was still answered with not_ready")
	}
	evidenceBundle := mustDecodeKind8(t, nrStore.recordOf(preparedClaimKey).requestBytes).ContentPayloadsCBOR
	if !bytes.Equal(parsedUpgraded.ContentPayloadsCBOR, evidenceBundle) {
		t.Fatal("rebuilt available did not bind the exact evidence bundle")
	}
	nonceDKey := preparedClaimKey + ":" + hex.EncodeToString(nonceD)
	nrStore.mu.Lock()
	storedUpgrade := append([]byte(nil), nrStore.servedResponses[nonceDKey]...)
	nrStore.mu.Unlock()
	if !bytes.Equal(storedUpgrade, upgradedAnswer) {
		t.Fatal("the committed first answer is not the rebuilt available response")
	}
	replayUpgrade, err := nrStore.handleContentRetrieval(raw10D, f.arbiter, f.arbiterKey)
	if err != nil || !bytes.Equal(replayUpgrade, storedUpgrade) {
		t.Fatalf("replay after upgraded answer diverged: %v", err)
	}
	nrStore.hookBeforeCommit = nil

	// ---- Barrier 5：NotReady 候选构造完成后、提交前 retention 删除。----
	// 状态感知提交必须改答并持久化签名的 Gone——删除后绝不回答 not_ready。
	ngStore := newMemoryArbitrationCustodyStore()
	ngPrepared, ngErr := f.arbiter.PreparePayment(f.ctx, mustDecodeKind8(t, rawKind8Prepared), f.facts(), arbitrationFeeSatoshis)
	if ngErr != nil {
		t.Fatal(ngErr)
	}
	ngClaimID := ngPrepared.ArbitrationClaimID()
	ngStore.putRecord(&arbitrationCustodyRecord{
		requestBytes:          append([]byte(nil), rawKind8Prepared...),
		claimID:               ngPrepared.ArbitrationClaimID(),
		arbiterAmountSatoshis: ngPrepared.ArbiterAmountSatoshis(),
	})
	nonceE := bytes.Repeat([]byte{0x25}, 32)
	kind10E, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonceE)
	if err != nil {
		t.Fatal(err)
	}
	raw10E := mustMarshalKind10(t, kind10E)
	ngStore.hookBeforeCommit = func() {
		// 确定性屏障：NotReady 候选已构造，事务提交前 retention 删除落地。
		ngStore.expireRetention(ngClaimID)
	}
	goneAfterDelete, err := ngStore.handleContentRetrieval(raw10E, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatalf("post-retention not_ready commit returned an error: %v", err)
	}
	assertSignedUnavailable(t, f, kind10E, goneAfterDelete, arbitration.RetrievalCustodyGone)
	nonceEKey := hex.EncodeToString(ngClaimID[:]) + ":" + hex.EncodeToString(nonceE)
	ngStore.mu.Lock()
	storedGone := append([]byte(nil), ngStore.servedResponses[nonceEKey]...)
	ngStore.mu.Unlock()
	if !bytes.Equal(storedGone, goneAfterDelete) {
		t.Fatal("the committed first answer is not the gone response")
	}
	ngStore.hookBeforeCommit = nil

	// ---- Barrier 6：重复执行 retention 不得删除 tombstone 状态下已提交的
	// Gone 应答——幂等重放在留存终止后继续生效。----
	goneReplay, err := fullStore.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	fullStore.expireRetention(mustClaimIDOf(t, rawKind8))
	goneReplayAgain, err := fullStore.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goneReplayAgain, goneReplay) {
		t.Fatal("repeated retention deleted the already committed gone answer")
	}

	// ---- Barrier 7：验证完成后、提交前同 Claim 存储字节被替换。----
	// 这不是 retention：绝不能降级成 custody_gone，必须报证据冲突，
	// 不占用 nonce、不落任何 Kind 11。
	conflictStore := newMemoryArbitrationCustodyStore()
	conflictRawKind8, _ := conflictStore.runCustodyThroughKind9(t, f, request003)
	conflictClaimID := mustClaimIDOf(t, conflictRawKind8)
	nonceG := bytes.Repeat([]byte{0x27}, 32)
	kind10G, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonceG)
	if err != nil {
		t.Fatal(err)
	}
	raw10G := mustMarshalKind10(t, kind10G)

	// 构造另一条完全合法的 Kind 8（不同 deadline -> 不同 Claim ID），
	// 再把它的字节塞进同一条 custody 键下：模拟存储冲突。
	otherInput := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(20 * time.Minute).Unix())}
	request003Other, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, otherInput)
	if err != nil {
		t.Fatal(err)
	}
	otherKind8 := mustMarshalKind8ForRetrievalTest(t, f, request003Other)
	conflictStore.hookBeforeCommit = func() {
		conflictStore.putRecord(&arbitrationCustodyRecord{
			requestBytes:          append([]byte(nil), otherKind8...),
			claimID:               conflictClaimID,
			arbiterAmountSatoshis: arbitrationFeeSatoshis,
		})
	}
	_, commitErr := conflictStore.handleContentRetrieval(raw10G, f.arbiter, f.arbiterKey)
	if !errors.Is(commitErr, errCustodyConflict) {
		t.Fatalf("storage conflict error = %v, want errCustodyConflict", commitErr)
	}
	nonceGKey := hex.EncodeToString(conflictClaimID[:]) + ":" + hex.EncodeToString(nonceG)
	conflictStore.mu.Lock()
	servedAfterConflict := len(conflictStore.servedResponses)
	_, occupied := conflictStore.servedResponses[nonceGKey]
	conflictStore.mu.Unlock()
	if servedAfterConflict != 0 || occupied {
		t.Fatal("a storage conflict persisted an answer or occupied the nonce")
	}
	conflictStore.hookBeforeCommit = nil

	// ---- Barrier 8：验证完成后、提交前记录无 tombstone 消失。----
	// 内部存储错误：绝不凭空签署 custody_gone。
	vanishStore := newMemoryArbitrationCustodyStore()
	vanishRawKind8, _ := vanishStore.runCustodyThroughKind9(t, f, request003)
	vanishClaimID := mustClaimIDOf(t, vanishRawKind8)
	nonceH := bytes.Repeat([]byte{0x28}, 32)
	kind10H, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, nonceH)
	if err != nil {
		t.Fatal(err)
	}
	raw10H := mustMarshalKind10(t, kind10H)
	vanishClaimKey := hex.EncodeToString(vanishClaimID[:])
	vanishStore.hookBeforeCommit = func() {
		// 模拟内部存储故障：记录消失且没有任何 tombstone。
		vanishStore.mu.Lock()
		delete(vanishStore.records, vanishClaimKey)
		vanishStore.mu.Unlock()
	}
	_, vanishErr := vanishStore.handleContentRetrieval(raw10H, f.arbiter, f.arbiterKey)
	if !errors.Is(vanishErr, errInternalStorage) {
		t.Fatalf("vanishing-record error = %v, want errInternalStorage", vanishErr)
	}
	nonceHKey := vanishClaimKey + ":" + hex.EncodeToString(nonceH)
	vanishStore.mu.Lock()
	servedAfterVanish := len(vanishStore.servedResponses)
	_, occupiedVanish := vanishStore.servedResponses[nonceHKey]
	vanishStore.mu.Unlock()
	if servedAfterVanish != 0 || occupiedVanish {
		t.Fatal("an internal storage error persisted an answer or occupied the nonce")
	}
}

// mustMarshalKind8ForRetrievalTest builds the exact raw Kind 8 for request003.
func mustMarshalKind8ForRetrievalTest(t *testing.T, f *protocolFixture, request003 *bitfs.SignedContentRequest) []byte {
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

func mustDecodeKind10ForBarrier(t *testing.T, raw []byte) *arbitration.ContentRetrievalRequest {
	t.Helper()
	request, err := arbitration.UnmarshalContentRetrievalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
