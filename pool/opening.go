package pool

import (
	"bytes"
	"encoding/binary"
	"fmt"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv8/go-bitfs/protocol"
)

// DeriveRefundTemplateTxID returns the stable pool correlation ID: the
// canonical transaction ID of the unsigned presigned refund template carried by
// the OpeningProof. Transaction identity is calculated by the fixed SDK
// transaction parser; applications do not supply a calculator. The merged,
// broadcastable refund transaction has a different on-chain txid; that final
// txid is a submission result and never replaces RefundTemplateTxID.
func DeriveRefundTemplateTxID(proof *OpeningProof) (RefundTemplateTxID, error) {
	if proof == nil {
		return RefundTemplateTxID{}, invalid("opening proof is required")
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return RefundTemplateTxID{}, err
	}
	if err := validateRefundTemplate(proof.RefundTemplateRaw, proof.BuyerPublicKey, proof.SellerPublicKey, proof.ArbiterPublicKey, proof.MinerFeeRateSatoshisPerKilobyte); err != nil {
		return RefundTemplateTxID{}, err
	}
	// 模板字节不直接编码费率；当资金交易已交付时，用资金池输出的实际金额
	// 与按该费率重建的规范池金额交叉锁定费率。
	if len(proof.FundingTransactionRaw) > 0 {
		engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
		if err != nil {
			return RefundTemplateTxID{}, err
		}
		if err := engine.VerifyFundingTx(proof.FundingTransactionRaw, proof); err != nil {
			return RefundTemplateTxID{}, protocol.Wrap(fmt.Errorf("funding transaction does not pin the template fee: %v", err), "pool.DeriveRefundTemplateTxID", protocol.CodeInvalidEvidence, 0, "funding_transaction_raw")
		}
	}
	return refundTemplateTxIDFromBytes(proof.RefundTemplateRaw)
}

// DeriveRefundTemplateTxIDFromRequest derives the same pool correlation ID
// directly from a 0201 RefundPresignRequest, before any OpeningProof exists. It
// shares the single canonical parse and TxID calculation with
// DeriveRefundTemplateTxID, so both entries return byte-identical values for
// the same RefundTemplateRaw.
func DeriveRefundTemplateTxIDFromRequest(request *RefundPresignRequest) (RefundTemplateTxID, error) {
	if request == nil {
		return RefundTemplateTxID{}, invalid("refund presign request is required")
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return RefundTemplateTxID{}, err
	}
	if err := validateRefundTemplate(request.RefundTemplateRaw, request.BuyerPublicKey, request.SellerPublicKey, request.ArbiterPublicKey, request.MinerFeeRateSatoshisPerKilobyte); err != nil {
		return RefundTemplateTxID{}, err
	}
	return refundTemplateTxIDFromBytes(request.RefundTemplateRaw)
}

// validateRefundTemplate 是唯一的协议级退款模板验证：以 RefundTemplateRaw 原文、三个
// 角色压缩公钥和矿工费率为输入，按 MultisigPool v4 规则重建规范开池状态并逐
// 字节比较。它覆盖规范编码、单输入固定花费资金池输出 0、解锁脚本为空、三输
// 出的角色脚本与顺序、金额与费率、sequence 与 nLockTime。模板身份验证不要
// 求 Seller 签名已存在，但不跳过任何结构与角色验证。
func validateRefundTemplate(refundTx []byte, buyerPubKey, sellerPubKey, arbiterPubKey []byte, minerFeeRateSatPerKB uint64) error {
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyerPubKey, SellerPublicKey: sellerPubKey, ArbiterPublicKey: arbiterPubKey})
	if err != nil {
		return err
	}
	request := &RefundPresignRequest{
		RefundTemplateRaw: refundTx,
		BuyerPublicKey:    buyerPubKey, SellerPublicKey: sellerPubKey, ArbiterPublicKey: arbiterPubKey,
		MinerFeeRateSatoshisPerKilobyte: minerFeeRateSatPerKB,
	}
	_, err = engine.deriveRefundPresignTerms(request)
	return err
}

// refundTemplateTxIDFromBytes computes the ID only after the caller has run
// the full protocol template validation; it re-parses canonically and copies
// the fixed SDK TxID bytes without reversing their display order.
func refundTemplateTxIDFromBytes(refundTx []byte) (RefundTemplateTxID, error) {
	if len(refundTx) == 0 {
		return RefundTemplateTxID{}, invalid("refund transaction is required")
	}
	value, err := parseCanonicalTransaction(refundTx)
	if err != nil {
		return RefundTemplateTxID{}, err
	}
	computed := RefundTemplateTxID(value.TxID().CloneBytes())
	if computed == (RefundTemplateTxID{}) {
		return RefundTemplateTxID{}, invalid("refund template transaction ID is zero")
	}
	return computed, nil
}

// DeriveOpeningDetails derives transaction identities and pool-output terms
// from the proof's transaction bytes and participant keys. The returned view
// is ephemeral and is never part of the transmitted OpeningProof.
func DeriveOpeningDetails(proof *OpeningProof) (*OpeningDetails, error) {
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{
		BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey,
	})
	if err != nil {
		return nil, err
	}
	return engine.deriveOpeningDetails(proof)
}

// 以下 Opening* 方法实现 bitfs.PoolOpeningEvidence：bitfs 验证 003 池绑定
// 时只需要角色公钥与统一关联 ID 的只读视图，bitfs 不反向依赖本包。
// OpeningRefundTemplateTxID 在证据无效时返回 nil，由调用方按长度拒绝。

func (proof *OpeningProof) OpeningBuyerPublicKey() []byte {
	if proof == nil {
		return nil
	}
	return proof.BuyerPublicKey
}

func (proof *OpeningProof) OpeningSellerPublicKey() []byte {
	if proof == nil {
		return nil
	}
	return proof.SellerPublicKey
}

func (proof *OpeningProof) OpeningArbiterPublicKey() []byte {
	if proof == nil {
		return nil
	}
	return proof.ArbiterPublicKey
}

func (proof *OpeningProof) OpeningRefundTemplateTxID() []byte {
	if proof == nil {
		return nil
	}
	details, err := DeriveOpeningDetails(proof)
	if err != nil {
		return nil
	}
	return append([]byte(nil), details.RefundTemplateTxID[:]...)
}

// parseCanonicalTransaction is the only parser used for protocol transaction
// identities.  The wire bytes themselves are the transaction identity: a
// parser that accepts an alternate CompactSize encoding must not silently
// canonicalize it before hashing or broadcasting.
func parseCanonicalTransaction(raw []byte) (*tx.Transaction, error) {
	if err := preflightTransactionRaw(raw); err != nil {
		return nil, err
	}
	value, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(value.Bytes(), raw) {
		return nil, protocol.Errorf("pool.parseCanonicalTransaction", protocol.CodeNonCanonical, 0, "raw_tx", "transaction encoding is not canonical")
	}
	return value, nil
}

// ValidateCloseTransactionRaw 在 direct API 与 wire API 共用的关池交易边界。
func ValidateCloseTransactionRaw(raw []byte) error {
	if len(raw) == 0 {
		return protocol.Errorf("pool.ValidateCloseTransactionRaw", protocol.CodeInvalidEvidence, 0, "close_transaction_raw", "close transaction is required")
	}
	if len(raw) > maxPoolCloseTransactionBytes {
		return protocol.Errorf("pool.ValidateCloseTransactionRaw", protocol.CodeMalformedWire, 0, "close_transaction_raw", "close transaction exceeds 65536 bytes")
	}
	parsed, err := parseCanonicalTransaction(raw)
	if err != nil {
		return err
	}
	if len(parsed.Inputs) != 1 || len(parsed.Outputs) != 3 {
		return protocol.Errorf("pool.ValidateCloseTransactionRaw", protocol.CodeInvalidEvidence, 0, "close_transaction_raw", "close transaction must have one input and three outputs")
	}
	return nil
}

// preflightTransactionRaw 在调用 SDK 交易解析器前验证所有 CompactSize
// 数量与脚本长度都落在输入字节范围内。SDK 的反序列化器会按声明长度 make
// 脚本切片，因此不可信的短交易必须先通过这里，不能把长度字段直接交给它。
// 10,000 个输入/输出是本 SDK 的资源上限，并非链上共识限制。
func preflightTransactionRaw(raw []byte) error {
	const op = "pool.parseCanonicalTransaction"
	malformed := func() error {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "raw_tx", "transaction length fields exceed available bytes")
	}
	if len(raw) < 4 {
		return malformed()
	}
	cursor := transactionCursor{raw: raw, offset: 4}
	inputCount, ok := cursor.readCompactSize()
	if !ok {
		return malformed()
	}
	const maxTransactionElements = 10000
	if inputCount > maxTransactionElements {
		return malformed()
	}
	var outputCount uint64
	extended := false
	if inputCount == 0 {
		outputCount, ok = cursor.readCompactSize()
		if !ok {
			return malformed()
		}
		if outputCount == 0 {
			if cursor.remaining() < 4 {
				return malformed()
			}
			marker := binary.BigEndian.Uint32(raw[cursor.offset : cursor.offset+4])
			cursor.offset += 4
			if marker != 0xEF {
				if cursor.remaining() != 0 {
					return malformed()
				}
				return nil
			}
			extended = true
			inputCount, ok = cursor.readCompactSize()
			if !ok {
				return malformed()
			}
			if inputCount > maxTransactionElements {
				return malformed()
			}
		}
	}

	minimumInputBytes := uint64(41)
	if extended {
		minimumInputBytes += 9
	}
	if inputCount > uint64(cursor.remaining())/minimumInputBytes {
		return malformed()
	}
	for index := uint64(0); index < inputCount; index++ {
		if !cursor.skip(36) { // 前序交易 ID 与输出索引
			return malformed()
		}
		unlockingLength, ok := cursor.readCompactSize()
		if !ok || !cursor.skipLength(unlockingLength) || !cursor.skip(4) { // 解锁脚本与 sequence
			return malformed()
		}
		if extended {
			if !cursor.skip(8) { // 被花费输出金额
				return malformed()
			}
			lockingLength, ok := cursor.readCompactSize()
			if !ok || !cursor.skipLength(lockingLength) {
				return malformed()
			}
		}
	}

	if inputCount > 0 || extended {
		outputCount, ok = cursor.readCompactSize()
		if !ok {
			return malformed()
		}
	}
	if cursor.remaining() < 4 || outputCount > maxTransactionElements || outputCount > uint64(cursor.remaining()-4)/9 {
		return malformed()
	}
	for index := uint64(0); index < outputCount; index++ {
		if !cursor.skip(8) { // 输出金额
			return malformed()
		}
		lockingLength, ok := cursor.readCompactSize()
		if !ok || !cursor.skipLength(lockingLength) {
			return malformed()
		}
	}
	if !cursor.skip(4) || cursor.remaining() != 0 { // nLockTime 必须是最后四字节
		return malformed()
	}
	return nil
}

// transactionCursor 只在已存在的 raw 字节上移动，不按输入中的长度分配内存。
type transactionCursor struct {
	raw    []byte
	offset int
}

func (cursor *transactionCursor) remaining() int { return len(cursor.raw) - cursor.offset }

func (cursor *transactionCursor) skip(length int) bool {
	if length < 0 || cursor.remaining() < length {
		return false
	}
	cursor.offset += length
	return true
}

func (cursor *transactionCursor) skipLength(length uint64) bool {
	if length > uint64(cursor.remaining()) {
		return false
	}
	cursor.offset += int(length)
	return true
}

func (cursor *transactionCursor) readCompactSize() (uint64, bool) {
	if cursor.remaining() < 1 {
		return 0, false
	}
	prefix := cursor.raw[cursor.offset]
	cursor.offset++
	switch prefix {
	case 0xfd:
		if cursor.remaining() < 2 {
			return 0, false
		}
		value := uint64(binary.LittleEndian.Uint16(cursor.raw[cursor.offset : cursor.offset+2]))
		cursor.offset += 2
		return value, true
	case 0xfe:
		if cursor.remaining() < 4 {
			return 0, false
		}
		value := uint64(binary.LittleEndian.Uint32(cursor.raw[cursor.offset : cursor.offset+4]))
		cursor.offset += 4
		return value, true
	case 0xff:
		if cursor.remaining() < 8 {
			return 0, false
		}
		value := binary.LittleEndian.Uint64(cursor.raw[cursor.offset : cursor.offset+8])
		cursor.offset += 8
		return value, true
	default:
		return uint64(prefix), true
	}
}

// ParseCanonicalTransaction parses a protocol transaction only when its raw
// bytes are the SDK's canonical serialization. Workflows use this before
// deriving outpoints, IDs, or signatures.
func ParseCanonicalTransaction(raw []byte) (*tx.Transaction, error) {
	return parseCanonicalTransaction(raw)
}

// RefundUsesBlockHeight deterministically classifies a refund locktime. It
// parses the supplied refund bytes and returns true for Bitcoin nLockTime
// values below the timestamp threshold; malformed bytes are rejected.
func RefundUsesBlockHeight(refundTx []byte) (bool, error) {
	value, err := parseCanonicalTransaction(refundTx)
	if err != nil {
		return false, fmt.Errorf("parse refund transaction: %w", err)
	}
	return value.LockTime < lockTimeTimestampThreshold, nil
}
