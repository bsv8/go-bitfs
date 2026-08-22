package pool

import (
	"bytes"
	"context"
	"fmt"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
)

// DeriveRefundTemplateTxID returns the stable pool correlation ID: the
// canonical transaction ID of the unsigned presigned refund template carried by
// the OpeningProof. Transaction identity is calculated by the fixed SDK
// transaction parser; applications do not supply a calculator. The merged,
// broadcastable refund transaction has a different on-chain txid; that final
// txid is a submission result and never replaces RefundTemplateTxID.
func DeriveRefundTemplateTxID(_ context.Context, proof *OpeningProof) (RefundTemplateTxID, error) {
	if proof == nil {
		return RefundTemplateTxID{}, fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return RefundTemplateTxID{}, err
	}
	if err := validateRefundTemplate(proof.RefundTx, proof.BuyerPubKey, proof.SellerPubKey, proof.ArbiterPubKey, proof.MinerFeeRateSatPerKB); err != nil {
		return RefundTemplateTxID{}, err
	}
	// 模板字节不直接编码费率；当资金交易已交付时，用资金池输出的实际金额
	// 与按该费率重建的规范池金额交叉锁定费率。
	if len(proof.FundingTx) > 0 {
		engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
		if err != nil {
			return RefundTemplateTxID{}, err
		}
		if err := engine.VerifyFundingTx(nil, proof.FundingTx, proof); err != nil {
			return RefundTemplateTxID{}, fmt.Errorf("%w: funding transaction does not pin the template fee: %v", ErrInvalidEvidence, err)
		}
	}
	return refundTemplateTxIDFromBytes(proof.RefundTx)
}

// DeriveRefundTemplateTxIDFromRequest derives the same pool correlation ID
// directly from a 0201 RefundPresignRequest, before any OpeningProof exists. It
// shares the single canonical parse and TxID calculation with
// DeriveRefundTemplateTxID, so both entries return byte-identical values for
// the same RefundTx.
func DeriveRefundTemplateTxIDFromRequest(request *RefundPresignRequest) (RefundTemplateTxID, error) {
	if request == nil {
		return RefundTemplateTxID{}, fmt.Errorf("%w: refund presign request is required", ErrInvalidEvidence)
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return RefundTemplateTxID{}, err
	}
	if err := validateRefundTemplate(request.RefundTx, request.BuyerPubKey, request.SellerPubKey, request.ArbiterPubKey, request.MinerFeeRateSatPerKB); err != nil {
		return RefundTemplateTxID{}, err
	}
	return refundTemplateTxIDFromBytes(request.RefundTx)
}

// validateRefundTemplate 是唯一的协议级退款模板验证：以 RefundTx 原文、三个
// 角色压缩公钥和矿工费率为输入，按 MultisigPool v4 规则重建规范开池状态并逐
// 字节比较。它覆盖规范编码、单输入固定花费资金池输出 0、解锁脚本为空、三输
// 出的角色脚本与顺序、金额与费率、sequence 与 nLockTime。模板身份验证不要
// 求 Seller 签名已存在，但不跳过任何结构与角色验证。
func validateRefundTemplate(refundTx []byte, buyerPubKey, sellerPubKey, arbiterPubKey []byte, minerFeeRateSatPerKB uint64) error {
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: buyerPubKey, SellerPubKey: sellerPubKey, ArbiterPubKey: arbiterPubKey})
	if err != nil {
		return err
	}
	request := &RefundPresignRequest{
		Version: MajorVersion, RefundTx: refundTx,
		BuyerPubKey: buyerPubKey, SellerPubKey: sellerPubKey, ArbiterPubKey: arbiterPubKey,
		MinerFeeRateSatPerKB: minerFeeRateSatPerKB,
	}
	_, err = engine.deriveRefundPresignTerms(request)
	return err
}

// refundTemplateTxIDFromBytes computes the ID only after the caller has run
// the full protocol template validation; it re-parses canonically and copies
// the fixed SDK TxID bytes without reversing their display order.
func refundTemplateTxIDFromBytes(refundTx []byte) (RefundTemplateTxID, error) {
	if len(refundTx) == 0 {
		return RefundTemplateTxID{}, fmt.Errorf("%w: refund transaction is required", ErrInvalidEvidence)
	}
	value, err := parseCanonicalTransaction(refundTx)
	if err != nil {
		return RefundTemplateTxID{}, err
	}
	computed := RefundTemplateTxID(value.TxID().CloneBytes())
	if computed == (RefundTemplateTxID{}) {
		return RefundTemplateTxID{}, fmt.Errorf("%w: refund template transaction ID is zero", ErrInvalidEvidence)
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
		BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey,
	})
	if err != nil {
		return nil, err
	}
	return engine.deriveOpeningDetails(proof)
}

// 以下 Opening* 方法实现 bitfs.PoolOpeningEvidence：bitfs 验证 003 池绑定
// 时只需要角色公钥与统一关联 ID 的只读视图，bitfs 不反向依赖本包。
// OpeningRefundTemplateTxID 在证据无效时返回 nil，由调用方按长度拒绝。

func (proof *OpeningProof) OpeningBuyerPubKey() []byte {
	if proof == nil {
		return nil
	}
	return proof.BuyerPubKey
}

func (proof *OpeningProof) OpeningSellerPubKey() []byte {
	if proof == nil {
		return nil
	}
	return proof.SellerPubKey
}

func (proof *OpeningProof) OpeningArbiterPubKey() []byte {
	if proof == nil {
		return nil
	}
	return proof.ArbiterPubKey
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
	value, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(value.Bytes(), raw) {
		return nil, fmt.Errorf("%w: transaction encoding is not canonical", ErrInvalidEvidence)
	}
	return value, nil
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
