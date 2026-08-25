package pool

import (
	"bytes"

	"github.com/bsv8/go-bitfs/protocol"
)

// VerifiedOpening 是字段私有、访问器防御性复制的已验证开池证明：它证明退款
// 模板结构、角色脚本、买卖双方退款签名与（若已交付）资金交易关系全部正确。
// 它不拥有存储或网络行为；应用自行持久化 exact evidence 并负责广播边界。
type VerifiedOpening struct {
	proof *OpeningProof
}

// newVerifiedOpening 是包内唯一构造入口：只能在完整验证成功后调用。
func newVerifiedOpening(proof *OpeningProof) (*VerifiedOpening, error) {
	if proof == nil {
		return nil, protocol.Errorf("pool.VerifyOpeningProof", protocol.CodeInvalidEvidence, 0, "opening_proof", "opening proof is required")
	}
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, protocol.Wrap(err, "pool.VerifyOpeningProof", protocol.CodeInvalidEvidence, 0, "opening_proof")
	}
	return &VerifiedOpening{proof: cloneOpeningProof(proof)}, nil
}

// VerifyOpeningProof 对开池证据执行完整协议验证：退款模板 canonical 重建、
// 角色脚本、买卖双方退款签名与（若已交付）资金交易关系。伪造或篡改的
// OpeningProof 无法得到 VerifiedOpening。角色归属绑定由调用方补充检查。
func VerifyOpeningProof(proof *OpeningProof) (*VerifiedOpening, error) {
	return newVerifiedOpening(proof)
}

// Proof 返回深拷贝的完整开池证据（含全部公钥、签名与交易原文）。
func (v *VerifiedOpening) Proof() *OpeningProof {
	if v == nil || v.proof == nil {
		return nil
	}
	return cloneOpeningProof(v.proof)
}

// RefundTemplateTxID 返回派生的费用池统一关联 ID。
func (v *VerifiedOpening) RefundTemplateTxID() RefundTemplateTxID {
	if v == nil || v.proof == nil {
		return RefundTemplateTxID{}
	}
	details, err := DeriveOpeningDetails(v.proof)
	if err != nil {
		return RefundTemplateTxID{}
	}
	return details.RefundTemplateTxID
}

// BuyerPublicKey 返回买方压缩公钥副本。
func (v *VerifiedOpening) BuyerPublicKey() []byte {
	if v == nil || v.proof == nil {
		return nil
	}
	return append([]byte(nil), v.proof.BuyerPublicKey...)
}

// SellerPublicKey 返回卖方压缩公钥副本。
func (v *VerifiedOpening) SellerPublicKey() []byte {
	if v == nil || v.proof == nil {
		return nil
	}
	return append([]byte(nil), v.proof.SellerPublicKey...)
}

// ArbiterPublicKey 返回仲裁方压缩公钥副本。
func (v *VerifiedOpening) ArbiterPublicKey() []byte {
	if v == nil || v.proof == nil {
		return nil
	}
	return append([]byte(nil), v.proof.ArbiterPublicKey...)
}

// FundingTransactionRaw 返回已交付资金交易的原始字节副本；未交付时为空。
func (v *VerifiedOpening) FundingTransactionRaw() []byte {
	if v == nil || v.proof == nil {
		return nil
	}
	return append([]byte(nil), v.proof.FundingTransactionRaw...)
}

// MatchesBuyer 报告该开池证明是否属于指定买方压缩公钥。
func (v *VerifiedOpening) MatchesBuyer(publicKey []byte) bool {
	if v == nil || v.proof == nil {
		return false
	}
	return bytes.Equal(v.proof.BuyerPublicKey, publicKey)
}

// MatchesSeller 报告该开池证明是否属于指定卖方压缩公钥。
func (v *VerifiedOpening) MatchesSeller(publicKey []byte) bool {
	if v == nil || v.proof == nil {
		return false
	}
	return bytes.Equal(v.proof.SellerPublicKey, publicKey)
}

// VerifiedPaymentState 是字段私有、访问器防御性复制的已验证付款状态：
// RawTx 必须是完整可验证交易；SDK 不声明节点接受或业务最新状态。
type VerifiedPaymentState struct {
	state *PaymentState
}

// newVerifiedPaymentState 是包内唯一构造入口：state 必须先通过完整签名与
// 关系验证。
func newVerifiedPaymentState(state *PaymentState) (*VerifiedPaymentState, error) {
	if state == nil || len(state.RawTx) == 0 {
		return nil, protocol.Errorf("pool.VerifyPaymentState", protocol.CodeInvalidEvidence, 0, "payment_state", "complete payment state is required")
	}
	return &VerifiedPaymentState{state: clonePaymentState(state)}, nil
}

// VerifyPaymentState 验证一份已合并付款状态在给定 opening 下密码学完整：
// 依次尝试普通 Buyer+Seller 与仲裁 Seller+Arbiter 两条完整签名路径；两者都
// 失败即拒绝。伪造的 PaymentState 无法得到 VerifiedPaymentState。
func VerifyPaymentState(state *PaymentState, proof *OpeningProof) (*VerifiedPaymentState, error) {
	const op = "pool.VerifyPaymentState"
	if state == nil || proof == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "payment_state", "payment state and opening proof are required")
	}
	engine, err := engineFromProof(proof)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyAcceptedPayment(state, proof); err != nil {
		if arbErr := engine.VerifyArbitratedPayment(state, proof); arbErr != nil {
			return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "payment_state")
		}
	}
	return newVerifiedPaymentState(state)
}

func engineFromProof(proof *OpeningProof) (*MultisigPoolEngine, error) {
	return NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
}

// State 返回深拷贝的付款状态（金额、序号、池身份与角色签名）。
func (v *VerifiedPaymentState) State() *PaymentState {
	if v == nil || v.state == nil {
		return nil
	}
	return clonePaymentState(v.state)
}

// RawTx 返回完整签名的付款状态交易原始字节副本。
func (v *VerifiedPaymentState) RawTx() []byte {
	if v == nil || v.state == nil {
		return nil
	}
	return append([]byte(nil), v.state.RawTx...)
}

// PaymentSequence 返回该状态的付款序号。
func (v *VerifiedPaymentState) PaymentSequence() protocol.PaymentSequence {
	if v == nil || v.state == nil {
		return 0
	}
	return protocol.PaymentSequence(v.state.PaymentSequence)
}

// SellerAmountSatoshis 返回卖方的绝对累计金额（绝对聪数）。
func (v *VerifiedPaymentState) SellerAmountSatoshis() protocol.Satoshis {
	if v == nil || v.state == nil {
		return 0
	}
	return protocol.Satoshis(v.state.SellerAmountSatoshis)
}

// BuyerAmountSatoshis 返回买方分配金额（绝对聪数）。
func (v *VerifiedPaymentState) BuyerAmountSatoshis() protocol.Satoshis {
	if v == nil || v.state == nil {
		return 0
	}
	return protocol.Satoshis(v.state.BuyerAmountSatoshis)
}

// ArbiterAmountSatoshis 返回仲裁方绝对分配额（绝对聪数）；普通付款恒为零。
func (v *VerifiedPaymentState) ArbiterAmountSatoshis() protocol.Satoshis {
	if v == nil || v.state == nil {
		return 0
	}
	return protocol.Satoshis(v.state.ArbiterAmountSatoshis)
}

// RefundTemplateTxID 返回所属费用池统一关联 ID。
func (v *VerifiedPaymentState) RefundTemplateTxID() RefundTemplateTxID {
	if v == nil || v.state == nil {
		return RefundTemplateTxID{}
	}
	return v.state.RefundTemplateTxID
}

// VerifiedSignedTransaction 是字段私有、访问器防御性复制的完整签名交易结果：
// 密码学签名已完成并经 SDK 自验/复核（Complete），但 SDK 绝不声称它已被节点
// 接受、已广播或已确认；广播与对账是应用的决定。
type VerifiedSignedTransaction struct {
	rawTx []byte
	state *PaymentState
}

// newVerifiedSignedTransaction 是包内唯一构造入口：只能由完成完整验证的
// 路径调用（VerifySignedTransaction 或引擎内部自验后的 merge 结果）。
func newVerifiedSignedTransaction(rawTx []byte, state *PaymentState) *VerifiedSignedTransaction {
	return &VerifiedSignedTransaction{rawTx: append([]byte(nil), rawTx...), state: clonePaymentState(state)}
}

// VerifySignedTransaction 解析并完整验证一笔 opening 约束下的完整签名交易
// （累计付款、立即关闭或到期退款提交）：逐字节解析、池 outpoint/输出关系、
// 双方角色签名全部复核。伪造 raw bytes 无法得到 VerifiedSignedTransaction；
// 广播与否仍由应用决定。
func VerifySignedTransaction(rawTx []byte, proof *OpeningProof) (*VerifiedSignedTransaction, error) {
	const op = "pool.VerifySignedTransaction"
	if proof == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "opening_proof", "opening proof is required")
	}
	engine, err := engineFromProof(proof)
	if err != nil {
		return nil, err
	}
	state, err := engine.ParsePaymentState(rawTx, proof)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "raw_tx")
	}
	if err := engine.VerifyAcceptedPayment(state, proof); err != nil {
		if arbErr := engine.VerifyArbitratedPayment(state, proof); arbErr != nil {
			return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "raw_tx")
		}
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	if state.RefundTemplateTxID != details.RefundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 0, "refund_template_txid", "transaction belongs to another pool")
	}
	return newVerifiedSignedTransaction(rawTx, state), nil
}

// CompleteArbitratedTransaction 是 007 收款合并的唯一原子入口：在 pool 内部
// 一次完成 Seller/Arbiter 双签名验证、canonical 合并与 Verified 构造。
// 它不依赖任何"调用前已验证"的顺序约定——双签名中任意一个无效都会整体失败，
// 不产生部分结果；成功返回的 VerifiedSignedTransaction 才代表密码学完整。
func CompleteArbitratedTransaction(unsigned *UnsignedPayment, sellerSignature, arbiterSignature []byte) (*VerifiedSignedTransaction, error) {
	const op = "pool.CompleteArbitratedTransaction"
	if unsigned == nil || len(unsigned.PoolLockingScript) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "unsigned", "arbitration candidate with its pool locking script is required")
	}
	engine, err := NewMultisigPoolEngineFromPoolLockingScript(unsigned.PoolLockingScript)
	if err != nil {
		return nil, err
	}
	signed, err := engine.MergeArbitratedPoolSellerArbiterSignatures(unsigned, sellerSignature, arbiterSignature)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidSignature, 9, "")
	}
	return newVerifiedSignedTransaction(signed.RawTx, &signed.State), nil
}

// VerifyRefundPresignRequestEvidence 完整验证 Kind 2 预签请求自身证据：
// 结构、角色、退款模板 canonical 重建与买方对模板的交易签名。恢复路径用它
// 保证 checkpoint 只能由真实证据重建。
func VerifyRefundPresignRequestEvidence(request *RefundPresignRequest) error {
	const op = "pool.VerifyRefundPresignRequestEvidence"
	if request == nil {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 2, "request", "refund presign request is required")
	}
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		return err
	}
	if _, err := engine.validateRefundPresignRequestAndBuyer(request); err != nil {
		return err
	}
	return nil
}

// RawTx 返回完整签名交易原始字节副本；仅供应用决定是否广播。
func (t *VerifiedSignedTransaction) RawTx() []byte {
	if t == nil {
		return nil
	}
	return append([]byte(nil), t.rawTx...)
}

// State 返回解析后的状态元数据深拷贝；可能为 nil（例如纯退款提交场景由
// 调用方自行解析）。
func (t *VerifiedSignedTransaction) State() *PaymentState {
	if t == nil {
		return nil
	}
	return clonePaymentState(t.state)
}

// PaymentSequence 返回状态序号；无状态元数据时返回 0。
func (t *VerifiedSignedTransaction) PaymentSequence() protocol.PaymentSequence {
	if t == nil || t.state == nil {
		return 0
	}
	return protocol.PaymentSequence(t.state.PaymentSequence)
}

// SellerAmountSatoshis 返回卖方累计金额（绝对聪数）；无状态元数据时返回 0。
func (t *VerifiedSignedTransaction) SellerAmountSatoshis() protocol.Satoshis {
	if t == nil || t.state == nil {
		return 0
	}
	return protocol.Satoshis(t.state.SellerAmountSatoshis)
}

// RefundTemplateTxID 返回所属费用池统一关联 ID。
func (t *VerifiedSignedTransaction) RefundTemplateTxID() RefundTemplateTxID {
	if t == nil || t.state == nil {
		return RefundTemplateTxID{}
	}
	return t.state.RefundTemplateTxID
}

var _ = protocol.ErrZeroIdentifier // 保留协议错误引用以维持依赖方向清晰
