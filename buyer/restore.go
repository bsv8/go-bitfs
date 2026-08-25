package buyer

import (
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

func wireParseAsKind2(raw []byte) (wire.Artifact, error) {
	return wire.ParseAs(wire.RefundPresignRequest, raw)
}

func wireParseAsKind5(raw []byte) (wire.Artifact, error) {
	return wire.ParseAs(wire.ContentRequest, raw)
}

// RestoreOpeningCheckpoint 从应用持久化的 exact evidence（exact Kind 2 bytes +
// 资金交易原文）恢复开池 checkpoint：严格解析、退款模板 canonical 重建与买方
// 对模板的交易签名全量验证，并重新派生 RefundTemplateTxID——不信任持久化的
// 派生字段。
func RestoreOpeningCheckpoint(rawKind2 []byte, fundingTransactionRaw []byte) (*OpeningCheckpoint, error) {
	const op = "buyer.RestoreOpeningCheckpoint"
	artifact, err := wire.ParseAs(wire.RefundPresignRequest, rawKind2)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		return nil, err
	}
	if len(fundingTransactionRaw) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 2, "funding_transaction_raw", "funding transaction bytes are required")
	}
	// 完整请求证据验证：结构、角色、canonical 模板重建与买方交易签名。
	if err := pool.VerifyRefundPresignRequestEvidence(request); err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 2, "request")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyFundingTx(append([]byte(nil), fundingTransactionRaw...), &pool.OpeningProof{RefundTemplateRaw: request.RefundTemplateRaw, BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey, MinerFeeRateSatoshisPerKilobyte: request.MinerFeeRateSatoshisPerKilobyte}); err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 2, "funding_transaction_raw")
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	return &OpeningCheckpoint{refundTemplateTxID: refundTemplateTxID, request: request, fundingTransactionRaw: append([]byte(nil), fundingTransactionRaw...)}, nil
}

// RestorePoolCheckpoint 从 exact evidence（canonical opening proof 编码 + 当前
// 完整付款状态 raw tx）恢复池 checkpoint：opening 全量重验（签名/关系），付款
// 状态经完整双签名验证路径解析——伪造或错池证据都会被拒绝，不信任任何派生字段。
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error) {
	const op = "buyer.RestorePoolCheckpoint"
	opening, err := pool.DecodeOpeningProof(openingProofCBOR)
	if err != nil {
		return nil, err
	}
	if _, err := pool.VerifyOpeningProof(opening); err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "opening_proof")
	}
	state, err := engineParsedPaymentState(opening, paymentRawTx)
	if err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if state.State().RefundTemplateTxID != details.RefundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 0, "payment_state", "restored payment belongs to another pool")
	}
	return &PoolCheckpoint{opening: opening, payment: state.State()}, nil
}

// engineParsedPaymentState 经完整签名验证路径解析付款状态（Buyer+Seller 或
// Seller+Arbiter 双签任一成立）。
func engineParsedPaymentState(opening *pool.OpeningProof, paymentRawTx []byte) (*pool.VerifiedSignedTransaction, error) {
	return pool.VerifySignedTransaction(paymentRawTx, opening)
}

// RestoreAuthorizationCheckpoint 从完整本地证据（exact Kind 1 + exact Kind 5 +
// canonical opening proof）恢复授权 checkpoint：执行时间无关的 003 全链验证
// （报价证据与卖方签名、池绑定、买方统一签名、FileQuoteTermsID 与角色绑定），
// 并重算 typed ID。报价过期判断由调用方用显式事实完成；后续消费点会再次用
// 当时的事实做时间门禁。
func RestoreAuthorizationCheckpoint(rawKind1 []byte, rawKind5 []byte, openingProofCBOR []byte) (*AuthorizationCheckpoint, error) {
	const op = "buyer.RestoreAuthorizationCheckpoint"
	quoteArtifact, err := wire.ParseAs(wire.FileQuote, rawKind1)
	if err != nil {
		return nil, err
	}
	quote, err := wire.DecodeFileQuote(quoteArtifact)
	if err != nil {
		return nil, err
	}
	opening, err := pool.DecodeOpeningProof(openingProofCBOR)
	if err != nil {
		return nil, err
	}
	requestArtifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeContentRequest(requestArtifact)
	if err != nil {
		return nil, err
	}
	if _, _, err := content.VerifyContentRequestEvidence(request, quote, opening); err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 5, "authorization_evidence")
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	return &AuthorizationCheckpoint{authorizationID: authID, request: request}, nil
}
