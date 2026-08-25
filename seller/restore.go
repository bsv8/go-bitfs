package seller

import (
	"bytes"
	"fmt"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// RestoreOpeningCheckpoint 从 exact evidence（exact Kind 2 请求 bytes + exact
// Kind 3 响应 bytes）恢复卖方预签 checkpoint：请求侧做完整证据验证（结构、
// 角色、canonical 模板重建、买方交易签名），响应侧验证其关联 ID 与请求重派生
// 值一致、并确认其中的卖方签名确实覆盖该模板——预签证明只能由真实证据重建。
func RestoreOpeningCheckpoint(rawKind2 []byte, rawKind3 []byte) (*OpeningCheckpoint, error) {
	const op = "seller.RestoreOpeningCheckpoint"
	requestArtifact, err := wire.ParseAs(wire.RefundPresignRequest, rawKind2)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeRefundPresignRequest(requestArtifact)
	if err != nil {
		return nil, err
	}
	responseArtifact, err := wire.ParseAs(wire.RefundPresignResponse, rawKind3)
	if err != nil {
		return nil, err
	}
	response, err := wire.DecodeRefundPresignResponse(responseArtifact)
	if err != nil {
		return nil, err
	}
	if err := pool.VerifyRefundPresignRequestEvidence(request); err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 2, "request")
	}
	computedID, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	if response.RefundTemplateTxID != computedID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 3, "refund_template_txid", "persisted response does not match the request-derived correlation ID")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	// 卖方签名必须与持久化 Kind 3 一致且覆盖同一模板：BuildOpeningProof 内部
	// 完整验证 Seller 签名后产出预签证明。
	proof, err := engine.BuildOpeningProof(request, response.SellerRefundTransactionSignature, nil)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 3, "seller_signature")
	}
	return &OpeningCheckpoint{opening: proof}, nil
}

// RestorePoolCheckpoint 从 exact evidence（canonical opening proof 编码 + 当前
// 完整付款状态 raw tx）恢复池 checkpoint：opening 与付款状态都走完整签名验证
// 路径；角色归属绑定由后续操作用 Workflow 公钥再次强制执行。
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error) {
	const op = "seller.RestorePoolCheckpoint"
	opening, err := pool.DecodeOpeningProof(openingProofCBOR)
	if err != nil {
		return nil, err
	}
	if _, err := pool.VerifyOpeningProof(opening); err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "opening_proof")
	}
	state, err := pool.VerifySignedTransaction(paymentRawTx, opening)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "payment_raw_tx")
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if state.RefundTemplateTxID() != details.RefundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 0, "payment_state", "restored payment belongs to another pool")
	}
	return &PoolCheckpoint{opening: opening, payment: state.State()}, nil
}

// RestoreDeliveryCheckpoint 从本方生成并签署该交付时的完整 exact evidence
// （exact Kind 1 + canonical opening proof 编码 + exact 已签 Kind 5 + 本方发出
// 的 exact Kind 6）恢复交付 checkpoint，并做全量重验：
//   - 003 全链证据：报价证据与卖方签名、池绑定、买方统一签名、条款 ID 与角色绑定；
//   - 004 归属：content_delivery_cbor 绑定的授权 ID 与 Kind 5 重算值一致，
//     卖方对精确 content_delivery_cbor 的统一签名有效（证明本方确实签署过该交付）；
//   - 四个 checkpoint 字段全部从授权原文重派生，绝不信任持久化派生值。
func RestoreDeliveryCheckpoint(rawKind1, openingProofCBOR, rawKind5, rawKind6 []byte) (*DeliveryCheckpoint, error) {
	const op = "seller.RestoreDeliveryCheckpoint"
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
	// 003 全链时间无关证据重验。
	requestTerms, _, err := content.VerifyContentRequestEvidence(request, quote, opening)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 5, "authorization_evidence")
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	// 004 归属与本方签署证明。
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, rawKind6)
	if err != nil {
		return nil, err
	}
	delivery, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		return nil, err
	}
	deliveryAuthID, err := content.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		return nil, err
	}
	if deliveryAuthID != authID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 6, "content_delivery_cbor", "persisted delivery does not belong to this authorization")
	}
	if !bytes.Equal(opening.SellerPublicKey, quote.SellerPublicKey) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "seller_public_key", "opening and quote sellers disagree")
	}
	if err := protocol.VerifyWireDocument(opening.SellerPublicKey, protocol.WireVersion, 6, delivery.ContentDeliveryCBOR, delivery.SellerContentDeliverySignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("persisted delivery signature is not ours: %v", err), op, protocol.CodeInvalidSignature, 6, "seller_content_delivery_signature")
	}
	if len(delivery.ContentPayloadsCBOR) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "content_payloads_cbor", "persisted delivery carries no payload bundle")
	}
	if _, err := content.DecodeContentPayloads(delivery.ContentPayloadsCBOR); err != nil {
		return nil, err
	}
	if len(requestTerms.RefundTemplateTxID) != 32 {
		return nil, protocol.Errorf(op, protocol.CodeMalformedWire, 5, "refund_template_txid", "must be 32 bytes")
	}
	var refundTemplateTxID pool.RefundTemplateTxID
	copy(refundTemplateTxID[:], requestTerms.RefundTemplateTxID)
	return &DeliveryCheckpoint{
		refundTemplateTxID:        refundTemplateTxID,
		authorizationID:           authID,
		paymentSequence:           protocol.PaymentSequence(requestTerms.PaymentSequence),
		sellerAmountAfterSatoshis: protocol.Satoshis(requestTerms.SellerAmountAfterSatoshis),
	}, nil
}
