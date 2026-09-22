// Package seller 是内部测试兼容适配器：把卖方纯函数 API 包装成旧的“持有 Signer
// 的 workflow”形状，仅用于让既有安全测试继续以新实现为唯一底层执行。它不是
// SDK 公开面，也不进入发布文档。
package seller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	realseller "github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

// QuoteDraft 是真实公开草稿类型的别名。
type QuoteDraft = realseller.QuoteDraft

// Workflow 是测试用卖方会话：只固定 Signer 与公钥，不保存任何协议进度。
type Workflow struct {
	signer    protocol.Signer
	publicKey protocol.PublicKey
}

// NewWorkflow 固定并验证 Signer 公钥。
func NewWorkflow(signer protocol.Signer) (*Workflow, error) {
	if signer == nil {
		return nil, protocol.Errorf("seller.NewWorkflow", protocol.CodeSignerUnavailable, 0, "signer", "seller workflow requires a signer")
	}
	bound, err := protocol.BindSigner(signer)
	if err != nil {
		return nil, protocol.Wrap(err, "seller.NewWorkflow", protocol.CodeInvalidEvidence, 0, "signer")
	}
	return &Workflow{signer: bound, publicKey: bound.PublicKey()}, nil
}

// PublicKey 返回固定压缩公钥副本。
func (w *Workflow) PublicKey() []byte { return append([]byte(nil), w.publicKey[:]...) }

// QuoteResult 是旧形状的报价结果。
type QuoteResult struct {
	Outbound wire.Artifact
	Terms    *content.FileQuoteTerms
}

// CreateQuote 签署确定性 Kind 1。
func (w *Workflow) CreateQuote(ctx context.Context, facts protocol.Facts, draft QuoteDraft) (*QuoteResult, error) {
	outbound, terms, err := realseller.CreateQuote(ctx, facts, w.signer, draft)
	if err != nil {
		return nil, err
	}
	return &QuoteResult{Outbound: outbound, Terms: terms}, nil
}

// OpeningCheckpoint 保存卖方预签证据（旧形状）。
type OpeningCheckpoint struct {
	evidence realseller.SellerOpeningEvidence
}

// Opening 从 exact Kind 2/3 重建预签开池证明。
func (c *OpeningCheckpoint) Opening() *pool.OpeningProof {
	if c == nil {
		return nil
	}
	request, response, err := decodePresignPair(c.evidence)
	if err != nil {
		return nil
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		return nil
	}
	proof, err := engine.BuildOpeningProof(request, response.SellerRefundTransactionSignature, nil)
	if err != nil {
		return nil
	}
	return proof
}

// PreparePoolOpeningResult 是旧形状的预签结果。
type PreparePoolOpeningResult struct {
	Outbound   wire.Artifact
	Checkpoint *OpeningCheckpoint
}

// PreparePoolOpening 验证 exact Kind 2 并签署 exact Kind 3。
func (w *Workflow) PreparePoolOpening(ctx context.Context, rawKind2 []byte) (*PreparePoolOpeningResult, error) {
	outbound, evidence, err := realseller.PreparePresign(ctx, rawKind2, w.signer)
	if err != nil {
		return nil, err
	}
	return &PreparePoolOpeningResult{Outbound: outbound, Checkpoint: &OpeningCheckpoint{evidence: evidence}}, nil
}

// PoolCheckpoint 保存完整开池证明与当前链上付款状态（旧形状）。
type PoolCheckpoint struct {
	opening    *pool.OpeningProof
	payment    *pool.PaymentState
	paymentRaw []byte
}

// Opening 返回深拷贝的开池证据。
func (c *PoolCheckpoint) Opening() *pool.OpeningProof {
	if c == nil || c.opening == nil {
		return nil
	}
	return pool.CloneOpeningProof(c.opening)
}

// Payment 返回深拷贝的付款状态。
func (c *PoolCheckpoint) Payment() *pool.PaymentState {
	if c == nil || c.payment == nil {
		return nil
	}
	return pool.ClonePaymentState(c.payment)
}

// RefundTemplateTxID 返回费用池关联 ID。
func (c *PoolCheckpoint) RefundTemplateTxID() pool.RefundTemplateTxID {
	if c == nil || c.opening == nil {
		return pool.RefundTemplateTxID{}
	}
	details, err := pool.DeriveOpeningDetails(c.opening)
	if err != nil {
		return pool.RefundTemplateTxID{}
	}
	return details.RefundTemplateTxID
}

// VerifiedOpening 返回完整重验后的不可变开池证明。
func (c *PoolCheckpoint) VerifiedOpening() (*pool.VerifiedOpening, error) {
	if c == nil || c.opening == nil {
		return nil, protocol.Errorf("seller.PoolCheckpoint.VerifiedOpening", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is empty")
	}
	return pool.VerifyOpeningProof(c.opening)
}

// FundingVerificationResult 是旧形状的验资结果。
type FundingVerificationResult struct {
	Opening               *pool.VerifiedOpening
	InitialPool           *PoolCheckpoint
	FundingTransactionRaw []byte
}

// VerifyFundingDelivery 验收 exact Kind 4。
func (w *Workflow) VerifyFundingDelivery(checkpoint *OpeningCheckpoint, rawKind4 []byte) (*FundingVerificationResult, error) {
	if checkpoint == nil {
		return nil, protocol.Errorf("seller.VerifyFundingDelivery", protocol.CodeStateConflict, 4, "checkpoint", "persisted presign evidence is required")
	}
	proof := checkpoint.Opening()
	if proof == nil {
		return nil, protocol.Errorf("seller.VerifyFundingDelivery", protocol.CodeStateConflict, 4, "checkpoint", "persisted presign evidence is required")
	}
	if !bytes.Equal(w.publicKey[:], proof.SellerPublicKey) {
		return nil, protocol.Errorf("seller.VerifyFundingDelivery", protocol.CodeUnauthorized, 0, "seller_public_key", "workflow key does not match opening seller")
	}
	fundingRaw, evidence, err := realseller.VerifyFunding(rawKind4, checkpoint.evidence)
	if err != nil {
		return nil, err
	}
	verifiedOpening, err := pool.VerifyOpeningProof(evidence.Opening)
	if err != nil {
		return nil, err
	}
	initial, err := sellerPoolCheckpoint(evidence)
	if err != nil {
		return nil, err
	}
	return &FundingVerificationResult{Opening: verifiedOpening, InitialPool: initial, FundingTransactionRaw: fundingRaw}, nil
}

// DeliveryCommand 是旧形状的交付输入。
type DeliveryCommand struct {
	Quote           *content.SignedFileQuote
	Pool            *PoolCheckpoint
	RequestRaw      []byte
	ContentPayloads [][]byte
	Seed            []byte
}

// DeliveryCheckpoint 是旧形状的交付 checkpoint。
type DeliveryCheckpoint struct {
	refundTemplateTxID        pool.RefundTemplateTxID
	authorizationID           protocol.PaymentAuthorizationID
	paymentSequence           protocol.PaymentSequence
	sellerAmountAfterSatoshis protocol.Satoshis
	rawKind5                  []byte
	rawKind6                  []byte
}

// RefundTemplateTxID 返回所属费用池关联 ID。
func (c *DeliveryCheckpoint) RefundTemplateTxID() pool.RefundTemplateTxID {
	if c == nil {
		return pool.RefundTemplateTxID{}
	}
	return c.refundTemplateTxID
}

// AuthorizationID 返回本批次授权 typed ID。
func (c *DeliveryCheckpoint) AuthorizationID() protocol.PaymentAuthorizationID {
	if c == nil {
		return protocol.PaymentAuthorizationID{}
	}
	return c.authorizationID
}

// PaymentSequence 返回目标付款序号。
func (c *DeliveryCheckpoint) PaymentSequence() protocol.PaymentSequence {
	if c == nil {
		return 0
	}
	return c.paymentSequence
}

// SellerAmountAfterSatoshis 返回绝对累计卖方金额。
func (c *DeliveryCheckpoint) SellerAmountAfterSatoshis() protocol.Satoshis {
	if c == nil {
		return 0
	}
	return c.sellerAmountAfterSatoshis
}

// DeliveryResult 是旧形状的交付结果。
type DeliveryResult struct {
	Outbound   wire.Artifact
	Checkpoint *DeliveryCheckpoint
}

// DeliverContent 验收 exact Kind 5 并签署 exact Kind 6。
func (w *Workflow) DeliverContent(ctx context.Context, facts protocol.Facts, command DeliveryCommand) (*DeliveryResult, error) {
	if command.Quote == nil || command.Pool == nil {
		return nil, protocol.Errorf("seller.DeliverContent", protocol.CodeInvalidEvidence, 6, "command", "quote and pool checkpoint are required")
	}
	quoteArtifact, err := wire.EncodeFileQuote(command.Quote)
	if err != nil {
		return nil, err
	}
	outbound, evidence, err := realseller.PrepareDelivery(ctx, facts, realseller.DeliveryInput{
		QuoteRaw:        quoteArtifact.Bytes(),
		Pool:            command.Pool.evidence(),
		RequestRaw:      command.RequestRaw,
		ContentPayloads: command.ContentPayloads,
		Seed:            command.Seed,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	checkpoint, err := deliveryCheckpointFrom(evidence.RawKind5)
	if err != nil {
		return nil, err
	}
	checkpoint.rawKind5 = bytes.Clone(evidence.RawKind5)
	checkpoint.rawKind6 = bytes.Clone(evidence.RawKind6)
	return &DeliveryResult{Outbound: outbound, Checkpoint: checkpoint}, nil
}

// PaymentCommand 是旧形状的收款输入。
type PaymentCommand struct {
	Pool       *PoolCheckpoint
	Request    *content.SignedContentRequest
	UpdateRaw  []byte
	Checkpoint *DeliveryCheckpoint
}

// CompletePaymentResult 是旧形状的收款结果。
type CompletePaymentResult struct {
	Transaction *pool.VerifiedSignedTransaction
	NextPool    *PoolCheckpoint
}

// CompletePayment 验收 exact Kind 7 并合并完整付款交易。
func (w *Workflow) CompletePayment(ctx context.Context, facts protocol.Facts, command PaymentCommand) (*CompletePaymentResult, error) {
	if command.Pool == nil || command.Request == nil {
		return nil, protocol.Errorf("seller.CompletePayment", protocol.CodeInvalidEvidence, 7, "request", "original signed content request is required")
	}
	requestArtifact, err := wire.EncodeContentRequest(command.Request)
	if err != nil {
		return nil, err
	}
	deliveryEvidence := realseller.SellerDeliveryEvidence{}
	if command.Checkpoint != nil {
		deliveryEvidence.RawKind5 = bytes.Clone(command.Checkpoint.rawKind5)
		deliveryEvidence.RawKind6 = bytes.Clone(command.Checkpoint.rawKind6)
	}
	if len(deliveryEvidence.RawKind5) == 0 {
		deliveryEvidence.RawKind5 = requestArtifact.Bytes()
	}
	raw, evidence, err := realseller.CompletePayment(ctx, facts, realseller.CompletePaymentInput{
		Pool:       command.Pool.evidence(),
		Delivery:   deliveryEvidence,
		RequestRaw: requestArtifact.Bytes(),
		UpdateRaw:  command.UpdateRaw,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	verified, err := pool.VerifySignedTransaction(raw, evidence.Opening)
	if err != nil {
		return nil, err
	}
	next, err := sellerPoolCheckpoint(evidence)
	if err != nil {
		return nil, err
	}
	if next.payment != nil {
		if authID, authErr := content.PaymentAuthorizationID(command.Request.PaymentAuthorizationCBOR); authErr == nil {
			next.payment.PaymentAuthorizationID = authID
		}
	}
	return &CompletePaymentResult{Transaction: verified, NextPool: next}, nil
}

// CloseCommand 是旧形状的关池输入。
type CloseCommand struct {
	Pool           *PoolCheckpoint
	Unsigned       *pool.UnsignedPayment
	BuyerSignature []byte
}

// CompleteClose 验收买方关闭 candidate 并合并完整交易。
func (w *Workflow) CompleteClose(ctx context.Context, facts protocol.Facts, command CloseCommand) (*pool.VerifiedSignedTransaction, error) {
	if command.Pool == nil || command.Unsigned == nil {
		return nil, protocol.Errorf("seller.CompleteClose", protocol.CodeInvalidEvidence, 0, "unsigned_close", "unsigned close candidate is required")
	}
	raw, err := realseller.CompleteClose(ctx, facts, realseller.CompleteCloseInput{
		Pool:           command.Pool.evidence(),
		UnsignedRaw:    command.Unsigned.RawTx,
		BuyerSignature: command.BuyerSignature,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	return pool.VerifySignedTransaction(raw, command.Pool.opening)
}

// ArbitrationCommand 是旧形状的仲裁证据输入。
type ArbitrationCommand struct {
	Pool        *PoolCheckpoint
	Request     *content.SignedContentRequest
	DeliveryRaw []byte
}

// PrepareArbitration 构造并签署 exact Kind 8。
func (w *Workflow) PrepareArbitration(ctx context.Context, facts protocol.Facts, command ArbitrationCommand) (wire.Artifact, error) {
	if command.Pool == nil || command.Request == nil {
		return wire.Artifact{}, protocol.Errorf("seller.PrepareArbitration", protocol.CodeInvalidEvidence, 8, "command", "pool checkpoint and signed request are required")
	}
	requestArtifact, err := wire.EncodeContentRequest(command.Request)
	if err != nil {
		return wire.Artifact{}, err
	}
	outbound, _, err := realseller.PrepareArbitration(ctx, facts, realseller.PrepareArbitrationInput{
		Pool:        command.Pool.evidence(),
		RequestRaw:  requestArtifact.Bytes(),
		DeliveryRaw: command.DeliveryRaw,
	}, w.signer)
	return outbound, err
}

// ArbitratedPaymentCommand 是旧形状的仲裁收款输入。
type ArbitratedPaymentCommand struct {
	RequestRaw           []byte
	ResponseRaw          []byte
	DeliveryPayloadsCBOR []byte
}

// CompleteArbitratedPayment 验证 exact Kind 8/9 并合并卖方+仲裁方签名。
func (w *Workflow) CompleteArbitratedPayment(ctx context.Context, facts protocol.Facts, command ArbitratedPaymentCommand) (*pool.VerifiedSignedTransaction, error) {
	request, err := wire.ParseAs(wire.ArbitrationRequest, command.RequestRaw)
	if err != nil {
		return nil, err
	}
	decodedRequest, err := wire.DecodeArbitrationRequest(request)
	if err != nil {
		return nil, err
	}
	response, err := wire.ParseAs(wire.ArbitrationResponse, command.ResponseRaw)
	if err != nil {
		return nil, err
	}
	decodedResponse, err := wire.DecodeArbitrationResponse(response)
	if err != nil {
		return nil, err
	}
	receipt, err := arbitration.UnmarshalReceipt(decodedResponse.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	claim, _, _, unsigned, claimID, _, keys, err := arbitration.ValidateRequestEvidence(decodedRequest, receipt.ArbiterAmountSatoshis)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(w.publicKey[:], keys.SellerPublicKey) {
		return nil, protocol.Errorf("seller.CompleteArbitratedPayment", protocol.CodeUnauthorized, 9, "seller_public_key", "workflow key does not match Claim seller")
	}
	if receipt.ArbitrationClaimID != claimID {
		return nil, protocol.Errorf("seller.CompleteArbitratedPayment", protocol.CodeStateConflict, 9, "arbitration_claim_id", "receipt Claim ID does not match the independently computed Claim ID")
	}
	if len(command.DeliveryPayloadsCBOR) > 0 && !bytes.Equal(command.DeliveryPayloadsCBOR, decodedRequest.ContentPayloadsCBOR) {
		return nil, protocol.Errorf("seller.CompleteArbitratedPayment", protocol.CodeStateConflict, 9, "content_payloads_cbor", "stored delivery payload bundle does not match the custodied attachment")
	}
	if err := protocol.VerifyWireDocument(keys.ArbiterPublicKey, protocol.WireVersion, 9, decodedResponse.ArbitrationReceiptCBOR, decodedResponse.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbitration receipt signature is invalid: %v", err), "seller.CompleteArbitratedPayment", protocol.CodeInvalidSignature, 9, "arbiter_arbitration_receipt_signature")
	}
	claimLockTime, err := pool.RefundTemplateLockTime(claim.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	if err := facts.CheckRefundNotExpired(claimLockTime); err != nil {
		return nil, protocol.WrapClassified(fmt.Errorf("refund template is no longer available for arbitration: %w", err), "seller.CompleteArbitratedPayment", 9, "refund_template_raw")
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, receipt.ArbiterPaymentTransactionSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbiter transaction signature is invalid: %v", err), "seller.CompleteArbitratedPayment", protocol.CodeInvalidSignature, 9, "arbiter_payment_transaction_signature")
	}
	sellerSignature, err := engine.SignArbitrationSellerPayment(ctx, unsigned, w.signer)
	if err != nil {
		return nil, err
	}
	return pool.CompleteArbitratedTransaction(unsigned, sellerSignature, receipt.ArbiterPaymentTransactionSignature)
}

// RestoreOpeningCheckpoint 从 exact Kind 2/3 恢复预签 checkpoint。
func RestoreOpeningCheckpoint(rawKind2 []byte, rawKind3 []byte) (*OpeningCheckpoint, error) {
	request, response, err := decodePresignPair(realseller.SellerOpeningEvidence{RawKind2: rawKind2, RawKind3: rawKind3})
	if err != nil {
		return nil, err
	}
	if err := pool.VerifyRefundPresignRequestEvidence(request); err != nil {
		return nil, protocol.Wrap(err, "seller.RestoreOpeningCheckpoint", protocol.CodeInvalidEvidence, 2, "request")
	}
	computedID, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	if response.RefundTemplateTxID != computedID {
		return nil, protocol.Errorf("seller.RestoreOpeningCheckpoint", protocol.CodeStateConflict, 3, "refund_template_txid", "persisted response does not match the request-derived correlation ID")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if _, err := engine.BuildOpeningProof(request, response.SellerRefundTransactionSignature, nil); err != nil {
		return nil, protocol.Wrap(err, "seller.RestoreOpeningCheckpoint", protocol.CodeInvalidEvidence, 3, "seller_signature")
	}
	return &OpeningCheckpoint{evidence: realseller.SellerOpeningEvidence{RawKind2: bytes.Clone(rawKind2), RawKind3: bytes.Clone(rawKind3)}}, nil
}

// RestorePoolCheckpoint 从 canonical opening proof + 付款 raw tx 恢复池 checkpoint。
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error) {
	opening, err := pool.DecodeOpeningProof(openingProofCBOR)
	if err != nil {
		return nil, err
	}
	if _, err := pool.VerifyOpeningProof(opening); err != nil {
		return nil, protocol.Wrap(err, "seller.RestorePoolCheckpoint", protocol.CodeInvalidEvidence, 0, "opening_proof")
	}
	verified, err := pool.VerifySignedTransaction(paymentRawTx, opening)
	if err != nil {
		return nil, protocol.Wrap(err, "seller.RestorePoolCheckpoint", protocol.CodeInvalidEvidence, 0, "payment_raw_tx")
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if verified.RefundTemplateTxID() != details.RefundTemplateTxID {
		return nil, protocol.Errorf("seller.RestorePoolCheckpoint", protocol.CodeStateConflict, 0, "payment_state", "restored payment belongs to another pool")
	}
	return &PoolCheckpoint{opening: opening, payment: verified.State()}, nil
}

// RestoreDeliveryCheckpoint 从 exact Kind 1/5/6 与 canonical opening proof 恢复交付 checkpoint。
func RestoreDeliveryCheckpoint(rawKind1, openingProofCBOR, rawKind5, rawKind6 []byte) (*DeliveryCheckpoint, error) {
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
	requestTerms, _, err := content.VerifyContentRequestEvidence(request, quote, opening)
	if err != nil {
		return nil, protocol.Wrap(err, "seller.RestoreDeliveryCheckpoint", protocol.CodeInvalidEvidence, 5, "authorization_evidence")
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
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
		return nil, protocol.Errorf("seller.RestoreDeliveryCheckpoint", protocol.CodeStateConflict, 6, "content_delivery_cbor", "persisted delivery does not belong to this authorization")
	}
	if err := protocol.VerifyWireDocument(opening.SellerPublicKey, protocol.WireVersion, 6, delivery.ContentDeliveryCBOR, delivery.SellerContentDeliverySignature); err != nil {
		return nil, protocol.Wrap(err, "seller.RestoreDeliveryCheckpoint", protocol.CodeInvalidSignature, 6, "seller_content_delivery_signature")
	}
	if len(requestTerms.RefundTemplateTxID) != 32 {
		return nil, protocol.Errorf("seller.RestoreDeliveryCheckpoint", protocol.CodeMalformedWire, 5, "refund_template_txid", "must be 32 bytes")
	}
	var refundTemplateTxID pool.RefundTemplateTxID
	copy(refundTemplateTxID[:], requestTerms.RefundTemplateTxID)
	return &DeliveryCheckpoint{refundTemplateTxID: refundTemplateTxID, authorizationID: authID, paymentSequence: protocol.PaymentSequence(requestTerms.PaymentSequence), sellerAmountAfterSatoshis: protocol.Satoshis(requestTerms.SellerAmountAfterSatoshis)}, nil
}

// ---- 内部小工具 ----

func (c *PoolCheckpoint) evidence() realseller.SellerPoolEvidence {
	if c == nil {
		return realseller.SellerPoolEvidence{}
	}
	evidence := realseller.SellerPoolEvidence{Opening: c.opening, LatestPaymentRawTx: bytes.Clone(c.paymentRaw)}
	if c.opening != nil {
		evidence.FundingTransactionRaw = bytes.Clone(c.opening.FundingTransactionRaw)
	}
	return evidence
}

func sellerPoolCheckpoint(evidence realseller.SellerPoolEvidence) (*PoolCheckpoint, error) {
	opening := pool.CloneOpeningProof(evidence.Opening)
	if opening == nil {
		return nil, protocol.Errorf("seller.sellerPoolCheckpoint", protocol.CodeInvalidEvidence, 0, "opening", "pool opening evidence is required")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, err
	}
	var payment *pool.PaymentState
	if len(evidence.LatestPaymentRawTx) == 0 {
		initialRaw, err := engine.BuildRefundSubmission(opening)
		if err != nil {
			return nil, err
		}
		payment, err = engine.ParsePaymentState(initialRaw, opening)
		if err != nil {
			return nil, err
		}
	} else {
		payment, err = engine.ParsePaymentState(evidence.LatestPaymentRawTx, opening)
		if err != nil {
			return nil, err
		}
		if err := engine.VerifyAcceptedPayment(payment, opening); err != nil {
			if arbitratedErr := engine.VerifyArbitratedPayment(payment, opening); arbitratedErr != nil {
				return nil, protocol.Wrap(err, "seller.sellerPoolCheckpoint", protocol.CodeInvalidEvidence, 0, "latest_payment_raw_tx")
			}
		}
	}
	return &PoolCheckpoint{opening: opening, payment: payment, paymentRaw: bytes.Clone(evidence.LatestPaymentRawTx)}, nil
}

func deliveryCheckpointFrom(rawKind5 []byte) (*DeliveryCheckpoint, error) {
	artifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeContentRequest(artifact)
	if err != nil {
		return nil, err
	}
	terms, err := content.DecodePaymentAuthorization(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	if len(terms.RefundTemplateTxID) != sha256.Size {
		return nil, protocol.Errorf("seller.deliveryCheckpointFrom", protocol.CodeMalformedWire, 5, "refund_template_txid", "must be 32 bytes")
	}
	var refundTemplateTxID pool.RefundTemplateTxID
	copy(refundTemplateTxID[:], terms.RefundTemplateTxID)
	return &DeliveryCheckpoint{refundTemplateTxID: refundTemplateTxID, authorizationID: authID, paymentSequence: protocol.PaymentSequence(terms.PaymentSequence), sellerAmountAfterSatoshis: protocol.Satoshis(terms.SellerAmountAfterSatoshis)}, nil
}

func decodePresignPair(evidence realseller.SellerOpeningEvidence) (*pool.RefundPresignRequest, *pool.RefundPresignResponse, error) {
	requestArtifact, err := wire.ParseAs(wire.RefundPresignRequest, evidence.RawKind2)
	if err != nil {
		return nil, nil, err
	}
	request, err := wire.DecodeRefundPresignRequest(requestArtifact)
	if err != nil {
		return nil, nil, err
	}
	responseArtifact, err := wire.ParseAs(wire.RefundPresignResponse, evidence.RawKind3)
	if err != nil {
		return nil, nil, err
	}
	response, err := wire.DecodeRefundPresignResponse(responseArtifact)
	if err != nil {
		return nil, nil, err
	}
	return request, response, nil
}
