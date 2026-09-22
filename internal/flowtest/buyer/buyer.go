// Package buyer 是内部测试兼容适配器：把买方纯函数 API 包装成旧的“持有 Signer
// 的 workflow”形状，仅用于让既有安全测试继续以新实现为唯一底层执行。它不是
// SDK 公开面，也不进入发布文档。
package buyer

import (
	"bytes"
	"context"

	"github.com/bsv8/go-bitfs/arbitration"
	realbuyer "github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// Workflow 是测试用买方会话：只固定 Signer 与公钥，不保存任何协议进度。
type Workflow struct {
	signer    protocol.Signer
	publicKey protocol.PublicKey
}

// NewWorkflow 固定并验证 Signer 公钥。
func NewWorkflow(signer protocol.Signer) (*Workflow, error) {
	if signer == nil {
		return nil, protocol.Errorf("buyer.NewWorkflow", protocol.CodeSignerUnavailable, 0, "signer", "buyer workflow requires a signer")
	}
	bound, err := protocol.BindSigner(signer)
	if err != nil {
		return nil, protocol.Wrap(err, "buyer.NewWorkflow", protocol.CodeInvalidEvidence, 0, "signer")
	}
	return &Workflow{signer: bound, publicKey: bound.PublicKey()}, nil
}

// PublicKey 返回固定压缩公钥副本。
func (w *Workflow) PublicKey() []byte { return append([]byte(nil), w.publicKey[:]...) }

// AcceptQuote 验收 exact Kind 1 并绑定买方身份。
func (w *Workflow) AcceptQuote(facts protocol.Facts, rawKind1 []byte) (*content.VerifiedQuote, error) {
	verified, err := realbuyer.AcceptQuote(facts, rawKind1)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(verified.BuyerPublicKey(), w.publicKey[:]) {
		return nil, protocol.Errorf("buyer.AcceptQuote", protocol.CodeUnauthorized, 1, "buyer_public_key", "this quote names another buyer")
	}
	return verified, nil
}

// OpeningCheckpoint 保存买方开池证据（普通数据的旧形状）。
type OpeningCheckpoint struct {
	evidence realbuyer.BuyerOpeningEvidence
}

// RefundTemplateTxID 从请求重派生费用池关联 ID。
func (c *OpeningCheckpoint) RefundTemplateTxID() pool.RefundTemplateTxID {
	if c == nil {
		return pool.RefundTemplateTxID{}
	}
	request := c.Request()
	if request == nil {
		return pool.RefundTemplateTxID{}
	}
	id, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		return pool.RefundTemplateTxID{}
	}
	return id
}

// Request 返回深拷贝的 exact Kind 2 请求。
func (c *OpeningCheckpoint) Request() *pool.RefundPresignRequest {
	if c == nil {
		return nil
	}
	artifact, err := wire.ParseAs(wire.RefundPresignRequest, c.evidence.RawKind2)
	if err != nil {
		return nil
	}
	request, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		return nil
	}
	return request
}

// FundingTransactionRaw 返回资金交易原文副本。
func (c *OpeningCheckpoint) FundingTransactionRaw() []byte {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.evidence.FundingTransactionRaw)
}

// PrepareOpeningCommand 是旧形状的开池输入。
type PrepareOpeningCommand struct {
	Quote                           *content.VerifiedQuote
	FundingTransactionRaw           []byte
	ExpiryLockTime                  protocol.RefundLockTime
	MinerFeeRateSatoshisPerKilobyte protocol.SatoshisPerKilobyte
	SellerPublicKey                 protocol.PublicKey
	ArbiterPublicKey                protocol.PublicKey
}

// PreparePoolOpeningResult 是旧形状的开池结果。
type PreparePoolOpeningResult struct {
	Outbound   wire.Artifact
	Checkpoint *OpeningCheckpoint
}

// PreparePoolOpening 构造并签署 exact Kind 2。
func (w *Workflow) PreparePoolOpening(ctx context.Context, command PrepareOpeningCommand) (*PreparePoolOpeningResult, error) {
	quoteRaw, err := encodeQuote(command.Quote)
	if err != nil {
		return nil, protocol.Wrap(err, "buyer.PreparePoolOpening", protocol.CodeInvalidEvidence, 2, "quote")
	}
	outbound, evidence, err := realbuyer.PrepareOpening(ctx, realbuyer.PrepareOpeningInput{
		QuoteRaw:                        quoteRaw,
		FundingTransactionRaw:           command.FundingTransactionRaw,
		ExpiryLockTime:                  command.ExpiryLockTime,
		MinerFeeRateSatoshisPerKilobyte: command.MinerFeeRateSatoshisPerKilobyte,
		SellerPublicKey:                 command.SellerPublicKey,
		ArbiterPublicKey:                command.ArbiterPublicKey,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	return &PreparePoolOpeningResult{Outbound: outbound, Checkpoint: &OpeningCheckpoint{evidence: evidence}}, nil
}

// PoolCheckpoint 保存完整开池证明与当前付款状态（旧形状）。
type PoolCheckpoint struct {
	evidence realbuyer.BuyerPoolEvidence
	opening  *pool.OpeningProof
	payment  *pool.PaymentState
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

// VerifiedPayment 返回完整重验后的不可变付款状态。
func (c *PoolCheckpoint) VerifiedPayment() (*pool.VerifiedPaymentState, error) {
	if c == nil || c.payment == nil || c.opening == nil {
		return nil, protocol.Errorf("buyer.PoolCheckpoint.VerifiedPayment", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is empty")
	}
	return pool.VerifyPaymentState(c.payment, c.opening)
}

// VerifiedOpening 返回完整重验后的不可变开池证明。
func (c *PoolCheckpoint) VerifiedOpening() (*pool.VerifiedOpening, error) {
	if c == nil || c.opening == nil {
		return nil, protocol.Errorf("buyer.PoolCheckpoint.VerifiedOpening", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is empty")
	}
	return pool.VerifyOpeningProof(c.opening)
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

// CompleteOpeningResult 是旧形状的完成开池结果。
type CompleteOpeningResult struct {
	Opening     *pool.VerifiedOpening
	InitialPool *PoolCheckpoint
}

// CompletePoolOpening 验收 exact Kind 3 并返回初始池状态。
func (w *Workflow) CompletePoolOpening(checkpoint *OpeningCheckpoint, rawKind3 []byte) (*CompleteOpeningResult, error) {
	if checkpoint == nil {
		return nil, protocol.Errorf("buyer.CompletePoolOpening", protocol.CodeStateConflict, 3, "checkpoint", "buyer opening checkpoint is required")
	}
	_, poolEvidence, err := realbuyer.CompleteOpening(checkpoint.evidence, rawKind3)
	if err != nil {
		return nil, err
	}
	parsed, err := parsePoolEvidence(poolEvidence)
	if err != nil {
		return nil, err
	}
	verifiedOpening, err := pool.VerifyOpeningProof(parsed.opening)
	if err != nil {
		return nil, err
	}
	return &CompleteOpeningResult{Opening: verifiedOpening, InitialPool: parsed}, nil
}

// PrepareFundingDelivery 打包 exact Kind 4。
func (w *Workflow) PrepareFundingDelivery(checkpoint *PoolCheckpoint) (wire.Artifact, error) {
	if checkpoint == nil || checkpoint.opening == nil {
		return wire.Artifact{}, protocol.Errorf("buyer.PrepareFundingDelivery", protocol.CodeInvalidEvidence, 4, "checkpoint", "buyer pool checkpoint is required")
	}
	if !bytes.Equal(checkpoint.opening.BuyerPublicKey, w.publicKey[:]) {
		return wire.Artifact{}, protocol.Errorf("buyer.PrepareFundingDelivery", protocol.CodeUnauthorized, 0, "buyer_public_key", "workflow key does not match opening buyer")
	}
	return realbuyer.PrepareFundingDelivery(checkpoint.evidence)
}

// AuthorizationCheckpoint 保存一次已签 Kind 5。
type AuthorizationCheckpoint struct {
	authorizationID protocol.PaymentAuthorizationID
	request         *content.SignedContentRequest
}

// AuthorizationID 返回授权 typed ID。
func (c *AuthorizationCheckpoint) AuthorizationID() protocol.PaymentAuthorizationID {
	if c == nil {
		return protocol.PaymentAuthorizationID{}
	}
	return c.authorizationID
}

// Request 返回深拷贝的 exact 已签 Kind 5。
func (c *AuthorizationCheckpoint) Request() *content.SignedContentRequest {
	if c == nil || c.request == nil {
		return nil
	}
	return content.CloneSignedContentRequest(c.request)
}

// RequestContentCommand 是旧形状的内容请求输入。
type RequestContentCommand struct {
	Quote            *content.VerifiedQuote
	Pool             *PoolCheckpoint
	ContentHashes    [][]byte
	DeliveryDeadline content.UnixSeconds
	Seed             []byte
}

// RequestContentResult 是旧形状的内容请求结果。
type RequestContentResult struct {
	Outbound        wire.Artifact
	AuthorizationID protocol.PaymentAuthorizationID
	Checkpoint      *AuthorizationCheckpoint
}

// RequestContent 构造并签署 exact Kind 5。
func (w *Workflow) RequestContent(ctx context.Context, facts protocol.Facts, command RequestContentCommand) (*RequestContentResult, error) {
	if command.Quote == nil || command.Pool == nil {
		return nil, protocol.Errorf("buyer.RequestContent", protocol.CodeInvalidEvidence, 5, "command", "verified quote and pool checkpoint are required")
	}
	quoteRaw, err := encodeQuote(command.Quote)
	if err != nil {
		return nil, err
	}
	outbound, evidence, err := realbuyer.PrepareContentRequest(ctx, facts, realbuyer.RequestContentInput{
		QuoteRaw:         quoteRaw,
		Pool:             command.Pool.evidence,
		ContentHashes:    command.ContentHashes,
		DeliveryDeadline: command.DeliveryDeadline,
		Seed:             command.Seed,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	request, err := decodeSignedRequest(evidence.RawKind5)
	if err != nil {
		return nil, err
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	return &RequestContentResult{Outbound: outbound, AuthorizationID: authID, Checkpoint: &AuthorizationCheckpoint{authorizationID: authID, request: request}}, nil
}

// VerifyDeliveryCommand 是旧形状的交付验收输入。
type VerifyDeliveryCommand struct {
	Quote       *content.VerifiedQuote
	Pool        *PoolCheckpoint
	Request     *AuthorizationCheckpoint
	DeliveryRaw []byte
	Seed        []byte
}

// PaymentPreparationResult 是旧形状的最小 005 构造结果。
type PaymentPreparationResult struct {
	Payloads      [][]byte
	Outbound      wire.Artifact
	NextCandidate *pool.UnsignedPayment
}

// VerifyDeliveryAndPreparePayment 验收 exact Kind 6 并构造 exact Kind 7。
func (w *Workflow) VerifyDeliveryAndPreparePayment(ctx context.Context, facts protocol.Facts, command VerifyDeliveryCommand) (*PaymentPreparationResult, error) {
	if command.Quote == nil || command.Pool == nil || command.Request == nil {
		return nil, protocol.Errorf("buyer.VerifyDeliveryAndPreparePayment", protocol.CodeStateConflict, 6, "command", "pool checkpoint and persisted authorization are required")
	}
	quoteRaw, err := encodeQuote(command.Quote)
	if err != nil {
		return nil, err
	}
	payloads, outbound, err := realbuyer.VerifyDelivery(ctx, facts, realbuyer.VerifyDeliveryInput{
		Authorization: realbuyer.BuyerAuthorizationEvidence{RawKind1: quoteRaw, RawKind5: signedRequestRaw(command.Request)},
		Pool:          command.Pool.evidence,
		DeliveryRaw:   command.DeliveryRaw,
		Seed:          command.Seed,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	return &PaymentPreparationResult{Payloads: payloads, Outbound: outbound}, nil
}

// PrepareCloseCommand 是旧形状的关池准备输入。
type PrepareCloseCommand struct {
	Pool                       *PoolCheckpoint
	Base                       *pool.PaymentState
	TargetSellerAmountSatoshis protocol.Satoshis
}

// ClosePreparationResult 是旧形状的关池准备结果。
type ClosePreparationResult struct {
	Unsigned       *pool.UnsignedPayment
	BuyerSignature []byte
}

// PrepareClose 构造未签名关闭 candidate 与买方签名。
func (w *Workflow) PrepareClose(ctx context.Context, facts protocol.Facts, command PrepareCloseCommand) (*ClosePreparationResult, error) {
	if command.Pool == nil {
		return nil, protocol.Errorf("buyer.PrepareClose", protocol.CodeInvalidEvidence, 0, "pool", "pool checkpoint is required")
	}
	unsignedRaw, buyerSignature, err := realbuyer.PrepareClose(ctx, facts, realbuyer.PrepareCloseInput{
		Pool:                       command.Pool.evidence,
		TargetSellerAmountSatoshis: command.TargetSellerAmountSatoshis,
	}, w.signer)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: command.Pool.opening.BuyerPublicKey, SellerPublicKey: command.Pool.opening.SellerPublicKey, ArbiterPublicKey: command.Pool.opening.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	unsigned, err := engine.ParseUnsignedPayment(unsignedRaw, command.Pool.opening)
	if err != nil {
		return nil, err
	}
	return &ClosePreparationResult{Unsigned: unsigned, BuyerSignature: buyerSignature}, nil
}

// VerifyCloseCommand 是旧形状的关池验收输入。
type VerifyCloseCommand struct {
	Pool  *PoolCheckpoint
	Close *pool.SignedPayment
}

// VerifyCompletedClose 验证完整关闭交易。
func (w *Workflow) VerifyCompletedClose(command VerifyCloseCommand) (*pool.VerifiedSignedTransaction, error) {
	if command.Pool == nil || command.Close == nil || command.Pool.opening == nil {
		return nil, protocol.Errorf("buyer.VerifyCompletedClose", protocol.CodeInvalidEvidence, 0, "close_payment", "final signed payment is required")
	}
	if !bytes.Equal(command.Pool.opening.BuyerPublicKey, w.publicKey[:]) {
		return nil, protocol.Errorf("buyer.VerifyCompletedClose", protocol.CodeUnauthorized, 0, "buyer_public_key", "workflow key does not match opening buyer")
	}
	return realbuyer.VerifyCompletedClose(realbuyer.VerifyCompletedCloseInput{Pool: command.Pool.evidence, CloseRaw: command.Close.RawTx})
}

// BuildMaturedRefund 在显式事实判定到期后合并退款。
func (w *Workflow) BuildMaturedRefund(facts protocol.Facts, checkpoint *PoolCheckpoint) (*pool.VerifiedSignedTransaction, error) {
	if checkpoint == nil || checkpoint.opening == nil {
		return nil, protocol.Errorf("buyer.BuildMaturedRefund", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is required")
	}
	if !bytes.Equal(checkpoint.opening.BuyerPublicKey, w.publicKey[:]) {
		return nil, protocol.Errorf("buyer.BuildMaturedRefund", protocol.CodeUnauthorized, 0, "buyer_public_key", "workflow key does not match opening buyer")
	}
	return realbuyer.BuildMaturedRefund(facts, checkpoint.evidence)
}

// ArbitrationRetrievalCommand 是旧形状的取回请求输入。
type ArbitrationRetrievalCommand struct {
	Pool          *PoolCheckpoint
	Authorization *AuthorizationCheckpoint
}

// RequestArbitratedContent 构造 exact Kind 10。
func (w *Workflow) RequestArbitratedContent(ctx context.Context, command ArbitrationRetrievalCommand) (wire.Artifact, error) {
	if command.Pool == nil || command.Authorization == nil {
		return wire.Artifact{}, protocol.Errorf("buyer.RequestArbitratedContent", protocol.CodeInvalidEvidence, 10, "command", "pool checkpoint and authorization are required")
	}
	return realbuyer.RequestArbitratedContent(ctx, realbuyer.RetrievalRequestInput{
		Pool:          command.Pool.evidence,
		Authorization: realbuyer.BuyerAuthorizationEvidence{RawKind5: signedRequestRaw(command.Authorization)},
	}, w.signer)
}

// ArbitratedContentCommand 是旧形状的取回验收输入。
type ArbitratedContentCommand struct {
	Quote                *content.VerifiedQuote
	Pool                 *PoolCheckpoint
	Request              *AuthorizationCheckpoint
	RetrievalRequestRaw  []byte
	RetrievalResponseRaw []byte
	Seed                 []byte
}

// ArbitratedContentResult 是旧形状的取回验收结果。
type ArbitratedContentResult struct {
	ContentRetrievalRequestID protocol.ContentRetrievalRequestID
	ArbitrationClaimID        protocol.ArbitrationClaimID
	Available                 bool
	UnavailableReason         arbitration.ContentRetrievalUnavailableReason
	Payloads                  [][]byte
}

// VerifyArbitratedContent 时间无关验收 exact Kind 10/11。
func (w *Workflow) VerifyArbitratedContent(ctx context.Context, command ArbitratedContentCommand) (*ArbitratedContentResult, error) {
	if command.Quote == nil || command.Pool == nil || command.Request == nil {
		return nil, protocol.Errorf("buyer.VerifyArbitratedContent", protocol.CodeStateConflict, 11, "command", "quote, pool checkpoint and persisted authorization are required")
	}
	quoteRaw, err := encodeQuote(command.Quote)
	if err != nil {
		return nil, err
	}
	result, err := realbuyer.VerifyArbitratedContent(ctx, realbuyer.ArbitratedContentInput{
		Authorization:        realbuyer.BuyerAuthorizationEvidence{RawKind1: quoteRaw, RawKind5: signedRequestRaw(command.Request)},
		Pool:                 command.Pool.evidence,
		RetrievalRequestRaw:  command.RetrievalRequestRaw,
		RetrievalResponseRaw: command.RetrievalResponseRaw,
		Seed:                 command.Seed,
	})
	if err != nil {
		return nil, err
	}
	return &ArbitratedContentResult{
		ContentRetrievalRequestID: result.ContentRetrievalRequestID,
		ArbitrationClaimID:        result.ArbitrationClaimID,
		Available:                 result.Available,
		UnavailableReason:         result.UnavailableReason,
		Payloads:                  result.Payloads,
	}, nil
}

// RestoreOpeningCheckpoint 从 exact evidence 恢复开池 checkpoint。
func RestoreOpeningCheckpoint(rawKind2 []byte, fundingTransactionRaw []byte) (*OpeningCheckpoint, error) {
	artifact, err := wire.ParseAs(wire.RefundPresignRequest, rawKind2)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		return nil, err
	}
	if len(fundingTransactionRaw) == 0 {
		return nil, protocol.Errorf("buyer.RestoreOpeningCheckpoint", protocol.CodeInvalidEvidence, 2, "funding_transaction_raw", "funding transaction bytes are required")
	}
	if err := pool.VerifyRefundPresignRequestEvidence(request); err != nil {
		return nil, protocol.Wrap(err, "buyer.RestoreOpeningCheckpoint", protocol.CodeInvalidEvidence, 2, "request")
	}
	return &OpeningCheckpoint{evidence: realbuyer.BuyerOpeningEvidence{RawKind2: bytes.Clone(rawKind2), FundingTransactionRaw: bytes.Clone(fundingTransactionRaw)}}, nil
}

// RestorePoolCheckpoint 从 exact evidence 恢复池 checkpoint。
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error) {
	opening, err := pool.DecodeOpeningProof(openingProofCBOR)
	if err != nil {
		return nil, err
	}
	if _, err := pool.VerifyOpeningProof(opening); err != nil {
		return nil, protocol.Wrap(err, "buyer.RestorePoolCheckpoint", protocol.CodeInvalidEvidence, 0, "opening_proof")
	}
	return parsePoolEvidence(realbuyer.BuyerPoolEvidence{Opening: opening, LatestPaymentRawTx: paymentRawTx})
}

// RestoreAuthorizationCheckpoint 从完整本地证据恢复授权 checkpoint。
func RestoreAuthorizationCheckpoint(rawKind1 []byte, rawKind5 []byte, openingProofCBOR []byte) (*AuthorizationCheckpoint, error) {
	quote, err := decodeQuote(rawKind1)
	if err != nil {
		return nil, err
	}
	opening, err := pool.DecodeOpeningProof(openingProofCBOR)
	if err != nil {
		return nil, err
	}
	request, err := decodeSignedRequest(rawKind5)
	if err != nil {
		return nil, err
	}
	if _, _, err := content.VerifyContentRequestEvidence(request, quote, opening); err != nil {
		return nil, protocol.Wrap(err, "buyer.RestoreAuthorizationCheckpoint", protocol.CodeInvalidEvidence, 5, "authorization_evidence")
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	return &AuthorizationCheckpoint{authorizationID: authID, request: request}, nil
}

// ---- 内部小工具 ----

func parsePoolEvidence(evidence realbuyer.BuyerPoolEvidence) (*PoolCheckpoint, error) {
	opening := pool.CloneOpeningProof(evidence.Opening)
	if opening == nil {
		return nil, protocol.Errorf("buyer.parsePoolEvidence", protocol.CodeInvalidEvidence, 0, "opening", "pool opening evidence is required")
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
		initial, err := engine.ParsePaymentState(initialRaw, opening)
		if err != nil {
			return nil, err
		}
		payment = initial
	} else {
		parsed, err := engine.ParsePaymentState(evidence.LatestPaymentRawTx, opening)
		if err != nil {
			return nil, err
		}
		if err := engine.VerifyAcceptedPayment(parsed, opening); err != nil {
			if arbitratedErr := engine.VerifyArbitratedPayment(parsed, opening); arbitratedErr != nil {
				return nil, protocol.Wrap(err, "buyer.parsePoolEvidence", protocol.CodeInvalidEvidence, 0, "latest_payment_raw_tx")
			}
		}
		payment = parsed
	}
	return &PoolCheckpoint{evidence: realbuyer.BuyerPoolEvidence{Opening: opening, LatestPaymentRawTx: bytes.Clone(evidence.LatestPaymentRawTx)}, opening: opening, payment: payment}, nil
}

func encodeQuote(verified *content.VerifiedQuote) ([]byte, error) {
	artifact, err := wire.EncodeFileQuote(verified.Quote())
	if err != nil {
		return nil, err
	}
	return artifact.Bytes(), nil
}

func decodeQuote(rawKind1 []byte) (*content.SignedFileQuote, error) {
	artifact, err := wire.ParseAs(wire.FileQuote, rawKind1)
	if err != nil {
		return nil, err
	}
	return wire.DecodeFileQuote(artifact)
}

func decodeSignedRequest(rawKind5 []byte) (*content.SignedContentRequest, error) {
	artifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		return nil, err
	}
	return wire.DecodeContentRequest(artifact)
}

// signedRequestRaw 把授权 checkpoint 中的已签 Kind 5 重新编码为 exact wire bytes。
func signedRequestRaw(checkpoint *AuthorizationCheckpoint) []byte {
	if checkpoint == nil || checkpoint.request == nil {
		return nil
	}
	artifact, err := wire.EncodeContentRequest(checkpoint.request)
	if err != nil {
		return nil
	}
	return artifact.Bytes()
}
