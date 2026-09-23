package seller

// 本文件是 Seller 的纯函数边界：每个入口只接收原始报文字节、普通证据包与
// 一次调用专用的受约束 Signer，返回原始报文字节或普通证据包。SDK 不持有
// 跨步骤对象、不保存进度、不读取时钟、不访问存储，也不广播任何交易。
// 证据包只含原始字节与明确字段，可序列化、可复制、无行为；安全由每个步骤
// 从原始证据全量重验保证，而不是由对象不可构造保证。

import (
	"bytes"
	"context"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// SellerOpeningEvidence 是卖方预签阶段的普通证据包：保存买方 exact Kind 2
// 请求与卖方自己发出的 exact Kind 3 响应。应用先持久化它再发送 Kind 3；
// VerifyFunding 需要原样回传。
type SellerOpeningEvidence struct {
	// RawKind2 是买方发来的 exact Kind 2 预签请求字节。
	RawKind2 []byte
	// RawKind3 是卖方发出的 exact Kind 3 预签响应字节（含卖方退款签名）。
	RawKind3 []byte
}

// SellerPoolEvidence 是卖方视角的资金池普通证据包：完整开池证明加当前链上
// 付款状态原文。省略 LatestPaymentRawTx 表示池仍处于初始退款状态，SDK 会从
// opening 重建初始状态；提供时 SDK 逐字节解析并全量重验它，绝不信任调用方
// 声明的序号或金额。
type SellerPoolEvidence struct {
	// Opening 是含资金交易原文的完整开池证明（普通数据，可深拷贝）。
	Opening *pool.OpeningProof
	// FundingTransactionRaw 是资金交易原文的副本；必须与 Opening 内部一致。
	FundingTransactionRaw []byte
	// LatestPaymentRawTx 是链上取得的最新完整付款交易原文；省略（nil/空）
	// 表示初始退款状态。不得填写未上链的本地候选。
	LatestPaymentRawTx []byte
}

// SellerDeliveryEvidence 是卖方交付阶段的普通证据包：exact Kind 1 报价、
// 买方 exact Kind 5 授权与卖方自己发出的 exact Kind 6 交付。CompletePayment
// 与 PrepareArbitration 需要原样回传其中的授权与交付证据。
type SellerDeliveryEvidence struct {
	// RawKind1 是卖方签署的 exact Kind 1 报价字节。
	RawKind1 []byte
	// RawKind5 是买方签署的 exact Kind 5 付款授权字节。
	RawKind5 []byte
	// RawKind6 是卖方发出的 exact Kind 6 内容交付字节（含 payload attachment）。
	RawKind6 []byte
}

// DeliveryInput 携带构造一次内容交付所需的全部普通输入。授权哈希绝不重复
// 提供：它们只来自买方 exact Kind 5。
type DeliveryInput struct {
	// QuoteRaw 是本池对应的 exact Kind 1 报价字节。
	QuoteRaw []byte
	// Pool 是当前池普通证据包。
	Pool SellerPoolEvidence
	// RequestRaw 是买方发来的 exact Kind 5 bytes。
	RequestRaw []byte
	// ContentPayloads 是原始 payload 批次，顺序与授权哈希一一对应。
	ContentPayloads [][]byte
	// Seed 在批次包含任何块时提供 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// InspectDeliveryRequestInput 携带预检一次 exact Kind 5 所需的原始证据。
// 它不要求 payload；调用方可先用返回清单读取内容仓库，再调用 PrepareDelivery。
type InspectDeliveryRequestInput struct {
	// QuoteRaw 是与费用池绑定的 exact Kind 1 报价字节。
	QuoteRaw []byte
	// Pool 是包含开池证明与当前链上付款状态的卖方证据。
	Pool SellerPoolEvidence
	// RequestRaw 是买方签署的 exact Kind 5 付款授权字节。
	RequestRaw []byte
}

// DeliveryRequestSummary 是已通过 Kind 5、报价、开池、签名、时序与当前池状态
// 预检的摘要。它不证明 payload 可用、属于 seed 或与授权价格相符；签署 Kind 6
// 前仍必须调用 PrepareDelivery 完成全量内容验收。
type DeliveryRequestSummary struct {
	// PaymentAuthorizationID 是 SHA-256(exact payment_authorization_cbor)，用于
	// 关联本次授权；它不同于目标付款状态序号 PaymentSequence。
	PaymentAuthorizationID protocol.PaymentAuthorizationID
	// FileQuoteTermsID 是该授权所引用的 exact 报价条款 ID。
	FileQuoteTermsID protocol.FileQuoteTermsID
	// RefundTemplateTxID 是该授权绑定的费用池 ID。
	RefundTemplateTxID pool.RefundTemplateTxID
	// PaymentSequence 是目标付款状态序号，必须等于当前状态序号加一。
	PaymentSequence protocol.PaymentSequence
	// SellerAmountAfterSatoshis 是交付后卖方的绝对累计金额，单位 satoshi。
	SellerAmountAfterSatoshis protocol.Satoshis
	// DeliveryDeadlineUnixSeconds 是授权签入的交付截止时间（UTC Unix 秒）。
	DeliveryDeadlineUnixSeconds content.UnixSeconds
	// ContentHashes 是授权签入的有序内容哈希副本，按此顺序读取和传入 payload。
	ContentHashes [][]byte
}

// CompletePaymentInput 携带完成一笔累计付款所需的全部普通证据。
type CompletePaymentInput struct {
	// Pool 是当前池普通证据包。
	Pool SellerPoolEvidence
	// Delivery 是生成本批次 exact Kind 6 时保存的交付证据包；SDK 会用它交叉
	// 核对授权 ID 与本方已发交付逐字节一致，而不是只信任传入的 Kind 5。
	Delivery SellerDeliveryEvidence
	// RequestRaw 是按 Kind 7 携带的授权 ID 取回的 exact 已签 Kind 5；必须与
	// Delivery.RawKind5 逐字节相等。
	RequestRaw []byte
	// UpdateRaw 是对端发来的 exact Kind 7 bytes。
	UpdateRaw []byte
}

// CompleteCloseInput 携带完成立即关闭所需的买方材料。
type CompleteCloseInput struct {
	// Pool 是当前池普通证据包。
	Pool SellerPoolEvidence
	// UnsignedRaw 是买方准备好的未签名关闭 candidate 原文。
	UnsignedRaw []byte
	// BuyerSignature 是买方对该 candidate 的 detached 交易签名。
	BuyerSignature []byte
}

// PrepareArbitrationInput 携带构造 exact Kind 8 所需的本地普通证据。
type PrepareArbitrationInput struct {
	// Pool 是当前池普通证据包。
	Pool SellerPoolEvidence
	// RequestRaw 是被托管批次的 exact 已签 Kind 5。
	RequestRaw []byte
	// DeliveryRaw 是本方发出的 exact Kind 6 bytes。
	DeliveryRaw []byte
}

// CompleteArbitratedPaymentInput 携带完成仲裁收款所需的 exact Kind 8/9 与本地证据。
type CompleteArbitratedPaymentInput struct {
	// RequestRaw 是 exact Kind 8 bytes。
	RequestRaw []byte
	// ResponseRaw 是 exact Kind 9 bytes。
	ResponseRaw []byte
	// DeliveryPayloadsCBOR 是本方保存的 exact content_payloads_cbor（可选；
	// 提供时与 Kind 8 attachment 逐字节比对）。
	DeliveryPayloadsCBOR []byte
}

// CreateQuote 以单一 QuoteDraft 签署确定性 Kind 1 条款：先 sanitize 文件名再
// 编码与签名，返回待发送 exact Kind 1 与最终规范化 terms（展示实际签署值）。
// 唯一时间事实为 facts.Now；签名能力只在本调用内使用。
func CreateQuote(ctx context.Context, facts protocol.Facts, signer protocol.Signer, draft QuoteDraft) (wire.Artifact, *content.FileQuoteTerms, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, nil, err
	}
	result, err := workflow.CreateQuote(ctx, facts, draft)
	if err != nil {
		return wire.Artifact{}, nil, err
	}
	return result.Outbound, result.Terms, nil
}

// PreparePresign 顺序固定：解析 exact Kind 2 → 角色/模板/费率验证 → 买方
// 退款签名验证 → 才调用 Signer。金额从退款模板推导，不接收调用方金额。
// 返回待发送 exact Kind 3 与必须先持久化的普通证据包；相同的重复请求只会
// 得到等价的新鲜计算结果——SDK 不存储、不重放。
func PreparePresign(ctx context.Context, rawKind2 []byte, signer protocol.Signer) (wire.Artifact, SellerOpeningEvidence, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, SellerOpeningEvidence{}, err
	}
	result, err := workflow.PreparePoolOpening(ctx, rawKind2)
	if err != nil {
		return wire.Artifact{}, SellerOpeningEvidence{}, err
	}
	evidence := SellerOpeningEvidence{RawKind2: bytes.Clone(rawKind2), RawKind3: result.Outbound.Bytes()}
	return result.Outbound, evidence, nil
}

// VerifyFunding 用预签证据包验收 exact Kind 4：重建完整开池证明，验证资金
// 交易 output[0] 金额/脚本与退款模板重建一致，并解析初始链上付款状态。
// 返回资金交易原文（由应用自行广播）与必须在广播决策前持久化的普通证据包；
// 调用方不需要也不应该提供自己的池状态。
func VerifyFunding(rawKind4 []byte, opening SellerOpeningEvidence) ([]byte, SellerPoolEvidence, error) {
	checkpoint, err := restoreOpeningCheckpoint(opening.RawKind2, opening.RawKind3)
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	proof := checkpoint.Opening()
	if proof == nil {
		return nil, SellerPoolEvidence{}, protocol.Errorf("seller.VerifyFunding", protocol.CodeInvalidEvidence, 4, "opening", "presign evidence is required")
	}
	result, err := verifyFundingDelivery(proof, rawKind4)
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	poolEvidence := SellerPoolEvidence{
		Opening:               pool.CloneOpeningProof(proof),
		FundingTransactionRaw: bytes.Clone(result.FundingTransactionRaw),
	}
	return bytes.Clone(result.FundingTransactionRaw), poolEvidence, nil
}

// InspectDeliveryRequest 严格解析并预检买方 exact Kind 5，返回授权 ID、目标付款
// 序号和有序内容哈希，使应用能在读取内容仓库前完成协议门禁。预检验证报价、开池、
// 买家签名、截止时间、当前付款状态与容量；它不读取内容、不签名、不生成 Kind 6。
// 调用方读取 payload 后仍须把同一请求和当前池证据传给 PrepareDelivery，由其验证
// payload 哈希、seed/block 归属、长度与价格后再签署交付。
func InspectDeliveryRequest(facts protocol.Facts, input InspectDeliveryRequestInput) (*DeliveryRequestSummary, error) {
	const op = "seller.InspectDeliveryRequest"
	quote, err := decodeKind1Quote(input.QuoteRaw)
	if err != nil {
		return nil, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, err
	}
	preflight, err := preflightDeliveryRequest(op, facts, quote, checkpoint, input.RequestRaw)
	if err != nil {
		return nil, err
	}
	return &DeliveryRequestSummary{
		PaymentAuthorizationID:      preflight.authorizationID,
		FileQuoteTermsID:            preflight.authorization.FileQuoteTermsID,
		RefundTemplateTxID:          preflight.refundTemplateTxID,
		PaymentSequence:             protocol.PaymentSequence(preflight.authorization.PaymentSequence),
		SellerAmountAfterSatoshis:   protocol.Satoshis(preflight.authorization.SellerAmountAfterSatoshis),
		DeliveryDeadlineUnixSeconds: content.UnixSeconds(preflight.authorization.DeliveryDeadlineUnixSeconds),
		ContentHashes:               cloneByteBatch(preflight.contentHashes),
	}, nil
}

// PrepareDelivery 完成 quote/opening/时序/序号/容量/价格/payload 全量校验后
// 签署 Kind 6，返回待发送 exact Kind 6 与普通证据包。Send 之前应用必须先
// 持久化 payload 与本证据包。
func PrepareDelivery(ctx context.Context, facts protocol.Facts, input DeliveryInput, signer protocol.Signer) (wire.Artifact, SellerDeliveryEvidence, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, SellerDeliveryEvidence{}, err
	}
	signedQuote, err := decodeKind1Quote(input.QuoteRaw)
	if err != nil {
		return wire.Artifact{}, SellerDeliveryEvidence{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return wire.Artifact{}, SellerDeliveryEvidence{}, err
	}
	result, err := workflow.DeliverContent(ctx, facts, deliveryCommand{
		Quote:           signedQuote,
		Pool:            checkpoint,
		RequestRaw:      bytes.Clone(input.RequestRaw),
		ContentPayloads: cloneByteBatch(input.ContentPayloads),
		Seed:            bytes.Clone(input.Seed),
	})
	if err != nil {
		return wire.Artifact{}, SellerDeliveryEvidence{}, err
	}
	evidence := SellerDeliveryEvidence{
		RawKind1: bytes.Clone(input.QuoteRaw),
		RawKind5: bytes.Clone(input.RequestRaw),
		RawKind6: result.Outbound.Bytes(),
	}
	return result.Outbound, evidence, nil
}

// CompletePayment 从输入重建池状态：验证 exact Kind 7 的授权 ID 与本批
// only exact Kind 5 一致、序号恰好 +1、金额不倒退、容量足够，验过买方签名后
// 补签并合并完整交易。返回完整交易原文与付款后的普通证据包；是否广播由
// 应用决定，SDK 不声称节点接受。
func CompletePayment(ctx context.Context, facts protocol.Facts, input CompletePaymentInput, signer protocol.Signer) ([]byte, SellerPoolEvidence, error) {
	const op = "seller.CompletePayment"
	workflow, err := newWorkflow(signer)
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	if !bytes.Equal(input.Delivery.RawKind5, input.RequestRaw) {
		return nil, SellerPoolEvidence{}, protocol.Errorf(op, protocol.CodeStateConflict, 7, "request_raw", "supplied Kind 5 does not match the stored delivery evidence")
	}
	request, requestTerms, err := decodeSignedContentRequest(input.RequestRaw)
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	if len(requestTerms.RefundTemplateTxID) != 32 {
		return nil, SellerPoolEvidence{}, protocol.Errorf(op, protocol.CodeMalformedWire, 7, "refund_template_txid", "must be 32 bytes")
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	if err := verifyStoredDelivery(op, checkpoint.opening, input.Delivery, authID); err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	var refundTemplateTxID pool.RefundTemplateTxID
	copy(refundTemplateTxID[:], requestTerms.RefundTemplateTxID)
	result, err := workflow.CompletePayment(ctx, facts, paymentCommand{
		Pool:       checkpoint,
		Request:    request,
		UpdateRaw:  bytes.Clone(input.UpdateRaw),
		Checkpoint: &deliveryCheckpoint{refundTemplateTxID: refundTemplateTxID, authorizationID: authID, paymentSequence: protocol.PaymentSequence(requestTerms.PaymentSequence), sellerAmountAfterSatoshis: protocol.Satoshis(requestTerms.SellerAmountAfterSatoshis)},
	})
	if err != nil {
		return nil, SellerPoolEvidence{}, err
	}
	raw := result.Transaction.RawTx()
	evidence := SellerPoolEvidence{
		Opening:               pool.CloneOpeningProof(checkpoint.opening),
		FundingTransactionRaw: bytes.Clone(checkpoint.opening.FundingTransactionRaw),
		LatestPaymentRawTx:    bytes.Clone(raw),
	}
	return raw, evidence, nil
}

// CompleteClose 校验买方关闭 candidate 结构与角色签名后补签并合并完整交易。
// 它不读取任何卖方数据库金额，也不判断 candidate 是否匹配业务目标；返回的
// 完整交易原文是否广播由应用决定。
func CompleteClose(ctx context.Context, facts protocol.Facts, input CompleteCloseInput, signer protocol.Signer) ([]byte, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return nil, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: checkpoint.opening.BuyerPublicKey, SellerPublicKey: checkpoint.opening.SellerPublicKey, ArbiterPublicKey: checkpoint.opening.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	unsigned, err := engine.ParseUnsignedPayment(input.UnsignedRaw, checkpoint.opening)
	if err != nil {
		return nil, err
	}
	verified, err := workflow.CompleteClose(ctx, facts, closeCommand{Pool: checkpoint, Unsigned: unsigned, BuyerSignature: bytes.Clone(input.BuyerSignature)})
	if err != nil {
		return nil, err
	}
	return verified.RawTx(), nil
}

// PrepareArbitration 验证本地开池、买方授权与本方已发交付后，签署紧凑 Claim
// 证据并返回 exact Kind 8 与独立计算的 Claim ID。它不构造也不预测仲裁方响应；
// 应用保存 Claim ID 以便路由 Kind 9 回执。
func PrepareArbitration(ctx context.Context, facts protocol.Facts, input PrepareArbitrationInput, signer protocol.Signer) (wire.Artifact, protocol.ArbitrationClaimID, error) {
	const op = "seller.PrepareArbitration"
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, err
	}
	request, _, err := decodeSignedContentRequest(input.RequestRaw)
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, err
	}
	outbound, err := workflow.PrepareArbitration(ctx, facts, arbitrationCommand{Pool: checkpoint, Request: request, DeliveryRaw: bytes.Clone(input.DeliveryRaw)})
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, err
	}
	artifact, err := wire.ParseAs(wire.ArbitrationRequest, outbound.Bytes())
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, err
	}
	decoded, err := wire.DecodeArbitrationRequest(artifact)
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, err
	}
	claimID, err := arbitration.ArbitrationClaimID(decoded.ArbitrationClaimCBOR)
	if err != nil {
		return wire.Artifact{}, protocol.ArbitrationClaimID{}, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 8, "arbitration_claim_cbor")
	}
	return outbound, claimID, nil
}

// CompleteArbitratedPayment 从 exact Kind 8/9 完整验证托管收款路径：独立重建
// paid candidate、验证回执消息签名与仲裁交易签名，然后补签卖方交易签名并
// 合并完整交易。返回完整交易原文；不广播，是否入账由应用决定。
func CompleteArbitratedPayment(ctx context.Context, facts protocol.Facts, input CompleteArbitratedPaymentInput, signer protocol.Signer) ([]byte, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return nil, err
	}
	verified, err := workflow.CompleteArbitratedPayment(ctx, facts, arbitratedPaymentCommand{
		RequestRaw:           bytes.Clone(input.RequestRaw),
		ResponseRaw:          bytes.Clone(input.ResponseRaw),
		DeliveryPayloadsCBOR: bytes.Clone(input.DeliveryPayloadsCBOR),
	})
	if err != nil {
		return nil, err
	}
	return verified.RawTx(), nil
}

// ---- 包内小工具 ----

// internalPoolCheckpoint 把普通证据包还原为内部池状态：opening 全量重验，
// 付款状态要么由 opening 重建初始退款状态，要么逐字节解析调用方提供的
// 链上交易原文并全量重验；绝不接受调用方声明的序号或金额。
func internalPoolCheckpoint(evidence SellerPoolEvidence) (*poolCheckpoint, error) {
	const op = "seller.poolEvidence"
	opening := pool.CloneOpeningProof(evidence.Opening)
	if opening == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "opening", "pool opening evidence is required")
	}
	if len(evidence.FundingTransactionRaw) > 0 {
		if len(opening.FundingTransactionRaw) > 0 && !bytes.Equal(opening.FundingTransactionRaw, evidence.FundingTransactionRaw) {
			return nil, protocol.Errorf(op, protocol.CodeStateConflict, 0, "funding_transaction_raw", "pool evidence carries inconsistent funding transactions")
		}
		opening.FundingTransactionRaw = bytes.Clone(evidence.FundingTransactionRaw)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, err
	}
	if len(evidence.LatestPaymentRawTx) == 0 {
		initialRaw, err := engine.BuildRefundSubmission(opening)
		if err != nil {
			return nil, fmt.Errorf("assemble initial refund state: %w", err)
		}
		initial, err := engine.ParsePaymentState(initialRaw, opening)
		if err != nil {
			return nil, fmt.Errorf("parse initial pool state: %w", err)
		}
		if err := engine.VerifyAcceptedPayment(initial, opening); err != nil {
			return nil, fmt.Errorf("verify initial pool state: %w", err)
		}
		return &poolCheckpoint{opening: opening, payment: initial}, nil
	}
	state, err := engine.ParsePaymentState(evidence.LatestPaymentRawTx, opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyAcceptedPayment(state, opening); err != nil {
		if arbitratedErr := engine.VerifyArbitratedPayment(state, opening); arbitratedErr != nil {
			return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "latest_payment_raw_tx")
		}
	}
	return &poolCheckpoint{opening: opening, payment: state}, nil
}

// verifyStoredDelivery 交叉核对应用保存的交付证据包：exact Kind 6 的
// content_delivery_cbor 必须绑定同一授权 ID，且卖方对精确交付文档的统一签名
// 必须由本池卖方公钥验证通过；payload attachment 必须是可解码的规范子文档。
func verifyStoredDelivery(op string, opening *pool.OpeningProof, deliveryEvidence SellerDeliveryEvidence, authID protocol.PaymentAuthorizationID) error {
	if len(deliveryEvidence.RawKind6) == 0 {
		return protocol.Errorf(op, protocol.CodeStateConflict, 7, "delivery", "stored content delivery evidence is required")
	}
	artifact, err := wire.ParseAs(wire.ContentDelivery, deliveryEvidence.RawKind6)
	if err != nil {
		return err
	}
	delivery, err := wire.DecodeContentDelivery(artifact)
	if err != nil {
		return err
	}
	deliveryAuthID, err := content.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		return err
	}
	if deliveryAuthID != authID {
		return protocol.Errorf(op, protocol.CodeStateConflict, 7, "content_delivery_cbor", "stored delivery references a different authorization")
	}
	if opening == nil {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 7, "opening", "pool opening evidence is required")
	}
	if err := protocol.VerifyWireDocument(opening.SellerPublicKey, protocol.WireVersion, 6, delivery.ContentDeliveryCBOR, delivery.SellerContentDeliverySignature); err != nil {
		return protocol.Wrap(fmt.Errorf("stored delivery signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 7, "seller_content_delivery_signature")
	}
	if _, err := content.DecodeContentPayloads(delivery.ContentPayloadsCBOR); err != nil {
		return err
	}
	return nil
}

// cloneByteBatch 深拷贝字节批次，保证调用方持有的切片与结果解耦。
func cloneByteBatch(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

// decodeKind1Quote 严格解析 exact Kind 1 报价字节。
func decodeKind1Quote(raw []byte) (*content.SignedFileQuote, error) {
	const op = "seller.decodeKind1Quote"
	artifact, err := wire.ParseAs(wire.FileQuote, raw)
	if err != nil {
		return nil, err
	}
	quote, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		return nil, err
	}
	if quote == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 1, "quote", "exact Kind 1 quote is required")
	}
	return quote, nil
}

// decodeSignedContentRequest 严格解析 exact Kind 5 并返回解码结果与授权条款。
func decodeSignedContentRequest(raw []byte) (*content.SignedContentRequest, *content.PaymentAuthorization, error) {
	artifact, err := wire.ParseAs(wire.ContentRequest, raw)
	if err != nil {
		return nil, nil, err
	}
	request, err := wire.DecodeContentRequest(artifact)
	if err != nil {
		return nil, nil, err
	}
	terms, err := content.DecodePaymentAuthorization(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, nil, err
	}
	return request, terms, nil
}
