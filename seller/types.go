package seller

import (
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// 本文件定义 Seller 角色 API 的 Command / Result / opaque checkpoint。
// 词义约定与 buyer 相同：Parsed / Verified / Prepared / Complete；Broadcast /
// Confirmed / Latest 只能由应用声明。

// QuoteDraft 是 CreateQuote 的单一完整草稿：filename 只能有一个来源
// （RecommendedFilename 字段，SDK 会先 sanitize 再签署并在最终 terms 中展示
// 实际签署值）。
type QuoteDraft struct {
	// SeedHash 是内容仓库种子摘要（SHA-256，32 字节）。
	SeedHash []byte
	// BuyerPublicKey 是唯一被授权买方的压缩公钥。
	BuyerPublicKey protocol.PublicKey
	// SeedPriceSatoshis 是整个 MasterSeed 的绝对单价（绝对聪数）。
	SeedPriceSatoshis protocol.Satoshis
	// FullBlockPriceSatoshis 是一个完整块（256 KiB）的绝对单价（绝对聪数）；
	// 尾块按比例并享 10% 让利。
	FullBlockPriceSatoshis protocol.Satoshis
	// FileSizeBytes 是文件总字节数；块数由它派生。
	FileSizeBytes uint64
	// QuoteExpiresAtUnixSeconds 是报价失效时间（UTC Unix 秒）；必须晚于 Facts.Now。
	QuoteExpiresAtUnixSeconds content.UnixSeconds
	// SupportedArbiterPublicKeys 是允许的仲裁强类型公钥列表；可为空但不得重复。
	SupportedArbiterPublicKeys []protocol.PublicKey
	// RecommendedFilename 是唯一的文件名来源：sanitize 后进入签名条款。
	RecommendedFilename string
}

// quoteResult 是 CreateQuote 的统一 Result：Outbound 是待发送 exact Kind 1；
// Terms 是实际签署的最终规范化条款（含 sanitize 后的 RecommendedFilename）。
type quoteResult struct {
	// Outbound 是待发送 exact Kind 1 wire Artifact。
	Outbound wire.Artifact
	// Terms 是最终规范化并已签署的条款快照。
	Terms *content.FileQuoteTerms
}

// openingCheckpoint 是卖方本地预签状态（尚未注资）：应用必须在发送 Kind 3 之前
// 先持久化本 checkpoint 的 evidence；VerifyFundingDelivery 与仲裁路径需要它。
type openingCheckpoint struct {
	// opening 是预签形态的开池证明（无资金交易原文）。
	opening *pool.OpeningProof
}

// Opening 返回深拷贝的预签开池证据。
func (c *openingCheckpoint) Opening() *pool.OpeningProof {
	if c == nil || c.opening == nil {
		return nil
	}
	return pool.CloneOpeningProof(c.opening)
}

// poolCheckpoint 是卖方本地资金池状态：完整开池证明 + 当前付款状态。
type poolCheckpoint struct {
	opening *pool.OpeningProof
	payment *pool.PaymentState
}

// Opening 返回深拷贝的完整开池证据。
func (c *poolCheckpoint) Opening() *pool.OpeningProof {
	if c == nil || c.opening == nil {
		return nil
	}
	return pool.CloneOpeningProof(c.opening)
}

// Payment 返回深拷贝的当前付款状态。
func (c *poolCheckpoint) Payment() *pool.PaymentState {
	if c == nil || c.payment == nil {
		return nil
	}
	return pool.ClonePaymentState(c.payment)
}

// VerifiedOpening 返回经完整重验的不可变 verified opening。
func (c *poolCheckpoint) VerifiedOpening() (*pool.VerifiedOpening, error) {
	if c == nil || c.opening == nil {
		return nil, protocol.Errorf("seller.poolCheckpoint.VerifiedOpening", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is empty")
	}
	return pool.VerifyOpeningProof(c.opening)
}

// RefundTemplateTxID 返回费用池统一关联 ID。
func (c *poolCheckpoint) RefundTemplateTxID() pool.RefundTemplateTxID {
	if c == nil || c.opening == nil {
		return pool.RefundTemplateTxID{}
	}
	details, err := pool.DeriveOpeningDetails(c.opening)
	if err != nil {
		return pool.RefundTemplateTxID{}
	}
	return details.RefundTemplateTxID
}

// preparePoolOpeningResult 是 PreparePoolOpening 的统一 Result：Outbound 是
// 待发送 exact Kind 3——发送前必须先持久化 Checkpoint。
type preparePoolOpeningResult struct {
	// Outbound 是待发送 exact Kind 3 预签响应 Artifact。
	Outbound wire.Artifact
	// Checkpoint 是必须先持久化的卖方预签 checkpoint。
	Checkpoint *openingCheckpoint
}

// fundingVerificationResult 是 VerifyFundingDelivery 的统一 Result：
// FundingTransactionRaw 仅供应用经自己的节点适配器广播；SDK 不广播也不声称
// 节点接受。InitialPool 必须在广播决策前持久化。
type fundingVerificationResult struct {
	// Opening 是含资金交易原文的完整 verified 开池证明。
	Opening *pool.VerifiedOpening
	// InitialPool 是初始池 checkpoint。
	InitialPool *poolCheckpoint
	// FundingTransactionRaw 是已验证资金交易字节的原样副本，供应用广播。
	FundingTransactionRaw []byte
}

// deliveryCommand 携带构造一次 004 交付所需的全部输入。授权哈希绝不重复提供：
// 它们只来自买方已签 003。
type deliveryCommand struct {
	// Quote 是本池对应的已签报价凭证（exact Kind 1 解码结果）。
	Quote *content.SignedFileQuote
	// Pool 是当前池 checkpoint。
	Pool *poolCheckpoint
	// RequestRaw 是买方发来的 exact Kind 5 bytes。
	RequestRaw []byte
	// ContentPayloads 是原始 payload 批次，顺序与授权哈希一一对应。
	ContentPayloads [][]byte
	// Seed 在批次包含任何块时提供 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// deliveryResult 是 DeliverContent 的统一 Result：Outbound 是待发送 exact
// Kind 6——发送前必须先保存 Payloads 与 Checkpoint（先保存后发送）。
type deliveryResult struct {
	// Outbound 是待发送 exact Kind 6 wire Artifact。
	Outbound wire.Artifact
	// Checkpoint 记录验收买方 005 所需的全部协议上下文。
	Checkpoint *deliveryCheckpoint
}

// deliveryCheckpoint 是无锁本地角色状态：记录验收 005 时必需的目标序号与
// 绝对累计金额等上下文。它不携带 owner/lease/expiry 语义，也不复制 base 值。
type deliveryCheckpoint struct {
	// refundTemplateTxID 标识本交付所属费用池。
	refundTemplateTxID pool.RefundTemplateTxID
	// authorizationID = SHA-256(exact payment_authorization_cbor)。
	authorizationID protocol.PaymentAuthorizationID
	// paymentSequence 是本批次目标付款序号（= previous + 1）。
	paymentSequence protocol.PaymentSequence
	// sellerAmountAfterSatoshis 是授权提交的绝对累计卖方金额（绝对聪数）。
	sellerAmountAfterSatoshis protocol.Satoshis
}

// RefundTemplateTxID 返回所属费用池关联 ID。
func (c *deliveryCheckpoint) RefundTemplateTxID() pool.RefundTemplateTxID {
	if c == nil {
		return pool.RefundTemplateTxID{}
	}
	return c.refundTemplateTxID
}

// AuthorizationID 返回本批次的授权 typed ID。
func (c *deliveryCheckpoint) AuthorizationID() protocol.PaymentAuthorizationID {
	if c == nil {
		return protocol.PaymentAuthorizationID{}
	}
	return c.authorizationID
}

// PaymentSequence 返回目标付款序号。
func (c *deliveryCheckpoint) PaymentSequence() protocol.PaymentSequence {
	if c == nil {
		return 0
	}
	return c.paymentSequence
}

// SellerAmountAfterSatoshis 返回绝对累计卖方金额（绝对聪数）。
func (c *deliveryCheckpoint) SellerAmountAfterSatoshis() protocol.Satoshis {
	if c == nil {
		return 0
	}
	return c.sellerAmountAfterSatoshis
}

// paymentCommand 携带完成一笔累计付款所需的全部证据。
type paymentCommand struct {
	// Pool 是当前池 checkpoint。
	Pool *poolCheckpoint
	// Request 是按 005 携带的 AuthorizationID 取回的 exact 已签 003。
	Request *content.SignedContentRequest
	// Update 是对端发来的 exact Kind 7 bytes。
	UpdateRaw []byte
	// Checkpoint 是生成本批次 004 时保存的 deliveryCheckpoint。
	Checkpoint *deliveryCheckpoint
}

// closeCommand 携带完成立即关闭所需的买方材料。
type closeCommand struct {
	// Pool 是当前池 checkpoint。
	Pool *poolCheckpoint
	// Unsigned 是买方 prepared 的未签名关闭 candidate。
	Unsigned *pool.UnsignedPayment
	// BuyerSignature 是买方对该 candidate 的 detached 交易签名。
	BuyerSignature []byte
}

// arbitrationCommand 携带构造 Kind 8 所需的本地证据。
type arbitrationCommand struct {
	// Pool 是当前池 checkpoint。
	Pool *poolCheckpoint
	// Request 是被托管批次的 exact 已签 003。
	Request *content.SignedContentRequest
	// DeliveryRaw 是本方发出的 exact Kind 6 bytes。
	DeliveryRaw []byte
}

// arbitratedPaymentCommand 携带完成仲裁收款所需的 exact Kind 8/9 与本地证据。
type arbitratedPaymentCommand struct {
	// RequestRaw 是 exact Kind 8 bytes。
	RequestRaw []byte
	// ResponseRaw 是 exact Kind 9 bytes。
	ResponseRaw []byte
	// DeliveryPayloadsCBOR 是本方保存的 exact content_payloads_cbor（可选；
	// 提供时与 Kind 8 attachment 逐字节比对）。
	DeliveryPayloadsCBOR []byte
}
