package buyer

import (
	"bytes"
	"time"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// 本文件定义 Buyer 角色 API 的 Command / Result / opaque checkpoint。
// 词义约定：Parsed = 结构正确；Verified = 身份/签名/证据链正确；Prepared =
// 已计算签名候选但要求应用先持久化；Complete = 协议材料完整。Broadcast /
// Confirmed / Latest 只能由应用声明，SDK 绝不使用。

// OpeningCheckpoint 是买方本地开池状态（Prepared 阶段产物）：字段私有，
// getter 防御性复制。应用必须在发送 Kind 2 之前先持久化本 checkpoint 的
// evidence；CompletePoolOpening 需要 Request 与 FundingTransactionRaw 原样回传。
type OpeningCheckpoint struct {
	// refundTemplateTxID 是从 Kind 2 请求规范派生的费用池统一关联 ID；
	// Restore 时重新派生，不信任持久化的派生值。
	refundTemplateTxID pool.RefundTemplateTxID
	// request 是 exact 已签 Kind 2 请求（深拷贝保存）。
	request *pool.RefundPresignRequest
	// fundingTransactionRaw 是买方私密资金交易原文；0204 交付前绝不进入
	// 其他网络报文。
	fundingTransactionRaw []byte
}

// RefundTemplateTxID 返回费用池统一关联 ID。
func (c *OpeningCheckpoint) RefundTemplateTxID() pool.RefundTemplateTxID {
	if c == nil {
		return pool.RefundTemplateTxID{}
	}
	return c.refundTemplateTxID
}

// Request 返回深拷贝的已签 Kind 2 预签请求。
func (c *OpeningCheckpoint) Request() *pool.RefundPresignRequest {
	if c == nil || c.request == nil {
		return nil
	}
	return pool.CloneRefundPresignRequest(c.request)
}

// FundingTransactionRaw 返回资金交易原始字节副本。
func (c *OpeningCheckpoint) FundingTransactionRaw() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.fundingTransactionRaw...)
}

// PoolCheckpoint 是买方本地资金池状态（Verified 阶段产物）：完整开池证明 +
// 初始/最新付款状态。应用负责持久化其 evidence 并自行判断业务最新状态。
type PoolCheckpoint struct {
	// opening 是完整开池证明（含资金交易原文）。
	opening *pool.OpeningProof
	// payment 是当前已验证付款状态（初始状态或上一笔累计付款）。
	payment *pool.PaymentState
}

// Opening 返回深拷贝的完整开池证据。
func (c *PoolCheckpoint) Opening() *pool.OpeningProof {
	if c == nil || c.opening == nil {
		return nil
	}
	return pool.CloneOpeningProof(c.opening)
}

// Payment 返回深拷贝的当前已验证付款状态。
func (c *PoolCheckpoint) Payment() *pool.PaymentState {
	if c == nil || c.payment == nil {
		return nil
	}
	return pool.ClonePaymentState(c.payment)
}

// VerifiedPayment 返回经完整重验的不可变 verified payment value；验证失败
// 返回错误而不是降级包装。
func (c *PoolCheckpoint) VerifiedPayment() (*pool.VerifiedPaymentState, error) {
	if c == nil || c.payment == nil || c.opening == nil {
		return nil, protocol.Errorf("buyer.PoolCheckpoint.VerifiedPayment", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is empty")
	}
	return pool.VerifyPaymentState(c.payment, c.opening)
}

// VerifiedOpening 返回经完整重验的不可变 verified opening。
func (c *PoolCheckpoint) VerifiedOpening() (*pool.VerifiedOpening, error) {
	if c == nil || c.opening == nil {
		return nil, protocol.Errorf("buyer.PoolCheckpoint.VerifiedOpening", protocol.CodeInvalidEvidence, 0, "checkpoint", "pool checkpoint is empty")
	}
	return pool.VerifyOpeningProof(c.opening)
}

// RefundTemplateTxID 返回费用池统一关联 ID。
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

// AuthorizationCheckpoint 记录一次已签 Kind 5 授权的应用侧上下文：
// PaymentAuthorizationID 是查找键；Request 是 exact 已签 003（发送前必须
// 先持久化）。
type AuthorizationCheckpoint struct {
	// authorizationID = SHA-256(exact payment_authorization_cbor)，内容寻址键。
	authorizationID protocol.PaymentAuthorizationID
	// request 是 exact 已签 Kind 5 授权凭证（深拷贝）。
	request *content.SignedContentRequest
}

// AuthorizationID 返回本次授权的 typed ID。
func (c *AuthorizationCheckpoint) AuthorizationID() protocol.PaymentAuthorizationID {
	if c == nil {
		return protocol.PaymentAuthorizationID{}
	}
	return c.authorizationID
}

// Request 返回深拷贝的 exact 已签 003 凭证。
func (c *AuthorizationCheckpoint) Request() *content.SignedContentRequest {
	if c == nil || c.request == nil {
		return nil
	}
	return content.CloneSignedContentRequest(c.request)
}

// PrepareOpeningCommand 携带构造 Kind 2 所需的全部显式输入：verified quote、
// 资金交易、退款锁定、费率与对手方公钥。
type PrepareOpeningCommand struct {
	// Quote 是买方已验证接受的报价（AcceptQuote 的返回值）。
	Quote *content.VerifiedQuote
	// FundingTransactionRaw 是买方资金交易原始字节；输出 0 必须是池输出。
	FundingTransactionRaw []byte
	// ExpiryLockTime 是退款交易的到期锁定时间（低于阈值按区块高解释，否则
	// 按 UTC Unix 时间戳）。
	ExpiryLockTime protocol.RefundLockTime
	// MinerFeeRateSatoshisPerKilobyte 是池内交易矿工费率（每千字节聪数）。
	MinerFeeRateSatoshisPerKilobyte protocol.SatoshisPerKilobyte
	// SellerPublicKey 是卖方压缩公钥。
	SellerPublicKey protocol.PublicKey
	// ArbiterPublicKey 是仲裁方压缩公钥。
	ArbiterPublicKey protocol.PublicKey
}

// PreparePoolOpeningResult 是 PreparePoolOpening 的统一 Result：Outbound 是待发送
// 的 exact Kind 2 Artifact——发送前必须先持久化 Checkpoint。
type PreparePoolOpeningResult struct {
	// Outbound 是待发送 exact Kind 2 wire Artifact。
	Outbound wire.Artifact
	// Checkpoint 是必须先于 Outbound 发送而持久化的买方开池 checkpoint。
	Checkpoint *OpeningCheckpoint
}

// CompleteOpeningResult 是 CompletePoolOpening 的统一 Result：Opening 是
// verified 开池证明；InitialPool 是初始池 checkpoint（应用需持久化）。
type CompleteOpeningResult struct {
	// Opening 是含卖方预签与资金交易原文的完整已验证开池证明。
	Opening *pool.VerifiedOpening
	// InitialPool 是初始池 checkpoint（sequence=2、卖方/仲裁金额为零）。
	InitialPool *PoolCheckpoint
}

// RequestContentCommand 携带构造一次 003 授权的全部输入。
type RequestContentCommand struct {
	// Quote 是已验证报价。
	Quote *content.VerifiedQuote
	// Pool 是当前池 checkpoint（opening + previous payment state）。
	Pool *PoolCheckpoint
	// ContentHashes 是有序不重复的内容哈希批次（1..64）；等于 SeedHash 即购 seed。
	ContentHashes [][]byte
	// DeliveryDeadline 是交付截止时间（UTC Unix 秒）；必须晚于 Facts.Now 且
	// 不超过报价有效期。
	DeliveryDeadline content.UnixSeconds
	// Seed 在批次包含任何块时必须提供已验证 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// RequestContentResult 是 RequestContent 的统一 Result：Outbound 是待发送的
// exact Kind 5 Artifact；AuthorizationID 是路由键；Checkpoint 必须在发送前
// 与 Outbound 一同持久化。
type RequestContentResult struct {
	// Outbound 是待发送 exact Kind 5 wire Artifact。
	Outbound wire.Artifact
	// AuthorizationID 是本批授权的内容寻址键：SHA-256(exact payment_authorization_cbor)。
	AuthorizationID protocol.PaymentAuthorizationID
	// Checkpoint 保存 exact 已签 003，供 VerifyDeliveryAndPreparePayment 与
	// 仲裁取回路径复用。
	Checkpoint *AuthorizationCheckpoint
}

// VerifyDeliveryCommand 携带验收一次 004 交付所需的全部证据。
type VerifyDeliveryCommand struct {
	// Quote 是已验证报价。
	Quote *content.VerifiedQuote
	// Pool 是当前池 checkpoint。
	Pool *PoolCheckpoint
	// Request 是本批次的授权 checkpoint（RequestContent 返回并持久化者）。
	Request *AuthorizationCheckpoint
	// DeliveryRaw 是对端发来的 exact Kind 6 bytes。
	DeliveryRaw []byte
	// Seed 在批次包含任何块时提供已验证 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// PaymentPreparationResult 是 VerifyDeliveryAndPreparePayment 的统一 Result：
// Payloads 落盘由应用负责；Outbound 是待发送 exact Kind 7（发送前必须先
// 持久化 payloads 与本 Result 的全部字段）；NextCandidate 是重建出的目标
// 未签名状态交易，仅供审计，不进入 wire。
type PaymentPreparationResult struct {
	// Payloads 是按授权顺序排列的已验证 payload 字节。
	Payloads [][]byte
	// Outbound 是待发送 exact Kind 7 最小付款凭证 Artifact。
	Outbound wire.Artifact
	// NextCandidate 是确定性重建的目标未签名状态交易（本地审计用）。
	NextCandidate *pool.UnsignedPayment
}

// PrepareCloseCommand 携带立即关闭所需输入：调用方自选基准状态与目标金额。
type PrepareCloseCommand struct {
	// Pool 是当前池 checkpoint。
	Pool *PoolCheckpoint
	// Base 是调用方选定的基准付款状态；SDK 不声称它是业务最新。
	Base *pool.PaymentState
	// TargetSellerAmountSatoshis 是最终关闭中卖方的累计金额（绝对聪数）。
	TargetSellerAmountSatoshis protocol.Satoshis
}

// ClosePreparationResult 是 PrepareClose 的统一 Result：Unsigned 是未签名最终
// 关闭 candidate，BuyerSignature 是买方 detached 交易签名（均须先持久化再
// 发送给卖方）。两者都不是 complete transaction。
type ClosePreparationResult struct {
	// Unsigned 是 sequence=4294967295 的未签名关闭 candidate。
	Unsigned *pool.UnsignedPayment
	// BuyerSignature 是买方对该 candidate 的 DER+flag 交易签名。
	BuyerSignature []byte
}

// VerifyCloseCommand 携带验收卖方完整关闭交易所需的证据。
type VerifyCloseCommand struct {
	// Pool 是当前池 checkpoint（用于 opening 归属绑定）。
	Pool *PoolCheckpoint
	// Close 是卖方合并后的完整关闭交易。
	Close *pool.SignedPayment
}

// ArbitratedContentCommand 携带 008 取回验证所需的本地证据。
type ArbitratedContentCommand struct {
	// Quote 是已验证报价。
	Quote *content.VerifiedQuote
	// Pool 是当前池 checkpoint。
	Pool *PoolCheckpoint
	// Request 是取回所引用授权的 checkpoint（exact 已签 003）。
	Request *AuthorizationCheckpoint
	// RetrievalRequestRaw 是本地保存的 exact Kind 10 bytes（重放原请求，
	// 绝不生成新 nonce）。
	RetrievalRequestRaw []byte
	// RetrievalResponseRaw 是对端返回的 exact Kind 11 bytes。
	RetrievalResponseRaw []byte
	// Seed 在取回批次包含任何块时提供已验证 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// ArbitratedContentResult 是 VerifyArbitratedContent 的统一 Result：
// Available=false 表示 valid unavailable（已验签协议结果，不是 error），应用
// 按 UnavailableReason 决定新 nonce、等待或终止；Available=true 时 Payloads
// 为已验证内容字节，落盘由应用负责。两种分支都不产生 Kind 7 或任何付款状态。
type ArbitratedContentResult struct {
	// ContentRetrievalRequestID 是本应答对应的 exact Kind 10 请求文档哈希。
	ContentRetrievalRequestID protocol.ContentRetrievalRequestID
	// ArbitrationClaimID 是托管记录的仲裁 Claim 身份。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// Available 报告分支结果。
	Available bool
	// UnavailableReason 仅 Available=false 时有意义。
	UnavailableReason arbitration.ContentRetrievalUnavailableReason
	// Payloads 仅 Available=true 时非空：按授权顺序的已验证内容字节。
	Payloads [][]byte
}

// ensureOwnership 把 caller-supplied opening evidence 绑定到本 Workflow 公钥；
// 加载证据绝不等于授权他人开池。
func ensureOwnership(publicKey []byte, proof *pool.OpeningProof) error {
	if proof == nil {
		return protocol.Errorf("buyer", protocol.CodeInvalidEvidence, 0, "opening_proof", "opening proof is required")
	}
	if !bytes.Equal(publicKey, proof.BuyerPublicKey) {
		return protocol.Errorf("buyer", protocol.CodeUnauthorized, 0, "buyer_public_key", "workflow key does not match opening buyer")
	}
	return nil
}

// unixSeconds 把协议 UTC Unix 秒还原为 UTC time.Time。
func unixSeconds(value int64) time.Time { return time.Unix(value, 0).UTC() }
