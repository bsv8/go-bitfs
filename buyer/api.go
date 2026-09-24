package buyer

// 本文件是 Buyer 的纯函数边界：每个入口只接收原始报文字节、普通证据包与
// 一次调用专用的受约束 Signer，返回原始报文字节或普通证据包。SDK 不持有
// 跨步骤对象、不保存进度、不读取时钟、不访问存储，也不广播任何交易。
//
// 买方推进池状态的唯一方式：从链上取得完整付款交易原文，作为普通证据包的
// LatestPaymentRawTx 传入下一步，由 SDK 全量重验；不存在跳过链上结果的入口。

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

// BuyerOpeningEvidence 是买方开池阶段的普通证据包：买方 exact Kind 2 请求、
// 卖方 exact Kind 3 响应与买方私密资金交易原文。应用必须在发送 Kind 2 前
// 持久化它；CompleteOpening 需要原样回传。
type BuyerOpeningEvidence struct {
	// RawKind2 是买方发出的 exact Kind 2 预签请求字节。
	RawKind2 []byte
	// RawKind3 是卖方返回的 exact Kind 3 预签响应字节；PrepareOpening 阶段为空。
	RawKind3 []byte
	// FundingTransactionRaw 是买方资金交易原文；0204 交付前绝不进入其他网络报文。
	FundingTransactionRaw []byte
}

// BuyerPoolEvidence 是买方视角的资金池普通证据包：完整开池证明加当前链上
// 付款状态原文。省略 LatestPaymentRawTx 表示池仍处于初始退款状态，SDK 会从
// opening 重建初始状态；提供时 SDK 逐字节解析并全量重验它，绝不信任调用方
// 声明的序号或金额。
type BuyerPoolEvidence struct {
	// Opening 是含资金交易原文的完整开池证明（普通数据，可深拷贝）。
	Opening *pool.OpeningProof
	// LatestPaymentRawTx 是链上取得的最新完整付款交易原文；省略（nil/空）
	// 表示初始退款状态。不得填写未上链的本地候选。
	LatestPaymentRawTx []byte
}

// BuyerAuthorizationEvidence 是一次已签授权的普通证据包：exact Kind 1 报价
// 与买方 exact Kind 5 授权。交付验收、关池与仲裁取回都需要它。
type BuyerAuthorizationEvidence struct {
	// RawKind1 是卖方签署的 exact Kind 1 报价字节。
	RawKind1 []byte
	// RawKind5 是买方签署的 exact Kind 5 付款授权字节。
	RawKind5 []byte
}

// PrepareOpeningInput 携带构造 exact Kind 2 所需的全部显式输入。
type PrepareOpeningInput struct {
	// QuoteRaw 是本池对应的 exact Kind 1 报价字节；SDK 会用其条款绑定买方身份、
	// 卖方公钥与受支持仲裁方，拒绝把资金池开给报价之外的角色。
	QuoteRaw []byte
	// FundingTransactionRaw 是买方资金交易原文；输出 0 必须是池输出。
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

// RequestContentInput 携带构造一次 exact Kind 5 授权的全部输入。
type RequestContentInput struct {
	// QuoteRaw 是本池对应的 exact Kind 1 报价字节。
	QuoteRaw []byte
	// Pool 是当前池普通证据包（初始状态可省略 LatestPaymentRawTx）。
	Pool BuyerPoolEvidence
	// ContentHashes 是有序不重复的内容哈希批次（1..64）；等于 SeedHash 即购 seed。
	ContentHashes [][]byte
	// DeliveryDeadline 是交付截止时间（UTC Unix 秒）；必须晚于 Facts.Now 且
	// 不超过报价有效期。
	DeliveryDeadline content.UnixSeconds
	// Seed 在批次包含任何块时必须提供已验证 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// VerifyDeliveryInput 携带验收一次 exact Kind 6 所需的全部证据。
type VerifyDeliveryInput struct {
	// Authorization 是本批次的已签授权证据包（exact Kind 1 + exact Kind 5）。
	Authorization BuyerAuthorizationEvidence
	// Pool 是当前池普通证据包。
	Pool BuyerPoolEvidence
	// DeliveryRaw 是对端发来的 exact Kind 6 bytes。
	DeliveryRaw []byte
	// Seed 在批次包含任何块时提供已验证 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// PrepareCloseInput 携带立即关闭所需的输入：调用方自选基准池证据与目标金额。
type PrepareCloseInput struct {
	// Pool 是当前池普通证据包；LatestPaymentRawTx 就是本关闭的基准状态。
	Pool BuyerPoolEvidence
	// TargetSellerAmountSatoshis 是最终关闭中卖方的累计金额（绝对聪数）。
	TargetSellerAmountSatoshis protocol.Satoshis
}

// VerifyCompletedCloseInput 携带验收卖方完整关闭交易所需的证据。
type VerifyCompletedCloseInput struct {
	// Pool 是当前池普通证据包（用于 opening 归属绑定）。
	Pool BuyerPoolEvidence
	// CloseRaw 是卖方合并后的完整关闭交易原文。
	CloseRaw []byte
}

// VerifyCompletedCloseArtifactInput 携带 Kind 13 响应与验收所需的本地池证据。
type VerifyCompletedCloseArtifactInput struct {
	// Pool 是用于验证费用池归属与完整交易签名的普通证据包。
	Pool BuyerPoolEvidence
	// ResponseRaw 是卖方返回的 exact Kind 13 关池响应。
	ResponseRaw []byte
}

// RetrievalRequestInput 携带构造 exact Kind 10 所需的本地证据。
type RetrievalRequestInput struct {
	// Pool 是当前池普通证据包。
	Pool BuyerPoolEvidence
	// Authorization 是取回所引用授权的普通证据包（exact Kind 1 + exact Kind 5）。
	Authorization BuyerAuthorizationEvidence
	// Nonce 是可选的 32 字节重放键；nil/空时由 SDK 用 crypto/rand 生成。
	// 网络重试必须重放已持久化的 exact Kind 10，绝不能重新生成 nonce。
	Nonce []byte
}

// ArbitratedContentInput 携带 exact Kind 10/11 验收所需的本地证据。
type ArbitratedContentInput struct {
	// Authorization 是取回所引用授权的普通证据包（exact Kind 1 + exact Kind 5）。
	Authorization BuyerAuthorizationEvidence
	// Pool 是当前池普通证据包。
	Pool BuyerPoolEvidence
	// RetrievalRequestRaw 是本地保存的 exact Kind 10 bytes（重放原请求）。
	RetrievalRequestRaw []byte
	// RetrievalResponseRaw 是对端返回的 exact Kind 11 bytes。
	RetrievalResponseRaw []byte
	// Seed 在取回批次包含任何块时提供已验证 seed 原文；纯 seed 批次可空。
	Seed []byte
}

// ArbitratedContentResult 是 VerifyArbitratedContent 的统一 Result：
// Available=false 表示 valid unavailable（已验签协议结果，不是 error），应用
// 按 UnavailableReason 决定新 nonce、等待或终止；Available=true 时 Payloads
// 为已验证内容字节，落盘由应用负责。两种分支都不产生 Kind 7 或付款状态。
type ArbitratedContentResult struct {
	// ContentRetrievalRequestID 是本应答对应的 exact Kind 10 请求文档哈希。
	ContentRetrievalRequestID protocol.ContentRetrievalRequestID
	// ArbitrationClaimID 是托管记录的仲裁 Claim 身份。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// Available 报告分支结果。
	Available bool
	// UnavailableReason 仅 Available=false 时有意义：0 未收到、1 未就绪、
	// 2 托管已丢失。
	UnavailableReason arbitration.ContentRetrievalUnavailableReason
	// Payloads 仅 Available=true 时非空：按授权顺序的已验证内容字节。
	Payloads [][]byte
}

// AcceptQuote 严格解析 exact Kind 1 bytes，验签与过期判断（唯一时间事实为
// facts.Now）通过后返回不可变 VerifiedQuote。本操作不接收身份参数：买方应用
// 必须自行比较返回 Terms().BuyerPublicKey 与本地身份，再决定是否购买。
// 纯验证路径不签名，因此不接收 context。
func AcceptQuote(facts protocol.Facts, rawKind1 []byte) (*content.VerifiedQuote, error) {
	artifact, err := wire.ParseAs(wire.FileQuote, rawKind1)
	if err != nil {
		return nil, err
	}
	quote, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		return nil, err
	}
	return content.VerifyQuote(quote, facts)
}

// PrepareOpening 构造并签署 exact Kind 2 预签请求：返回待发送 Artifact 与必须
// 先持久化的普通证据包。它先按 exact Kind 1 报价条款绑定买方身份、卖方公钥与
// 受支持仲裁方，再进入交易构造；本操作不含任何时间/高度判断，因此不接收
// Facts；资金交易原文只存在于证据包，SDK 不持久化。
func PrepareOpening(ctx context.Context, input PrepareOpeningInput, signer protocol.Signer) (wire.Artifact, BuyerOpeningEvidence, error) {
	const op = "buyer.PrepareOpening"
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, BuyerOpeningEvidence{}, err
	}
	if err := bindOpeningToQuote(op, input, workflow.publicKey[:]); err != nil {
		return wire.Artifact{}, BuyerOpeningEvidence{}, err
	}
	result, err := workflow.PreparePoolOpening(ctx, prepareOpeningCommand{
		FundingTransactionRaw:           bytes.Clone(input.FundingTransactionRaw),
		ExpiryLockTime:                  input.ExpiryLockTime,
		MinerFeeRateSatoshisPerKilobyte: input.MinerFeeRateSatoshisPerKilobyte,
		SellerPublicKey:                 input.SellerPublicKey,
		ArbiterPublicKey:                input.ArbiterPublicKey,
	})
	if err != nil {
		return wire.Artifact{}, BuyerOpeningEvidence{}, err
	}
	if result.Checkpoint == nil {
		return wire.Artifact{}, BuyerOpeningEvidence{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 2, "opening", "prepared opening evidence is required")
	}
	evidence := BuyerOpeningEvidence{
		RawKind2:              result.Outbound.Bytes(),
		FundingTransactionRaw: bytes.Clone(result.Checkpoint.fundingTransactionRaw),
	}
	return result.Outbound, evidence, nil
}

// CompleteOpening 用保存的普通证据包验收 exact Kind 3：重派生池 ID 并拒绝任何
// 错配，验卖方预签，产出完整开池证据包与初始池证据包。纯验证路径不签名，
// 因此不接收 context。
func CompleteOpening(opening BuyerOpeningEvidence, rawKind3 []byte) (BuyerOpeningEvidence, BuyerPoolEvidence, error) {
	checkpoint, err := restoreOpeningCheckpoint(opening.RawKind2, opening.FundingTransactionRaw)
	if err != nil {
		return BuyerOpeningEvidence{}, BuyerPoolEvidence{}, err
	}
	workflow := &workflow{signer: nil, publicKey: publicKeyOf(checkpoint.request.BuyerPublicKey)}
	result, err := workflow.CompletePoolOpening(checkpoint, rawKind3)
	if err != nil {
		return BuyerOpeningEvidence{}, BuyerPoolEvidence{}, err
	}
	proof := result.Opening.Proof()
	completedEvidence := BuyerOpeningEvidence{
		RawKind2:              bytes.Clone(opening.RawKind2),
		RawKind3:              bytes.Clone(rawKind3),
		FundingTransactionRaw: bytes.Clone(opening.FundingTransactionRaw),
	}
	poolEvidence := BuyerPoolEvidence{Opening: proof}
	resultCheckpoint := result.InitialPool
	if resultCheckpoint != nil {
		poolEvidence.Opening = pool.CloneOpeningProof(resultCheckpoint.opening)
	}
	if poolEvidence.Opening == nil {
		poolEvidence.Opening = proof
	}
	return completedEvidence, poolEvidence, nil
}

// PrepareFundingDelivery 把完整开池证据包携带的资金交易打包成 exact Kind 4
// Artifact；纯打包路径不签名，不广播资金交易——广播边界属于应用。
func PrepareFundingDelivery(evidence BuyerPoolEvidence) (wire.Artifact, error) {
	const op = "buyer.PrepareFundingDelivery"
	checkpoint, err := internalPoolCheckpoint(evidence)
	if err != nil {
		return wire.Artifact{}, err
	}
	opening := checkpoint.opening
	if opening == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 4, "opening", "pool opening evidence is required")
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxID(opening)
	if err != nil {
		return wire.Artifact{}, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
	if err != nil {
		return wire.Artifact{}, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return wire.Artifact{}, protocol.Wrap(fmt.Errorf("opening proof is invalid: %v", err), op, protocol.CodeInvalidEvidence, 4, "opening_proof")
	}
	if len(opening.FundingTransactionRaw) == 0 {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 4, "funding_transaction_raw", "complete funding transaction is required")
	}
	delivery := &pool.FundingTransactionDelivery{RefundTemplateTxID: refundTemplateTxID, FundingTransactionRaw: bytes.Clone(opening.FundingTransactionRaw)}
	return wire.EncodeFundingTransactionDelivery(delivery)
}

// PrepareContentRequest 验证报价/池/批次上下文/聚合价格/余额后签署 exact
// Kind 5：返回待发送 Artifact 与必须先持久化的普通授权证据包。
func PrepareContentRequest(ctx context.Context, facts protocol.Facts, input RequestContentInput, signer protocol.Signer) (wire.Artifact, BuyerAuthorizationEvidence, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, BuyerAuthorizationEvidence{}, err
	}
	verifiedQuote, err := verifyQuoteForWorkflow(input.QuoteRaw, facts, workflow.publicKey[:])
	if err != nil {
		return wire.Artifact{}, BuyerAuthorizationEvidence{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return wire.Artifact{}, BuyerAuthorizationEvidence{}, err
	}
	hashes := clonePayloads(input.ContentHashes)
	result, err := workflow.RequestContent(ctx, facts, requestContentCommand{
		Quote:            verifiedQuote,
		Pool:             checkpoint,
		ContentHashes:    hashes,
		DeliveryDeadline: input.DeliveryDeadline,
		Seed:             bytes.Clone(input.Seed),
	})
	if err != nil {
		return wire.Artifact{}, BuyerAuthorizationEvidence{}, err
	}
	evidence := BuyerAuthorizationEvidence{RawKind1: bytes.Clone(input.QuoteRaw), RawKind5: result.Outbound.Bytes()}
	return result.Outbound, evidence, nil
}

// VerifyDelivery 验收 exact Kind 6 并产生整批唯一的最小 exact Kind 7 凭证：
// 先验 payload 与 seed 归属，再签 Kind 7；不产生“已付款”状态。返回按授权
// 顺序的已验证 payload 批次与待发送 exact Kind 7。
func VerifyDelivery(ctx context.Context, facts protocol.Facts, input VerifyDeliveryInput, signer protocol.Signer) ([][]byte, wire.Artifact, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return nil, wire.Artifact{}, err
	}
	verifiedQuote, err := verifyQuoteForWorkflow(input.Authorization.RawKind1, facts, workflow.publicKey[:])
	if err != nil {
		return nil, wire.Artifact{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, wire.Artifact{}, err
	}
	authorization, err := internalAuthorizationCheckpoint(input.Authorization.RawKind5)
	if err != nil {
		return nil, wire.Artifact{}, err
	}
	result, err := workflow.VerifyDeliveryAndPreparePayment(ctx, facts, verifyDeliveryCommand{
		Quote:       verifiedQuote,
		Pool:        checkpoint,
		Request:     authorization,
		DeliveryRaw: bytes.Clone(input.DeliveryRaw),
		Seed:        bytes.Clone(input.Seed),
	})
	if err != nil {
		return nil, wire.Artifact{}, err
	}
	return result.Payloads, result.Outbound, nil
}

// PrepareClose 从调用方选定的基准池状态与目标金额构造未签名关闭 candidate 和
// 买方 detached 签名。SDK 不声称基准是业务最新，也不判断目标金额是否符合订单
// 或账本；不广播。返回未签名 candidate 原文与买方签名。
func PrepareClose(ctx context.Context, facts protocol.Facts, input PrepareCloseInput, signer protocol.Signer) ([]byte, []byte, error) {
	unsignedRaw, buyerSignature, _, err := prepareCloseArtifactData(ctx, facts, input, signer)
	return unsignedRaw, buyerSignature, err
}

func prepareCloseArtifactData(ctx context.Context, facts protocol.Facts, input PrepareCloseInput, signer protocol.Signer) ([]byte, []byte, pool.RefundTemplateTxID, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return nil, nil, pool.RefundTemplateTxID{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, nil, pool.RefundTemplateTxID{}, err
	}
	details, err := pool.DeriveOpeningDetails(checkpoint.opening)
	if err != nil {
		return nil, nil, pool.RefundTemplateTxID{}, err
	}
	result, err := workflow.PrepareClose(ctx, facts, prepareCloseCommand{
		Pool:                       checkpoint,
		Base:                       pool.ClonePaymentState(checkpoint.payment),
		TargetSellerAmountSatoshis: input.TargetSellerAmountSatoshis,
	})
	if err != nil {
		return nil, nil, pool.RefundTemplateTxID{}, err
	}
	if result.Unsigned == nil {
		return nil, nil, pool.RefundTemplateTxID{}, protocol.Errorf("buyer.PrepareClose", protocol.CodeInvalidEvidence, 0, "unsigned_close", "close candidate is required")
	}
	if err := pool.ValidateCloseTransactionRaw(result.Unsigned.RawTx); err != nil {
		return nil, nil, pool.RefundTemplateTxID{}, err
	}
	return bytes.Clone(result.Unsigned.RawTx), bytes.Clone(result.BuyerSignature), details.RefundTemplateTxID, nil
}

// PrepareCloseArtifact 构造买方 exact Kind 12 关池请求。返回的 Artifact
// 必须先由应用持久化再发送；其中首个业务字段由开池证据派生，广播仍由应用负责。
func PrepareCloseArtifact(ctx context.Context, facts protocol.Facts, input PrepareCloseInput, signer protocol.Signer) (wire.Artifact, error) {
	unsignedRaw, buyerSignature, refundTemplateTxID, err := prepareCloseArtifactData(ctx, facts, input, signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	return wire.EncodePoolCloseRequest(&pool.PoolCloseRequest{
		RefundTemplateTxID:             refundTemplateTxID,
		UnsignedCloseTransactionRaw:    unsignedRaw,
		BuyerCloseTransactionSignature: buyerSignature,
	})
}

// VerifyCompletedClose 验证卖方完整关闭交易在给定开池证据下密码学、结构与
// 交易关系全部正确，返回不可变 Complete 结果；不声称已广播或已确认。
func VerifyCompletedClose(input VerifyCompletedCloseInput) (*pool.VerifiedSignedTransaction, error) {
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, err
	}
	return verifyCompletedCloseFromCheckpoint(input.CloseRaw, checkpoint)
}

func verifyCompletedCloseFromCheckpoint(closeRaw []byte, checkpoint *poolCheckpoint) (*pool.VerifiedSignedTransaction, error) {
	if err := pool.ValidateCloseTransactionRaw(closeRaw); err != nil {
		return nil, err
	}
	workflow := &workflow{signer: nil, publicKey: publicKeyOf(checkpoint.opening.BuyerPublicKey)}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: checkpoint.opening.BuyerPublicKey, SellerPublicKey: checkpoint.opening.SellerPublicKey, ArbiterPublicKey: checkpoint.opening.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	state, err := engine.ParsePaymentState(closeRaw, checkpoint.opening)
	if err != nil {
		return nil, err
	}
	signed := &pool.SignedPayment{State: *state, RawTx: bytes.Clone(closeRaw)}
	return workflow.VerifyCompletedClose(verifyCloseCommand{Pool: checkpoint, Close: signed})
}

// VerifyCompletedCloseArtifact 严格解析 Kind 13、复核响应池 ID，再验收卖方完整
// 关闭交易。它不声称交易已广播或已确认。
func VerifyCompletedCloseArtifact(input VerifyCompletedCloseArtifactInput) (*pool.VerifiedSignedTransaction, error) {
	artifact, err := wire.ParseAs(wire.PoolCloseResponse, input.ResponseRaw)
	if err != nil {
		return nil, err
	}
	response, err := wire.DecodePoolCloseResponse(artifact)
	if err != nil {
		return nil, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(checkpoint.opening)
	if err != nil {
		return nil, err
	}
	if response.RefundTemplateTxID != details.RefundTemplateTxID {
		return nil, protocol.Errorf("buyer.VerifyCompletedCloseArtifact", protocol.CodeStateConflict, 13, "refund_template_txid", "close response belongs to another pool")
	}
	return verifyCompletedCloseFromCheckpoint(response.CompleteCloseTransactionRaw, checkpoint)
}

// BuildMaturedRefund 在显式事实判定退款到期后合并双方退款签名，返回可广播的
// verified refund transaction；是否广播由应用决定，不调用任何 Signer。
func BuildMaturedRefund(facts protocol.Facts, evidence BuyerPoolEvidence) (*pool.VerifiedSignedTransaction, error) {
	checkpoint, err := internalPoolCheckpoint(evidence)
	if err != nil {
		return nil, err
	}
	workflow := &workflow{signer: nil, publicKey: publicKeyOf(checkpoint.opening.BuyerPublicKey)}
	return workflow.BuildMaturedRefund(facts, checkpoint)
}

// RequestArbitratedContent 为一条托管记录构造 exact Kind 10 Artifact：默认入口
// 由 SDK 生成安全随机 nonce；网络超时重试必须原样重放已持久化的 Artifact，
// 绝不能重新调用本方法生成新 nonce。显式 Nonce 只服务测试与恢复路径。
// Signer 只在本次调用内用于签署 Kind 10。
func RequestArbitratedContent(ctx context.Context, input RetrievalRequestInput, signer protocol.Signer) (wire.Artifact, error) {
	workflow, err := newWorkflow(signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return wire.Artifact{}, err
	}
	authorization, err := internalAuthorizationCheckpoint(input.Authorization.RawKind5)
	if err != nil {
		return wire.Artifact{}, err
	}
	if !bytes.Equal(workflow.publicKey[:], checkpoint.opening.BuyerPublicKey) {
		return wire.Artifact{}, protocol.Errorf("buyer.RequestArbitratedContent", protocol.CodeUnauthorized, 10, "buyer_public_key", "signer does not match pool buyer")
	}
	nonce := protocol.RetrievalNonce{}
	if len(input.Nonce) == 0 {
		nonce, err = protocol.GenerateRetrievalNonce()
		if err != nil {
			return wire.Artifact{}, err
		}
	} else {
		nonce, err = protocol.NewRetrievalNonce(input.Nonce)
		if err != nil {
			return wire.Artifact{}, protocol.Wrap(err, "buyer.RequestArbitratedContent", protocol.CodeInvalidEvidence, 10, "nonce")
		}
	}
	return workflow.buildRetrievalRequest(ctx, arbitrationRetrievalCommand{Pool: checkpoint, Authorization: authorization}, nonce)
}

// VerifyArbitratedContent 时间无关地验收 exact Kind 10/11：available 分支额外
// 复核 payload 归属与价格；unavailable 分支作为已验签协议结果返回。过期报价、
// 截止或退款锁定绝不拒绝已签托管证据；available 不生成 Kind 7，也不产生付款
// 状态。本入口不需要 Signer：Kind 10 的买方签名直接对照开池证据中的买方公钥
// 验证，不产生任何新签名。
func VerifyArbitratedContent(ctx context.Context, input ArbitratedContentInput) (*ArbitratedContentResult, error) {
	verifiedQuote, err := content.VerifyQuoteEvidence(mustSignedQuote(input.Authorization.RawKind1))
	if err != nil {
		return nil, err
	}
	checkpoint, err := internalPoolCheckpoint(input.Pool)
	if err != nil {
		return nil, err
	}
	authorization, err := internalAuthorizationCheckpoint(input.Authorization.RawKind5)
	if err != nil {
		return nil, err
	}
	workflow := &workflow{publicKey: publicKeyOf(checkpoint.opening.BuyerPublicKey)}
	result, err := workflow.VerifyArbitratedContent(ctx, arbitratedContentCommand{
		Quote:                verifiedQuote,
		Pool:                 checkpoint,
		Request:              authorization,
		RetrievalRequestRaw:  bytes.Clone(input.RetrievalRequestRaw),
		RetrievalResponseRaw: bytes.Clone(input.RetrievalResponseRaw),
		Seed:                 bytes.Clone(input.Seed),
	})
	if err != nil {
		return nil, err
	}
	return &ArbitratedContentResult{
		ContentRetrievalRequestID: result.ContentRetrievalRequestID,
		ArbitrationClaimID:        result.ArbitrationClaimID,
		Available:                 result.Available,
		UnavailableReason:         result.UnavailableReason,
		Payloads:                  clonePayloads(result.Payloads),
	}, nil
}

// ---- 包内小工具 ----

// publicKeyOf 把压缩公钥字节复制为强类型公钥；失败时返回零值，交由后续验证拒绝。
func publicKeyOf(raw []byte) protocol.PublicKey {
	publicKey, err := protocol.PublicKeyFromBytes(raw)
	if err != nil {
		return protocol.PublicKey{}
	}
	return publicKey
}

// internalPoolCheckpoint 把普通证据包还原为内部池状态：opening 全量重验，
// 付款状态要么由 opening 重建初始退款状态，要么逐字节解析调用方提供的
// 链上交易原文并全量重验；绝不接受调用方声明的序号或金额。
func internalPoolCheckpoint(evidence BuyerPoolEvidence) (*poolCheckpoint, error) {
	const op = "buyer.poolEvidence"
	opening := pool.CloneOpeningProof(evidence.Opening)
	if opening == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "opening", "pool opening evidence is required")
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

// internalAuthorizationCheckpoint 从 exact Kind 5 还原授权 checkpoint：解析、
// 结构验证并重算授权 ID，不信任任何持久化派生值。
func internalAuthorizationCheckpoint(rawKind5 []byte) (*authorizationCheckpoint, error) {
	const op = "buyer.authorizationEvidence"
	artifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeContentRequest(artifact)
	if err != nil {
		return nil, err
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	return &authorizationCheckpoint{authorizationID: authID, request: request}, nil
}

// bindOpeningToQuote 在构造 exact Kind 2 之前把开池输入绑定到 exact Kind 1 报价：
// 买方必须是报价命名的买方，卖方与仲裁方必须分别是报价卖方与报价允许的仲裁方。
// 报价证据是时间无关验证；过期判断由内容请求与交付步骤用显式 Facts 完成。
func bindOpeningToQuote(op string, input PrepareOpeningInput, buyerPublicKey []byte) error {
	verified, err := content.VerifyQuoteEvidence(mustSignedQuote(input.QuoteRaw))
	if err != nil {
		return protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 2, "quote_raw")
	}
	terms := verified.Terms()
	if terms == nil {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 2, "quote_raw", "exact Kind 1 quote is required")
	}
	if !bytes.Equal(terms.BuyerPublicKey, buyerPublicKey) {
		return protocol.Errorf(op, protocol.CodeUnauthorized, 2, "buyer_public_key", "signer does not match quote buyer")
	}
	if !bytes.Equal(verified.SellerPublicKey(), input.SellerPublicKey[:]) {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 2, "seller_public_key", "opening seller does not match quote seller")
	}
	if !verified.AllowsArbiter(input.ArbiterPublicKey[:]) {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 2, "supported_arbiter_public_keys", "opening arbiter is not allowed by quote")
	}
	return nil
}

// verifyQuoteForWorkflow 解析 exact Kind 1 并把报价绑定到给定买方压缩公钥。
func verifyQuoteForWorkflow(rawKind1 []byte, facts protocol.Facts, buyerPublicKey []byte) (*content.VerifiedQuote, error) {
	artifact, err := wire.ParseAs(wire.FileQuote, rawKind1)
	if err != nil {
		return nil, err
	}
	quote, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		return nil, err
	}
	return content.VerifyQuoteForBuyer(quote, facts, buyerPublicKey)
}

// mustSignedQuote 解析 exact Kind 1 为 SignedFileQuote；失败返回 nil，由调用方
// 的 VerifyQuoteEvidence 统一拒绝。
func mustSignedQuote(rawKind1 []byte) *content.SignedFileQuote {
	artifact, err := wire.ParseAs(wire.FileQuote, rawKind1)
	if err != nil {
		return nil
	}
	quote, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		return nil
	}
	return quote
}
