package pool

import (
	"context"
	"crypto/sha256"
)

// ProtocolFamily 表示 go-bitfs 资金池工作流协议族的名称。
const ProtocolFamily = "bitfs.pool.workflow.v4"

// MajorVersion 是当前资金池工作流协议的主版本号。
//
// 主版本号参与协议对象的编码与校验。发生不兼容的字段、语义或验证规则
// 变化时应递增该值。
const MajorVersion uint64 = 4

// MultisigProtocol 标识实现使用的底层 MultisigPool 交易协议。
const MultisigProtocol = "bitfs.pool.v4"

// MultisigVersion 是实现使用的底层 MultisigPool 协议版本号。
const MultisigVersion uint64 = 4

// PoolOutputIndex 是 FundingTx 中资金池输出的协议固定索引。
// v4 工作流只接受第 0 个输出作为资金池输出，因此无需在消息中重复传输。
const PoolOutputIndex uint32 = 0

// Hash32 保存固定长度的 32 字节哈希值。
//
// 该类型用于表示交易 ID、授权哈希等协议身份标识。它使用数组而不是字节
// 切片，因此可以直接比较，也能保证值始终具有 SHA-256 的固定宽度。
type Hash32 [sha256.Size]byte

// Reference 标识内容请求所使用的结算资金池以及请求建立在其上的付款序号。
type Reference struct {
	// SpendTxID 是资金池的支出锚点，即预签名退款交易的交易 ID。
	// 后续付款状态和内容请求都必须属于该资金池。
	SpendTxID Hash32
	// BasePaymentSequence 是内容请求发起前已接受状态的付款序号。
	// 内容交付产生的新付款通常必须以该序号为基准，并递增一个序号。
	BasePaymentSequence uint32
}

// OpeningProof 保存买卖双方相互验证后、用于开立资金池的退款交易和资金交易证据。
//
// 该对象通常在卖方签署退款交易后形成，在买方交付资金交易原文后补全。
// RefundTx、FundingTx 以及各类公钥和签名均为协议要求的原始字节，调用方
// 不应在持久化或传输前擅自重新编码。
type OpeningProof struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// RefundTx 是预签名退款交易的原始序列化字节。
	// 该交易构成资金池的支出锚点，并由买方和卖方共同提供退款签名。
	RefundTx []byte
	// BuyerPubKey 是买方的 33 字节压缩 secp256k1 公钥。
	BuyerPubKey []byte
	// SellerPubKey 是卖方的 33 字节压缩 secp256k1 公钥。
	SellerPubKey []byte
	// ArbiterPubKey 是仲裁方的 33 字节压缩 secp256k1 公钥。
	ArbiterPubKey []byte
	// MinerFeeRateSatPerKB 是构造池内交易时采用的矿工费率，单位为 satoshi/KB。
	MinerFeeRateSatPerKB uint64
	// BuyerRefundSignature 是买方对预签名退款交易提供的 DER 签名原始字节。
	BuyerRefundSignature []byte
	// SellerRefundSignature 是卖方对同一预签名退款交易提供的 DER 签名原始字节。
	SellerRefundSignature []byte
	// FundingTx 是买方资金交易的原始序列化字节。
	// 它通常在退款证据验证完成后单独交付给卖方。
	FundingTx []byte
}

// OpeningDetails 是从 OpeningProof 原始证据即时计算出的只读视图。
// 它不属于协议消息，也不会被编码或持久化为 OpeningProof 的字段。
type OpeningDetails struct {
	SpendTxID          Hash32
	FundingTxID        Hash32
	PoolOutputSatoshis uint64
	PoolLockingScript  []byte
}

// RefundPresignRequest 包含买方请求卖方预签退款交易时发送的开池条款和交易材料。
//
// 该请求由买方构造，卖方验证退款交易、资金池输出、公钥及费率后，使用
// SellerPubKey 对退款交易签名并返回 RefundPresignResponse。请求本身不包含
// FundingTx 原文；资金交易 ID 和固定输出索引直接从 RefundTx 的 input 推导。
type RefundPresignRequest struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// RefundTx 是买方构造的预签名退款交易原始字节。
	RefundTx []byte
	// BuyerPubKey 是买方的压缩 secp256k1 公钥原始字节。
	BuyerPubKey []byte
	// SellerPubKey 是买方期望用于卖方签名校验的压缩 secp256k1 公钥。
	SellerPubKey []byte
	// ArbiterPubKey 是仲裁方的压缩 secp256k1 公钥原始字节。
	ArbiterPubKey []byte
	// MinerFeeRateSatPerKB 是池内交易采用的矿工费率，单位为 satoshi/KB。
	MinerFeeRateSatPerKB uint64
	// BuyerRefundSignature 是买方已经附加到退款交易上的 DER 签名原始字节。
	BuyerRefundSignature []byte
}

// RefundPresignResponse 携带卖方对预签名退款交易的 DER 签名。
type RefundPresignResponse struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// SellerRefundSignature 是卖方对 RefundPresignRequest.RefundTx 的签名原始字节。
	SellerRefundSignature []byte
}

// FundingTxDelivery 携带买方在退款交易验证完成后公开的、已由买方签名的资金交易。
type FundingTxDelivery struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// FundingTx 是买方资金交易的原始序列化字节，卖方据此验证交易 ID、输入和池输出。
	FundingTx []byte
}

// PaymentUpdate 是 v4 协议 005 使用的付款更新传输容器。
//
// 它携带未签名的状态交易和独立传输的买方签名，绝不携带只有部分解锁
// 脚本的交易。接收方应分别验证授权哈希、交易内容和买方签名，然后再与
// 卖方签名合并为可接受的 PaymentState。
type PaymentUpdate struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// PaymentAuthorizationHash 是内容请求条款规范编码的 SHA-256 哈希，长度固定为 32 字节。
	// 它把本次付款绑定到具体的内容授权，而不是仅绑定到交易字节。
	PaymentAuthorizationHash []byte
	// UnsignedStateTxRaw 是下一付款状态交易的未签名原始字节。
	// 交易中不应包含任何解锁脚本或角色签名。
	UnsignedStateTxRaw []byte
	// BuyerTransactionSignature 是买方针对 UnsignedStateTxRaw 的 DER 签名原始字节。
	// 该签名与交易原文分离传输，不能把它预先写回 UnsignedStateTxRaw。
	BuyerTransactionSignature []byte
}

// PaymentState 表示节点已经接受的、签名完整合并后的付款状态。
//
// RawTx 必须是完整可验证的交易，不能是未签名交易，也不能是只有一个角色
// 签名的中间交易。若工作流需要跨 API 边界传递独立签名，可以保存在下面的
// 签名字段中，但这些字段不改变 RawTx 必须完整的约束。
type PaymentState struct {
	// SpendTxID 是该付款所属资金池的支出锚点，即预签名退款交易 ID。
	SpendTxID Hash32
	// RawTx 是节点接受的完整付款状态交易原始字节。
	RawTx []byte
	// PaymentSequence 是该状态在资金池付款链中的序号。
	// 普通内容交付更新必须相对于上一状态恰好递增 1。
	PaymentSequence uint32
	// BuyerAmountSat 是交易向买方分配的金额，单位为 satoshi。
	BuyerAmountSat uint64
	// SellerAmountSat 是交易向卖方分配的累计金额，单位为 satoshi。
	SellerAmountSat uint64
	// ArbiterAmountSat 是交易向仲裁方分配的金额，单位为 satoshi。
	ArbiterAmountSat uint64
	// PaymentAuthorizationHash 是绑定该付款的内容授权哈希，长度固定为 32 字节。
	PaymentAuthorizationHash Hash32
	// BuyerTransactionSignature 是买方在该付款交易中的 DER 签名原始字节。
	BuyerTransactionSignature []byte
	// SellerTransactionSignature 是卖方在该付款交易中的 DER 签名原始字节。
	SellerTransactionSignature []byte
	// ArbiterTransactionSignature 是仲裁方在该付款交易中的 DER 签名原始字节。
	ArbiterTransactionSignature []byte
	// PoolOutputSatoshis 是创建该付款状态时引用的资金池输出金额，单位为 satoshi。
	PoolOutputSatoshis uint64
	// PoolLockingScript 是创建该付款状态时引用的资金池输出锁定脚本原始字节。
	PoolLockingScript []byte
}

// SignedPayment 包含一份付款状态及其对应的交易原始字节。
type SignedPayment struct {
	// State 保存付款金额、序号、资金池身份和交易签名等解析后的状态信息。
	State PaymentState
	// RawTx 保存与 State 对应的付款交易原始字节。
	RawTx []byte
}

// UnsignedPayment 是单角色签名方法唯一接受的交易对象。
//
// 它只描述未签名交易及其可验证的状态元数据，不包含解锁脚本，也不包含
// 任何嵌入式签名；各角色应在此对象基础上独立生成签名。
type UnsignedPayment struct {
	// SpendTxID 是该付款所属资金池的支出锚点，即预签名退款交易 ID。
	SpendTxID Hash32
	// RawTx 是未签名付款交易的原始字节，不得包含解锁脚本或交易签名。
	RawTx []byte
	// PaymentSequence 是待签名付款状态的序号。
	PaymentSequence uint32
	// BuyerAmountSat 是交易向买方分配的金额，单位为 satoshi。
	BuyerAmountSat uint64
	// SellerAmountSat 是交易向卖方分配的累计金额，单位为 satoshi。
	SellerAmountSat uint64
	// ArbiterAmountSat 是交易向仲裁方分配的金额，单位为 satoshi。
	ArbiterAmountSat uint64
	// PoolOutputSatoshis 是该付款所引用的资金池输出金额，单位为 satoshi。
	PoolOutputSatoshis uint64
	// PoolLockingScript 是该付款所引用的资金池输出锁定脚本原始字节。
	PoolLockingScript []byte
}

// PaymentUpdateInput 提供构造下一笔累计付款状态所需的开池证据、上一状态和目标金额。
type PaymentUpdateInput struct {
	// Opening 是用于验证资金池身份、输出和参与方密钥的开池证据。
	Opening *OpeningProof
	// Previous 是上一笔已被接受的付款状态；首次构造付款时可表示初始退款状态。
	Previous *PaymentState
	// PaymentSequenceAfter 是新付款状态的目标序号，通常必须为上一序号加 1。
	PaymentSequenceAfter uint32
	// SellerAmountAfterSat 是新状态中卖方的累计金额，单位为 satoshi。
	SellerAmountAfterSat uint64
}

// CloseInput 提供立即关闭资金池、构造最终付款交易所需的开池证据和最新状态。
type CloseInput struct {
	// Opening 是用于验证资金池身份和多签交易规则的开池证据。
	Opening *OpeningProof
	// Latest 是当前已接受的最新付款状态，关闭交易应从该状态继续构造。
	Latest *PaymentState
	// SellerAmountAfterSat 是最终关闭状态中卖方的累计金额，单位为 satoshi。
	SellerAmountAfterSat uint64
}

// UpdateAcceptance 描述节点接受一笔非最终付款更新后的结果。
type UpdateAcceptance struct {
	// TxID 是节点接受的付款更新交易 ID。
	TxID Hash32
	// SpendTxID 是该更新所属资金池的支出锚点。
	SpendTxID Hash32
	// PaymentSequence 是节点接受的付款状态序号。
	PaymentSequence uint32
}

// OpeningProofStore 按 SpendTxID 持久化和读取已验证的 002 开池证据。
// SpendTxID 是预签名退款交易证据的规范交易 ID，也是资金池的稳定主键。
type OpeningProofStore interface {
	// SaveOpeningProof 保存开池证据；实现通常应校验其身份与已有记录一致。
	SaveOpeningProof(context.Context, *OpeningProof) error
	// LoadOpeningProof 根据资金池支出锚点读取开池证据。
	LoadOpeningProof(context.Context, Hash32) (*OpeningProof, error)
}

// PendingOpeningProofStore 在资金交易尚未被接受前保存开池证据，
// 并允许在资金交易原文公开后按 FundingTxID 找回该证据。
type PendingOpeningProofStore interface {
	// SaveOpeningProof 保存尚未完成资金交付确认的开池证据。
	SaveOpeningProof(context.Context, *OpeningProof) error
	// LoadOpeningProofByFundingTxID 根据公开的资金交易 ID 读取对应开池证据。
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
}

// PoolStore 汇合开池证据、已接受付款状态的持久化能力，以及资金池健康检查和关闭对账能力。
// 内容交付使用的并发租约由 PendingRequestStore 单独提供。
type PoolStore interface {
	OpeningProofStore
	// LoadOpeningProofByFundingTxID 根据资金交易 ID 读取开池证据。
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
	// SaveAcceptedPayment 保存节点已接受的完整付款状态。
	SaveAcceptedPayment(context.Context, *PaymentState) error
	// LoadAcceptedPayment 根据资金池支出锚点读取当前已接受付款状态。
	LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
	// EnsurePoolHealthy 检查资金池是否处于可继续付款的健康状态。
	EnsurePoolHealthy(context.Context, Hash32) error
	// EnsurePoolOpen 检查资金池是否仍处于开放状态。
	EnsurePoolOpen(context.Context, Hash32) error
	// MarkPoolClosing 将资金池标记为正在关闭，阻止不兼容的新付款进入。
	MarkPoolClosing(context.Context, Hash32) error
	// ReconcilePoolClosing 对正在关闭的资金池执行外部链状态对账。
	ReconcilePoolClosing(context.Context, Hash32) error
	// MarkExternalStateUncertain 标记本地提交结果与外部节点结果不明确的状态。
	MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
	// ReconcileExternalState 根据外部状态重新确认本地付款状态。
	ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}

// PendingRequest 记录内容交付租约的归属及其基准状态，用于串行化同一资金池的交付操作。
type PendingRequest struct {
	// SpendTxID 是该租约保护的资金池支出锚点。
	SpendTxID Hash32
	// BasePaymentSequence 是内容交付前已接受状态的付款序号。
	BasePaymentSequence uint32
	// BaseSellerAmountSat 是内容交付前已接受状态中的卖方累计金额，单位为 satoshi。
	BaseSellerAmountSat uint64
	// ContentRequestHash 是已签名 003 内容请求规范条款的哈希值。
	ContentRequestHash Hash32
	// ExpectedSellerAmountSat 是本次交付承诺增加给卖方的精确金额，单位为 satoshi。
	ExpectedSellerAmountSat uint64
}

// PendingAcquireResult 表示交付租约的获取结果：新获取、同一请求已持有，或发生所有权冲突。
type PendingAcquireResult uint8

const (
	// PendingAcquired 表示已成功获取该资金池的交付租约。
	PendingAcquired PendingAcquireResult = 1
	// PendingAlreadyHeld 表示完全相同的内容请求已经持有该租约，可按幂等请求处理。
	PendingAlreadyHeld PendingAcquireResult = 2
	// PendingConflict 表示当前请求哈希与已有租约所有者冲突，不能并行交付。
	PendingConflict PendingAcquireResult = 3
)

// PendingRequestStore 管理以资金池支出交易 ID 为键的内容请求交付租约。
type PendingRequestStore interface {
	// TryAcquire 尝试获取请求中的交付租约，并返回获取、已持有或冲突结果。
	TryAcquire(context.Context, PendingRequest) (PendingAcquireResult, error)
	// Load 读取指定资金池当前持有的交付租约；不存在时由实现返回相应错误或空值。
	Load(context.Context, Hash32) (*PendingRequest, error)
	// Release 释放指定资金池上由给定内容请求哈希持有的租约。
	Release(context.Context, Hash32, Hash32) error
}

// Signer 向资金池工作流提供规范的压缩公钥和仅生成 DER 签名的基础签名能力。
//
// PublicKey 必须返回有效的 33 字节压缩 secp256k1 公钥。角色工作流传入的
// message 始终是 SDK 计算出的 32 字节摘要：001/003/004 消息使用规范 CBOR
// 字节执行一次 SHA-256，资金池交易则使用固定的 sighash 摘要。实现应只返回
// DER 签名，并将私钥保管在 SDK 之外。
type Signer interface {
	// PublicKey 返回当前签名角色的规范压缩 secp256k1 公钥。
	PublicKey(context.Context) ([]byte, error)
	// Sign 对给定的 32 字节摘要签名，并返回不包含额外封装的 DER 签名。
	Sign(context.Context, []byte) ([]byte, error)
}

// OpeningInput 仅包含构造资金池所需的通用输入数据。
//
// 该对象由买方使用，不携带卖方签名；它用于生成 RefundPresignRequest，
// 而不是直接表示已经完成的 OpeningProof。
type OpeningInput struct {
	// FundingTx 是买方资金交易的原始序列化字节；其第 0 个输出必须是资金池输出。
	FundingTx []byte
	// ExpiryLockTime 是退款交易使用的到期锁定时间，具体解释遵循底层交易协议。
	ExpiryLockTime uint32
	// MinerFeeRateSatPerKB 是构造退款和付款交易时采用的矿工费率，单位为 satoshi/KB。
	MinerFeeRateSatPerKB uint64
	// SellerPubKey 是卖方的压缩 secp256k1 公钥原始字节。
	SellerPubKey []byte
	// ArbiterPubKey 是仲裁方的压缩 secp256k1 公钥原始字节。
	ArbiterPubKey []byte
}
