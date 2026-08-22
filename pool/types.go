package pool

import (
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

// RefundTemplateTxID 是费用池的统一关联 ID：未嵌入角色签名的规范退款模板
// 交易的 TxID。它只标识资金池本身，不标识同一资金池内的某次关闭或付款尝试，
// 也不是最终广播退款交易的链上 txid。普通内容哈希继续使用各自的 Hash32，
// 不能把所有 32 字节值混成资金池关联 ID。
type RefundTemplateTxID [sha256.Size]byte

// Reference 标识内容请求所使用的结算资金池以及返回引用时的当前付款状态序号。
type Reference struct {
	// RefundTemplateTxID 是费用池的统一关联 ID，即未嵌入角色签名的规范退款
	// 模板交易的交易 ID。后续付款状态和内容请求都必须属于该资金池。
	RefundTemplateTxID RefundTemplateTxID
	// PaymentSequence 是返回引用时资金池已接受状态的付款序号。003 wire 只
	// 携带本次目标序号；目标序号由接收方验证为该当前状态序号加一。
	PaymentSequence uint32
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
	// 该交易构成资金池的关联 ID 源，并由买方和卖方共同提供退款签名。
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
	RefundTemplateTxID RefundTemplateTxID
	FundingTxID        Hash32
	PoolOutputSatoshis uint64
	PoolLockingScript  []byte
	// RefundLockTime 是从规范退款模板派生的 nLockTime 原始值，供 SDK 内部
	// 协议操作和调用方审计使用。公开 Workflow 的当前时间判断始终由 SDK 读取
	// 系统 UTC；调用方只提供区块高度。
	RefundLockTime uint32
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

// RefundPresignResponse 携带卖方对预签名退款交易的 DER 签名以及该请求的
// 统一关联 ID。
type RefundPresignResponse struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// RefundTemplateTxID 是费用池统一关联 ID，由卖方从收到的 request 的
	// 规范退款模板重新派生，不允许调用方任意填写。
	RefundTemplateTxID RefundTemplateTxID
	// SellerRefundSignature 是卖方对 RefundPresignRequest.RefundTx 的签名原始字节。
	SellerRefundSignature []byte
}

// FundingTxDelivery 携带买方在退款交易验证完成后公开的、已由买方签名的资金交易，
// 以及用于路由到对应费用池的统一关联 ID。
type FundingTxDelivery struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// RefundTemplateTxID 是费用池统一关联 ID，只能从买方已验证的 OpeningProof
	// 派生，不得由调用方另行拼接。
	RefundTemplateTxID RefundTemplateTxID
	// FundingTx 是买方资金交易的原始序列化字节，卖方据此验证交易 ID、输入和池输出。
	FundingTx []byte
}

// PaymentUpdate 是 v4 协议 005 使用的最小付款凭证传输容器。
//
// 它只携带内容授权哈希和买方对确定性重建状态交易的签名；费用池 ID 与未签名
// 状态交易不再进入 wire。接收方先用 PaymentAuthorizationHash 取回保存的精确
// 原始 003，再从 003、OpeningProof 和 previous PaymentState 在本地调用唯一的
// BuildPaymentUpdate 重建同一笔未签名状态交易，验过买方签名后补签并合并。
// 授权哈希是内容寻址键，不可解码出池 ID、金额或交易字节。
type PaymentUpdate struct {
	// Version 是资金池工作流协议主版本号，应等于 MajorVersion。
	Version uint64
	// PaymentAuthorizationHash 是内容请求条款规范编码的 SHA-256 哈希，长度固定为 32 字节。
	// 它是本次付款授权的应用查找键，不携带任何池身份或路由信息。
	PaymentAuthorizationHash []byte
	// BuyerTransactionSignature 是买方针对双方本地确定性重建的未签名状态交易的
	// DER 签名原始字节。该签名与交易原文分离传输，不能把它预先写回重建交易，
	// 也不是对授权哈希的普通消息签名。
	BuyerTransactionSignature []byte
}

// PaymentState 表示角色签名完整合并后的付款状态。
//
// RawTx 必须是完整可验证的交易，不能是未签名交易，也不能是只有一个角色
// 签名的中间交易。若工作流需要跨 API 边界传递独立签名，可以保存在下面的
// 签名字段中，但这些字段不改变 RawTx 必须完整的约束。是否已被节点接受由
// 调用方根据自己的广播与对账结果决定，SDK 不做此声明。
type PaymentState struct {
	// RefundTemplateTxID 是该付款所属费用池的统一关联 ID，即未嵌入角色签名的
	// 规范退款模板交易 ID，而非最终链上退款 txid。
	RefundTemplateTxID RefundTemplateTxID
	// RawTx 是签名完整的付款状态交易原始字节。
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
	// RefundTemplateTxID 是该付款所属费用池的统一关联 ID，即未嵌入角色签名的
	// 规范退款模板交易 ID。
	RefundTemplateTxID RefundTemplateTxID
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
	// Previous 是上一笔已接受的付款状态；首次构造付款时可表示初始退款状态。
	Previous *PaymentState
	// PaymentSequence 是新付款状态的目标序号；普通内容交付更新必须为
	// 上一序号恰好加 1，且不得使用保留的最终关闭序号。
	PaymentSequence uint32
	// SellerAmountAfterSat 是新状态中卖方的累计金额，单位为 satoshi。
	SellerAmountAfterSat uint64
}

// CloseInput 提供立即关闭资金池、构造最终付款交易所需的开池证据、调用方
// 选定的基准状态和业务目标金额。Base 是否为业务最新状态、目标金额是否符合
// 订单或账本，由调用方决定；SDK 只验证协议编码与守恒边界。
type CloseInput struct {
	// Opening 是用于验证资金池身份和多签交易规则的开池证据。
	Opening *OpeningProof
	// Base 是调用方选定的基准付款状态；SDK 不声称它是数据库最新状态。
	Base *PaymentState
	// SellerAmountAfterSat 是候选最终关闭状态中卖方的累计金额，单位为 satoshi。
	SellerAmountAfterSat uint64
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
