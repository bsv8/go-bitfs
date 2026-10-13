package pool

import (
	"crypto/sha256"

	"github.com/bsv8/go-bitfs/protocol"
)

// PoolOutputIndex 是 FundingTransactionRaw 中资金池输出的协议固定索引。
// 工作流只接受第 0 个输出作为资金池输出，因此无需在消息中重复传输。
// 对外协议版本只使用 protocol.WireVersion，本包不再定义任何平行版本常量。
const PoolOutputIndex uint32 = 0

// Hash32 是通用 32 字节哈希的仓库唯一真值（protocol.Hash32 的别名）：
// 资金池域内表示资金交易 TxID 等协议身份标识。领域专属身份继续使用独立
// 命名类型（如 RefundTemplateTxID），不与通用哈希互换。
type Hash32 = protocol.Hash32

// RefundTemplateTxID 是费用池的统一关联 ID：未嵌入角色签名的规范退款模板
// 交易的 TxID。它只标识资金池本身，不标识同一资金池内的某次关闭或付款尝试，
// 也不是最终广播退款交易的链上 txid。普通内容哈希继续使用各自的 Hash32，
// 不能把所有 32 字节值混成资金池关联 ID。
type RefundTemplateTxID [sha256.Size]byte

// OpeningProof 保存买卖双方相互验证后、用于开立资金池的退款交易和资金交易证据。
//
// 该对象通常在卖方签署退款交易后形成，在买方交付资金交易原文后补全。
// RefundTemplateRaw、FundingTransactionRaw 以及各类公钥和签名均为协议要求的原始字节，调用方
// 不应在持久化或传输前擅自重新编码。
type OpeningProof struct {
	// RefundTemplateRaw 是预签名退款交易的原始序列化字节。
	// 该交易构成资金池的关联 ID 源，并由买方和卖方共同提供退款签名。
	RefundTemplateRaw []byte
	// BuyerPublicKey 是买方的 33 字节压缩 secp256k1 公钥。
	BuyerPublicKey []byte
	// SellerPublicKey 是卖方的 33 字节压缩 secp256k1 公钥。
	SellerPublicKey []byte
	// ArbiterPublicKey 是仲裁方的 33 字节压缩 secp256k1 公钥。
	ArbiterPublicKey []byte
	// MinerFeeRateSatoshisPerKilobyte 是构造池内交易时采用的矿工费率，单位为 satoshi/KB。
	MinerFeeRateSatoshisPerKilobyte uint64
	// BuyerRefundTransactionSignature 是买方对预签名退款交易提供的 DER 签名原始字节。
	BuyerRefundTransactionSignature []byte
	// SellerRefundTransactionSignature 是卖方对同一预签名退款交易提供的 DER 签名原始字节。
	SellerRefundTransactionSignature []byte
	// FundingTransactionRaw 是买方资金交易的原始序列化字节。
	// 它通常在退款证据验证完成后单独交付给卖方。
	FundingTransactionRaw []byte
}

// OpeningDetails 是从 OpeningProof 原始证据即时计算出的只读视图。
// 它不属于协议消息，也不会被编码或持久化为 OpeningProof 的字段。
type OpeningDetails struct {
	// RefundTemplateTxID 是费用池统一关联 ID（按交易 TxID 算法从规范退款模板派生，
	// 不是普通 SHA-256 文档 ID），路由 002–007 的全部报文。
	RefundTemplateTxID RefundTemplateTxID
	// FundingTxID 是资金交易的链上交易 ID（Hash32）。
	FundingTxID Hash32
	// PoolOutputSatoshis 是资金池输出的聪数；重建 candidate 时作为输入金额。
	PoolOutputSatoshis uint64
	// PoolLockingScript 是角色顺序固定 [Buyer, Seller, Arbiter] 的 2-of-3
	// 锁定脚本字节（105 字节）。
	PoolLockingScript []byte
	// RefundLockTime 是从规范退款模板派生的 nLockTime 原始值，供 SDK 内部
	// 协议操作和调用方审计使用。时间与高度都是显式事实：timestamp 锁定由
	// Facts.Now 判断，height 锁定由 Facts.BlockHeight 判断；SDK 绝不读取时钟。
	RefundLockTime uint32
}

// RefundPresignRequest 包含买方请求卖方预签退款交易时发送的开池条款和交易材料。
//
// 该请求由买方构造，卖方验证退款交易、资金池输出、公钥及费率后，使用
// SellerPublicKey 对退款交易签名并返回 RefundPresignResponse。请求本身不包含
// FundingTransactionRaw 原文；资金交易 ID 和固定输出索引直接从 RefundTemplateRaw 的 input 推导。
type RefundPresignRequest struct {
	// RefundTemplateRaw 是买方构造的预签名退款交易原始字节。
	RefundTemplateRaw []byte
	// BuyerPublicKey 是买方的压缩 secp256k1 公钥原始字节。
	BuyerPublicKey []byte
	// SellerPublicKey 是买方期望用于卖方签名校验的压缩 secp256k1 公钥。
	SellerPublicKey []byte
	// ArbiterPublicKey 是仲裁方的压缩 secp256k1 公钥原始字节。
	ArbiterPublicKey []byte
	// MinerFeeRateSatoshisPerKilobyte 是池内交易采用的矿工费率，单位为 satoshi/KB。
	MinerFeeRateSatoshisPerKilobyte uint64
	// BuyerRefundTransactionSignature 是买方已经附加到退款交易上的 DER 签名原始字节。
	BuyerRefundTransactionSignature []byte
}

// RefundPresignResponse 携带卖方对预签名退款交易的 DER 签名以及该请求的
// 统一关联 ID。
type RefundPresignResponse struct {
	// RefundTemplateTxID 是费用池统一关联 ID，由卖方从收到的 request 的
	// 规范退款模板重新派生，不允许调用方任意填写。
	RefundTemplateTxID RefundTemplateTxID
	// SellerRefundTransactionSignature 是卖方对 RefundPresignRequest.RefundTemplateRaw 的签名原始字节。
	SellerRefundTransactionSignature []byte
}

// FundingTransactionDelivery 携带买方在退款交易验证完成后公开的、已由买方签名的资金交易，
// 以及用于路由到对应费用池的统一关联 ID。
type FundingTransactionDelivery struct {
	// RefundTemplateTxID 是费用池统一关联 ID，只能从买方已验证的 OpeningProof
	// 派生，不得由调用方另行拼接。
	RefundTemplateTxID RefundTemplateTxID
	// FundingTransactionRaw 是买方资金交易的原始序列化字节，卖方据此验证交易 ID、输入和池输出。
	FundingTransactionRaw []byte
}

// PoolCloseRequest 是 Kind 12 买方关池请求。它把买方已经签名的未完成最终
// 关闭交易发送给卖方；交易签名仍是 MultisigPool 交易签名，不是 wire 文档签名。
type PoolCloseRequest struct {
	// RefundTemplateTxID 是费用池统一关联 ID，必须是报文的首个业务字段。
	RefundTemplateTxID RefundTemplateTxID
	// UnsignedCloseTransactionRaw 是 sequence 为最终关闭值的未签名交易原文。
	UnsignedCloseTransactionRaw []byte
	// BuyerCloseTransactionSignature 是买方对未签名关闭交易的分离式交易签名。
	BuyerCloseTransactionSignature []byte
}

// PoolCloseResponse 是 Kind 13 卖方关池响应。完整交易的 unlocking script
// 携带买方与卖方的交易签名；接收方仍须按本地 OpeningProof 完整验证交易。
type PoolCloseResponse struct {
	// RefundTemplateTxID 是费用池统一关联 ID，必须是报文的首个业务字段。
	RefundTemplateTxID RefundTemplateTxID
	// CompleteCloseTransactionRaw 是包含买卖双方签名的完整关闭交易原文。
	CompleteCloseTransactionRaw []byte
}

// PaymentUpdate 是 Kind 7 PaymentUpdate 使用的最小付款凭证传输容器。
//
// 它只携带内容授权哈希和买方对确定性重建状态交易的签名；费用池 ID 与未签名
// 状态交易不再进入 wire。接收方先用 PaymentAuthorizationID 取回保存的精确
// 原始 003，再从 003、OpeningProof 和 previous PaymentState 在本地调用唯一的
// BuildPaymentUpdate 重建同一笔未签名状态交易，验过买方签名后补签并合并。
// 授权哈希是内容寻址键，不可解码出池 ID、金额或交易字节。
type PaymentUpdate struct {
	// PaymentAuthorizationID 是 payment_authorization_cbor 的 SHA-256 typed ID。
	// 它是本次付款授权的应用查找键，不携带任何池身份或路由信息。
	PaymentAuthorizationID protocol.PaymentAuthorizationID
	// BuyerPaymentTransactionSignature 是买方针对双方本地确定性重建的未签名
	// 状态交易的 DER 签名原始字节。该签名与交易原文分离传输，不能把它预先写回
	// 重建交易，也不是对任何文档的普通消息签名。
	BuyerPaymentTransactionSignature []byte
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
	// BuyerAmountSatoshis 是交易向买方分配的金额，单位为 satoshi。
	BuyerAmountSatoshis uint64
	// SellerAmountSatoshis 是交易向卖方分配的累计金额，单位为 satoshi。
	SellerAmountSatoshis uint64
	// ArbiterAmountSatoshis 是交易向仲裁方分配的绝对金额，单位为 satoshi。
	// 普通 005 付款恒为零；007 仲裁状态交易必须为正数，且等于回执中的
	// 仲裁费。两种场景下它都是本次交易的绝对分配额，不是增量。
	ArbiterAmountSatoshis uint64
	// PaymentAuthorizationID 是绑定该付款的 Kind 5 文档 typed ID。
	PaymentAuthorizationID protocol.PaymentAuthorizationID
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
	// BuyerAmountSatoshis 是交易向买方分配的金额，单位为 satoshi。
	BuyerAmountSatoshis uint64
	// SellerAmountSatoshis 是交易向卖方分配的累计金额，单位为 satoshi。
	SellerAmountSatoshis uint64
	// ArbiterAmountSatoshis 是交易向仲裁方分配的绝对金额，单位为 satoshi。
	// 普通 005 付款恒为零；007 仲裁状态交易必须为正数，且等于调用方传入
	// builder 的明确仲裁费。两种场景下它都是本次交易的绝对分配额，不是增量。
	ArbiterAmountSatoshis uint64
	// PoolOutputSatoshis 是该付款所引用的资金池输出金额，单位为 satoshi。
	PoolOutputSatoshis uint64
	// PoolLockingScript 是该付款所引用的资金池输出锁定脚本原始字节。
	PoolLockingScript []byte
	// arbitrationSourceTxID is the funding outpoint recovered from the Claim's
	// refund template. It remains in memory only so arbitration signers can
	// reject a raw candidate whose input was changed after construction.
	arbitrationSourceTxID []byte
	// arbitrationCandidateCommitment binds every public candidate field and the
	// exact unsigned transaction bytes to the builder output. It is deliberately
	// private: callers may inspect or copy an UnsignedPayment, but cannot update
	// the commitment after mutating a candidate.
	arbitrationCandidateCommitment []byte
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
	// SellerAmountAfterSatoshis 是新状态中卖方的累计金额，单位为 satoshi。
	SellerAmountAfterSatoshis uint64
}

// CloseInput 提供立即关闭资金池、构造最终付款交易所需的开池证据、调用方
// 选定的基准状态和业务目标金额。Base 是否为业务最新状态、目标金额是否符合
// 订单或账本，由调用方决定；SDK 只验证协议编码与守恒边界。
type CloseInput struct {
	// Opening 是用于验证资金池身份和多签交易规则的开池证据。
	Opening *OpeningProof
	// Base 是调用方选定的基准付款状态；SDK 不声称它是数据库最新状态。
	Base *PaymentState
	// SellerAmountAfterSatoshis 是候选最终关闭状态中卖方的累计金额，单位为 satoshi。
	SellerAmountAfterSatoshis uint64
}

// OpeningInput 仅包含构造资金池所需的通用输入数据。
//
// 该对象由买方使用，不携带卖方签名；它用于生成 RefundPresignRequest，
// 而不是直接表示已经完成的 OpeningProof。
type OpeningInput struct {
	// FundingTransactionRaw 是买方资金交易的原始序列化字节；其第 0 个输出必须是资金池输出。
	FundingTransactionRaw []byte
	// ExpiryLockTime 是退款交易使用的到期锁定时间，具体解释遵循底层交易协议。
	ExpiryLockTime uint32
	// MinerFeeRateSatoshisPerKilobyte 是构造退款和付款交易时采用的矿工费率，单位为 satoshi/KB。
	MinerFeeRateSatoshisPerKilobyte uint64
	// SellerPublicKey 是卖方的压缩 secp256k1 公钥原始字节。
	SellerPublicKey []byte
	// ArbiterPublicKey 是仲裁方的压缩 secp256k1 公钥原始字节。
	ArbiterPublicKey []byte
}
