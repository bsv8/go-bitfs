// Package wire 是 Wire v1 的 exact Artifact 层与严格分派入口。每个完整报文
// 以 [protocol.WireVersion, kind] 开头：Parse 从外层头自读版本与 Kind，分派到
// 对应的严格 decoder，验证完整数组长度、canonical CBOR、attachment 分支与
// trailing 字段；ParseAs 额外交叉验证传输路由声明的 Kind 与报文自描述 Kind。
// 本包复制 exact CBOR 字节，不添加 envelope、签名、存储、业务验证或网络行为；
// 签名、金额、身份与业务状态验证由角色 API 或领域包完成。
package wire

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bsv8/go-bitfs/protocol"
)

// ProtocolFamily 是外部协议族/manifest 标识字符串（wire 报文本身只携带
// [WireVersion, kind, ...]，不含族名称）。它是 protocol.ProtocolFamily 的
// 别名，仓库内不存在第二份版本字符串。
const ProtocolFamily = protocol.ProtocolFamily

// Kind identifies the message type selected by the transport. The outer pair
// [protocol.WireVersion, kind] opens every complete wire message; the strict
// decoder selected by Kind re-checks both values before interpreting any
// child document. Kind never identifies a pool instance: messages that define
// a RefundTemplateTxID carry it in their payload, while the presign request
// derives it from refund_template_raw.
type Kind uint16

const (
	// FileQuote is a signed file quote. Direction: seller -> buyer.
	FileQuote Kind = 1
	// RefundPresignRequest requests the seller's refund transaction signature.
	// Direction: buyer -> seller.
	RefundPresignRequest Kind = 2
	// RefundPresignResponse carries the seller's refund transaction signature.
	// Direction: seller -> buyer.
	RefundPresignResponse Kind = 3
	// FundingTransactionDelivery carries the signed funding transaction.
	// Direction: buyer -> seller.
	FundingTransactionDelivery Kind = 4
	// ContentRequest carries the signed payment authorization.
	// Direction: buyer -> seller.
	ContentRequest Kind = 5
	// ContentDelivery carries the signed content delivery and its payload
	// attachment. Direction: seller -> buyer.
	ContentDelivery Kind = 6
	// PaymentUpdate carries a minimal cumulative payment credential: the
	// payment authorization ID plus the buyer transaction signature over the
	// locally rebuilt state transaction. The receiver routes it by the
	// authorization ID to the exact saved signed content request; no pool ID
	// or raw transaction travels on the wire.
	// Direction: buyer -> seller.
	PaymentUpdate Kind = 7
	// ArbitrationRequest carries evidence for arbitration.
	// Direction: seller -> arbiter.
	ArbitrationRequest Kind = 8
	// ArbitrationResponse carries the arbitration receipt and the arbiter's
	// unified signature over [1, 9, exact_receipt_cbor]; the receipt binds the
	// Claim ID, the positive arbiter amount, and the arbitration transaction
	// signature over the independently rebuilt candidate.
	// Direction: arbiter -> seller.
	ArbitrationResponse Kind = 9
	// ContentRetrievalRequest carries a buyer's authenticated retrieval request
	// for one arbitrated custody record:
	// [1, 10, content_retrieval_request_cbor, buyer_signature]. The Claim ID
	// inside the signed document routes the lookup; only the buyer key
	// recovered from the stored Claim can authorize it.
	// Direction: buyer -> arbiter.
	ContentRetrievalRequest Kind = 10
	// ContentRetrievalResponse returns one arbiter-signed retrieval result:
	// branch 0 answers unavailable with a structured reason and no attachment;
	// branch 1 binds the exact content_payloads_cbor through its
	// content_payloads_id and attaches the payloads verbatim.
	// Direction: arbiter -> buyer.
	ContentRetrievalResponse Kind = 11
)

var strictDec cbor.DecMode

func init() {
	var err error
	strictDec, err = cbor.DecOptions{
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  16,
		MaxArrayElements: 64,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// readOuterHeader 只读取 [version, kind] 外层对的值；完整形状由各 Kind 的
// 严格 decoder 复核。
func readOuterHeader(raw []byte) (uint64, uint64, error) {
	var values []cbor.RawMessage
	if err := strictDec.Unmarshal(raw, &values); err != nil {
		return 0, 0, protocol.Wrap(err, "wire.readOuterHeader", protocol.CodeMalformedWire, 0, "wire")
	}
	if len(values) < 3 {
		return 0, 0, protocol.Errorf("wire.readOuterHeader", protocol.CodeMalformedWire, 0, "wire", "array length %d is below the minimum complete shape", len(values))
	}
	var version, kind uint64
	if err := strictDec.Unmarshal(values[0], &version); err != nil {
		return 0, 0, protocol.Wrap(err, "wire.readOuterHeader", protocol.CodeMalformedWire, 0, "wire_version")
	}
	if err := strictDec.Unmarshal(values[1], &kind); err != nil {
		return 0, 0, protocol.Wrap(err, "wire.readOuterHeader", protocol.CodeMalformedWire, 0, "wire_kind")
	}
	return version, kind, nil
}
