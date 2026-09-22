package wire

import (
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/protocol"
)

// Artifact 是已通过严格解析的不可变 exact bytes：它证明 complete wire 的规范
// 结构（outer header、canonical CBOR、attachment 分支、trailing 字段全部
// 正确），不代表签名、金额、身份或业务状态已经验证。字段私有：构造只能经
// Parse/ParseAs 或 typed encoder；Bytes() 返回副本，调用方无法修改内部字节，
// 输入 raw 的后续变异也不影响 Artifact。
type Artifact struct {
	kind Kind
	raw  []byte
}

// newArtifact 内部构造入口：立即深拷贝 exact bytes。
func newArtifact(kind Kind, raw []byte) Artifact {
	return Artifact{kind: kind, raw: append([]byte(nil), raw...)}
}

// Kind 返回报文自描述的 Kind（从 outer header 派生）。
func (a Artifact) Kind() Kind {
	if a.raw == nil {
		return 0
	}
	return a.kind
}

// Bytes 返回 exact CBOR 字节的副本；调用方修改副本不会影响本 Artifact。
func (a Artifact) Bytes() []byte {
	if a.raw == nil {
		return nil
	}
	return append([]byte(nil), a.raw...)
}

// IsZero 报告该 Artifact 是否为空值（未经过 Parse 或编码失败后的零值）。
func (a Artifact) IsZero() bool { return a.raw == nil }

// maxWireParseBytes 是进入 CBOR decoder 之前的全局字节上限：它必须容纳所有
// Kind 的合法最大报文。Kind 11 available 分支的 payload bundle 与 Kind 8 满
// 载整包（payload 上限 + Claim 上限 + 签名上限 + 外壳开销）分别决定两个下
// 界；任何超限输入直接以 malformed_wire 拒绝，保证超大不可信输入不会消耗解
// 码内存与 CPU。应用可设置更小的传输层限额，但不得静默抬高本值。
// MaxWireParseBytes 是完整 BitFS 报文的协议解析上限，也是 bitcoin-libp2p
// uvarint transport 的默认单帧接收上限。应用可以配置更小的本地限额，但不能
// 配置得更大后绕过 wire parser 的协议边界。
const MaxWireParseBytes = max(content.MaxContentPayloadsCBORBytes+1024, arbitration.MaxArbitrationRequestBytes)

// enforceWireSizeLimit 在任何 CBOR 解码之前执行。
func enforceWireSizeLimit(op string, raw []byte) error {
	if len(raw) > MaxWireParseBytes {
		return protocol.Errorf(op, protocol.CodeMalformedWire, 0, "wire", "message exceeds the protocol size limit %d bytes", MaxWireParseBytes)
	}
	return nil
}

// parseHeaderKind 只做外层分派读取并返回自描述 Kind；完整验证交给 typed decoder。
func parseHeaderKind(raw []byte) (Kind, error) {
	version, kindValue, err := readOuterHeader(raw)
	if err != nil {
		return 0, err
	}
	if version != protocol.WireVersion {
		return 0, protocol.Errorf("wire.Parse", protocol.CodeUnsupportedVersion, uint16(kindValue), "wire_version", "unsupported wire version %d", version)
	}
	if kindValue == 0 || kindValue > 11 {
		return 0, protocol.Errorf("wire.Parse", protocol.CodeUnsupportedKind, uint16(kindValue), "wire_kind", "unsupported wire kind %d", kindValue)
	}
	return Kind(kindValue), nil
}

// decodeArtifact 对已确定 Kind 的 exact bytes 运行该 Kind 唯一的严格 decoder：
// 完整数组长度、canonical CBOR、子文档与 attachment 分支都在这里复核。
func decodeArtifact(artifact Artifact) error {
	switch artifact.Kind() {
	case FileQuote:
		_, err := DecodeFileQuote(artifact)
		return err
	case RefundPresignRequest:
		_, err := DecodeRefundPresignRequest(artifact)
		return err
	case RefundPresignResponse:
		_, err := DecodeRefundPresignResponse(artifact)
		return err
	case FundingTransactionDelivery:
		_, err := DecodeFundingTransactionDelivery(artifact)
		return err
	case ContentRequest:
		_, err := DecodeContentRequest(artifact)
		return err
	case ContentDelivery:
		_, err := DecodeContentDelivery(artifact)
		return err
	case PaymentUpdate:
		_, err := DecodePaymentUpdate(artifact)
		return err
	case ArbitrationRequest:
		_, err := DecodeArbitrationRequest(artifact)
		return err
	case ArbitrationResponse:
		_, err := DecodeArbitrationResponse(artifact)
		return err
	case ContentRetrievalRequest:
		_, err := DecodeContentRetrievalRequest(artifact)
		return err
	case ContentRetrievalResponse:
		_, err := DecodeContentRetrievalResponse(artifact)
		return err
	default:
		return protocol.Errorf("wire.decodeArtifact", protocol.CodeUnsupportedKind, uint16(artifact.Kind()), "wire_kind", "unsupported wire kind %d", artifact.Kind())
	}
}

// Parse 从 exact bytes 解析一个 Artifact：外层头自读 version/kind，显式 switch
// 分派到对应严格 decoder。未知版本/Kind 返回 unsupported 错误并保留原 bytes
// 供调用方升级或审计。
func Parse(raw []byte) (Artifact, error) {
	const op = "wire.Parse"
	if len(raw) == 0 {
		return Artifact{}, protocol.Errorf(op, protocol.CodeMalformedWire, 0, "wire", "empty wire message")
	}
	if err := enforceWireSizeLimit(op, raw); err != nil {
		return Artifact{}, err
	}
	kind, err := parseHeaderKind(raw)
	if err != nil {
		return Artifact{}, err
	}
	artifact := newArtifact(kind, raw)
	if err := decodeArtifact(artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

// ParseAs 在 Parse 的基础上额外验证传输路由声明的 Kind 与报文自描述 Kind 一致；
// 路由声明可以用于分发，但不能成为唯一 Kind 真值。
func ParseAs(expected Kind, raw []byte) (Artifact, error) {
	const op = "wire.ParseAs"
	if len(raw) == 0 {
		return Artifact{}, protocol.Errorf(op, protocol.CodeMalformedWire, uint16(expected), "wire", "empty wire message")
	}
	if err := enforceWireSizeLimit(op, raw); err != nil {
		return Artifact{}, err
	}
	kind, err := parseHeaderKind(raw)
	if err != nil {
		return Artifact{}, err
	}
	if kind != expected {
		return Artifact{}, protocol.Errorf("wire.ParseAs", protocol.CodeUnsupportedKind, uint16(expected), "wire_kind", "route declared kind %d but message self-describes as %d", expected, kind)
	}
	artifact := newArtifact(kind, raw)
	if err := decodeArtifact(artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}
