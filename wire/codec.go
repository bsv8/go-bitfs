package wire

import (
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

// protocolErrorf 是 wire 包内统一的错误构造辅助。
func protocolErrorf(op string, kind uint16, field, format string, args ...any) error {
	return protocol.Errorf(op, protocol.CodeUnsupportedKind, kind, field, format, args...)
}

// encodeArtifact 在构造 transport-ready Artifact 前复用解析器的全局尺寸上限。
func encodeArtifact(kind Kind, raw []byte) (Artifact, error) {
	if len(raw) > MaxWireParseBytes {
		return Artifact{}, protocol.Errorf("wire.Encode", protocol.CodeMalformedWire, uint16(kind), "wire", "encoded message exceeds the protocol size limit %d bytes", MaxWireParseBytes)
	}
	return newArtifact(kind, raw), nil
}

// typed encoder：每个 Kind 一个唯一入口，返回 transport-ready Artifact，
// 不再让普通调用方自己组合 Kind 与 any。

// EncodeFileQuote encodes a SignedFileQuote into a Kind 1 Artifact.
func EncodeFileQuote(quote *content.SignedFileQuote) (Artifact, error) {
	raw, err := content.EncodeSignedFileQuote(quote)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(FileQuote, raw)
}

// EncodeRefundPresignRequest encodes a pool-opening presign request into a Kind 2 Artifact.
func EncodeRefundPresignRequest(request *pool.RefundPresignRequest) (Artifact, error) {
	raw, err := pool.EncodeRefundPresignRequest(request)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(RefundPresignRequest, raw)
}

// EncodeRefundPresignResponse encodes a presign response into a Kind 3 Artifact.
func EncodeRefundPresignResponse(response *pool.RefundPresignResponse) (Artifact, error) {
	raw, err := pool.EncodeRefundPresignResponse(response)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(RefundPresignResponse, raw)
}

// EncodeFundingTransactionDelivery encodes the funding delivery into a Kind 4 Artifact.
func EncodeFundingTransactionDelivery(delivery *pool.FundingTransactionDelivery) (Artifact, error) {
	raw, err := pool.EncodeFundingTransactionDelivery(delivery)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(FundingTransactionDelivery, raw)
}

// EncodeContentRequest encodes a signed payment authorization into a Kind 5 Artifact.
func EncodeContentRequest(request *content.SignedContentRequest) (Artifact, error) {
	raw, err := content.EncodeSignedContentRequest(request)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(ContentRequest, raw)
}

// EncodeContentDelivery encodes a signed delivery into a Kind 6 Artifact.
func EncodeContentDelivery(delivery *content.SignedContentDelivery) (Artifact, error) {
	raw, err := content.EncodeSignedContentDelivery(delivery)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(ContentDelivery, raw)
}

// EncodePaymentUpdate encodes a buyer payment credential into a Kind 7 Artifact.
func EncodePaymentUpdate(update *pool.PaymentUpdate) (Artifact, error) {
	raw, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(PaymentUpdate, raw)
}

// EncodeArbitrationRequest encodes the complete 007 evidence package into a Kind 8 Artifact.
func EncodeArbitrationRequest(request *arbitration.ArbitrationRequest) (Artifact, error) {
	raw, err := arbitration.MarshalRequest(request)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(ArbitrationRequest, raw)
}

// EncodeArbitrationResponse encodes the four-element receipt response into a Kind 9 Artifact.
func EncodeArbitrationResponse(response *arbitration.ArbitrationResponse) (Artifact, error) {
	raw, err := arbitration.MarshalResponse(response)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(ArbitrationResponse, raw)
}

// EncodeContentRetrievalRequest encodes a buyer retrieval request into a Kind 10 Artifact.
func EncodeContentRetrievalRequest(request *arbitration.ContentRetrievalRequest) (Artifact, error) {
	raw, err := arbitration.MarshalContentRetrievalRequest(request)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(ContentRetrievalRequest, raw)
}

// EncodeContentRetrievalResponse encodes an arbiter-signed retrieval result into a Kind 11 Artifact.
func EncodeContentRetrievalResponse(response *arbitration.ContentRetrievalResponse) (Artifact, error) {
	raw, err := arbitration.MarshalContentRetrievalResponse(response)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(ContentRetrievalResponse, raw)
}

// EncodePoolCloseRequest 将买方关池请求编码为 Kind 12 Artifact。
func EncodePoolCloseRequest(request *pool.PoolCloseRequest) (Artifact, error) {
	raw, err := pool.EncodePoolCloseRequest(request)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(PoolCloseRequest, raw)
}

// EncodePoolCloseResponse 将卖方关池响应编码为 Kind 13 Artifact。
func EncodePoolCloseResponse(response *pool.PoolCloseResponse) (Artifact, error) {
	raw, err := pool.EncodePoolCloseResponse(response)
	if err != nil {
		return Artifact{}, err
	}
	return encodeArtifact(PoolCloseResponse, raw)
}

// typed decoder：接收 Artifact（已通过严格解析），复核 Kind 一致后返回深拷贝
// 的领域 DTO。普通应用不需要直接使用它们；角色 API 内部调用。

func decodeTyped(artifact Artifact, want Kind, op string) ([]byte, error) {
	if artifact.Kind() != want {
		return nil, protocolErrorf(op, uint16(want), "wire_kind", "artifact kind %d does not match expected kind %d", artifact.Kind(), want)
	}
	return artifact.Bytes(), nil
}

// DecodeFileQuote strictly decodes a Kind 1 Artifact.
func DecodeFileQuote(artifact Artifact) (*content.SignedFileQuote, error) {
	raw, err := decodeTyped(artifact, FileQuote, "wire.DecodeFileQuote")
	if err != nil {
		return nil, err
	}
	return content.DecodeSignedFileQuote(raw)
}

// DecodeRefundPresignRequest strictly decodes a Kind 2 Artifact.
func DecodeRefundPresignRequest(artifact Artifact) (*pool.RefundPresignRequest, error) {
	raw, err := decodeTyped(artifact, RefundPresignRequest, "wire.DecodeRefundPresignRequest")
	if err != nil {
		return nil, err
	}
	return pool.DecodeRefundPresignRequest(raw)
}

// DecodeRefundPresignResponse strictly decodes a Kind 3 Artifact.
func DecodeRefundPresignResponse(artifact Artifact) (*pool.RefundPresignResponse, error) {
	raw, err := decodeTyped(artifact, RefundPresignResponse, "wire.DecodeRefundPresignResponse")
	if err != nil {
		return nil, err
	}
	return pool.DecodeRefundPresignResponse(raw)
}

// DecodeFundingTransactionDelivery strictly decodes a Kind 4 Artifact.
func DecodeFundingTransactionDelivery(artifact Artifact) (*pool.FundingTransactionDelivery, error) {
	raw, err := decodeTyped(artifact, FundingTransactionDelivery, "wire.DecodeFundingTransactionDelivery")
	if err != nil {
		return nil, err
	}
	return pool.DecodeFundingTransactionDelivery(raw)
}

// DecodeContentRequest strictly decodes a Kind 5 Artifact.
func DecodeContentRequest(artifact Artifact) (*content.SignedContentRequest, error) {
	raw, err := decodeTyped(artifact, ContentRequest, "wire.DecodeContentRequest")
	if err != nil {
		return nil, err
	}
	return content.DecodeSignedContentRequest(raw)
}

// DecodeContentDelivery strictly decodes a Kind 6 Artifact.
func DecodeContentDelivery(artifact Artifact) (*content.SignedContentDelivery, error) {
	raw, err := decodeTyped(artifact, ContentDelivery, "wire.DecodeContentDelivery")
	if err != nil {
		return nil, err
	}
	return content.DecodeSignedContentDelivery(raw)
}

// DecodePaymentUpdate strictly decodes a Kind 7 Artifact.
func DecodePaymentUpdate(artifact Artifact) (*pool.PaymentUpdate, error) {
	raw, err := decodeTyped(artifact, PaymentUpdate, "wire.DecodePaymentUpdate")
	if err != nil {
		return nil, err
	}
	return pool.DecodePaymentUpdate(raw)
}

// DecodeArbitrationRequest strictly decodes a Kind 8 Artifact.
func DecodeArbitrationRequest(artifact Artifact) (*arbitration.ArbitrationRequest, error) {
	raw, err := decodeTyped(artifact, ArbitrationRequest, "wire.DecodeArbitrationRequest")
	if err != nil {
		return nil, err
	}
	return arbitration.UnmarshalRequest(raw)
}

// DecodeArbitrationResponse strictly decodes a Kind 9 Artifact.
func DecodeArbitrationResponse(artifact Artifact) (*arbitration.ArbitrationResponse, error) {
	raw, err := decodeTyped(artifact, ArbitrationResponse, "wire.DecodeArbitrationResponse")
	if err != nil {
		return nil, err
	}
	return arbitration.UnmarshalResponse(raw)
}

// DecodeContentRetrievalRequest strictly decodes a Kind 10 Artifact.
func DecodeContentRetrievalRequest(artifact Artifact) (*arbitration.ContentRetrievalRequest, error) {
	raw, err := decodeTyped(artifact, ContentRetrievalRequest, "wire.DecodeContentRetrievalRequest")
	if err != nil {
		return nil, err
	}
	return arbitration.UnmarshalContentRetrievalRequest(raw)
}

// DecodeContentRetrievalResponse strictly decodes a Kind 11 Artifact.
func DecodeContentRetrievalResponse(artifact Artifact) (*arbitration.ContentRetrievalResponse, error) {
	raw, err := decodeTyped(artifact, ContentRetrievalResponse, "wire.DecodeContentRetrievalResponse")
	if err != nil {
		return nil, err
	}
	return arbitration.UnmarshalContentRetrievalResponse(raw)
}

// DecodePoolCloseRequest 严格解码 Kind 12 Artifact。
func DecodePoolCloseRequest(artifact Artifact) (*pool.PoolCloseRequest, error) {
	raw, err := decodeTyped(artifact, PoolCloseRequest, "wire.DecodePoolCloseRequest")
	if err != nil {
		return nil, err
	}
	return pool.DecodePoolCloseRequest(raw)
}

// DecodePoolCloseResponse 严格解码 Kind 13 Artifact。
func DecodePoolCloseResponse(artifact Artifact) (*pool.PoolCloseResponse, error) {
	raw, err := decodeTyped(artifact, PoolCloseResponse, "wire.DecodePoolCloseResponse")
	if err != nil {
		return nil, err
	}
	return pool.DecodePoolCloseResponse(raw)
}
