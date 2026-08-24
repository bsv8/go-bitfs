// Package wire maps transport-level message kinds to the canonical encoders and
// strict decoders for 001–008. Every complete wire message starts with
// [protocol.WireVersion, kind]; the outer pair is injected by each owning
// encoder, checked by every strict decoder, and folded into ordinary message
// signatures through protocol.SignWireDocument. The package copies exact CBOR
// bytes and adds no envelope, signature, storage, business validation, or
// network behavior; callers invoke the owning bitfs, pool, or arbitration
// verifier after decoding.
package wire

import (
	"errors"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

// ProtocolFamily is the wire protocol identifier carried by the transport layer.
const ProtocolFamily = "bitfs.protocol.v1"

// Kind identifies the message type selected by the transport. The outer pair
// [protocol.WireVersion, kind] opens every complete wire message; the strict
// decoder selected by Kind re-checks both values before interpreting any
// child document. Kind never identifies a pool instance: messages that define
// a RefundTemplateTxID carry it in their payload, while the 0201 presign
// request derives it from refund_template_raw.
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

// Packet carries a transport-selected Kind and the exact canonical CBOR bytes
// produced by the corresponding protocol encoder. It adds no envelope and no
// session semantics; pool instances are correlated by RefundTemplateTxID where
// the message defines that field, while the 0201 presign request derives it
// from refund_template_raw and the minimal 005 credential is routed by its
// payment authorization ID through the application's lookup index.
type Packet struct {
	// Kind 是传输层选择的报文类别（1..11）；严格 decoder 在解释任何子文档前
	// 都会复核外层 [protocol.WireVersion, kind] 对。
	Kind Kind
	// CBOR 是相应协议 encoder 产生的 exact 规范 CBOR 字节；本包不添加任何
	// envelope 或会话语义。
	CBOR []byte
}

// Marshal dispatches to the canonical encoder for kind, rejects a mismatched
// Go value, and returns transport-ready CBOR without changing signed bytes.
func Marshal(kind Kind, message any) (Packet, error) {
	var (
		raw []byte
		err error
	)
	switch kind {
	case FileQuote:
		value, ok := message.(*bitfs.SignedFileQuote)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *bitfs.SignedFileQuote", kind)
		}
		raw, err = bitfs.EncodeSignedFileQuote(value)
	case ContentRequest:
		value, ok := message.(*bitfs.SignedContentRequest)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *bitfs.SignedContentRequest", kind)
		}
		raw, err = bitfs.EncodeSignedContentRequest(value)
	case ContentDelivery:
		value, ok := message.(*bitfs.SignedContentDelivery)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *bitfs.SignedContentDelivery", kind)
		}
		raw, err = bitfs.EncodeSignedContentDelivery(value)
	case RefundPresignRequest:
		value, ok := message.(*pool.RefundPresignRequest)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.RefundPresignRequest", kind)
		}
		raw, err = pool.EncodeRefundPresignRequest(value)
	case RefundPresignResponse:
		value, ok := message.(*pool.RefundPresignResponse)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.RefundPresignResponse", kind)
		}
		raw, err = pool.EncodeRefundPresignResponse(value)
	case FundingTransactionDelivery:
		value, ok := message.(*pool.FundingTransactionDelivery)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.FundingTransactionDelivery", kind)
		}
		raw, err = pool.EncodeFundingTransactionDelivery(value)
	case PaymentUpdate:
		value, ok := message.(*pool.PaymentUpdate)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.PaymentUpdate", kind)
		}
		raw, err = pool.EncodePaymentUpdate(value)
	case ArbitrationRequest:
		value, ok := message.(*arbitration.ArbitrationRequest)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *arbitration.ArbitrationRequest", kind)
		}
		raw, err = arbitration.MarshalRequest(value)
	case ArbitrationResponse:
		value, ok := message.(*arbitration.ArbitrationResponse)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *arbitration.ArbitrationResponse", kind)
		}
		raw, err = arbitration.MarshalResponse(value)
	case ContentRetrievalRequest:
		value, ok := message.(*arbitration.ContentRetrievalRequest)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *arbitration.ContentRetrievalRequest", kind)
		}
		raw, err = arbitration.MarshalContentRetrievalRequest(value)
	case ContentRetrievalResponse:
		value, ok := message.(*arbitration.ContentRetrievalResponse)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *arbitration.ContentRetrievalResponse", kind)
		}
		raw, err = arbitration.MarshalContentRetrievalResponse(value)
	default:
		return Packet{}, fmt.Errorf("unsupported new wire kind %d", kind)
	}
	if err != nil {
		return Packet{}, fmt.Errorf("marshal wire kind %d: %w", kind, err)
	}
	return Packet{Kind: kind, CBOR: append([]byte(nil), raw...)}, nil
}

// Unmarshal dispatches rawCBOR to the strict decoder selected by kind. It checks
// canonical encoding, the outer version/kind pair, and shape; callers must
// still run the package verifier.
func Unmarshal(kind Kind, rawCBOR []byte) (any, error) {
	if len(rawCBOR) == 0 {
		return nil, errors.New("wire CBOR is required")
	}
	switch kind {
	case FileQuote:
		return bitfs.DecodeSignedFileQuote(rawCBOR)
	case ContentRequest:
		return bitfs.DecodeSignedContentRequest(rawCBOR)
	case ContentDelivery:
		return bitfs.DecodeSignedContentDelivery(rawCBOR)
	case RefundPresignRequest:
		return pool.DecodeRefundPresignRequest(rawCBOR)
	case RefundPresignResponse:
		return pool.DecodeRefundPresignResponse(rawCBOR)
	case FundingTransactionDelivery:
		return pool.DecodeFundingTransactionDelivery(rawCBOR)
	case PaymentUpdate:
		return pool.DecodePaymentUpdate(rawCBOR)
	case ArbitrationRequest:
		return arbitration.UnmarshalRequest(rawCBOR)
	case ArbitrationResponse:
		return arbitration.UnmarshalResponse(rawCBOR)
	case ContentRetrievalRequest:
		return arbitration.UnmarshalContentRetrievalRequest(rawCBOR)
	case ContentRetrievalResponse:
		return arbitration.UnmarshalContentRetrievalResponse(rawCBOR)
	default:
		return nil, fmt.Errorf("unsupported new wire kind %d", kind)
	}
}

// MarshalFileQuote encodes a SignedFileQuote with bitfs's canonical encoder.
func MarshalFileQuote(message *bitfs.SignedFileQuote) ([]byte, error) {
	packet, err := Marshal(FileQuote, message)
	return packet.CBOR, err
}

// UnmarshalFileQuote strictly decodes a SignedFileQuote.
func UnmarshalFileQuote(rawCBOR []byte) (*bitfs.SignedFileQuote, error) {
	message, err := Unmarshal(FileQuote, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*bitfs.SignedFileQuote), nil
}

// MarshalContentRequest encodes a SignedContentRequest with bitfs's canonical encoder.
func MarshalContentRequest(message *bitfs.SignedContentRequest) ([]byte, error) {
	packet, err := Marshal(ContentRequest, message)
	return packet.CBOR, err
}

// UnmarshalContentRequest strictly decodes a SignedContentRequest.
func UnmarshalContentRequest(rawCBOR []byte) (*bitfs.SignedContentRequest, error) {
	message, err := Unmarshal(ContentRequest, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*bitfs.SignedContentRequest), nil
}

// MarshalContentDelivery encodes a SignedContentDelivery with bitfs's canonical encoder.
func MarshalContentDelivery(message *bitfs.SignedContentDelivery) ([]byte, error) {
	packet, err := Marshal(ContentDelivery, message)
	return packet.CBOR, err
}

// UnmarshalContentDelivery strictly decodes a SignedContentDelivery.
func UnmarshalContentDelivery(rawCBOR []byte) (*bitfs.SignedContentDelivery, error) {
	message, err := Unmarshal(ContentDelivery, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*bitfs.SignedContentDelivery), nil
}

// MarshalRefundPresignRequest encodes a pool-opening presign request.
func MarshalRefundPresignRequest(message *pool.RefundPresignRequest) ([]byte, error) {
	packet, err := Marshal(RefundPresignRequest, message)
	return packet.CBOR, err
}

// UnmarshalRefundPresignRequest strictly decodes a pool-opening presign request.
func UnmarshalRefundPresignRequest(rawCBOR []byte) (*pool.RefundPresignRequest, error) {
	message, err := Unmarshal(RefundPresignRequest, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.RefundPresignRequest), nil
}

// MarshalRefundPresignResponse encodes a pool-opening presign response.
func MarshalRefundPresignResponse(message *pool.RefundPresignResponse) ([]byte, error) {
	packet, err := Marshal(RefundPresignResponse, message)
	return packet.CBOR, err
}

// UnmarshalRefundPresignResponse strictly decodes a pool-opening presign response.
func UnmarshalRefundPresignResponse(rawCBOR []byte) (*pool.RefundPresignResponse, error) {
	message, err := Unmarshal(RefundPresignResponse, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.RefundPresignResponse), nil
}

// MarshalFundingTransactionDelivery encodes delivery of the pool funding transaction.
func MarshalFundingTransactionDelivery(message *pool.FundingTransactionDelivery) ([]byte, error) {
	packet, err := Marshal(FundingTransactionDelivery, message)
	return packet.CBOR, err
}

// UnmarshalFundingTransactionDelivery strictly decodes a pool funding transaction delivery.
func UnmarshalFundingTransactionDelivery(rawCBOR []byte) (*pool.FundingTransactionDelivery, error) {
	message, err := Unmarshal(FundingTransactionDelivery, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.FundingTransactionDelivery), nil
}

// MarshalPaymentUpdate encodes a buyer-authorized cumulative payment update.
func MarshalPaymentUpdate(message *pool.PaymentUpdate) ([]byte, error) {
	packet, err := Marshal(PaymentUpdate, message)
	return packet.CBOR, err
}

// UnmarshalPaymentUpdate strictly decodes a cumulative payment update.
func UnmarshalPaymentUpdate(rawCBOR []byte) (*pool.PaymentUpdate, error) {
	message, err := Unmarshal(PaymentUpdate, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.PaymentUpdate), nil
}

// MarshalArbitrationRequest encodes a seller's complete 007 evidence package.
func MarshalArbitrationRequest(message *arbitration.ArbitrationRequest) ([]byte, error) {
	packet, err := Marshal(ArbitrationRequest, message)
	return packet.CBOR, err
}

// UnmarshalArbitrationRequest strictly decodes a 007 evidence package.
func UnmarshalArbitrationRequest(rawCBOR []byte) (*arbitration.ArbitrationRequest, error) {
	message, err := Unmarshal(ArbitrationRequest, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*arbitration.ArbitrationRequest), nil
}

// MarshalArbitrationResponse encodes the four-element receipt response with
// its detached receipt signature.
func MarshalArbitrationResponse(message *arbitration.ArbitrationResponse) ([]byte, error) {
	packet, err := Marshal(ArbitrationResponse, message)
	return packet.CBOR, err
}

// UnmarshalArbitrationResponse strictly decodes an arbiter response.
func UnmarshalArbitrationResponse(rawCBOR []byte) (*arbitration.ArbitrationResponse, error) {
	message, err := Unmarshal(ArbitrationResponse, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*arbitration.ArbitrationResponse), nil
}

// MarshalContentRetrievalRequest encodes a buyer's authenticated Kind 10
// retrieval request.
func MarshalContentRetrievalRequest(message *arbitration.ContentRetrievalRequest) ([]byte, error) {
	packet, err := Marshal(ContentRetrievalRequest, message)
	return packet.CBOR, err
}

// UnmarshalContentRetrievalRequest strictly decodes a Kind 10 retrieval request.
func UnmarshalContentRetrievalRequest(rawCBOR []byte) (*arbitration.ContentRetrievalRequest, error) {
	message, err := Unmarshal(ContentRetrievalRequest, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*arbitration.ContentRetrievalRequest), nil
}

// MarshalContentRetrievalResponse encodes the arbiter-signed Kind 11 retrieval
// result for whichever branch its result document declares.
func MarshalContentRetrievalResponse(message *arbitration.ContentRetrievalResponse) ([]byte, error) {
	packet, err := Marshal(ContentRetrievalResponse, message)
	return packet.CBOR, err
}

// UnmarshalContentRetrievalResponse strictly decodes a Kind 11 retrieval result.
func UnmarshalContentRetrievalResponse(rawCBOR []byte) (*arbitration.ContentRetrievalResponse, error) {
	message, err := Unmarshal(ContentRetrievalResponse, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*arbitration.ContentRetrievalResponse), nil
}
