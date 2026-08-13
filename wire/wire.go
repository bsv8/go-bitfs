// Package wire maps transport-level message kinds to the canonical encoders and
// strict decoders for 001–007. It copies exact CBOR bytes and adds no envelope,
// signature, storage, business validation, or network behavior; callers invoke
// the owning bitfs, pool, or arbitration verifier after decoding.
package wire

import (
	"errors"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

// ProtocolFamily is the wire protocol identifier carried by the transport layer.
const ProtocolFamily = "bitfs.protocol.v3"

// Kind identifies the message type selected by the transport. The tag is not
// inserted into the signed 001–007 CBOR document.
type Kind uint16

const (
	// Quote identifies a signed file quote message.
	Quote Kind = 1
	// PoolRefundPresignRequest identifies a pool opening request.
	PoolRefundPresignRequest Kind = 2
	// PoolRefundPresignResponse identifies a pool opening response.
	PoolRefundPresignResponse Kind = 3
	// PoolFundingTxDelivery identifies delivery of the pool funding transaction.
	PoolFundingTxDelivery Kind = 4
	// ContentRequest identifies a buyer's signed content request.
	ContentRequest Kind = 5
	// ContentDelivery identifies a seller's signed content delivery.
	ContentDelivery Kind = 6
	// CumulativePayment identifies a buyer-authorized payment update.
	CumulativePayment Kind = 7
	// ArbitrationRequest identifies evidence sent from a seller to an arbiter.
	ArbitrationRequest Kind = 8
	// ArbitrationResponse identifies the arbiter signature returned to a seller.
	ArbitrationResponse Kind = 9
)

// Packet carries a transport-selected Kind and the exact canonical CBOR bytes
// produced by the corresponding protocol encoder. It adds no envelope.
type Packet struct {
	Kind Kind
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
	case Quote:
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
	case PoolRefundPresignRequest:
		value, ok := message.(*pool.RefundPresignRequest)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.RefundPresignRequest", kind)
		}
		raw, err = pool.EncodeRefundPresignRequest(value)
	case PoolRefundPresignResponse:
		value, ok := message.(*pool.RefundPresignResponse)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.RefundPresignResponse", kind)
		}
		raw, err = pool.EncodeRefundPresignResponse(value)
	case PoolFundingTxDelivery:
		value, ok := message.(*pool.FundingTxDelivery)
		if !ok {
			return Packet{}, fmt.Errorf("wire kind %d requires *pool.FundingTxDelivery", kind)
		}
		raw, err = pool.EncodeFundingTxDelivery(value)
	case CumulativePayment:
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
	default:
		return Packet{}, fmt.Errorf("unsupported new wire kind %d", kind)
	}
	if err != nil {
		return Packet{}, fmt.Errorf("marshal wire kind %d: %w", kind, err)
	}
	return Packet{Kind: kind, CBOR: append([]byte(nil), raw...)}, nil
}

// Unmarshal dispatches rawCBOR to the strict decoder selected by kind. It checks
// canonical encoding and shape; callers must still run the package verifier.
func Unmarshal(kind Kind, rawCBOR []byte) (any, error) {
	if len(rawCBOR) == 0 {
		return nil, errors.New("wire CBOR is required")
	}
	switch kind {
	case Quote:
		return bitfs.DecodeSignedFileQuote(rawCBOR)
	case ContentRequest:
		return bitfs.DecodeSignedContentRequest(rawCBOR)
	case ContentDelivery:
		return bitfs.DecodeSignedContentDelivery(rawCBOR)
	case PoolRefundPresignRequest:
		return pool.DecodeRefundPresignRequest(rawCBOR)
	case PoolRefundPresignResponse:
		return pool.DecodeRefundPresignResponse(rawCBOR)
	case PoolFundingTxDelivery:
		return pool.DecodeFundingTxDelivery(rawCBOR)
	case CumulativePayment:
		return pool.DecodePaymentUpdate(rawCBOR)
	case ArbitrationRequest:
		return arbitration.UnmarshalRequest(rawCBOR)
	case ArbitrationResponse:
		return arbitration.UnmarshalResponse(rawCBOR)
	default:
		return nil, fmt.Errorf("unsupported new wire kind %d", kind)
	}
}

// MarshalQuote encodes a SignedFileQuote with bitfs's canonical encoder.
func MarshalQuote(message *bitfs.SignedFileQuote) ([]byte, error) {
	packet, err := Marshal(Quote, message)
	return packet.CBOR, err
}

// UnmarshalQuote strictly decodes a SignedFileQuote.
func UnmarshalQuote(rawCBOR []byte) (*bitfs.SignedFileQuote, error) {
	message, err := Unmarshal(Quote, rawCBOR)
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

// MarshalPoolRefundPresignRequest encodes a pool-opening presign request.
func MarshalPoolRefundPresignRequest(message *pool.RefundPresignRequest) ([]byte, error) {
	packet, err := Marshal(PoolRefundPresignRequest, message)
	return packet.CBOR, err
}

// UnmarshalPoolRefundPresignRequest strictly decodes a pool-opening presign request.
func UnmarshalPoolRefundPresignRequest(rawCBOR []byte) (*pool.RefundPresignRequest, error) {
	message, err := Unmarshal(PoolRefundPresignRequest, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.RefundPresignRequest), nil
}

// MarshalPoolRefundPresignResponse encodes a pool-opening presign response.
func MarshalPoolRefundPresignResponse(message *pool.RefundPresignResponse) ([]byte, error) {
	packet, err := Marshal(PoolRefundPresignResponse, message)
	return packet.CBOR, err
}

// UnmarshalPoolRefundPresignResponse strictly decodes a pool-opening presign response.
func UnmarshalPoolRefundPresignResponse(rawCBOR []byte) (*pool.RefundPresignResponse, error) {
	message, err := Unmarshal(PoolRefundPresignResponse, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.RefundPresignResponse), nil
}

// MarshalPoolFundingTxDelivery encodes delivery of the pool funding transaction.
func MarshalPoolFundingTxDelivery(message *pool.FundingTxDelivery) ([]byte, error) {
	packet, err := Marshal(PoolFundingTxDelivery, message)
	return packet.CBOR, err
}

// UnmarshalPoolFundingTxDelivery strictly decodes a pool funding transaction delivery.
func UnmarshalPoolFundingTxDelivery(rawCBOR []byte) (*pool.FundingTxDelivery, error) {
	message, err := Unmarshal(PoolFundingTxDelivery, rawCBOR)
	if err != nil {
		return nil, err
	}
	return message.(*pool.FundingTxDelivery), nil
}

// MarshalPaymentUpdate encodes a buyer-authorized cumulative payment update.
func MarshalPaymentUpdate(message *pool.PaymentUpdate) ([]byte, error) {
	packet, err := Marshal(CumulativePayment, message)
	return packet.CBOR, err
}

// UnmarshalPaymentUpdate strictly decodes a cumulative payment update.
func UnmarshalPaymentUpdate(rawCBOR []byte) (*pool.PaymentUpdate, error) {
	message, err := Unmarshal(CumulativePayment, rawCBOR)
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

// MarshalArbitrationResponse encodes the arbiter hashes and detached signature.
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
