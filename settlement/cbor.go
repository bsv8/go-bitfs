//go:build legacy

// Package settlement is the legacy proposal/session settlement protocol.
// Deprecated: use pool and wire for the protocol 001-007 state model.
package settlement

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var enc cbor.EncMode
var dec cbor.DecMode

func init() {
	var err error
	enc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	dec, err = cbor.DecOptions{IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 16, MaxArrayElements: 32, MaxMapPairs: 16, UTF8: cbor.UTF8RejectInvalid}.DecMode()
	if err != nil {
		panic(err)
	}
}

func EncodeMessage(message any) ([]byte, error) {
	if err := validate(message); err != nil {
		return nil, err
	}
	return enc.Marshal(message)
}

func DecodeMessage(data []byte) (any, error) {
	var header []cbor.RawMessage
	if err := dec.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("decode legacy settlement packet: %w", err)
	}
	if len(header) < 2 {
		return nil, errors.New("legacy settlement packet must contain version and kind")
	}
	var version uint64
	var kind Kind
	if err := dec.Unmarshal(header[0], &version); err != nil || version != MajorVersion {
		return nil, errors.New("unsupported legacy settlement major version")
	}
	if err := dec.Unmarshal(header[1], &kind); err != nil {
		return nil, errors.New("legacy settlement message kind is invalid")
	}
	message, err := messageForKind(kind)
	if err != nil {
		return nil, err
	}
	if err := dec.Unmarshal(data, message); err != nil {
		return nil, err
	}
	if err := validate(message); err != nil {
		return nil, err
	}
	canonical, err := EncodeMessage(message)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("legacy settlement packet is not deterministically encoded")
	}
	return message, nil
}

func PacketID(message any) ([sha256.Size]byte, error) {
	data, err := EncodeMessage(message)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func messageForKind(kind Kind) (any, error) {
	switch kind {
	case KindPaymentPrepare:
		return new(PaymentPrepare), nil
	case KindPaymentPrepared:
		return new(PaymentPrepared), nil
	case KindPaymentCommit:
		return new(PaymentCommit), nil
	case KindPaymentCommitted:
		return new(PaymentCommitted), nil
	case KindPaymentAbort:
		return new(PaymentAbort), nil
	case KindPaymentAborted:
		return new(PaymentAborted), nil
	case KindPaymentRejected:
		return new(PaymentRejected), nil
	case KindArbitrationRequest:
		return new(ArbitrationRequest), nil
	case KindCloseSignatureRequest:
		return new(CloseSignatureRequest), nil
	case KindCloseSignature:
		return new(CloseSignature), nil
	case KindPoolArbitrated:
		return new(PoolArbitrated), nil
	case KindPoolRefundPresignRequest:
		return new(PoolRefundPresignRequest), nil
	case KindPoolRefundPresignResponse:
		return new(PoolRefundPresignResponse), nil
	case KindPoolFundingTxDelivery:
		return new(PoolFundingTxDelivery), nil
	default:
		return nil, fmt.Errorf("unsupported pool message kind %d", kind)
	}
}

func validate(message any) error {
	var version uint64
	var kind, expected Kind
	switch value := message.(type) {
	case *PaymentPrepare:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentPrepare
		if err := validateTicket(value.Ticket); err != nil {
			return err
		}
	case *PaymentPrepared:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentPrepared
		if err := requireID("ticket_id", value.TicketID); err != nil {
			return err
		}
		if err := requireID("proposal_id", value.ProposalID); err != nil {
			return err
		}
	case *PaymentCommit:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentCommit
		if err := validateTicket(value.Ticket); err != nil {
			return err
		}
		if err := requireID("proposal_id", value.ProposalID); err != nil {
			return err
		}
	case *PaymentCommitted:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentCommitted
		if err := requireID("ticket_id", value.TicketID); err != nil {
			return err
		}
	case *PaymentAbort:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentAbort
		if err := validateTicket(value.Ticket); err != nil {
			return err
		}
		if err := requireID("proposal_id", value.ProposalID); err != nil {
			return err
		}
		if value.ReasonCode == "" {
			return errors.New("abort reason_code is required")
		}
	case *PaymentAborted:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentAborted
		if err := requireID("ticket_id", value.TicketID); err != nil {
			return err
		}
		if value.ReasonCode == "" {
			return errors.New("aborted reason_code is required")
		}
	case *PaymentRejected:
		version, kind = value.Version, value.MessageKind
		expected = KindPaymentRejected
		if err := requireID("ticket_id", value.TicketID); err != nil {
			return err
		}
		if value.ReasonCode == "" {
			return errors.New("rejected reason_code is required")
		}
	case *ArbitrationRequest:
		version, kind = value.Version, value.MessageKind
		expected = KindArbitrationRequest
		if err := requireID("spend_txid", value.SpendTxID); err != nil {
			return err
		}
		if err := ValidateArbitrationRequest(value); err != nil {
			return err
		}
	case *CloseSignatureRequest:
		version, kind = value.Version, value.MessageKind
		expected = KindCloseSignatureRequest
		if err := requireID("spend_txid", value.SpendTxID); err != nil {
			return err
		}
		if err := requireID("arbitration_id", value.ArbitrationID); err != nil {
			return err
		}
		if len(value.CloseSighash) != sha256.Size {
			return errors.New("close_sighash must be 32 bytes")
		}
	case *CloseSignature:
		version, kind = value.Version, value.MessageKind
		expected = KindCloseSignature
		if err := requireID("spend_txid", value.SpendTxID); err != nil {
			return err
		}
		if err := requireID("arbitration_id", value.ArbitrationID); err != nil {
			return err
		}
	case *PoolArbitrated:
		version, kind = value.Version, value.MessageKind
		expected = KindPoolArbitrated
		if err := requireID("spend_txid", value.SpendTxID); err != nil {
			return err
		}
		if err := requireID("arbitration_id", value.ArbitrationID); err != nil {
			return err
		}
		if err := requireID("closing_txid", value.ClosingTransactionID); err != nil {
			return err
		}
	case *PoolRefundPresignRequest:
		version, kind = value.Version, value.MessageKind
		expected = KindPoolRefundPresignRequest
		if err := validatePoolRefundPresignRequest(value); err != nil {
			return err
		}
	case *PoolRefundPresignResponse:
		version, kind = value.Version, value.MessageKind
		expected = KindPoolRefundPresignResponse
		if len(value.SellerRefundSignature) == 0 {
			return errors.New("seller_refund_signature is required")
		}
	case *PoolFundingTxDelivery:
		version, kind = value.Version, value.MessageKind
		expected = KindPoolFundingTxDelivery
		if len(value.FundingTx) == 0 {
			return errors.New("funding_tx is required")
		}
	default:
		return fmt.Errorf("unsupported pool message %T", message)
	}
	if version != MajorVersion {
		return fmt.Errorf("unsupported pool major version %d", version)
	}
	if kind != expected {
		return fmt.Errorf("pool message has kind %d, want %d", kind, expected)
	}
	if _, err := messageForKind(kind); err != nil {
		return err
	}
	return nil
}

func validateTicket(ticket TicketRef) error {
	if err := requireID("spend_txid", ticket.SpendTxID); err != nil {
		return err
	}
	if len(ticket.ContentHash) != sha256.Size {
		return errors.New("content_hash must be 32 bytes")
	}
	return requireID("ticket_id", ticket.TicketID)
}
func requireID(name string, value []byte) error {
	if len(value) != sha256.Size {
		return fmt.Errorf("%s must be 32 bytes", name)
	}
	return nil
}
