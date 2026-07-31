package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const protocolMajorVersion uint64 = 1

const (
	messageKindFileQuote           uint64 = 1
	messageKindHashGetTicket       uint64 = 2
	messageKindHashDelivery        uint64 = 3
	messageKindArbitrationClaim    uint64 = 4
	messageKindArbitrationDecision uint64 = 5
	messageKindArbitrationRecord   uint64 = 6
)

var (
	canonicalEnc cbor.EncMode
	strictDec    cbor.DecMode
)

func init() {
	var err error
	canonicalEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
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

// EncodeMessage returns the sole allowed BitFS v1 wire representation.
func EncodeMessage(message any) ([]byte, error) {
	if !isMessage(message) {
		return nil, fmt.Errorf("unsupported BitFS message %T", message)
	}
	if err := validateLegacyMessage(message); err != nil {
		return nil, err
	}
	return canonicalEnc.Marshal(message)
}

// DecodeMessage accepts one strict deterministic BitFS v1 packet.
func DecodeMessage(data []byte) (any, error) {
	var header []cbor.RawMessage
	if err := strictDec.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("decode BitFS CBOR packet: %w", err)
	}
	if len(header) < 2 {
		return nil, errors.New("BitFS CBOR packet must contain version and kind")
	}
	var version, kind uint64
	if err := strictDec.Unmarshal(header[0], &version); err != nil {
		return nil, errors.New("BitFS CBOR version is invalid")
	}
	if version != protocolMajorVersion {
		return nil, fmt.Errorf("unsupported BitFS major version %d", version)
	}
	if err := strictDec.Unmarshal(header[1], &kind); err != nil {
		return nil, errors.New("BitFS CBOR message kind is invalid")
	}
	message, err := messageForKind(kind)
	if err != nil {
		return nil, err
	}
	if kind == messageKindHashDelivery {
		if len(header) != 6 {
			return nil, errors.New("HashDelivery packet must contain exactly six fields")
		}
		if err := validateEncodedPayloadSize(header[5]); err != nil {
			return nil, err
		}
	}
	if err := strictDec.Unmarshal(data, message); err != nil {
		return nil, fmt.Errorf("decode BitFS CBOR message: %w", err)
	}
	canonical, err := EncodeMessage(message)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("BitFS CBOR packet is not deterministically encoded")
	}
	return message, nil
}

func validateLegacyMessage(message any) error {
	switch value := message.(type) {
	case *HashGetTicket:
		if err := ValidateHashGetTicket(value); err != nil {
			return fmt.Errorf("invalid HashGetTicket: %w", err)
		}
		return nil
	case *HashDelivery:
		return validateHashDeliveryPayload(value.Payload)
	default:
		return nil
	}
}

func validateHashDeliveryPayload(payload []byte) error {
	if uint64(len(payload)) > BlockSize {
		return fmt.Errorf("HashDelivery payload exceeds block size limit of %d bytes", BlockSize)
	}
	return nil
}

// validateEncodedPayloadSize checks a definite CBOR byte string before the
// decoder allocates its contents. The strict decoder rejects indefinite byte
// strings later, but this early check keeps an oversized legacy packet from
// becoming an oversized allocation first.
func validateEncodedPayloadSize(raw []byte) error {
	if len(raw) == 0 {
		return errors.New("HashDelivery payload is missing")
	}
	initial := raw[0]
	if initial>>5 != 2 {
		return errors.New("HashDelivery payload must be a CBOR byte string")
	}
	additional := initial & 0x1f
	var length uint64
	var headerLength int
	switch {
	case additional < 24:
		length, headerLength = uint64(additional), 1
	case additional == 24:
		if len(raw) < 2 {
			return errors.New("HashDelivery payload length is truncated")
		}
		length, headerLength = uint64(raw[1]), 2
	case additional == 25:
		if len(raw) < 3 {
			return errors.New("HashDelivery payload length is truncated")
		}
		length, headerLength = uint64(raw[1])<<8|uint64(raw[2]), 3
	case additional == 26:
		if len(raw) < 5 {
			return errors.New("HashDelivery payload length is truncated")
		}
		length, headerLength = uint64(raw[1])<<24|uint64(raw[2])<<16|uint64(raw[3])<<8|uint64(raw[4]), 5
	case additional == 27:
		if len(raw) < 9 {
			return errors.New("HashDelivery payload length is truncated")
		}
		for index := 1; index < 9; index++ {
			length = length<<8 | uint64(raw[index])
		}
		headerLength = 9
	default:
		return errors.New("HashDelivery payload uses an unsupported CBOR length")
	}
	if length > BlockSize {
		return fmt.Errorf("HashDelivery payload exceeds block size limit of %d bytes", BlockSize)
	}
	if uint64(len(raw)-headerLength) < length {
		return errors.New("HashDelivery payload is truncated")
	}
	return nil
}

// PacketID returns the stable content address of a canonical BitFS packet.
func PacketID(message any) ([sha256.Size]byte, error) {
	encoded, err := EncodeMessage(message)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func isMessage(message any) bool {
	switch message.(type) {
	case *FileQuote, *HashGetTicket, *HashDelivery, *ArbitrationClaim, *ArbitrationDecision, *ArbitrationRecord:
		return true
	default:
		return false
	}
}

func messageForKind(kind uint64) (any, error) {
	switch kind {
	case messageKindFileQuote:
		return new(FileQuote), nil
	case messageKindHashGetTicket:
		return new(HashGetTicket), nil
	case messageKindHashDelivery:
		return new(HashDelivery), nil
	case messageKindArbitrationClaim:
		return new(ArbitrationClaim), nil
	case messageKindArbitrationDecision:
		return new(ArbitrationDecision), nil
	case messageKindArbitrationRecord:
		return new(ArbitrationRecord), nil
	default:
		return nil, fmt.Errorf("unsupported BitFS message kind %d", kind)
	}
}

func encodeArray(values ...any) ([]byte, error) { return canonicalEnc.Marshal(values) }

func decodeArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := strictDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func decodeHeader(values []cbor.RawMessage, kind uint64) error {
	var version, receivedKind uint64
	if err := strictDec.Unmarshal(values[0], &version); err != nil || version != protocolMajorVersion {
		return errors.New("unsupported BitFS CBOR version")
	}
	if err := strictDec.Unmarshal(values[1], &receivedKind); err != nil || receivedKind != kind {
		return errors.New("unexpected BitFS CBOR message kind")
	}
	return nil
}

func decode(raw cbor.RawMessage, target any) error { return strictDec.Unmarshal(raw, target) }

func bstr(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func (message FileQuote) MarshalCBOR() ([]byte, error) {
	values := []any{protocolMajorVersion, messageKindFileQuote, bstr(message.SeedHash), message.SeedPriceSat, message.BlockPriceSat, message.EndblockPriceSat, message.FileSize, message.RecommendedFilename, message.QuoteExpiresAtUnix, uint64(message.BlockCount), bstr(message.SellerPubkey)}
	for _, key := range message.SupportedArbiterPubkeys {
		values = append(values, bstr(key))
	}
	return canonicalEnc.Marshal(values)
}

func (message *FileQuote) UnmarshalCBOR(data []byte) error {
	var values []cbor.RawMessage
	if err := strictDec.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) < 11 {
		return errors.New("file quote array is too short")
	}
	if err := decodeHeader(values, messageKindFileQuote); err != nil {
		return err
	}
	var blockCount uint64
	if err := decode(values[2], &message.SeedHash); err != nil {
		return err
	}
	if err := decode(values[3], &message.SeedPriceSat); err != nil {
		return err
	}
	if err := decode(values[4], &message.BlockPriceSat); err != nil {
		return err
	}
	if err := decode(values[5], &message.EndblockPriceSat); err != nil {
		return err
	}
	if err := decode(values[6], &message.FileSize); err != nil {
		return err
	}
	if err := decode(values[7], &message.RecommendedFilename); err != nil {
		return err
	}
	if err := decode(values[8], &message.QuoteExpiresAtUnix); err != nil {
		return err
	}
	if err := decode(values[9], &blockCount); err != nil {
		return err
	}
	if blockCount > uint64(^uint32(0)) {
		return errors.New("block_count overflows uint32")
	}
	message.BlockCount = uint32(blockCount)
	if err := decode(values[10], &message.SellerPubkey); err != nil {
		return err
	}
	message.SupportedArbiterPubkeys = make([][]byte, len(values)-11)
	for index := 11; index < len(values); index++ {
		if err := decode(values[index], &message.SupportedArbiterPubkeys[index-11]); err != nil {
			return err
		}
	}
	return nil
}

func (message HashGetTicket) MarshalCBOR() ([]byte, error) {
	if err := ValidateHashGetTicket(&message); err != nil {
		return nil, err
	}
	return encodeArray(protocolMajorVersion, messageKindHashGetTicket, message.SessionID, message.Sequence, bstr(message.RootSeedHash), bstr(message.ContentHash), message.ContentIndex, message.ExpectedSize, message.PriceSat, bstr(message.BuyerPubkey), bstr(message.SellerPubkey), message.ExpiresAtUnix, bstr(message.BuyerSignature))
}

func (message *HashGetTicket) UnmarshalCBOR(data []byte) error {
	values, err := decodeArray(data, 13)
	if err != nil {
		return err
	}
	if err := decodeHeader(values, messageKindHashGetTicket); err != nil {
		return err
	}
	if err := decode(values[2], &message.SessionID); err != nil {
		return err
	}
	if err := decode(values[3], &message.Sequence); err != nil {
		return err
	}
	if err := decode(values[4], &message.RootSeedHash); err != nil {
		return err
	}
	if err := decode(values[5], &message.ContentHash); err != nil {
		return err
	}
	if err := decode(values[6], &message.ContentIndex); err != nil {
		return err
	}
	if err := decode(values[7], &message.ExpectedSize); err != nil {
		return err
	}
	if err := decode(values[8], &message.PriceSat); err != nil {
		return err
	}
	if err := decode(values[9], &message.BuyerPubkey); err != nil {
		return err
	}
	if err := decode(values[10], &message.SellerPubkey); err != nil {
		return err
	}
	if err := decode(values[11], &message.ExpiresAtUnix); err != nil {
		return err
	}
	if err := decode(values[12], &message.BuyerSignature); err != nil {
		return err
	}
	return ValidateHashGetTicket(message)
}

func (message HashDelivery) MarshalCBOR() ([]byte, error) {
	if err := validateHashDeliveryPayload(message.Payload); err != nil {
		return nil, err
	}
	return encodeArray(protocolMajorVersion, messageKindHashDelivery, message.SessionID, message.Sequence, bstr(message.ContentHash), bstr(message.Payload))
}

func (message *HashDelivery) UnmarshalCBOR(data []byte) error {
	values, err := decodeArray(data, 6)
	if err != nil {
		return err
	}
	if err := decodeHeader(values, messageKindHashDelivery); err != nil {
		return err
	}
	if err := decode(values[2], &message.SessionID); err != nil {
		return err
	}
	if err := decode(values[3], &message.Sequence); err != nil {
		return err
	}
	if err := decode(values[4], &message.ContentHash); err != nil {
		return err
	}
	if err := validateEncodedPayloadSize(values[5]); err != nil {
		return err
	}
	return decode(values[5], &message.Payload)
}

func (message ArbitrationClaim) MarshalCBOR() ([]byte, error) {
	if message.Ticket == nil {
		return nil, errors.New("arbitration claim ticket is required")
	}
	return encodeArray(protocolMajorVersion, messageKindArbitrationClaim, message.Ticket, bstr(message.Payload), uint64(message.ClaimantRole))
}

func (message *ArbitrationClaim) UnmarshalCBOR(data []byte) error {
	values, err := decodeArray(data, 5)
	if err != nil {
		return err
	}
	if err := decodeHeader(values, messageKindArbitrationClaim); err != nil {
		return err
	}
	var role uint64
	ticket := new(HashGetTicket)
	if err := decode(values[2], ticket); err != nil {
		return err
	}
	if err := decode(values[3], &message.Payload); err != nil {
		return err
	}
	if err := decode(values[4], &role); err != nil {
		return err
	}
	if role > 255 {
		return errors.New("arbitration claimant role overflows uint8")
	}
	message.Ticket, message.ClaimantRole = ticket, ArbitrationClaimantRole(role)
	return nil
}

func (message ArbitrationDecision) MarshalCBOR() ([]byte, error) {
	return encodeArray(protocolMajorVersion, messageKindArbitrationDecision, message.SessionID, message.Sequence, bstr(message.TicketID), message.Approved, message.ReasonCode, message.FinalPayoutSat, bstr(message.SellerPubkey), bstr(message.RecoveredPayload))
}

func (message *ArbitrationDecision) UnmarshalCBOR(data []byte) error {
	values, err := decodeArray(data, 10)
	if err != nil {
		return err
	}
	if err := decodeHeader(values, messageKindArbitrationDecision); err != nil {
		return err
	}
	if err := decode(values[2], &message.SessionID); err != nil {
		return err
	}
	if err := decode(values[3], &message.Sequence); err != nil {
		return err
	}
	if err := decode(values[4], &message.TicketID); err != nil {
		return err
	}
	if err := decode(values[5], &message.Approved); err != nil {
		return err
	}
	if err := decode(values[6], &message.ReasonCode); err != nil {
		return err
	}
	if err := decode(values[7], &message.FinalPayoutSat); err != nil {
		return err
	}
	if err := decode(values[8], &message.SellerPubkey); err != nil {
		return err
	}
	return decode(values[9], &message.RecoveredPayload)
}

func (message ArbitrationRecord) MarshalCBOR() ([]byte, error) {
	if message.Claim == nil || message.Decision == nil {
		return nil, errors.New("arbitration record claim and decision are required")
	}
	return encodeArray(protocolMajorVersion, messageKindArbitrationRecord, message.SessionID, message.Sequence, uint64(message.State), message.Claim, message.Decision, message.CreatedAtUnix, message.UpdatedAtUnix, message.RejectReasonCode)
}

func (message *ArbitrationRecord) UnmarshalCBOR(data []byte) error {
	values, err := decodeArray(data, 10)
	if err != nil {
		return err
	}
	if err := decodeHeader(values, messageKindArbitrationRecord); err != nil {
		return err
	}
	var state uint64
	claim := new(ArbitrationClaim)
	decision := new(ArbitrationDecision)
	if err := decode(values[2], &message.SessionID); err != nil {
		return err
	}
	if err := decode(values[3], &message.Sequence); err != nil {
		return err
	}
	if err := decode(values[4], &state); err != nil {
		return err
	}
	if state > 255 {
		return errors.New("arbitration state overflows uint8")
	}
	if err := decode(values[5], claim); err != nil {
		return err
	}
	if err := decode(values[6], decision); err != nil {
		return err
	}
	if err := decode(values[7], &message.CreatedAtUnix); err != nil {
		return err
	}
	if err := decode(values[8], &message.UpdatedAtUnix); err != nil {
		return err
	}
	if err := decode(values[9], &message.RejectReasonCode); err != nil {
		return err
	}
	message.State, message.Claim, message.Decision = ArbitrationState(state), claim, decision
	return nil
}
