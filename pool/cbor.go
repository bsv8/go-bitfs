package pool

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Kind 2/3/4/7 的统一 wire Kind 值。完整报文外壳固定为
// [protocol.WireVersion, wireKind, ...]；认证内容不再携带任何内层版本或 Kind。
const (
	wireKindRefundPresignRequest  uint64 = 2
	wireKindRefundPresignResponse uint64 = 3
	wireKindFundingDelivery       uint64 = 4
	wireKindPaymentUpdate         uint64 = 7
)

var poolEnc cbor.EncMode
var poolDec cbor.DecMode

func init() {
	var err error
	poolEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	poolDec, err = cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden, MaxNestedLevels: 16, MaxArrayElements: 32,
		MaxMapPairs: 16, UTF8: cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// validatePoolHash32 checks that a decoded hash field is exactly 32 bytes and
// not the all-zero "unset" sentinel.
func validatePoolHash32(raw []byte, name string) error {
	if len(raw) != sha256.Size {
		return fmt.Errorf("%w: %s must be 32 bytes", ErrInvalidEvidence, name)
	}
	for _, b := range raw {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: %s must not be all zero", ErrInvalidEvidence, name)
}

func validatePoolHash32Value(value [sha256.Size]byte, name string) error {
	return validatePoolHash32(value[:], name)
}

// encodeWireEnvelope prepends the fixed [wire_version, wire_kind] outer pair.
// The encoder owns both values; callers never supply them.
func encodeWireEnvelope(wireKind uint64, fields ...any) ([]byte, error) {
	return poolEnc.Marshal(append([]any{protocol.WireVersion, wireKind}, fields...))
}

// decodeWireEnvelope strictly decodes the [wire_version, wire_kind, ...] outer
// pair and returns the remaining elements.
func decodeWireEnvelope(data []byte, wantKind uint64, totalLength int) ([]cbor.RawMessage, error) {
	values, err := decodePoolArray(data, totalLength)
	if err != nil {
		return nil, err
	}
	var version, kind uint64
	if err := poolDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, fmt.Errorf("%w: unsupported wire version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != wantKind {
		return nil, fmt.Errorf("%w: unexpected wire kind %d", ErrInvalidEvidence, kind)
	}
	return values[2:], nil
}

// EncodePaymentUpdate validates and encodes the minimal Kind 7 payment
// authorization ID plus detached buyer payment transaction signature as its
// four-field deterministic CBOR container. The pool correlation ID and the
// unsigned state transaction are not transmitted: both sides rebuild the exact
// transaction locally from the opening proof, previous payment state, and the
// signed payment authorization referenced by the ID. It performs structural
// validation, not node acceptance or signature verification.
func EncodePaymentUpdate(update *PaymentUpdate) ([]byte, error) {
	if err := ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindPaymentUpdate, update.PaymentAuthorizationID, update.BuyerPaymentTransactionSignature)
}

// DecodePaymentUpdate decodes and canonicality-checks the Kind 7 four-element
// minimal container, then validates its field shape. Any other shape is
// rejected outright; it does not prove pool ownership or verify the buyer
// signature against a rebuilt transaction.
func DecodePaymentUpdate(data []byte) (*PaymentUpdate, error) {
	fields, err := decodeWireEnvelope(data, wireKindPaymentUpdate, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payment update: %v", ErrInvalidEvidence, err)
	}
	update := new(PaymentUpdate)
	if err := poolDec.Unmarshal(fields[0], &update.PaymentAuthorizationID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &update.BuyerPaymentTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	canonical, err := EncodePaymentUpdate(update)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: payment update is not deterministically encoded", ErrInvalidEvidence)
	}
	return clonePaymentUpdate(update), nil
}

// EncodeRefundPresignRequest validates and encodes the Kind 2 buyer
// refund-presign request: the canonical unsigned refund template raw bytes,
// role keys, fee rate, and detached buyer transaction signature. The funding
// outpoint, pool amount, and pool lock are derived canonically from
// refund_template_raw and the participant keys. The request does not duplicate
// the derived RefundTemplateTxID.
func EncodeRefundPresignRequest(request *RefundPresignRequest) ([]byte, error) {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindRefundPresignRequest,
		request.RefundTemplateRaw,
		request.BuyerPublicKey, request.SellerPublicKey, request.ArbiterPublicKey,
		request.MinerFeeRateSatoshisPerKilobyte, request.BuyerRefundTransactionSignature,
	)
}

// DecodeRefundPresignRequest decodes and canonicality-checks the Kind 2
// request; cryptographic and funding-transaction acceptance remains the
// opening workflow's job.
func DecodeRefundPresignRequest(data []byte) (*RefundPresignRequest, error) {
	fields, err := decodeWireEnvelope(data, wireKindRefundPresignRequest, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refund presign request: %v", ErrInvalidEvidence, err)
	}
	request := new(RefundPresignRequest)
	if err := poolDec.Unmarshal(fields[0], &request.RefundTemplateRaw); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &request.BuyerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[2], &request.SellerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[3], &request.ArbiterPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[4], &request.MinerFeeRateSatoshisPerKilobyte); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[5], &request.BuyerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	canonical, err := EncodeRefundPresignRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: refund presign request is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneRefundPresignRequest(request), nil
}

// EncodeRefundPresignResponse validates and encodes the seller's Kind 3 refund
// signature response with the pool's RefundTemplateTxID correlation ID
// re-derived by the seller from the request.
func EncodeRefundPresignResponse(response *RefundPresignResponse) ([]byte, error) {
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindRefundPresignResponse, response.RefundTemplateTxID[:], response.SellerRefundTransactionSignature)
}

// DecodeRefundPresignResponse decodes and canonicality-checks the Kind 3
// seller response without deciding whether the signature matches a particular
// request.
func DecodeRefundPresignResponse(data []byte) (*RefundPresignResponse, error) {
	fields, err := decodeWireEnvelope(data, wireKindRefundPresignResponse, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refund presign response: %v", ErrInvalidEvidence, err)
	}
	response := new(RefundPresignResponse)
	if err := poolDec.Unmarshal(fields[0], &response.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &response.SellerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	canonical, err := EncodeRefundPresignResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: refund presign response is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneRefundPresignResponse(response), nil
}

// EncodeFundingTransactionDelivery validates and encodes the Kind 4
// funding-transaction delivery container with its RefundTemplateTxID
// correlation ID. It does not verify that the funding transaction spends the
// retained opening proof.
func EncodeFundingTransactionDelivery(delivery *FundingTransactionDelivery) ([]byte, error) {
	if err := ValidateFundingTransactionDelivery(delivery); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindFundingDelivery, delivery.RefundTemplateTxID[:], delivery.FundingTransactionRaw)
}

// DecodeFundingTransactionDelivery decodes and canonicality-checks the Kind 4
// funding delivery; SellerAcceptFundingTx performs the proof and node checks.
func DecodeFundingTransactionDelivery(data []byte) (*FundingTransactionDelivery, error) {
	fields, err := decodeWireEnvelope(data, wireKindFundingDelivery, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode funding transaction delivery: %v", ErrInvalidEvidence, err)
	}
	delivery := new(FundingTransactionDelivery)
	if err := poolDec.Unmarshal(fields[0], &delivery.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &delivery.FundingTransactionRaw); err != nil {
		return nil, err
	}
	if err := ValidateFundingTransactionDelivery(delivery); err != nil {
		return nil, err
	}
	canonical, err := EncodeFundingTransactionDelivery(delivery)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: funding transaction delivery is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneFundingTransactionDelivery(delivery), nil
}

// EncodeOpeningProof validates and encodes the complete opening proof. IDs,
// the fixed output index, amount, and locking script are deliberately omitted
// because they are derived from the transaction evidence and participant keys.
// The opening proof is application-local evidence, not one of the eleven wire
// kinds; its encoding carries no version or kind of its own.
func EncodeOpeningProof(proof *OpeningProof) ([]byte, error) {
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	if len(proof.FundingTransactionRaw) == 0 {
		return nil, fmt.Errorf("%w: complete funding transaction is required", ErrInvalidEvidence)
	}
	return poolEnc.Marshal([]any{
		proof.RefundTemplateRaw, proof.BuyerPublicKey, proof.SellerPublicKey,
		proof.ArbiterPublicKey, proof.MinerFeeRateSatoshisPerKilobyte,
		proof.BuyerRefundTransactionSignature, proof.SellerRefundTransactionSignature, proof.FundingTransactionRaw,
	})
}

// DecodeOpeningProof decodes and canonicality-checks an opening proof, then
// performs field validation; VerifyOpening is still required for signatures
// and transaction relationships.
func DecodeOpeningProof(data []byte) (*OpeningProof, error) {
	values, err := decodePoolArray(data, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: decode opening proof: %v", ErrInvalidEvidence, err)
	}
	proof := new(OpeningProof)
	if err := poolDec.Unmarshal(values[0], &proof.RefundTemplateRaw); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[1], &proof.BuyerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[2], &proof.SellerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &proof.ArbiterPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &proof.MinerFeeRateSatoshisPerKilobyte); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[5], &proof.BuyerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[6], &proof.SellerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[7], &proof.FundingTransactionRaw); err != nil {
		return nil, err
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	canonical, err := EncodeOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: opening proof is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneOpeningProof(proof), nil
}

// ValidatePaymentUpdate checks the Kind 7 minimal envelope, 32-byte non-zero
// authorization ID, and presence of the detached buyer payment transaction
// signature. It does not parse transactions or establish that a node accepted
// anything; the referenced signed payment authorization and the rebuilt
// unsigned state transaction are verified by the receiving workflow.
func ValidatePaymentUpdate(update *PaymentUpdate) error {
	if update == nil {
		return fmt.Errorf("%w: payment update is required", ErrInvalidEvidence)
	}
	if update.PaymentAuthorizationID.IsZero() {
		return fmt.Errorf("%w: payment_authorization_id", protocol.ErrZeroIdentifier)
	}
	if len(update.BuyerPaymentTransactionSignature) == 0 {
		return fmt.Errorf("%w: buyer payment transaction signature is required", ErrInvalidEvidence)
	}
	return nil
}

// ValidateRefundPresignRequest checks the Kind 2 request required refund
// evidence, role keys, fee rate, and buyer transaction signature presence.
// It does not verify the refund transaction or either signature cryptographically.
func ValidateRefundPresignRequest(request *RefundPresignRequest) error {
	if request == nil {
		return fmt.Errorf("%w: invalid refund presign request", ErrInvalidEvidence)
	}
	if len(request.RefundTemplateRaw) == 0 || len(request.BuyerRefundTransactionSignature) == 0 {
		return fmt.Errorf("%w: incomplete refund presign request", ErrInvalidEvidence)
	}
	roles := []struct {
		name string
		key  []byte
	}{{"buyer", request.BuyerPublicKey}, {"seller", request.SellerPublicKey}, {"arbiter", request.ArbiterPublicKey}}
	for _, role := range roles {
		if err := protocol.ValidateCompressedPubKey(role.key); err != nil {
			return fmt.Errorf("%w: %s public key: %v", ErrInvalidEvidence, role.name, err)
		}
	}
	return nil
}

// ValidateRefundPresignResponse requires a non-zero 32-byte RefundTemplateTxID
// and a seller refund transaction signature; matching them to a request is a
// workflow operation.
func ValidateRefundPresignResponse(response *RefundPresignResponse) error {
	if response == nil || len(response.SellerRefundTransactionSignature) == 0 {
		return fmt.Errorf("%w: invalid refund presign response", ErrInvalidEvidence)
	}
	if err := validatePoolHash32Value(response.RefundTemplateTxID, "refund_template_txid"); err != nil {
		return err
	}
	return nil
}

// ValidateFundingTransactionDelivery requires a non-zero 32-byte
// RefundTemplateTxID and raw funding transaction bytes; it does not prove the
// bytes spend the opening.
func ValidateFundingTransactionDelivery(delivery *FundingTransactionDelivery) error {
	if delivery == nil || len(delivery.FundingTransactionRaw) == 0 {
		return fmt.Errorf("%w: invalid funding transaction delivery", ErrInvalidEvidence)
	}
	if err := validatePoolHash32Value(delivery.RefundTemplateTxID, "refund_template_txid"); err != nil {
		return err
	}
	return nil
}

// ValidateOpeningProof checks role keys and raw refund evidence. It is
// structural; VerifyOpening performs transaction and signature relationship
// checks.
func ValidateOpeningProof(proof *OpeningProof) error {
	if proof == nil {
		return fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	if len(proof.RefundTemplateRaw) == 0 || len(proof.BuyerRefundTransactionSignature) == 0 || len(proof.SellerRefundTransactionSignature) == 0 {
		return fmt.Errorf("%w: opening proof contains incomplete evidence", ErrInvalidEvidence)
	}
	roles := []struct {
		name string
		key  []byte
	}{{"buyer", proof.BuyerPublicKey}, {"seller", proof.SellerPublicKey}, {"arbiter", proof.ArbiterPublicKey}}
	for _, role := range roles {
		if err := protocol.ValidateCompressedPubKey(role.key); err != nil {
			return fmt.Errorf("%w: %s public key: %v", ErrInvalidEvidence, role.name, err)
		}
	}
	return nil
}

func decodePoolArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := poolDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func clonePaymentUpdate(update *PaymentUpdate) *PaymentUpdate {
	if update == nil {
		return nil
	}
	return &PaymentUpdate{PaymentAuthorizationID: update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: append([]byte(nil), update.BuyerPaymentTransactionSignature...)}
}

func cloneRefundPresignRequest(request *RefundPresignRequest) *RefundPresignRequest {
	if request == nil {
		return nil
	}
	cloned := *request
	cloned.RefundTemplateRaw = append([]byte(nil), request.RefundTemplateRaw...)
	cloned.BuyerPublicKey = append([]byte(nil), request.BuyerPublicKey...)
	cloned.SellerPublicKey = append([]byte(nil), request.SellerPublicKey...)
	cloned.ArbiterPublicKey = append([]byte(nil), request.ArbiterPublicKey...)
	cloned.BuyerRefundTransactionSignature = append([]byte(nil), request.BuyerRefundTransactionSignature...)
	return &cloned
}

func cloneRefundPresignResponse(response *RefundPresignResponse) *RefundPresignResponse {
	if response == nil {
		return nil
	}
	return &RefundPresignResponse{RefundTemplateTxID: response.RefundTemplateTxID, SellerRefundTransactionSignature: append([]byte(nil), response.SellerRefundTransactionSignature...)}
}
func cloneFundingTransactionDelivery(delivery *FundingTransactionDelivery) *FundingTransactionDelivery {
	if delivery == nil {
		return nil
	}
	return &FundingTransactionDelivery{RefundTemplateTxID: delivery.RefundTemplateTxID, FundingTransactionRaw: append([]byte(nil), delivery.FundingTransactionRaw...)}
}

func cloneOpeningProof(proof *OpeningProof) *OpeningProof {
	if proof == nil {
		return nil
	}
	cloned := *proof
	cloned.RefundTemplateRaw = append([]byte(nil), proof.RefundTemplateRaw...)
	cloned.BuyerPublicKey = append([]byte(nil), proof.BuyerPublicKey...)
	cloned.SellerPublicKey = append([]byte(nil), proof.SellerPublicKey...)
	cloned.ArbiterPublicKey = append([]byte(nil), proof.ArbiterPublicKey...)
	cloned.BuyerRefundTransactionSignature = append([]byte(nil), proof.BuyerRefundTransactionSignature...)
	cloned.SellerRefundTransactionSignature = append([]byte(nil), proof.SellerRefundTransactionSignature...)
	cloned.FundingTransactionRaw = append([]byte(nil), proof.FundingTransactionRaw...)
	return &cloned
}

func clonePaymentState(state *PaymentState) *PaymentState {
	if state == nil {
		return nil
	}
	cloned := *state
	cloned.RawTx = append([]byte(nil), state.RawTx...)
	cloned.BuyerTransactionSignature = append([]byte(nil), state.BuyerTransactionSignature...)
	cloned.SellerTransactionSignature = append([]byte(nil), state.SellerTransactionSignature...)
	cloned.ArbiterTransactionSignature = append([]byte(nil), state.ArbiterTransactionSignature...)
	cloned.PoolLockingScript = append([]byte(nil), state.PoolLockingScript...)
	return &cloned
}
