package pool

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

const (
	// KindPoolRefundPresignRequest is the CBOR tag for a refund presign request.
	KindPoolRefundPresignRequest uint64 = 12
	// KindPoolRefundPresignResponse identifies a refund signature response.
	KindPoolRefundPresignResponse uint64 = 13
	// KindPoolFundingTxDelivery identifies a funding transaction delivery.
	KindPoolFundingTxDelivery uint64 = 14
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

func validatePoolHash32Value(value Hash32, name string) error {
	return validatePoolHash32(value[:], name)
}

// EncodePaymentUpdate validates and encodes the 005 unsigned transaction plus
// detached buyer signature as its five-field deterministic CBOR container,
// led by the pool's RefundTemplateTxID correlation ID. It performs structural
// validation, not node acceptance or signature verification.
func EncodePaymentUpdate(update *PaymentUpdate) ([]byte, error) {
	if err := ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, update.RefundTemplateTxID[:], update.PaymentAuthorizationHash, update.UnsignedStateTxRaw, update.BuyerTransactionSignature})
}

// DecodePaymentUpdate decodes and canonicality-checks the 005 five-field payment
// container, then validates its field shape. It does not prove pool ownership or
// verify the buyer signature against an opening proof.
func DecodePaymentUpdate(data []byte) (*PaymentUpdate, error) {
	values, err := decodePoolArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payment update: %v", ErrInvalidEvidence, err)
	}
	update := new(PaymentUpdate)
	if err := poolDec.Unmarshal(values[0], &update.Version); err != nil || update.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported payment update version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &update.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[2], &update.PaymentAuthorizationHash); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &update.UnsignedStateTxRaw); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &update.BuyerTransactionSignature); err != nil {
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

// EncodeRefundPresignRequest validates and encodes the 002 buyer refund-presign
// request, including the workflow version, refund bytes, role keys, fee rate, and
// detached buyer signature. The funding outpoint, pool amount, and pool lock
// are derived canonically from RefundTx and the participant keys. The request
// does not duplicate the derived RefundTemplateTxID.
func EncodeRefundPresignRequest(request *RefundPresignRequest) ([]byte, error) {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{
		MajorVersion, request.RefundTx,
		request.BuyerPubKey, request.SellerPubKey, request.ArbiterPubKey,
		request.MinerFeeRateSatPerKB, request.BuyerRefundSignature,
	})
}

// DecodeRefundPresignRequest decodes and canonicality-checks the 002 request;
// cryptographic and funding-transaction acceptance remains the opening workflow's job.
func DecodeRefundPresignRequest(data []byte) (*RefundPresignRequest, error) {
	values, err := decodePoolArray(data, 7)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refund presign request: %v", ErrInvalidEvidence, err)
	}
	request := new(RefundPresignRequest)
	if err := poolDec.Unmarshal(values[0], &request.Version); err != nil || request.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported refund presign request version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &request.RefundTx); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[2], &request.BuyerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &request.SellerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &request.ArbiterPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[5], &request.MinerFeeRateSatPerKB); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[6], &request.BuyerRefundSignature); err != nil {
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

// EncodeRefundPresignResponse validates and encodes the seller's 002 refund
// signature response with the workflow version, message kind, and the pool's
// RefundTemplateTxID correlation ID re-derived by the seller from the request.
func EncodeRefundPresignResponse(response *RefundPresignResponse) ([]byte, error) {
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, KindPoolRefundPresignResponse, response.RefundTemplateTxID[:], response.SellerRefundSignature})
}

// DecodeRefundPresignResponse decodes and canonicality-checks the 002 seller
// response without deciding whether the signature matches a particular request.
func DecodeRefundPresignResponse(data []byte) (*RefundPresignResponse, error) {
	values, err := decodePoolArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refund presign response: %v", ErrInvalidEvidence, err)
	}
	response := new(RefundPresignResponse)
	var kind uint64
	if err := poolDec.Unmarshal(values[0], &response.Version); err != nil || response.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported refund presign response version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != KindPoolRefundPresignResponse {
		return nil, fmt.Errorf("%w: unexpected refund presign response kind", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[2], &response.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &response.SellerRefundSignature); err != nil {
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

// EncodeFundingTxDelivery validates and encodes the 002 funding-transaction
// delivery container with its RefundTemplateTxID correlation ID. It does not verify
// that the funding transaction spends the retained opening proof.
func EncodeFundingTxDelivery(delivery *FundingTxDelivery) ([]byte, error) {
	if err := ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, KindPoolFundingTxDelivery, delivery.RefundTemplateTxID[:], delivery.FundingTx})
}

// DecodeFundingTxDelivery decodes and canonicality-checks the 002 funding
// delivery; SellerAcceptFundingTx performs the proof and node checks.
func DecodeFundingTxDelivery(data []byte) (*FundingTxDelivery, error) {
	values, err := decodePoolArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode funding transaction delivery: %v", ErrInvalidEvidence, err)
	}
	delivery := new(FundingTxDelivery)
	var kind uint64
	if err := poolDec.Unmarshal(values[0], &delivery.Version); err != nil || delivery.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported funding transaction delivery version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != KindPoolFundingTxDelivery {
		return nil, fmt.Errorf("%w: unexpected funding transaction delivery kind", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[2], &delivery.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &delivery.FundingTx); err != nil {
		return nil, err
	}
	if err := ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	canonical, err := EncodeFundingTxDelivery(delivery)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: funding transaction delivery is not deterministically encoded", ErrInvalidEvidence)
	}
	return cloneFundingTxDelivery(delivery), nil
}

// EncodeOpeningProof validates and encodes the complete 002 opening proof. IDs,
// the fixed output index, amount, and locking script are deliberately omitted
// because they are derived from the transaction evidence and participant keys.
func EncodeOpeningProof(proof *OpeningProof) ([]byte, error) {
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	if len(proof.FundingTx) == 0 {
		return nil, fmt.Errorf("%w: complete funding transaction is required", ErrInvalidEvidence)
	}
	return poolEnc.Marshal([]any{
		MajorVersion, proof.RefundTx, proof.BuyerPubKey, proof.SellerPubKey,
		proof.ArbiterPubKey, proof.MinerFeeRateSatPerKB,
		proof.BuyerRefundSignature, proof.SellerRefundSignature, proof.FundingTx,
	})
}

// DecodeOpeningProof decodes and canonicality-checks a 002 opening proof, then
// performs field validation; VerifyOpening is still required for signatures and
// transaction relationships.
func DecodeOpeningProof(data []byte) (*OpeningProof, error) {
	values, err := decodePoolArray(data, 9)
	if err != nil {
		return nil, fmt.Errorf("%w: decode opening proof: %v", ErrInvalidEvidence, err)
	}
	proof := new(OpeningProof)
	if err := poolDec.Unmarshal(values[0], &proof.Version); err != nil || proof.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported opening proof version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &proof.RefundTx); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[2], &proof.BuyerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &proof.SellerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &proof.ArbiterPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[5], &proof.MinerFeeRateSatPerKB); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[6], &proof.BuyerRefundSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[7], &proof.SellerRefundSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[8], &proof.FundingTx); err != nil {
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

// ValidatePaymentUpdate checks the 005 envelope version, 32-byte non-zero
// RefundTemplateTxID and authorization hash, and presence of the unsigned transaction
// and detached buyer signature. It does not parse the transaction or establish
// that a node accepted it.
func ValidatePaymentUpdate(update *PaymentUpdate) error {
	if update == nil {
		return fmt.Errorf("%w: payment update is required", ErrInvalidEvidence)
	}
	if update.Version != MajorVersion {
		return fmt.Errorf("%w: unsupported payment update version %d", ErrInvalidEvidence, update.Version)
	}
	if err := validatePoolHash32Value(Hash32(update.RefundTemplateTxID), "refund_template_txid"); err != nil {
		return err
	}
	if len(update.PaymentAuthorizationHash) != sha256.Size {
		return fmt.Errorf("%w: payment_authorization_hash must be 32 bytes", ErrInvalidEvidence)
	}
	if len(update.UnsignedStateTxRaw) == 0 {
		return fmt.Errorf("%w: unsigned_state_tx_raw is required", ErrInvalidEvidence)
	}
	if len(update.BuyerTransactionSignature) == 0 {
		return fmt.Errorf("%w: buyer transaction signature is required", ErrInvalidEvidence)
	}
	return nil
}

// ValidateRefundPresignRequest checks the 002 request version, required refund
// evidence, role keys, fee rate, and buyer signature presence.
// It does not verify the refund transaction or either signature cryptographically.
func ValidateRefundPresignRequest(request *RefundPresignRequest) error {
	if request == nil || request.Version != MajorVersion {
		return fmt.Errorf("%w: invalid refund presign request", ErrInvalidEvidence)
	}
	if len(request.RefundTx) == 0 || len(request.BuyerRefundSignature) == 0 {
		return fmt.Errorf("%w: incomplete refund presign request", ErrInvalidEvidence)
	}
	roles := []struct {
		name string
		key  []byte
	}{{"buyer", request.BuyerPubKey}, {"seller", request.SellerPubKey}, {"arbiter", request.ArbiterPubKey}}
	for _, role := range roles {
		if err := protocol.ValidateCompressedPubKey(role.key); err != nil {
			return fmt.Errorf("%w: %s public key: %v", ErrInvalidEvidence, role.name, err)
		}
	}
	return nil
}

// ValidateRefundPresignResponse checks the 002 response version, requires a
// non-zero 32-byte RefundTemplateTxID and a seller refund signature; matching them to
// a request is a workflow operation.
func ValidateRefundPresignResponse(response *RefundPresignResponse) error {
	if response == nil || response.Version != MajorVersion || len(response.SellerRefundSignature) == 0 {
		return fmt.Errorf("%w: invalid refund presign response", ErrInvalidEvidence)
	}
	if err := validatePoolHash32Value(Hash32(response.RefundTemplateTxID), "refund_template_txid"); err != nil {
		return err
	}
	return nil
}

// ValidateFundingTxDelivery checks the 002 delivery version, requires a non-zero
// 32-byte RefundTemplateTxID and raw funding transaction bytes; it does not prove the
// bytes spend the opening.
func ValidateFundingTxDelivery(delivery *FundingTxDelivery) error {
	if delivery == nil || delivery.Version != MajorVersion || len(delivery.FundingTx) == 0 {
		return fmt.Errorf("%w: invalid funding transaction delivery", ErrInvalidEvidence)
	}
	if err := validatePoolHash32Value(Hash32(delivery.RefundTemplateTxID), "refund_template_txid"); err != nil {
		return err
	}
	return nil
}

// ValidateOpeningProof checks the 002 version, role keys, and raw refund
// evidence. It is structural;
// VerifyOpening performs transaction and signature relationship checks.
func ValidateOpeningProof(proof *OpeningProof) error {
	if proof == nil {
		return fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	if proof.Version != MajorVersion {
		return fmt.Errorf("%w: unsupported opening proof version %d", ErrInvalidEvidence, proof.Version)
	}
	if len(proof.RefundTx) == 0 || len(proof.BuyerRefundSignature) == 0 || len(proof.SellerRefundSignature) == 0 {
		return fmt.Errorf("%w: opening proof contains incomplete evidence", ErrInvalidEvidence)
	}
	roles := []struct {
		name string
		key  []byte
	}{{"buyer", proof.BuyerPubKey}, {"seller", proof.SellerPubKey}, {"arbiter", proof.ArbiterPubKey}}
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
	return &PaymentUpdate{Version: update.Version, RefundTemplateTxID: update.RefundTemplateTxID, PaymentAuthorizationHash: append([]byte(nil), update.PaymentAuthorizationHash...), UnsignedStateTxRaw: append([]byte(nil), update.UnsignedStateTxRaw...), BuyerTransactionSignature: append([]byte(nil), update.BuyerTransactionSignature...)}
}

func cloneRefundPresignRequest(request *RefundPresignRequest) *RefundPresignRequest {
	if request == nil {
		return nil
	}
	cloned := *request
	cloned.RefundTx = append([]byte(nil), request.RefundTx...)
	cloned.BuyerPubKey = append([]byte(nil), request.BuyerPubKey...)
	cloned.SellerPubKey = append([]byte(nil), request.SellerPubKey...)
	cloned.ArbiterPubKey = append([]byte(nil), request.ArbiterPubKey...)
	cloned.BuyerRefundSignature = append([]byte(nil), request.BuyerRefundSignature...)
	return &cloned
}

func cloneRefundPresignResponse(response *RefundPresignResponse) *RefundPresignResponse {
	if response == nil {
		return nil
	}
	return &RefundPresignResponse{Version: response.Version, RefundTemplateTxID: response.RefundTemplateTxID, SellerRefundSignature: append([]byte(nil), response.SellerRefundSignature...)}
}
func cloneFundingTxDelivery(delivery *FundingTxDelivery) *FundingTxDelivery {
	if delivery == nil {
		return nil
	}
	return &FundingTxDelivery{Version: delivery.Version, RefundTemplateTxID: delivery.RefundTemplateTxID, FundingTx: append([]byte(nil), delivery.FundingTx...)}
}

func cloneOpeningProof(proof *OpeningProof) *OpeningProof {
	if proof == nil {
		return nil
	}
	cloned := *proof
	cloned.RefundTx = append([]byte(nil), proof.RefundTx...)
	cloned.BuyerPubKey = append([]byte(nil), proof.BuyerPubKey...)
	cloned.SellerPubKey = append([]byte(nil), proof.SellerPubKey...)
	cloned.ArbiterPubKey = append([]byte(nil), proof.ArbiterPubKey...)
	cloned.BuyerRefundSignature = append([]byte(nil), proof.BuyerRefundSignature...)
	cloned.SellerRefundSignature = append([]byte(nil), proof.SellerRefundSignature...)
	cloned.FundingTx = append([]byte(nil), proof.FundingTx...)
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
