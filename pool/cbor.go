package pool

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	KindPoolRefundPresignRequest  uint64 = 12
	KindPoolRefundPresignResponse uint64 = 13
	KindPoolFundingTxDelivery     uint64 = 14
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
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  16,
		MaxArrayElements: 32,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

func EncodePaymentUpdate(update *PaymentUpdate) ([]byte, error) {
	if err := ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, update.ContentRequestTermsHash, update.PartialSpendTx})
}

func EncodeRefundPresignRequest(request *RefundPresignRequest) ([]byte, error) {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, KindPoolRefundPresignRequest, request.RefundTx, request.FundingTxID, request.PoolOutputIndex, request.PoolOutputSatoshis, request.PoolLockingScript, request.ServerPubKey, request.BuyerPubKey, request.ArbiterPubKey, request.MinerFeeRateSatPerKB, request.BuyerRefundSignature})
}

func DecodeRefundPresignRequest(data []byte) (*RefundPresignRequest, error) {
	values, err := decodePoolArray(data, 12)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refund presign request: %v", ErrInvalidEvidence, err)
	}
	request := new(RefundPresignRequest)
	var version, kind uint64
	if err := poolDec.Unmarshal(values[0], &version); err != nil || version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported refund presign request version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != KindPoolRefundPresignRequest {
		return nil, fmt.Errorf("%w: unexpected refund presign request kind", ErrInvalidEvidence)
	}
	request.Version = version
	if err := poolDec.Unmarshal(values[2], &request.RefundTx); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &request.FundingTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &request.PoolOutputIndex); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[5], &request.PoolOutputSatoshis); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[6], &request.PoolLockingScript); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[7], &request.ServerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[8], &request.BuyerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[9], &request.ArbiterPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[10], &request.MinerFeeRateSatPerKB); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[11], &request.BuyerRefundSignature); err != nil {
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

func EncodeRefundPresignResponse(response *RefundPresignResponse) ([]byte, error) {
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, KindPoolRefundPresignResponse, response.SellerRefundSignature})
}

func DecodeRefundPresignResponse(data []byte) (*RefundPresignResponse, error) {
	values, err := decodePoolArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode refund presign response: %v", ErrInvalidEvidence, err)
	}
	response := new(RefundPresignResponse)
	var version, kind uint64
	if err := poolDec.Unmarshal(values[0], &version); err != nil || version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported refund presign response version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != KindPoolRefundPresignResponse {
		return nil, fmt.Errorf("%w: unexpected refund presign response kind", ErrInvalidEvidence)
	}
	response.Version = version
	if err := poolDec.Unmarshal(values[2], &response.SellerRefundSignature); err != nil {
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

func EncodeFundingTxDelivery(delivery *FundingTxDelivery) ([]byte, error) {
	if err := ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{MajorVersion, KindPoolFundingTxDelivery, delivery.FundingTx})
}

func DecodeFundingTxDelivery(data []byte) (*FundingTxDelivery, error) {
	values, err := decodePoolArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode funding transaction delivery: %v", ErrInvalidEvidence, err)
	}
	delivery := new(FundingTxDelivery)
	var version, kind uint64
	if err := poolDec.Unmarshal(values[0], &version); err != nil || version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported funding transaction delivery version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != KindPoolFundingTxDelivery {
		return nil, fmt.Errorf("%w: unexpected funding transaction delivery kind", ErrInvalidEvidence)
	}
	delivery.Version = version
	if err := poolDec.Unmarshal(values[2], &delivery.FundingTx); err != nil {
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

func ValidateRefundPresignRequest(request *RefundPresignRequest) error {
	if request == nil || (request.Version != 0 && request.Version != MajorVersion) {
		return fmt.Errorf("%w: invalid refund presign request", ErrInvalidEvidence)
	}
	if len(request.RefundTx) == 0 || len(request.FundingTxID) != sha256.Size || request.PoolOutputSatoshis == 0 || len(request.PoolLockingScript) == 0 || len(request.ServerPubKey) == 0 || len(request.BuyerPubKey) == 0 || len(request.ArbiterPubKey) == 0 || len(request.BuyerRefundSignature) == 0 {
		return fmt.Errorf("%w: incomplete refund presign request", ErrInvalidEvidence)
	}
	return nil
}

func ValidateRefundPresignResponse(response *RefundPresignResponse) error {
	if response == nil || (response.Version != 0 && response.Version != MajorVersion) || len(response.SellerRefundSignature) == 0 {
		return fmt.Errorf("%w: invalid refund presign response", ErrInvalidEvidence)
	}
	return nil
}

func ValidateFundingTxDelivery(delivery *FundingTxDelivery) error {
	if delivery == nil || (delivery.Version != 0 && delivery.Version != MajorVersion) || len(delivery.FundingTx) == 0 {
		return fmt.Errorf("%w: invalid funding transaction delivery", ErrInvalidEvidence)
	}
	return nil
}

func DecodePaymentUpdate(data []byte) (*PaymentUpdate, error) {
	values, err := decodePoolArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payment update: %v", ErrInvalidEvidence, err)
	}
	var version uint64
	update := new(PaymentUpdate)
	if err := poolDec.Unmarshal(values[0], &version); err != nil || version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported payment update version", ErrInvalidEvidence)
	}
	if err := poolDec.Unmarshal(values[1], &update.ContentRequestTermsHash); err != nil {
		return nil, fmt.Errorf("%w: content request terms hash: %v", ErrInvalidEvidence, err)
	}
	if err := poolDec.Unmarshal(values[2], &update.PartialSpendTx); err != nil {
		return nil, fmt.Errorf("%w: partial spend transaction: %v", ErrInvalidEvidence, err)
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

func ValidatePaymentUpdate(update *PaymentUpdate) error {
	if update == nil {
		return fmt.Errorf("%w: payment update is required", ErrInvalidEvidence)
	}
	if update.Version != 0 && update.Version != MajorVersion {
		return fmt.Errorf("%w: unsupported payment update version %d", ErrInvalidEvidence, update.Version)
	}
	if len(update.ContentRequestTermsHash) != sha256.Size {
		return fmt.Errorf("%w: content_request_terms_hash must be 32 bytes", ErrInvalidEvidence)
	}
	if len(update.PartialSpendTx) == 0 {
		return fmt.Errorf("%w: partial_spend_tx is required", ErrInvalidEvidence)
	}
	return nil
}

func EncodeOpeningProof(proof *OpeningProof) ([]byte, error) {
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	return poolEnc.Marshal([]any{
		MajorVersion,
		proof.RefundTx,
		proof.SpendTxID,
		proof.FundingTxID,
		proof.PoolOutputIndex,
		proof.PoolOutputSatoshis,
		proof.PoolLockingScript,
		proof.ServerPubKey,
		proof.BuyerPubKey,
		proof.ArbiterPubKey,
		proof.MinerFeeRateSatPerKB,
		proof.BuyerRefundSignature,
		proof.SellerRefundSignature,
		proof.FundingTx,
	})
}

func DecodeOpeningProof(data []byte) (*OpeningProof, error) {
	values, err := decodePoolArray(data, 14)
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
	if err := poolDec.Unmarshal(values[2], &proof.SpendTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &proof.FundingTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &proof.PoolOutputIndex); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[5], &proof.PoolOutputSatoshis); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[6], &proof.PoolLockingScript); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[7], &proof.ServerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[8], &proof.BuyerPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[9], &proof.ArbiterPubKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[10], &proof.MinerFeeRateSatPerKB); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[11], &proof.BuyerRefundSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[12], &proof.SellerRefundSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[13], &proof.FundingTx); err != nil {
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

func ValidateOpeningProof(proof *OpeningProof) error {
	if proof == nil {
		return fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	if proof.Version != 0 && proof.Version != MajorVersion {
		return fmt.Errorf("%w: unsupported opening proof version %d", ErrInvalidEvidence, proof.Version)
	}
	if len(proof.RefundTx) == 0 || len(proof.SpendTxID) != sha256.Size || len(proof.FundingTxID) != sha256.Size || proof.PoolOutputSatoshis == 0 || len(proof.PoolLockingScript) == 0 || len(proof.ServerPubKey) == 0 || len(proof.BuyerPubKey) == 0 || len(proof.ArbiterPubKey) == 0 || len(proof.BuyerRefundSignature) == 0 || len(proof.SellerRefundSignature) == 0 {
		return fmt.Errorf("%w: opening proof contains incomplete evidence", ErrInvalidEvidence)
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
	return &PaymentUpdate{Version: update.Version, ContentRequestTermsHash: append([]byte(nil), update.ContentRequestTermsHash...), PartialSpendTx: append([]byte(nil), update.PartialSpendTx...)}
}

func cloneRefundPresignRequest(request *RefundPresignRequest) *RefundPresignRequest {
	if request == nil {
		return nil
	}
	cloned := *request
	cloned.RefundTx = append([]byte(nil), request.RefundTx...)
	cloned.FundingTxID = append([]byte(nil), request.FundingTxID...)
	cloned.PoolLockingScript = append([]byte(nil), request.PoolLockingScript...)
	cloned.ServerPubKey = append([]byte(nil), request.ServerPubKey...)
	cloned.BuyerPubKey = append([]byte(nil), request.BuyerPubKey...)
	cloned.ArbiterPubKey = append([]byte(nil), request.ArbiterPubKey...)
	cloned.BuyerRefundSignature = append([]byte(nil), request.BuyerRefundSignature...)
	return &cloned
}

func cloneRefundPresignResponse(response *RefundPresignResponse) *RefundPresignResponse {
	if response == nil {
		return nil
	}
	return &RefundPresignResponse{Version: response.Version, SellerRefundSignature: append([]byte(nil), response.SellerRefundSignature...)}
}

func cloneFundingTxDelivery(delivery *FundingTxDelivery) *FundingTxDelivery {
	if delivery == nil {
		return nil
	}
	return &FundingTxDelivery{Version: delivery.Version, FundingTx: append([]byte(nil), delivery.FundingTx...)}
}

func cloneOpeningProof(proof *OpeningProof) *OpeningProof {
	if proof == nil {
		return nil
	}
	cloned := *proof
	cloned.RefundTx = append([]byte(nil), proof.RefundTx...)
	cloned.SpendTxID = append([]byte(nil), proof.SpendTxID...)
	cloned.FundingTxID = append([]byte(nil), proof.FundingTxID...)
	cloned.PoolLockingScript = append([]byte(nil), proof.PoolLockingScript...)
	cloned.ServerPubKey = append([]byte(nil), proof.ServerPubKey...)
	cloned.BuyerPubKey = append([]byte(nil), proof.BuyerPubKey...)
	cloned.ArbiterPubKey = append([]byte(nil), proof.ArbiterPubKey...)
	cloned.BuyerRefundSignature = append([]byte(nil), proof.BuyerRefundSignature...)
	cloned.SellerRefundSignature = append([]byte(nil), proof.SellerRefundSignature...)
	cloned.FundingTx = append([]byte(nil), proof.FundingTx...)
	return &cloned
}
