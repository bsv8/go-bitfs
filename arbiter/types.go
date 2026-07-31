// Package arbiter implements the new one-way 007 payment-signature workflow.
// It never receives or recomputes BitFS content prices.
package arbiter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/bsv8/go-bitfs/pool"
	"github.com/fxamacker/cbor/v2"
)

const MajorVersion uint64 = 1

var (
	arbiterEnc cbor.EncMode
	arbiterDec cbor.DecMode
)

func init() {
	var err error
	arbiterEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	arbiterDec, err = cbor.DecOptions{
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  16,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

type PaymentSignatureRequest struct {
	Version                uint64
	PoolOpeningProofCBOR   []byte
	LatestPaymentStateCBOR []byte
}

type PaymentSignatureResponse struct {
	Version                     uint64
	LatestPaymentStateHash      []byte
	ArbiterTransactionSignature []byte
}

type ServiceConfig struct {
	Signer       pool.Signer
	Transactions pool.TransactionEngine
}

type Service struct {
	signer       pool.Signer
	transactions pool.TransactionEngine
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Signer == nil || config.Transactions == nil {
		return nil, errors.New("arbiter service requires signer and transaction engine")
	}
	return &Service{signer: config.Signer, transactions: config.Transactions}, nil
}

func (service *Service) SignPayment(ctx context.Context, request *PaymentSignatureRequest) (*PaymentSignatureResponse, error) {
	if service == nil {
		return nil, errors.New("arbiter service is required")
	}
	request = cloneRequest(request)
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	opening, err := pool.DecodeOpeningProof(request.PoolOpeningProofCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode opening proof: %w", err)
	}
	if err := service.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify opening proof: %w", err)
	}
	update, err := pool.DecodePaymentUpdate(request.LatestPaymentStateCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode latest payment state: %w", err)
	}
	fundingTxID, err := service.transactions.FundingTxID(update.PartialSpendTx)
	if err != nil {
		return nil, fmt.Errorf("read payment funding outpoint: %w", err)
	}
	if !bytesEqual(fundingTxID[:], opening.FundingTxID) {
		return nil, fmt.Errorf("%w: payment does not spend opening funding transaction", pool.ErrInvalidEvidence)
	}
	state, err := service.transactions.ParsePaymentState(ctx, update.PartialSpendTx, opening)
	if err != nil {
		return nil, fmt.Errorf("parse payment state: %w", err)
	}
	if state == nil {
		return nil, fmt.Errorf("%w: empty payment state", pool.ErrInvalidEvidence)
	}
	if err := service.transactions.VerifyBuyerPayment(state, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	spendTxID, err := service.transactions.TransactionID(opening.RefundTx)
	if err != nil {
		return nil, fmt.Errorf("calculate spend transaction ID: %w", err)
	}
	if state.SpendTxID != spendTxID {
		return nil, fmt.Errorf("%w: payment spend transaction mismatch", pool.ErrInvalidEvidence)
	}
	signature, err := service.transactions.SignArbiterPayment(ctx, state, service.signer)
	if err != nil {
		return nil, fmt.Errorf("sign payment for arbitration: %w", err)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("%w: arbiter signature is empty", pool.ErrInvalidEvidence)
	}
	digest := sha256.Sum256(request.LatestPaymentStateCBOR)
	return &PaymentSignatureResponse{
		Version:                     MajorVersion,
		LatestPaymentStateHash:      append([]byte(nil), digest[:]...),
		ArbiterTransactionSignature: append([]byte(nil), signature...),
	}, nil
}

func MarshalRequest(request *PaymentSignatureRequest) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	return arbiterEnc.Marshal([]any{MajorVersion, request.PoolOpeningProofCBOR, request.LatestPaymentStateCBOR})
}

func UnmarshalRequest(data []byte) (*PaymentSignatureRequest, error) {
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration request: %v", pool.ErrInvalidEvidence, err)
	}
	request := new(PaymentSignatureRequest)
	if err := arbiterDec.Unmarshal(values[0], &request.Version); err != nil || request.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration request version", pool.ErrInvalidEvidence)
	}
	if err := arbiterDec.Unmarshal(values[1], &request.PoolOpeningProofCBOR); err != nil {
		return nil, err
	}
	if err := arbiterDec.Unmarshal(values[2], &request.LatestPaymentStateCBOR); err != nil {
		return nil, err
	}
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	canonical, err := MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration request is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneRequest(request), nil
}

func MarshalResponse(response *PaymentSignatureResponse) ([]byte, error) {
	if err := validateResponse(response); err != nil {
		return nil, err
	}
	return arbiterEnc.Marshal([]any{MajorVersion, response.LatestPaymentStateHash, response.ArbiterTransactionSignature})
}

func UnmarshalResponse(data []byte) (*PaymentSignatureResponse, error) {
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration response: %v", pool.ErrInvalidEvidence, err)
	}
	response := new(PaymentSignatureResponse)
	if err := arbiterDec.Unmarshal(values[0], &response.Version); err != nil || response.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration response version", pool.ErrInvalidEvidence)
	}
	if err := arbiterDec.Unmarshal(values[1], &response.LatestPaymentStateHash); err != nil {
		return nil, err
	}
	if err := arbiterDec.Unmarshal(values[2], &response.ArbiterTransactionSignature); err != nil {
		return nil, err
	}
	if err := validateResponse(response); err != nil {
		return nil, err
	}
	canonical, err := MarshalResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytesEqual(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration response is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneResponse(response), nil
}

func validateRequest(request *PaymentSignatureRequest) error {
	if request == nil || (request.Version != 0 && request.Version != MajorVersion) || len(request.PoolOpeningProofCBOR) == 0 || len(request.LatestPaymentStateCBOR) == 0 {
		return fmt.Errorf("%w: arbitration request is incomplete", pool.ErrInvalidEvidence)
	}
	return nil
}

func validateResponse(response *PaymentSignatureResponse) error {
	if response == nil || (response.Version != 0 && response.Version != MajorVersion) || len(response.LatestPaymentStateHash) != sha256.Size || len(response.ArbiterTransactionSignature) == 0 {
		return fmt.Errorf("%w: arbitration response is incomplete", pool.ErrInvalidEvidence)
	}
	return nil
}

func decodeArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := arbiterDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func cloneRequest(request *PaymentSignatureRequest) *PaymentSignatureRequest {
	if request == nil {
		return nil
	}
	return &PaymentSignatureRequest{Version: request.Version, PoolOpeningProofCBOR: append([]byte(nil), request.PoolOpeningProofCBOR...), LatestPaymentStateCBOR: append([]byte(nil), request.LatestPaymentStateCBOR...)}
}

func cloneResponse(response *PaymentSignatureResponse) *PaymentSignatureResponse {
	if response == nil {
		return nil
	}
	return &PaymentSignatureResponse{Version: response.Version, LatestPaymentStateHash: append([]byte(nil), response.LatestPaymentStateHash...), ArbiterTransactionSignature: append([]byte(nil), response.ArbiterTransactionSignature...)}
}
