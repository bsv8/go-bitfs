package settlement

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// ArbitrationSigningPayload is the domain-separated canonical CBOR preimage.
func ArbitrationSigningPayload(request *ArbitrationRequest) ([]byte, error) {
	if err := ValidateArbitrationRequest(request); err != nil {
		return nil, err
	}
	return enc.Marshal([]any{"settlement.arbitrate.v1", uint64(1), request.SpendTxID, request.Approved, request.ReasonCode, request.FinalPayoutSat})
}

func ArbitrationSigningDigest(request *ArbitrationRequest) ([sha256.Size]byte, error) {
	payload, err := ArbitrationSigningPayload(request)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func ValidateArbitrationRequest(request *ArbitrationRequest) error {
	if request == nil {
		return errors.New("pool arbitration request is required")
	}
	if err := requireID("spend_txid", request.SpendTxID); err != nil {
		return err
	}
	if request.ReasonCode == "" {
		return errors.New("pool arbitration reason is required")
	}
	if len(request.ArbiterSignature) == 0 {
		return errors.New("pool arbitration arbiter_signature is required")
	}
	if request.Approved && request.FinalPayoutSat == 0 {
		return errors.New("approved pool arbitration final_payout_sat must be positive")
	}
	if !request.Approved && request.FinalPayoutSat != 0 {
		return fmt.Errorf("rejected pool arbitration final_payout_sat must be zero, got %d", request.FinalPayoutSat)
	}
	return nil
}
