package pool

import mp "github.com/bsv8/MultisigPool/v4/pkg"

// BuildPoolLock is the public role-explicit lock adapter. The v4 role object
// determines each participant's meaning by its Buyer, Seller, and Arbiter fields.
func BuildPoolLock(roles mp.ArbitratedPoolRoles) ([]byte, error) {
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), lock.Bytes()...), nil
}

func unsignedFromRaw(raw []byte, details *OpeningDetails) (*UnsignedPayment, error) {
	if details == nil || len(raw) == 0 {
		return nil, invalid("unsigned state transaction and opening proof are required")
	}
	state, err := parseCanonicalTransaction(raw)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || len(state.Outputs) != 3 {
		return nil, invalid("pool state must have exactly three outputs")
	}
	if state.Inputs[0].SourceTXID == nil || hash32FromBytes(state.Inputs[0].SourceTXID.CloneBytes()) != details.FundingTxID || state.Inputs[0].SourceTxOutIndex != PoolOutputIndex {
		return nil, invalid("unsigned payment does not spend the opening pool outpoint")
	}
	setPoolSource(state, details.PoolOutputSatoshis, details.PoolLockingScript)
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, invalid("arbitration candidate must have an empty unlocking script")
	}
	return &UnsignedPayment{RefundTemplateTxID: details.RefundTemplateTxID, RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, BuyerAmountSatoshis: state.Outputs[0].Satoshis, SellerAmountSatoshis: state.Outputs[1].Satoshis, ArbiterAmountSatoshis: state.Outputs[2].Satoshis, PoolOutputSatoshis: details.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), details.PoolLockingScript...)}, nil
}
