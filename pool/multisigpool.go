package pool

import (
	"context"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	"github.com/bsv8/go-bitfs/bitfs"
)

// BuildPoolLock is the public role-explicit lock adapter. The v4 role object
// determines each participant's meaning by its Buyer, Seller, and Arbiter fields.
func BuildPoolLock(roles mp.ArbitratedPoolRoles) ([]byte, error) {
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), lock.Bytes()...), nil
}

// MultisigPoolAdapter is the arbiter-facing capability. It contains no legacy
// role aliases and never constructs a replacement candidate transaction.
type MultisigPoolAdapter struct {
	// Engine 是无状态的 MultisigPool v4 协议引擎。
	Engine *MultisigPoolEngine
	// ArbiterKey 是仲裁方官方 BSV 私钥；绝不进入报文、返回值或日志。
	ArbiterKey *ec.PrivateKey
}

// VerifyOpening validates the complete 002 OpeningProof through MultisigPool v4:
// role keys, funding output, unsigned refund state, and buyer/seller refund
// signatures must all agree before a workflow may accept the pool.
func (adapter *MultisigPoolAdapter) VerifyOpening(proof *OpeningProof) error {
	if adapter == nil || adapter.Engine == nil {
		return invalid("MultisigPool adapter requires an engine")
	}
	return adapter.Engine.VerifyOpening(proof)
}

// VerifyArbitrationCandidate validates the seller's 007 candidate against the
// standalone 003 authorization. It checks the opening proof, fee rate and next
// sequence, matches seller amount and sequence in the unsigned transaction, and
// verifies the seller's detached signature without constructing a replacement.
func (adapter *MultisigPoolAdapter) VerifyArbitrationCandidate(_ context.Context, raw []byte, proof *OpeningProof, terms *bitfs.ContentRequestTerms, sellerSig []byte) (*UnsignedPayment, error) {
	if adapter == nil || adapter.Engine == nil || terms == nil {
		return nil, invalid("arbitration candidate inputs are incomplete")
	}
	if err := adapter.Engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	if terms.MinerFeeRateSatPerKB != proof.MinerFeeRateSatPerKB || terms.PaymentSequenceAfter == 0 || terms.PaymentSequenceAfter > uint64(^uint32(0)-1) || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 {
		return nil, invalid("arbitration candidate authorization is invalid")
	}
	unsigned, err := adapter.Engine.ParseUnsignedPayment(context.Background(), raw, proof)
	if err != nil {
		return nil, err
	}
	if unsigned.PaymentSequence != uint32(terms.PaymentSequenceAfter) || unsigned.SellerAmountSat != terms.SellerAmountAfterSat {
		return nil, invalid("arbitration candidate does not match authorization")
	}
	if unsigned.PaymentSequence == finalPoolSequence {
		return nil, invalid("arbitration candidate cannot use final sequence")
	}
	if err := adapter.Engine.VerifySellerPayment(unsigned, sellerSig, proof); err != nil {
		return nil, err
	}
	return unsigned, nil
}

// SignArbitrationCandidate signs the role-specific transaction or authorization
// bytes with the adapter's bound arbiter signer.
func (adapter *MultisigPoolAdapter) SignArbitrationCandidate(ctx context.Context, raw []byte, proof *OpeningProof) ([]byte, error) {
	if adapter == nil || adapter.Engine == nil || adapter.ArbiterKey == nil {
		return nil, invalid("arbiter signer is required")
	}
	unsigned, err := adapter.Engine.ParseUnsignedPayment(ctx, raw, proof)
	if err != nil {
		return nil, err
	}
	if unsigned.PaymentSequence == finalPoolSequence {
		return nil, invalid("arbitration candidate cannot use final sequence")
	}
	state, err := adapter.Engine.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return nil, err
	}
	sig, err := adapter.Engine.signWithKey(state, unsigned.PoolOutputSatoshis, adapter.ArbiterKey, "arbiter")
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
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
	return &UnsignedPayment{RefundTemplateTxID: details.RefundTemplateTxID, RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, PoolOutputSatoshis: details.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), details.PoolLockingScript...)}, nil
}
