package pool

import (
	"context"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	"github.com/bsv8/go-bitfs/bitfs"
)

// BuildPoolLock is the public role-explicit lock adapter. The argument order
// is permanently Buyer, Seller, Arbiter through the v4 role object.
func BuildPoolLock(roles mp.ArbitratedPoolRoles) ([]byte, error) {
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), lock.Bytes()...), nil
}

// PrivateKeyProvider is intentionally narrower than the workflow Signer:
// MultisigPool must receive the actual private key so it can calculate its
// canonical sighash and detached signature.
type PrivateKeyProvider interface {
	PrivateKey(context.Context) (*ec.PrivateKey, error)
}

// MultisigPoolAdapter is the arbiter-facing capability. It contains no legacy
// role aliases and never constructs a replacement candidate transaction.
type MultisigPoolAdapter struct {
	Engine     *MultisigPoolEngine
	ArbiterKey PrivateKeyProvider
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
	if terms.MinerFeeRateSatPerKB != proof.MinerFeeRateSatPerKB || terms.PaymentSequenceAfter == 0 || terms.PaymentSequenceAfter > uint64(^uint32(0)) || terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 {
		return nil, invalid("arbitration candidate authorization is invalid")
	}
	unsigned, err := unsignedFromRaw(raw, proof)
	if err != nil {
		return nil, err
	}
	if unsigned.PaymentSequence != uint32(terms.PaymentSequenceAfter) || unsigned.SellerAmountSat != terms.SellerAmountAfterSat {
		return nil, invalid("arbitration candidate does not match authorization")
	}
	if err := adapter.Engine.VerifySellerPayment(unsigned, sellerSig, proof); err != nil {
		return nil, err
	}
	return unsigned, nil
}

// SignArbitrationCandidate signs the role-specific transaction or authorization bytes with the injected signer.
func (adapter *MultisigPoolAdapter) SignArbitrationCandidate(ctx context.Context, raw []byte, proof *OpeningProof, _ Signer) ([]byte, error) {
	if adapter == nil || adapter.Engine == nil || adapter.ArbiterKey == nil {
		return nil, invalid("arbiter private-key provider is required")
	}
	unsigned, err := unsignedFromRaw(raw, proof)
	if err != nil {
		return nil, err
	}
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	key, err := adapter.ArbiterKey.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(adapter.Engine.arbiter) {
		return nil, invalid("arbiter private key does not match arbiter role")
	}
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	sig, err := mp.SignArbitratedPoolAsArbiter(state, unsigned.PoolOutputSatoshis, adapter.Engine.roles(), key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func unsignedFromRaw(raw []byte, proof *OpeningProof) (*UnsignedPayment, error) {
	if proof == nil || len(raw) == 0 {
		return nil, invalid("unsigned state transaction and opening proof are required")
	}
	state, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || len(state.Outputs) != 3 {
		return nil, invalid("pool state must have exactly three outputs")
	}
	setPoolSource(state, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, invalid("arbitration candidate must have an empty unlocking script")
	}
	return &UnsignedPayment{SpendTxID: hash32FromBytes(proof.SpendTxID), RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, PoolOutputSatoshis: proof.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), proof.PoolLockingScript...)}, nil
}
