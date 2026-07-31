package pool

// The pool package is the sole transaction-library boundary. Workflow
// packages pass validated role material here and never construct scripts or
// calculate signatures themselves.
import (
	"bytes"
	"context"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/pkg"
	"github.com/bsv8/go-bitfs/bitfs"
)

type PoolRoles struct{ Server, A, B *ec.PublicKey }

type PrivateKeyProvider interface {
	PrivateKey(context.Context) (*ec.PrivateKey, error)
}

type MultisigPoolAdapter struct {
	Roles PoolRoles
	BKey  PrivateKeyProvider
}

func BuildPoolLock(roles PoolRoles) ([]byte, error) {
	if roles.Server == nil || roles.A == nil || roles.B == nil {
		return nil, fmt.Errorf("server, A and B public keys are required")
	}
	lock, err := mp.BuildTriplePoolLock(roles.Server, roles.A, roles.B)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), lock.Bytes()...), nil
}

func MergePoolServerA(rawTx string, serverSig, aSig *[]byte) ([]byte, error) {
	if serverSig == nil || aSig == nil || len(*serverSig) == 0 || len(*aSig) == 0 {
		return nil, fmt.Errorf("server and A signatures are required")
	}
	tx, err := mp.MergeTriplePoolServerA(rawTx, serverSig, aSig)
	if err != nil {
		return nil, err
	}
	return tx.Bytes(), nil
}

func MergePoolServerB(rawTx string, serverSig, bSig *[]byte) ([]byte, error) {
	if serverSig == nil || bSig == nil || len(*serverSig) == 0 || len(*bSig) == 0 {
		return nil, fmt.Errorf("server and B signatures are required")
	}
	tx, err := mp.MergeTriplePoolServerB(rawTx, serverSig, bSig)
	if err != nil {
		return nil, err
	}
	return tx.Bytes(), nil
}

func (adapter *MultisigPoolAdapter) VerifyOpening(proof *OpeningProof) error {
	if adapter == nil || proof == nil {
		return fmt.Errorf("multisig pool adapter and opening proof are required")
	}
	lock, err := BuildPoolLock(adapter.Roles)
	if err != nil {
		return err
	}
	if len(proof.PoolLockingScript) == 0 || !bytes.Equal(lock, proof.PoolLockingScript) {
		return fmt.Errorf("opening proof pool roles do not match adapter")
	}
	if err := ValidateOpeningProof(proof); err != nil { return err }
	if len(proof.FundingTx) == 0 { return fmt.Errorf("complete funding transaction is required") }
	funding, err := tx.NewTransactionFromBytes(proof.FundingTx)
	if err != nil { return err }
	if !bytes.Equal(funding.TxID().CloneBytes(), proof.FundingTxID) || int(proof.PoolOutputIndex) >= len(funding.Outputs) || funding.Outputs[proof.PoolOutputIndex] == nil { return fmt.Errorf("funding transaction does not match opening proof") }
	output := funding.Outputs[proof.PoolOutputIndex]
	if output.Satoshis != proof.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), proof.PoolLockingScript) { return fmt.Errorf("funding pool output does not match opening proof") }
	refund, err := tx.NewTransactionFromBytes(proof.RefundTx)
	if err != nil { return err }
	if refund.Inputs[0].SourceTxOutput() == nil { refund.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: proof.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), proof.PoolLockingScript...))}) }
	if err := mp.VerifyTriplePoolState(refund, adapter.Roles.Server, adapter.Roles.A, adapter.Roles.B, proof.PoolOutputSatoshis, 0); err != nil { return err }
	if ok, err := mp.VerifyTriplePoolASignature(refund, adapter.Roles.A, adapter.Roles.Server, adapter.Roles.B, &proof.BuyerRefundSignature); err != nil || !ok { if err != nil { return err }; return fmt.Errorf("A refund signature is invalid") }
	if ok, err := mp.VerifyTriplePoolServerSignature(refund, adapter.Roles.Server, adapter.Roles.A, adapter.Roles.B, &proof.SellerRefundSignature); err != nil || !ok { if err != nil { return err }; return fmt.Errorf("server refund signature is invalid") }
	return nil
}

func (adapter *MultisigPoolAdapter) VerifyArbitrationCandidate(_ context.Context, raw []byte, proof *OpeningProof, terms *bitfs.ContentRequestTerms, sellerSig []byte) (*PaymentState, error) {
	if err := adapter.VerifyOpening(proof); err != nil {
		return nil, err
	}
	if terms == nil || len(raw) == 0 || len(sellerSig) == 0 {
		return nil, fmt.Errorf("arbitration candidate inputs are incomplete")
	}
	if terms.PaymentSequenceAfter == 0 || terms.PaymentSequenceAfter > uint64(^uint32(0)) {
		return nil, fmt.Errorf("invalid target payment sequence")
	}
	candidate, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("decode arbitration candidate: %w", err)
	}
	if len(candidate.Inputs) != 1 || candidate.Inputs[0] == nil || len(candidate.Outputs) != 2 { return nil, fmt.Errorf("arbitration candidate shape is invalid") }
	if candidate.Inputs[0].SourceTxOutput() == nil {
		candidate.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: proof.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), proof.PoolLockingScript...))})
	}
	if candidate.Inputs[0].SequenceNumber != uint32(terms.PaymentSequenceAfter) || candidate.Outputs[0].Satoshis != terms.SellerAmountAfterSat {
		return nil, fmt.Errorf("arbitration candidate does not match authorization")
	}
	if err := mp.VerifyTriplePoolState(candidate, adapter.Roles.Server, adapter.Roles.A, adapter.Roles.B, proof.PoolOutputSatoshis, terms.SellerAmountAfterSat); err != nil { return nil, err }
	valid, err := mp.VerifyTriplePoolServerSignature(candidate, adapter.Roles.Server, adapter.Roles.A, adapter.Roles.B, &sellerSig)
	if err != nil { return nil, fmt.Errorf("seller signature: %w", err) }
	if !valid { return nil, fmt.Errorf("seller signature is invalid") }
	return &PaymentState{SpendTxID: hash32FromBytes(proof.SpendTxID), RawTx: append([]byte(nil), raw...), PaymentSequence: uint32(terms.PaymentSequenceAfter), SellerAmountSat: terms.SellerAmountAfterSat, ClientAmountSat: candidate.Outputs[1].Satoshis, PoolOutputSatoshis: proof.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), proof.PoolLockingScript...)}, nil
}

func (adapter *MultisigPoolAdapter) SignArbitrationCandidate(ctx context.Context, raw []byte, proof *OpeningProof, _ Signer) ([]byte, error) {
	if adapter == nil || adapter.BKey == nil {
		return nil, fmt.Errorf("B key provider is required")
	}
	b, err := adapter.BKey.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if b == nil || !b.PubKey().IsEqual(adapter.Roles.B) {
		return nil, fmt.Errorf("B private key does not match pool role")
	}
	candidate, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if candidate.Inputs[0].SourceTxOutput() == nil {
		candidate.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: proof.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), proof.PoolLockingScript...))})
	}
	sig, err := mp.SignTriplePoolAsB(candidate, b, adapter.Roles.Server, adapter.Roles.A)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), (*sig)...), nil
}
