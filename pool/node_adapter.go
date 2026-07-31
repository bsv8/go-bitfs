package pool

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// NonFinalPoolBackend is the narrow boundary for a concrete BSV node/RPC
// client. SubmitUpdate must return only after the node has accepted rawTx as
// the current non-final spend; SubmitFinal must return only after final
// acceptance. A JSON-RPC, gRPC or vendor SDK client can implement this port
// without being coupled to seller or buyer workflow code.
type NonFinalPoolBackend interface {
	SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
	SubmitFinal(context.Context, []byte) (Hash32, error)
}

// OpeningByFundingStore supplies the opening proof needed to verify a raw
// payment before it reaches a node adapter.
type OpeningByFundingStore interface {
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
}

// VerifiedNonFinalPoolNode is the production-side adapter between workflow
// code and a concrete node client. It verifies the exact input, outputs,
// buyer authorization and final signature set available in rawTx before
// forwarding it, then verifies that the backend response describes the same
// accepted transaction and sequence.
type VerifiedNonFinalPoolNode struct {
	engine   TransactionEngine
	openings OpeningByFundingStore
	backend  NonFinalPoolBackend
}

func NewVerifiedNonFinalPoolNode(engine TransactionEngine, openings OpeningByFundingStore, backend NonFinalPoolBackend) (*VerifiedNonFinalPoolNode, error) {
	if engine == nil || openings == nil || backend == nil {
		return nil, fmt.Errorf("%w: node adapter requires transaction engine, opening store and backend", ErrInvalidEvidence)
	}
	return &VerifiedNonFinalPoolNode{engine: engine, openings: openings, backend: backend}, nil
}

func (node *VerifiedNonFinalPoolNode) SubmitUpdate(ctx context.Context, rawTx []byte) (*UpdateAcceptance, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: node adapter is required", ErrInvalidEvidence)
	}
	raw := append([]byte(nil), rawTx...)
	fundingTxID, err := node.engine.FundingTxID(raw)
	if err != nil {
		return nil, fmt.Errorf("read payment funding outpoint: %w", err)
	}
	proof, err := node.openings.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	if err != nil {
		return nil, fmt.Errorf("load opening proof: %w", err)
	}
	if proof == nil {
		return nil, fmt.Errorf("%w: opening proof is missing", ErrInvalidEvidence)
	}
	proof = CloneOpeningProof(proof)
	state, err := node.engine.ParsePaymentState(ctx, raw, proof)
	if err != nil {
		return nil, fmt.Errorf("parse non-final payment: %w", err)
	}
	if err := node.engine.VerifyAcceptedPayment(state, proof); err != nil {
		return nil, fmt.Errorf("verify non-final payment: %w", err)
	}
	accepted, err := node.backend.SubmitUpdate(ctx, raw)
	if err != nil {
		return nil, err
	}
	txID, err := node.engine.TransactionID(raw)
	if err != nil {
		return nil, fmt.Errorf("calculate accepted transaction ID: %w", err)
	}
	if accepted == nil || accepted.TxID != txID || accepted.SpendTxID != state.SpendTxID || accepted.PaymentSequence != state.PaymentSequence {
		return nil, fmt.Errorf("%w: backend returned inconsistent non-final acceptance", ErrInvalidEvidence)
	}
	return &UpdateAcceptance{TxID: accepted.TxID, SpendTxID: accepted.SpendTxID, PaymentSequence: accepted.PaymentSequence}, nil
}

func (node *VerifiedNonFinalPoolNode) SubmitFinal(ctx context.Context, rawTx []byte) (Hash32, error) {
	if node == nil {
		return Hash32{}, fmt.Errorf("%w: node adapter is required", ErrInvalidEvidence)
	}
	raw := append([]byte(nil), rawTx...)
	fundingTxID, err := node.engine.FundingTxID(raw)
	if err != nil {
		return Hash32{}, fmt.Errorf("read final payment funding outpoint: %w", err)
	}
	proof, err := node.openings.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	if err != nil {
		return Hash32{}, fmt.Errorf("load opening proof for final payment: %w", err)
	}
	if proof == nil {
		return Hash32{}, fmt.Errorf("%w: opening proof is missing", ErrInvalidEvidence)
	}
	proof = CloneOpeningProof(proof)

	// A final submission can be either an immediate two-signature close or the
	// fully signed presigned refund after expiry. Refund bytes are rebuilt from
	// the stored proof and compared byte-for-byte so an arbitrary transaction
	// cannot be reclassified as a refund merely because it spends the same
	// funding output.
	expectedRefund, refundErr := node.engine.BuildRefundSubmission(proof)
	if refundErr == nil && bytes.Equal(expectedRefund, raw) {
		if err := node.engine.VerifyRefundExpired(proof, time.Now()); err != nil {
			return Hash32{}, fmt.Errorf("verify final refund expiry: %w", err)
		}
	} else {
		state, err := node.engine.ParseFinalPaymentState(ctx, raw, proof)
		if err != nil {
			return Hash32{}, fmt.Errorf("parse final payment: %w", err)
		}
		if state == nil {
			return Hash32{}, fmt.Errorf("%w: final payment parser returned no state", ErrInvalidEvidence)
		}
		payment := &SignedPayment{State: *state, RawTx: append([]byte(nil), raw...)}
		if err := node.engine.VerifyCompletedFinalPayment(payment, proof); err != nil {
			return Hash32{}, fmt.Errorf("verify completed final payment: %w", err)
		}
	}

	accepted, err := node.backend.SubmitFinal(ctx, raw)
	if err != nil {
		return Hash32{}, err
	}
	txID, err := node.engine.TransactionID(raw)
	if err != nil {
		return Hash32{}, fmt.Errorf("calculate final transaction ID: %w", err)
	}
	if accepted != txID {
		return Hash32{}, fmt.Errorf("%w: backend returned inconsistent final transaction ID", ErrInvalidEvidence)
	}
	return accepted, nil
}

var _ NonFinalPoolNode = (*VerifiedNonFinalPoolNode)(nil)
