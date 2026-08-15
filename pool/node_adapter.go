package pool

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

func fundingOutpointID(raw []byte) (Hash32, error) {
	value, err := parseCanonicalTransaction(raw)
	if err != nil {
		return Hash32{}, err
	}
	if len(value.Inputs) != 1 || value.Inputs[0] == nil || value.Inputs[0].SourceTXID == nil {
		return Hash32{}, fmt.Errorf("%w: funding outpoint is missing", ErrInvalidEvidence)
	}
	return hash32FromBytes(value.Inputs[0].SourceTXID.CloneBytes()), nil
}

// NonFinalPoolBackend is the narrow boundary for a concrete BSV node/RPC
// client. SubmitUpdate must return only after the node has accepted rawTx as
// the current non-final spend; SubmitFinal must return only after final
// acceptance. A JSON-RPC, gRPC or vendor SDK client can implement this port
// without being coupled to seller or buyer workflow code.
type NonFinalPoolBackend interface {
	SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
	SubmitFinal(context.Context, []byte) (Hash32, error)
}

// FundingBackend broadcasts a complete funding transaction. Funding has no
// pool-spend anchor yet, so it is intentionally separate from final submit.
type FundingBackend interface {
	// SubmitTransaction must broadcast by canonical transaction ID: if the
	// exact same raw transaction was already accepted, it returns the same
	// Hash32 and nil error instead of treating already-known as a failure.
	SubmitTransaction(context.Context, []byte) (Hash32, error)
}

// PoolBackend is the seller-side backend boundary: it supports funding,
// cumulative updates, and final settlement. Buyer workflows need only the
// narrower NonFinalPoolBackend.
type PoolBackend interface {
	NonFinalPoolBackend
	FundingBackend
}

type heightBackend interface {
	BlockHeight(context.Context) (uint32, error)
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
	openings OpeningByFundingStore
	backend  NonFinalPoolBackend
}

func (node *VerifiedNonFinalPoolNode) engineForExpiry(ctx context.Context, proof *OpeningProof) (*MultisigPoolEngine, error) {
	if node == nil || proof == nil {
		return nil, fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	config := MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey}
	needsHeight, err := RefundUsesBlockHeight(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	if needsHeight {
		height, err := node.BlockHeight(ctx)
		if err != nil {
			return nil, err
		}
		config.BlockHeight = func() uint32 { return height }
	}
	return NewMultisigPoolEngine(config)
}

// NewVerifiedNonFinalPoolNode requires a funding-indexed opening store and
// backend. It resolves the concrete MultisigPool engine from each proof,
// validates bytes and backend responses, and exposes only node acceptance to
// a workflow.
func NewVerifiedNonFinalPoolNode(openings OpeningByFundingStore, backend NonFinalPoolBackend) (*VerifiedNonFinalPoolNode, error) {
	if openings == nil || backend == nil {
		return nil, fmt.Errorf("%w: node adapter requires opening store and backend", ErrInvalidEvidence)
	}
	return &VerifiedNonFinalPoolNode{openings: openings, backend: backend}, nil
}

// SubmitUpdate validates a non-final state, submits it to the backend, and
// requires the returned transaction ID, spend anchor, and sequence to match.
func (node *VerifiedNonFinalPoolNode) SubmitUpdate(ctx context.Context, rawTx []byte) (*UpdateAcceptance, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: node adapter is required", ErrInvalidEvidence)
	}
	raw := append([]byte(nil), rawTx...)
	fundingTxID, err := fundingOutpointID(raw)
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
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify opening proof: %w", err)
	}
	state, err := engine.ParseNonFinalPaymentState(ctx, raw, proof)
	if err != nil {
		return nil, fmt.Errorf("parse non-final payment: %w", err)
	}
	if err := engine.VerifyAcceptedPayment(state, proof); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(state, proof); arbitrationErr != nil {
			return nil, fmt.Errorf("verify non-final payment: %w", err)
		}
	}
	// Resolve height immediately before the external call. A height fetched
	// before parsing/verification could be stale by the time the node accepts
	// the transaction.
	engine, err = node.engineForExpiry(ctx, proof)
	if err != nil {
		return nil, fmt.Errorf("build expiry engine for update: %w", err)
	}
	if err := engine.VerifyRefundNotExpired(proof, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("verify payment expiry: %w", err)
	}
	accepted, err := node.backend.SubmitUpdate(ctx, raw)
	if err != nil {
		return nil, err
	}
	txID, err := engine.TransactionID(raw)
	if err != nil {
		return nil, fmt.Errorf("calculate accepted transaction ID: %w", err)
	}
	if accepted == nil || accepted.TxID != txID || accepted.SpendTxID != state.SpendTxID || accepted.PaymentSequence != state.PaymentSequence {
		return nil, fmt.Errorf("%w: backend returned inconsistent non-final acceptance", ErrInvalidEvidence)
	}
	return &UpdateAcceptance{TxID: accepted.TxID, SpendTxID: accepted.SpendTxID, PaymentSequence: accepted.PaymentSequence}, nil
}

// SubmitFinal validates a final close or expired refund, submits it to the
// backend, and requires the returned transaction ID to match the raw bytes.
func (node *VerifiedNonFinalPoolNode) SubmitFinal(ctx context.Context, rawTx []byte) (Hash32, error) {
	if node == nil {
		return Hash32{}, fmt.Errorf("%w: node adapter is required", ErrInvalidEvidence)
	}
	raw := append([]byte(nil), rawTx...)
	fundingTxID, err := fundingOutpointID(raw)
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
	engineConfig := MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey}
	engine, err := NewMultisigPoolEngine(engineConfig)
	if err != nil {
		return Hash32{}, err
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return Hash32{}, fmt.Errorf("verify opening proof: %w", err)
	}

	// A final submission can be either an immediate two-signature close or the
	// fully signed presigned refund after expiry. Refund bytes are rebuilt from
	// the stored proof and compared byte-for-byte so an arbitrary transaction
	// cannot be reclassified as a refund merely because it spends the same
	// funding output.
	now := time.Now().UTC()
	expectedRefund, refundErr := engine.BuildRefundSubmission(proof)
	if refundErr == nil && bytes.Equal(expectedRefund, raw) {
		refund, parseErr := parseCanonicalTransaction(proof.RefundTx)
		if parseErr != nil {
			return Hash32{}, fmt.Errorf("parse final refund: %w", parseErr)
		}
		if refund.LockTime < lockTimeTimestampThreshold {
			height, heightErr := node.BlockHeight(ctx)
			if heightErr != nil {
				return Hash32{}, fmt.Errorf("load block height for refund: %w", heightErr)
			}
			engineConfig.BlockHeight = func() uint32 { return height }
			engine, err = NewMultisigPoolEngine(engineConfig)
			if err != nil {
				return Hash32{}, err
			}
		}
		if err := engine.VerifyRefundExpired(proof, now); err != nil {
			return Hash32{}, fmt.Errorf("verify final refund expiry: %w", err)
		}
	} else {
		state, err := engine.ParseFinalPaymentState(ctx, raw, proof)
		if err != nil {
			return Hash32{}, fmt.Errorf("parse final payment: %w", err)
		}
		if state == nil {
			return Hash32{}, fmt.Errorf("%w: final payment parser returned no state", ErrInvalidEvidence)
		}
		payment := &SignedPayment{State: *state, RawTx: append([]byte(nil), raw...)}
		if err := engine.VerifyCompletedFinalPayment(payment, proof); err != nil {
			return Hash32{}, fmt.Errorf("verify completed final payment: %w", err)
		}
		engine, err = node.engineForExpiry(ctx, proof)
		if err != nil {
			return Hash32{}, fmt.Errorf("build expiry engine for final payment: %w", err)
		}
		if err := engine.VerifyRefundNotExpired(proof, now); err != nil {
			return Hash32{}, fmt.Errorf("verify final payment expiry: %w", err)
		}
	}

	accepted, err := node.backend.SubmitFinal(ctx, raw)
	if err != nil {
		return Hash32{}, err
	}
	txID, err := engine.TransactionID(raw)
	if err != nil {
		return Hash32{}, fmt.Errorf("calculate final transaction ID: %w", err)
	}
	if accepted != txID {
		return Hash32{}, fmt.Errorf("%w: backend returned inconsistent final transaction ID", ErrInvalidEvidence)
	}
	return accepted, nil
}

// SubmitFunding validates and submits a funding transaction using the
// ordinary-broadcast backend semantics. Funding is intentionally not routed
// through SubmitFinal, which requires a pool spend anchor.
func (node *VerifiedNonFinalPoolNode) SubmitFunding(ctx context.Context, rawTx []byte) (Hash32, error) {
	if node == nil {
		return Hash32{}, fmt.Errorf("%w: node adapter is required", ErrInvalidEvidence)
	}
	if backend, ok := node.backend.(FundingBackend); ok {
		id, err := fixedTransactionID(rawTx)
		if err != nil {
			return Hash32{}, err
		}
		proof, err := node.openings.LoadOpeningProofByFundingTxID(ctx, id)
		if err != nil {
			return Hash32{}, err
		}
		if proof == nil {
			return Hash32{}, fmt.Errorf("%w: opening proof is missing", ErrInvalidEvidence)
		}
		proof = CloneOpeningProof(proof)
		engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
		if err != nil {
			return Hash32{}, err
		}
		if err := engine.VerifyOpening(proof); err != nil {
			return Hash32{}, fmt.Errorf("verify opening proof: %w", err)
		}
		if err := engine.VerifyFundingTx(ctx, rawTx, proof); err != nil {
			return Hash32{}, err
		}
		accepted, err := backend.SubmitTransaction(ctx, append([]byte(nil), rawTx...))
		if err != nil {
			return Hash32{}, err
		}
		if accepted != id {
			return Hash32{}, fmt.Errorf("%w: funding backend returned inconsistent transaction ID", ErrInvalidEvidence)
		}
		return id, nil
	}
	return Hash32{}, fmt.Errorf("%w: funding submission backend is unavailable", ErrInvalidEvidence)
}

func (node *VerifiedNonFinalPoolNode) BlockHeight(ctx context.Context) (uint32, error) {
	if node == nil {
		return 0, fmt.Errorf("%w: node adapter is required", ErrInvalidEvidence)
	}
	if backend, ok := node.backend.(heightBackend); ok {
		return backend.BlockHeight(ctx)
	}
	return 0, fmt.Errorf("%w: chain height source is unavailable", ErrInvalidEvidence)
}
