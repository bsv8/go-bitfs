package pool

import (
	"context"
	"fmt"
)

// BuyerOpeningPort composes the small external capabilities needed by the
// buyer-side 002 workflow without forcing applications to create boilerplate
// forwarding types.
type BuyerOpeningPort struct {
	Store      OpeningProofStore
	Verifier   RefundTxSignatureVerifier
	Calculator TransactionIDCalculator
}

func (port BuyerOpeningPort) SaveOpeningProof(ctx context.Context, proof *OpeningProof) error {
	if port.Store == nil {
		return fmt.Errorf("%w: buyer opening store is required", ErrInvalidEvidence)
	}
	return port.Store.SaveOpeningProof(ctx, proof)
}

func (port BuyerOpeningPort) LoadOpeningProof(ctx context.Context, spendTxID Hash32) (*OpeningProof, error) {
	if port.Store == nil {
		return nil, fmt.Errorf("%w: buyer opening store is required", ErrInvalidEvidence)
	}
	return port.Store.LoadOpeningProof(ctx, spendTxID)
}

func (port BuyerOpeningPort) VerifySellerRefundSignature(ctx context.Context, request *RefundPresignRequest, signature []byte) error {
	if port.Verifier == nil {
		return fmt.Errorf("%w: seller refund verifier is required", ErrInvalidEvidence)
	}
	return port.Verifier.VerifySellerRefundSignature(ctx, request, signature)
}

func (port BuyerOpeningPort) TransactionID(ctx context.Context, rawTx []byte) (Hash32, error) {
	if port.Calculator == nil {
		return Hash32{}, fmt.Errorf("%w: transaction ID calculator is required", ErrInvalidEvidence)
	}
	return port.Calculator.TransactionID(ctx, rawTx)
}

// SellerOpeningPort composes the external capabilities required by the
// seller-side 002 workflow. The submitter is deliberately separate from the
// non-final payment node: funding submission and payment-pool replacement are
// different state transitions.
type SellerOpeningPort struct {
	Store            PendingOpeningProofStore
	RefundSigner     RefundTxSigner
	Calculator       TransactionIDCalculator
	FundingVerifier  FundingTxVerifier
	FundingSubmitter TransactionSubmitter
}

func (port SellerOpeningPort) SaveOpeningProof(ctx context.Context, proof *OpeningProof) error {
	if port.Store == nil {
		return fmt.Errorf("%w: seller opening store is required", ErrInvalidEvidence)
	}
	return port.Store.SaveOpeningProof(ctx, proof)
}

func (port SellerOpeningPort) LoadOpeningProofByFundingTxID(ctx context.Context, fundingTxID Hash32) (*OpeningProof, error) {
	if port.Store == nil {
		return nil, fmt.Errorf("%w: seller opening store is required", ErrInvalidEvidence)
	}
	return port.Store.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
}

func (port SellerOpeningPort) SignRefundTx(ctx context.Context, request *RefundPresignRequest) ([]byte, error) {
	if port.RefundSigner == nil {
		return nil, fmt.Errorf("%w: seller refund signer is required", ErrInvalidEvidence)
	}
	return port.RefundSigner.SignRefundTx(ctx, request)
}

func (port SellerOpeningPort) TransactionID(ctx context.Context, rawTx []byte) (Hash32, error) {
	if port.Calculator == nil {
		return Hash32{}, fmt.Errorf("%w: transaction ID calculator is required", ErrInvalidEvidence)
	}
	return port.Calculator.TransactionID(ctx, rawTx)
}

func (port SellerOpeningPort) VerifyFundingTx(ctx context.Context, fundingTx []byte, proof *OpeningProof) error {
	if port.FundingVerifier == nil {
		return fmt.Errorf("%w: funding transaction verifier is required", ErrInvalidEvidence)
	}
	return port.FundingVerifier.VerifyFundingTx(ctx, fundingTx, proof)
}

func (port SellerOpeningPort) SubmitTransaction(ctx context.Context, rawTx []byte) (Hash32, error) {
	if port.FundingSubmitter == nil {
		return Hash32{}, fmt.Errorf("%w: funding transaction submitter is required", ErrInvalidEvidence)
	}
	return port.FundingSubmitter.SubmitTransaction(ctx, rawTx)
}
