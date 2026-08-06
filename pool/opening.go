package pool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
)

// SellerPresignRefund signs and durably records the refund evidence before
// returning. FundingTx is intentionally not required at this stage.
func SellerPresignRefund(ctx context.Context, request *RefundPresignRequest, hooks SellerPoolOpeningHooks) (*RefundPresignResponse, error) {
	if hooks == nil {
		return nil, fmt.Errorf("%w: seller pool opening hooks are required", ErrInvalidEvidence)
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	signature, err := hooks.SignRefundTx(ctx, cloneRefundPresignRequest(request))
	if err != nil {
		return nil, fmt.Errorf("sign refund transaction: %w", err)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("%w: seller refund signature is empty", ErrInvalidEvidence)
	}
	proof := &OpeningProof{
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx: append([]byte(nil), request.RefundTx...), SpendTxID: nil, FundingTxID: append([]byte(nil), request.FundingTxID...),
		PoolOutputIndex: request.PoolOutputIndex, PoolOutputSatoshis: request.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), request.PoolLockingScript...),
		BuyerPubKey: append([]byte(nil), request.BuyerPubKey...), SellerPubKey: append([]byte(nil), request.SellerPubKey...), ArbiterPubKey: append([]byte(nil), request.ArbiterPubKey...),
		MinerFeeRateSatPerKB: request.MinerFeeRateSatPerKB, BuyerRefundSignature: append([]byte(nil), request.BuyerRefundSignature...), SellerRefundSignature: append([]byte(nil), signature...),
	}
	if err := hooks.SaveOpeningProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("save pending opening proof: %w", err)
	}
	return &RefundPresignResponse{Version: MajorVersion, SellerRefundSignature: append([]byte(nil), signature...)}, nil
}

// BuyerAcceptRefundPresign verifies and persists the complete proof before the
// caller is allowed to reveal FundingTx to the seller.
func BuyerAcceptRefundPresign(ctx context.Context, request *RefundPresignRequest, response *RefundPresignResponse, fundingTx []byte, hooks BuyerPoolOpeningHooks) (*OpeningProof, error) {
	if hooks == nil {
		return nil, fmt.Errorf("%w: buyer pool opening hooks are required", ErrInvalidEvidence)
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	if len(fundingTx) == 0 {
		return nil, fmt.Errorf("%w: funding transaction is required", ErrInvalidEvidence)
	}
	if err := hooks.VerifySellerRefundSignature(ctx, cloneRefundPresignRequest(request), append([]byte(nil), response.SellerRefundSignature...)); err != nil {
		return nil, fmt.Errorf("verify seller refund signature: %w", err)
	}
	fundingTxID, err := hooks.TransactionID(ctx, append([]byte(nil), fundingTx...))
	if err != nil {
		return nil, fmt.Errorf("calculate funding transaction ID: %w", err)
	}
	if !bytes.Equal(fundingTxID[:], request.FundingTxID) {
		return nil, fmt.Errorf("%w: funding transaction ID does not match request", ErrInvalidEvidence)
	}
	spendTxID, err := hooks.TransactionID(ctx, append([]byte(nil), request.RefundTx...))
	if err != nil {
		return nil, fmt.Errorf("calculate spend transaction ID: %w", err)
	}
	proof := &OpeningProof{
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx: append([]byte(nil), request.RefundTx...), SpendTxID: spendTxID[:], FundingTxID: append([]byte(nil), request.FundingTxID...),
		PoolOutputIndex: request.PoolOutputIndex, PoolOutputSatoshis: request.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), request.PoolLockingScript...),
		BuyerPubKey: append([]byte(nil), request.BuyerPubKey...), SellerPubKey: append([]byte(nil), request.SellerPubKey...), ArbiterPubKey: append([]byte(nil), request.ArbiterPubKey...),
		MinerFeeRateSatPerKB: request.MinerFeeRateSatPerKB, BuyerRefundSignature: append([]byte(nil), request.BuyerRefundSignature...), SellerRefundSignature: append([]byte(nil), response.SellerRefundSignature...), FundingTx: append([]byte(nil), fundingTx...),
	}
	if err := hooks.SaveOpeningProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("save complete opening proof: %w", err)
	}
	return cloneOpeningProof(proof), nil
}

// SellerAcceptFundingTx verifies the funding transaction against the retained
// refund proof, persists it, then submits it. A submit retry is safe when the
// node treats transaction IDs idempotently.
func SellerAcceptFundingTx(ctx context.Context, delivery *FundingTxDelivery, hooks SellerPoolOpeningHooks) (*OpeningProof, error) {
	if hooks == nil {
		return nil, fmt.Errorf("%w: seller pool opening hooks are required", ErrInvalidEvidence)
	}
	if err := ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	fundingTx := append([]byte(nil), delivery.FundingTx...)
	fundingTxID, err := hooks.TransactionID(ctx, fundingTx)
	if err != nil {
		return nil, fmt.Errorf("calculate funding transaction ID: %w", err)
	}
	proof, err := hooks.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	if err != nil {
		return nil, fmt.Errorf("load pending opening proof: %w", err)
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	if !bytes.Equal(proof.FundingTxID, fundingTxID[:]) {
		return nil, fmt.Errorf("%w: opening proof funding transaction ID mismatch", ErrInvalidEvidence)
	}
	if err := hooks.VerifyFundingTx(ctx, fundingTx, cloneOpeningProof(proof)); err != nil {
		return nil, fmt.Errorf("verify funding transaction: %w", err)
	}
	complete := cloneOpeningProof(proof)
	complete.FundingTx = fundingTx
	if err := hooks.SaveOpeningProof(ctx, complete); err != nil {
		return nil, fmt.Errorf("save complete opening proof: %w", err)
	}
	submittedID, err := hooks.SubmitTransaction(ctx, append([]byte(nil), fundingTx...))
	if err != nil {
		return nil, fmt.Errorf("submit funding transaction: %w", err)
	}
	if submittedID != fundingTxID {
		return nil, fmt.Errorf("%w: submitted funding transaction ID mismatch", ErrInvalidEvidence)
	}
	return cloneOpeningProof(complete), nil
}

// SpendTxID is the stable transaction anchor defined by 002: the canonical ID
// of the presigned RefundTx evidence bytes. BuildRefundSubmission later adds
// the separate signatures for actual broadcast, which may produce another
// transaction ID because unlocking data is part of the txid.
func SpendTxID(ctx context.Context, proof *OpeningProof, calculator TransactionIDCalculator) (Hash32, error) {
	if proof == nil {
		return Hash32{}, fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	if len(proof.SpendTxID) == sha256.Size {
		var result Hash32
		copy(result[:], proof.SpendTxID)
		if err := ValidateOpeningProof(proof); err != nil {
			return Hash32{}, err
		}
		return result, nil
	}
	if calculator == nil {
		return Hash32{}, fmt.Errorf("%w: transaction ID calculator is required", ErrInvalidEvidence)
	}
	result, err := calculator.TransactionID(ctx, append([]byte(nil), proof.RefundTx...))
	if err != nil {
		return Hash32{}, err
	}
	copyProof := cloneOpeningProof(proof)
	copyProof.SpendTxID = append([]byte(nil), result[:]...)
	if err := ValidateOpeningProof(copyProof); err != nil {
		return Hash32{}, err
	}
	return result, nil
}
