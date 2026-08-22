package pool

// The exported clone helpers are for workflow/API boundaries. Pool stores and
// transaction engines must not retain caller-owned mutable byte slices.

// CloneOpeningProof returns an independent copy of OpeningProof, including copies of mutable byte slices.
func CloneOpeningProof(proof *OpeningProof) *OpeningProof {
	return cloneOpeningProof(proof)
}

// CloneRefundPresignRequest returns an independent copy of RefundPresignRequest, including copies of mutable byte slices.
func CloneRefundPresignRequest(request *RefundPresignRequest) *RefundPresignRequest {
	return cloneRefundPresignRequest(request)
}

// CloneRefundPresignResponse returns an independent copy of RefundPresignResponse, including copies of mutable byte slices.
func CloneRefundPresignResponse(response *RefundPresignResponse) *RefundPresignResponse {
	return cloneRefundPresignResponse(response)
}

// CloneFundingTxDelivery returns an independent copy of FundingTxDelivery, including copies of mutable byte slices.
func CloneFundingTxDelivery(delivery *FundingTxDelivery) *FundingTxDelivery {
	return cloneFundingTxDelivery(delivery)
}

// ClonePaymentUpdate returns an independent copy of PaymentUpdate, including copies of mutable byte slices.
func ClonePaymentUpdate(update *PaymentUpdate) *PaymentUpdate {
	return clonePaymentUpdate(update)
}

// ClonePaymentState returns an independent copy of PaymentState, including copies of mutable byte slices.
func ClonePaymentState(state *PaymentState) *PaymentState {
	return clonePaymentState(state)
}

// CloneSignedPayment returns an independent copy of SignedPayment, including copies of mutable byte slices.
func CloneSignedPayment(payment *SignedPayment) *SignedPayment {
	if payment == nil {
		return nil
	}
	return &SignedPayment{State: *clonePaymentState(&payment.State), RawTx: append([]byte(nil), payment.RawTx...)}
}

// CloneOpeningInput returns an independent copy of OpeningInput, including copies of mutable byte slices.
func CloneOpeningInput(input OpeningInput) OpeningInput {
	input.FundingTx = append([]byte(nil), input.FundingTx...)
	input.SellerPubKey = append([]byte(nil), input.SellerPubKey...)
	input.ArbiterPubKey = append([]byte(nil), input.ArbiterPubKey...)
	return input
}

// ClonePaymentUpdateInput returns an independent copy of PaymentUpdateInput, including copies of mutable byte slices.
func ClonePaymentUpdateInput(input PaymentUpdateInput) PaymentUpdateInput {
	input.Opening = cloneOpeningProof(input.Opening)
	input.Previous = clonePaymentState(input.Previous)
	return input
}

// CloneCloseInput returns an independent copy of CloseInput, including copies of mutable byte slices.
func CloneCloseInput(input CloseInput) CloseInput {
	input.Opening = cloneOpeningProof(input.Opening)
	input.Base = clonePaymentState(input.Base)
	return input
}
