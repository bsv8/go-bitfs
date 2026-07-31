package pool

// The exported clone helpers are for workflow/API boundaries. Pool stores and
// transaction engines must not retain caller-owned mutable byte slices.

func CloneOpeningProof(proof *OpeningProof) *OpeningProof {
	return cloneOpeningProof(proof)
}

func CloneRefundPresignRequest(request *RefundPresignRequest) *RefundPresignRequest {
	return cloneRefundPresignRequest(request)
}

func CloneRefundPresignResponse(response *RefundPresignResponse) *RefundPresignResponse {
	return cloneRefundPresignResponse(response)
}

func CloneFundingTxDelivery(delivery *FundingTxDelivery) *FundingTxDelivery {
	return cloneFundingTxDelivery(delivery)
}

func ClonePaymentUpdate(update *PaymentUpdate) *PaymentUpdate {
	return clonePaymentUpdate(update)
}

func ClonePaymentState(state *PaymentState) *PaymentState {
	return clonePaymentState(state)
}

func CloneSignedPayment(payment *SignedPayment) *SignedPayment {
	if payment == nil {
		return nil
	}
	return &SignedPayment{State: *clonePaymentState(&payment.State), RawTx: append([]byte(nil), payment.RawTx...)}
}

func CloneOpeningInput(input OpeningInput) OpeningInput {
	input.FundingTx = append([]byte(nil), input.FundingTx...)
	input.SellerPubKey = append([]byte(nil), input.SellerPubKey...)
	input.ArbiterPubKey = append([]byte(nil), input.ArbiterPubKey...)
	return input
}

func ClonePaymentUpdateInput(input PaymentUpdateInput) PaymentUpdateInput {
	input.Opening = cloneOpeningProof(input.Opening)
	input.Previous = clonePaymentState(input.Previous)
	return input
}

func CloneCloseInput(input CloseInput) CloseInput {
	input.Opening = cloneOpeningProof(input.Opening)
	input.Latest = clonePaymentState(input.Latest)
	return input
}
