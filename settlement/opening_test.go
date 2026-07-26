package settlement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestPoolOpeningMessagesCBORRoundTrip(t *testing.T) {
	fundingID := bytes.Repeat([]byte{0x11}, sha256.Size)
	request := NewPoolRefundPresignRequest(
		[]byte("refund-tx"), fundingID, 7, 1000, []byte("2of3-script"), []byte("buyer-refund-signature"),
	)
	for _, message := range []any{
		request,
		NewPoolRefundPresignResponse([]byte("seller-refund-signature")),
		NewPoolFundingTxDelivery([]byte("funding-tx")),
	} {
		encoded, err := EncodeMessage(message)
		if err != nil {
			t.Fatalf("EncodeMessage(%T) error = %v", message, err)
		}
		decoded, err := DecodeMessage(encoded)
		if err != nil {
			t.Fatalf("DecodeMessage(%T) error = %v", message, err)
		}
		switch got := decoded.(type) {
		case *PoolRefundPresignRequest:
			if got.PoolOutputIndex != 7 || !bytes.Equal(got.FundingTxID, fundingID) {
				t.Fatalf("decoded request = %#v", got)
			}
		case *PoolRefundPresignResponse:
			if !bytes.Equal(got.SellerRefundSignature, []byte("seller-refund-signature")) {
				t.Fatalf("decoded response = %#v", got)
			}
		case *PoolFundingTxDelivery:
			if !bytes.Equal(got.FundingTx, []byte("funding-tx")) {
				t.Fatalf("decoded delivery = %#v", got)
			}
		default:
			t.Fatalf("unexpected decoded type %T", decoded)
		}
	}
}

func TestPoolOpeningEndToEndHooks(t *testing.T) {
	ctx := context.Background()
	fundingTx := []byte("buyer-signed-funding-tx")
	fundingID := testTransactionID(fundingTx)
	request := NewPoolRefundPresignRequest(
		[]byte("timelocked-refund-tx"), fundingID, 4, 1_000, []byte("buyer-seller-arbiter-2of3"), []byte("buyer-refund-signature"),
	)
	sellerHooks := &testOpeningHooks{expectedFundingTx: fundingTx}
	buyerHooks := &testOpeningHooks{expectedFundingTx: fundingTx}

	response, err := SellerPresignRefund(ctx, request, sellerHooks)
	if err != nil {
		t.Fatalf("SellerPresignRefund() error = %v", err)
	}
	if sellerHooks.signCalls != 1 || sellerHooks.fundingVerifyCalls != 0 || sellerHooks.submitCalls != 0 {
		t.Fatalf("seller presign hooks = sign:%d verify:%d submit:%d", sellerHooks.signCalls, sellerHooks.fundingVerifyCalls, sellerHooks.submitCalls)
	}
	if !bytes.Equal(response.SellerRefundSignature, []byte("seller-refund-signature")) {
		t.Fatalf("response signature = %q", response.SellerRefundSignature)
	}

	buyerProof, err := BuyerAcceptRefundPresign(ctx, request, response, fundingTx, buyerHooks)
	if err != nil {
		t.Fatalf("BuyerAcceptRefundPresign() error = %v", err)
	}
	if !bytes.Equal(buyerProof.FundingTx, fundingTx) || buyerHooks.sellerVerifyCalls != 1 {
		t.Fatalf("buyer proof / verification = %#v / %d", buyerProof, buyerHooks.sellerVerifyCalls)
	}

	sellerProof, err := SellerAcceptFundingTx(ctx, NewPoolFundingTxDelivery(fundingTx), sellerHooks)
	if err != nil {
		t.Fatalf("SellerAcceptFundingTx() error = %v", err)
	}
	if sellerHooks.fundingVerifyCalls != 1 || sellerHooks.submitCalls != 1 {
		t.Fatalf("seller submit hooks = verify:%d submit:%d", sellerHooks.fundingVerifyCalls, sellerHooks.submitCalls)
	}
	if !bytes.Equal(sellerProof.FundingTxID, fundingID) {
		t.Fatalf("funding txid = %x, want %x", sellerProof.FundingTxID, fundingID)
	}
	if sellerHooks.saveCalls != 2 { // seller pending, seller complete
		t.Fatalf("seller SavePoolOpeningProof calls = %d, want 2", sellerHooks.saveCalls)
	}
	if buyerHooks.saveCalls != 1 { // buyer proof before PoolFundingTxDelivery
		t.Fatalf("buyer SavePoolOpeningProof calls = %d, want 1", buyerHooks.saveCalls)
	}

	encoded, err := EncodePoolOpeningProof(sellerProof)
	if err != nil {
		t.Fatalf("EncodePoolOpeningProof() error = %v", err)
	}
	decoded, err := DecodePoolOpeningProof(encoded)
	if err != nil {
		t.Fatalf("DecodePoolOpeningProof() error = %v", err)
	}
	if !bytes.Equal(decoded.FundingTx, fundingTx) || !bytes.Equal(decoded.FundingTxID, fundingID) {
		t.Fatalf("decoded proof = %#v", decoded)
	}
	hash, err := PoolOpeningProofHash(decoded)
	if err != nil {
		t.Fatalf("PoolOpeningProofHash() error = %v", err)
	}
	if hash != sha256.Sum256(encoded) {
		t.Fatal("opening proof hash is not canonical CBOR hash")
	}
}

func TestSellerAcceptFundingTxRejectsMismatchedSubmitterTransactionID(t *testing.T) {
	ctx := context.Background()
	fundingTx := []byte("funding-tx")
	fundingID := testTransactionID(fundingTx)
	request := NewPoolRefundPresignRequest([]byte("refund"), fundingID, 0, 100, []byte("script"), []byte("buyer-refund-sig"))
	hooks := &testOpeningHooks{expectedFundingTx: fundingTx, submittedID: bytes.Repeat([]byte{0xff}, sha256.Size)}
	if _, err := SellerPresignRefund(ctx, request, hooks); err != nil {
		t.Fatalf("SellerPresignRefund() error = %v", err)
	}
	if _, err := SellerAcceptFundingTx(ctx, NewPoolFundingTxDelivery(fundingTx), hooks); err == nil {
		t.Fatal("SellerAcceptFundingTx() accepted a mismatched submitted transaction ID")
	}
	if hooks.saveCalls != 2 { // pending + complete; txid is already FundingTxID
		t.Fatalf("SavePoolOpeningProof calls = %d, want 2", hooks.saveCalls)
	}
}

func TestSellerPresignDoesNotReturnBeforeProofSaved(t *testing.T) {
	fundingTx := []byte("funding-tx")
	request := NewPoolRefundPresignRequest([]byte("refund"), testTransactionID(fundingTx), 0, 100, []byte("script"), []byte("buyer-refund-sig"))
	hooks := &testOpeningHooks{saveErr: errors.New("storage unavailable")}
	if _, err := SellerPresignRefund(context.Background(), request, hooks); err == nil {
		t.Fatal("SellerPresignRefund() succeeded without saving proof")
	}
}

type testOpeningHooks struct {
	byFundingID        map[string]*PoolOpeningProof
	expectedFundingTx  []byte
	submittedID        []byte
	saveErr            error
	signCalls          int
	sellerVerifyCalls  int
	fundingVerifyCalls int
	submitCalls        int
	saveCalls          int
}

func (h *testOpeningHooks) SavePoolOpeningProof(_ context.Context, proof *PoolOpeningProof) error {
	h.saveCalls++
	if h.saveErr != nil {
		return h.saveErr
	}
	if h.byFundingID == nil {
		h.byFundingID = make(map[string]*PoolOpeningProof)
	}
	h.byFundingID[string(proof.FundingTxID)] = clonePoolOpeningProof(proof)
	return nil
}

func (h *testOpeningHooks) LoadPoolOpeningProofByFundingTxID(_ context.Context, fundingTxID []byte) (*PoolOpeningProof, error) {
	proof, ok := h.byFundingID[string(fundingTxID)]
	if !ok {
		return nil, fmt.Errorf("proof not found")
	}
	return clonePoolOpeningProof(proof), nil
}

func (h *testOpeningHooks) SignRefundTx(_ context.Context, _ *PoolRefundPresignRequest) ([]byte, error) {
	h.signCalls++
	return []byte("seller-refund-signature"), nil
}

func (h *testOpeningHooks) VerifySellerRefundSignature(_ context.Context, _ *PoolRefundPresignRequest, signature []byte) error {
	h.sellerVerifyCalls++
	if !bytes.Equal(signature, []byte("seller-refund-signature")) {
		return errors.New("unexpected seller refund signature")
	}
	return nil
}

func (h *testOpeningHooks) TransactionID(_ context.Context, rawTx []byte) ([]byte, error) {
	return testTransactionID(rawTx), nil
}

func (h *testOpeningHooks) VerifyFundingTx(_ context.Context, fundingTx []byte, proof *PoolOpeningProof) error {
	h.fundingVerifyCalls++
	if !bytes.Equal(fundingTx, h.expectedFundingTx) {
		return errors.New("unexpected funding transaction")
	}
	if !bytes.Equal(proof.FundingTxID, testTransactionID(fundingTx)) {
		return errors.New("funding transaction ID does not match proof")
	}
	if len(proof.FundingTx) != 0 {
		return errors.New("funding transaction must be saved only after verification")
	}
	return nil
}

func (h *testOpeningHooks) SubmitTransaction(_ context.Context, rawTx []byte) ([]byte, error) {
	h.submitCalls++
	if !bytes.Equal(rawTx, h.expectedFundingTx) {
		return nil, errors.New("unexpected submitted transaction")
	}
	if len(h.submittedID) != 0 {
		return append([]byte(nil), h.submittedID...), nil
	}
	return testTransactionID(rawTx), nil
}

func testTransactionID(rawTx []byte) []byte {
	digest := sha256.Sum256(rawTx)
	return append([]byte(nil), digest[:]...)
}
