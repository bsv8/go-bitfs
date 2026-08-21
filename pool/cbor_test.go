package pool

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestPaymentUpdateRoundTripAndIsolation(t *testing.T) {
	update := &PaymentUpdate{
		Version:                   MajorVersion,
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, sha256.Size),
		UnsignedStateTxRaw:        []byte{2, 3, 4},
		BuyerTransactionSignature: []byte{5, 6},
	}
	raw, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x84 {
		t.Fatalf("005 payment update must be a four-element array: %x", raw)
	}
	decoded, err := DecodePaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.UnsignedStateTxRaw[0] = 9
	if update.UnsignedStateTxRaw[0] != 2 {
		t.Fatal("decoded payment update aliases input data")
	}
	if _, err := DecodePaymentUpdate(append(raw, 0)); err == nil {
		t.Fatal("payment decoder accepted trailing bytes")
	}
}

func TestOpeningProofRoundTrip(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 500000100, nil)
	raw, err := EncodeOpeningProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOpeningProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x89 {
		t.Fatalf("opening proof must be a nine-element array: %x", raw)
	}
	if !bytes.Equal(decoded.FundingTx, proof.FundingTx) || !bytes.Equal(decoded.RefundTx, proof.RefundTx) {
		t.Fatalf("decoded proof = %#v", decoded)
	}
	details, err := DeriveOpeningDetails(decoded)
	if err != nil || details.PoolOutputSatoshis == 0 || details.FundingTxID == (Hash32{}) {
		t.Fatalf("derived opening details = %#v, err = %v", details, err)
	}
}

func TestPaymentUpdateRejectsInvalidReference(t *testing.T) {
	_, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: []byte{1}, UnsignedStateTxRaw: []byte{2}, BuyerTransactionSignature: []byte{3}})
	if err == nil {
		t.Fatal("payment update with short request hash was accepted")
	}
}

func TestRefundPresignRequestRoundTripUsesDerivedPoolTerms(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	request := &RefundPresignRequest{
		Version:  MajorVersion,
		RefundTx: []byte{1, 2, 3}, BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
		MinerFeeRateSatPerKB: 100, BuyerRefundSignature: []byte{4, 5, 6},
	}
	raw, err := EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x87 {
		t.Fatalf("refund presign request must be a seven-element array: %x", raw)
	}
	decoded, err := DecodeRefundPresignRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.RefundTx, request.RefundTx) || decoded.MinerFeeRateSatPerKB != request.MinerFeeRateSatPerKB {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestRoleKeyValidationHasStableBuyerPriority(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	request := &RefundPresignRequest{
		Version:  MajorVersion,
		RefundTx: []byte{1}, BuyerRefundSignature: []byte{4},
		BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
	}
	request.BuyerPubKey = []byte{1}
	request.SellerPubKey = []byte{2}
	request.ArbiterPubKey = []byte{3}
	for i := 0; i < 20; i++ {
		err := ValidateRefundPresignRequest(request)
		if err == nil || !strings.Contains(err.Error(), "buyer public key") {
			t.Fatalf("request validation error = %v, want stable buyer error", err)
		}
	}

	proof := &OpeningProof{
		Version: MajorVersion, RefundTx: []byte{1}, BuyerRefundSignature: []byte{7}, SellerRefundSignature: []byte{8},
		BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
	}
	proof.BuyerPubKey = []byte{1}
	proof.SellerPubKey = []byte{2}
	proof.ArbiterPubKey = []byte{3}
	for i := 0; i < 20; i++ {
		err := ValidateOpeningProof(proof)
		if err == nil || !strings.Contains(err.Error(), "buyer public key") {
			t.Fatalf("proof validation error = %v, want stable buyer error", err)
		}
	}
}
