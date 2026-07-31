package pool

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestPaymentUpdateRoundTripAndIsolation(t *testing.T) {
	update := &PaymentUpdate{
		Version:                 MajorVersion,
		ContentRequestTermsHash: bytes.Repeat([]byte{1}, sha256.Size),
		PartialSpendTx:          []byte{2, 3, 4},
	}
	raw, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x83 {
		t.Fatalf("005 payment update must be a three-element array: %x", raw)
	}
	decoded, err := DecodePaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.PartialSpendTx[0] = 9
	if update.PartialSpendTx[0] != 2 {
		t.Fatal("decoded payment update aliases input data")
	}
	if _, err := DecodePaymentUpdate(append(raw, 0)); err == nil {
		t.Fatal("payment decoder accepted trailing bytes")
	}
}

func TestOpeningProofRoundTrip(t *testing.T) {
	proof := &OpeningProof{
		Version:               MajorVersion,
		RefundTx:              []byte("refund"),
		SpendTxID:             bytes.Repeat([]byte{2}, sha256.Size),
		FundingTxID:           bytes.Repeat([]byte{1}, sha256.Size),
		PoolOutputIndex:       2,
		PoolOutputSatoshis:    1000,
		PoolLockingScript:     []byte("2of3"),
		ServerPubKey:          []byte("server"),
		BuyerPubKey:           []byte("buyer-key"),
		ArbiterPubKey:         []byte("arbiter"),
		BuyerRefundSignature:  []byte("buyer"),
		SellerRefundSignature: []byte("seller"),
		FundingTx:             []byte("funding"),
	}
	raw, err := EncodeOpeningProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOpeningProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.FundingTx, proof.FundingTx) || !bytes.Equal(decoded.FundingTxID, proof.FundingTxID) {
		t.Fatalf("decoded proof = %#v", decoded)
	}
}

func TestPaymentUpdateRejectsInvalidReference(t *testing.T) {
	_, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, ContentRequestTermsHash: []byte{1}, PartialSpendTx: []byte{2}})
	if err == nil {
		t.Fatal("payment update with short request hash was accepted")
	}
}
