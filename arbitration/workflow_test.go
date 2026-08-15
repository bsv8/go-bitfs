package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

func TestV3ArbitrationRequestRoundTrip(t *testing.T) {
	request := &ArbitrationRequest{
		Version:                    MajorVersion,
		PoolOpeningProofCBOR:       []byte{1, 2},
		PaymentAuthorizationCBOR:   []byte{3, 4},
		UnsignedStateTxRaw:         []byte{5, 6},
		SellerTransactionSignature: []byte{7, 8},
	}
	raw, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("8503420102420304420506420708")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("request CBOR changed: %x", raw)
	}
	decoded, err := UnmarshalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.PaymentAuthorizationCBOR, request.PaymentAuthorizationCBOR) || !bytes.Equal(decoded.UnsignedStateTxRaw, request.UnsignedStateTxRaw) {
		t.Fatalf("decoded request = %#v", decoded)
	}
	if _, err := UnmarshalRequest(append(raw, 0)); err == nil {
		t.Fatal("request decoder accepted trailing bytes")
	}
}

func TestV3ArbitrationResponseBindsTwoHashes(t *testing.T) {
	response := &ArbitrationResponse{Version: MajorVersion, PaymentAuthorizationHash: bytes.Repeat([]byte{1}, 32), UnsignedStateTxHash: bytes.Repeat([]byte{2}, 32), ArbiterTransactionSignature: []byte{3}}
	raw, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("840358200101010101010101010101010101010101010101010101010101010101010101582002020202020202020202020202020202020202020202020202020202020202024103")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("response CBOR changed: %x", raw)
	}
	decoded, err := UnmarshalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.UnsignedStateTxHash, response.UnsignedStateTxHash) {
		t.Fatal("response hash changed")
	}
}

func TestSignPaymentRejectsInvalidBuyerAuthorization(t *testing.T) {
	proofCBOR, authorization := testArbitrationEvidence(t)
	workflow, err := NewWorkflow(WorkflowConfig{
		Signer: testArbitrationSigner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = workflow.SignPayment(context.Background(), &ArbitrationRequest{
		Version: MajorVersion, PoolOpeningProofCBOR: proofCBOR,
		PaymentAuthorizationCBOR: authorization, UnsignedStateTxRaw: []byte{7}, SellerTransactionSignature: []byte{8},
	})
	if err == nil {
		t.Fatal("invalid buyer authorization was accepted")
	}
}

func TestSignPaymentRejectsCandidateValidationFailure(t *testing.T) {
	proofCBOR, authorization := testArbitrationEvidence(t)
	workflow, err := NewWorkflow(WorkflowConfig{
		Signer: testArbitrationSigner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = workflow.SignPayment(context.Background(), &ArbitrationRequest{
		Version: MajorVersion, PoolOpeningProofCBOR: proofCBOR,
		PaymentAuthorizationCBOR: authorization, UnsignedStateTxRaw: []byte{7}, SellerTransactionSignature: []byte{8},
	})
	if err == nil {
		t.Fatal("invalid candidate was accepted")
	}
}

type testArbitrationSigner struct{}

func (testArbitrationSigner) PublicKey(context.Context) ([]byte, error) {
	return arbitrationTestPubkey("3333333333333333333333333333333333333333333333333333333333333333"), nil
}
func (testArbitrationSigner) Sign(context.Context, []byte) ([]byte, error) { return []byte{9}, nil }

func testArbitrationEvidence(t *testing.T) ([]byte, []byte) {
	t.Helper()
	spend := bytes.Repeat([]byte{1}, sha256.Size)
	buyer := arbitrationTestPubkey("1111111111111111111111111111111111111111111111111111111111111111")
	seller := arbitrationTestPubkey("2222222222222222222222222222222222222222222222222222222222222222")
	arbiter := arbitrationTestPubkey("3333333333333333333333333333333333333333333333333333333333333333")
	proof, err := pool.EncodeOpeningProof(&pool.OpeningProof{
		Version: MajorVersion, MultisigProtocol: pool.MultisigProtocol, MultisigVersion: pool.MultisigVersion, RefundTx: []byte("refund"), SpendTxID: spend, FundingTxID: bytes.Repeat([]byte{2}, sha256.Size),
		PoolOutputSatoshis: 1000, PoolLockingScript: []byte("lock"), SellerPubKey: seller, BuyerPubKey: buyer, ArbiterPubKey: arbiter,
		MinerFeeRateSatPerKB: 1, BuyerRefundSignature: []byte("a"), SellerRefundSignature: []byte("server"), FundingTx: []byte("funding"),
	})
	if err != nil {
		t.Fatal(err)
	}
	terms, err := bitfs.EncodeContentRequestTerms(&bitfs.ContentRequestTerms{
		QuoteTermsHash: bytes.Repeat([]byte{3}, sha256.Size), SpendTxID: spend, BasePaymentSequence: 1, PaymentSequenceAfter: 2,
		SellerAmountAfterSat: 100, MinerFeeRateSatPerKB: 1, BuyerPubkey: buyer, SellerPubkey: seller, SelectedArbiterPubkey: arbiter,
		ContentType: bitfs.ContentSeed, ContentHash: bytes.Repeat([]byte{4}, sha256.Size), DeliveryDeadlineUnix: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := bitfs.EncodeSignedContentRequest(&bitfs.SignedContentRequest{TermsCBOR: terms, BuyerSignature: []byte("buyer-signature")})
	if err != nil {
		t.Fatal(err)
	}
	return proof, authorization
}

func arbitrationTestPubkey(hexKey string) []byte {
	key, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}
