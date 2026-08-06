package arbiter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

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
	decoded, err := UnmarshalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.UnsignedStateTxHash, response.UnsignedStateTxHash) {
		t.Fatal("response hash changed")
	}
}

type testArbitrationPool struct {
	candidateErr error
	signErr      error
}

func (p testArbitrationPool) VerifyOpening(*pool.OpeningProof) error { return nil }

func (p testArbitrationPool) VerifyArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, *bitfs.ContentRequestTerms, []byte) (*pool.UnsignedPayment, error) {
	if p.candidateErr != nil {
		return nil, p.candidateErr
	}
	return &pool.UnsignedPayment{}, nil
}

func (p testArbitrationPool) SignArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, pool.Signer) ([]byte, error) {
	if p.signErr != nil {
		return nil, p.signErr
	}
	return []byte{9}, nil
}

func TestSignPaymentRejectsInvalidBuyerAuthorization(t *testing.T) {
	proofCBOR, authorization := testArbitrationEvidence(t)
	service, err := NewService(ServiceConfig{
		Signer:                testArbitrationSigner{},
		Pool:                  testArbitrationPool{},
		AuthorizationVerifier: func(_, _, signature []byte) error { return errors.New("invalid buyer signature") },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SignPayment(context.Background(), &ArbitrationRequest{
		Version: MajorVersion, PoolOpeningProofCBOR: proofCBOR,
		PaymentAuthorizationCBOR: authorization, UnsignedStateTxRaw: []byte{7}, SellerTransactionSignature: []byte{8},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("buyer authorization signature invalid")) {
		t.Fatalf("invalid buyer authorization error = %v", err)
	}
}

func TestSignPaymentRejectsCandidateValidationFailure(t *testing.T) {
	proofCBOR, authorization := testArbitrationEvidence(t)
	service, err := NewService(ServiceConfig{
		Signer:                testArbitrationSigner{},
		Pool:                  testArbitrationPool{candidateErr: errors.New("third output")},
		AuthorizationVerifier: func(_, _, _ []byte) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SignPayment(context.Background(), &ArbitrationRequest{
		Version: MajorVersion, PoolOpeningProofCBOR: proofCBOR,
		PaymentAuthorizationCBOR: authorization, UnsignedStateTxRaw: []byte{7}, SellerTransactionSignature: []byte{8},
	})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("third output")) {
		t.Fatalf("candidate validation error = %v", err)
	}
}

type testArbitrationSigner struct{}

func (testArbitrationSigner) PublicKey(context.Context) ([]byte, error) {
	return []byte("arbiter"), nil
}
func (testArbitrationSigner) Sign(context.Context, []byte) ([]byte, error) { return []byte{9}, nil }

func testArbitrationEvidence(t *testing.T) ([]byte, []byte) {
	t.Helper()
	spend := bytes.Repeat([]byte{1}, sha256.Size)
	proof, err := pool.EncodeOpeningProof(&pool.OpeningProof{
		Version: MajorVersion, MultisigProtocol: pool.MultisigProtocol, MultisigVersion: pool.MultisigVersion, RefundTx: []byte("refund"), SpendTxID: spend, FundingTxID: bytes.Repeat([]byte{2}, sha256.Size),
		PoolOutputSatoshis: 1000, PoolLockingScript: []byte("lock"), SellerPubKey: []byte("seller"), BuyerPubKey: []byte("buyer"), ArbiterPubKey: []byte("arbiter"),
		MinerFeeRateSatPerKB: 1, BuyerRefundSignature: []byte("a"), SellerRefundSignature: []byte("server"), FundingTx: []byte("funding"),
	})
	if err != nil {
		t.Fatal(err)
	}
	terms, err := bitfs.EncodeContentRequestTerms(&bitfs.ContentRequestTerms{
		QuoteTermsHash: bytes.Repeat([]byte{3}, sha256.Size), SpendTxID: spend, BasePaymentSequence: 1, PaymentSequenceAfter: 2,
		SellerAmountAfterSat: 100, MinerFeeRateSatPerKB: 1, BuyerPubkey: []byte("buyer"), SellerPubkey: []byte("seller"), SelectedArbiterPubkey: []byte("arbiter"),
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
