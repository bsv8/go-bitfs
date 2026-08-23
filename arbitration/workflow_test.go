package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

type arbitrationEvidence struct {
	request *ArbitrationRequest
	proof   *pool.OpeningProof
	keys    [3]*ec.PrivateKey
}

func TestV4ArbitrationWireShapeAndSigningDomains(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	raw, err := MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0x85 || raw[1] != 0x04 {
		t.Fatalf("Kind 8 request must be a five-element [4,...] array: %x", raw)
	}
	decoded, err := UnmarshalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ClaimCBOR, evidence.request.ClaimCBOR) || !bytes.Equal(decoded.ContentPayloadsCBOR, evidence.request.ContentPayloadsCBOR) {
		t.Fatal("request evidence changed during round trip")
	}
	if _, err := UnmarshalRequest(append(raw, 0)); err == nil {
		t.Fatal("request decoder accepted trailing bytes")
	}
	claimDomain, err := SellerClaimSigningCBOR(evidence.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(evidence.keys[1].PubKey().Compressed(), claimDomain, evidence.request.SellerClaimSignature); err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(evidence.keys[1].PubKey().Compressed(), evidence.request.ClaimCBOR, evidence.request.SellerClaimSignature); err == nil {
		t.Fatal("Seller Claim signature verified over Claim alone")
	}
}

func TestPrepareThenSignProducesCustodyAndTransactionEvidence(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow, err := NewWorkflow(WorkflowConfig{PrivateKey: evidence.keys[2]})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PreparePayment(context.Background(), evidence.request, 900000)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.RefundTemplateTxID()) != sha256.Size || len(prepared.RequestCommitment()) != sha256.Size || len(prepared.ContentPayloadsHash()) != sha256.Size || len(prepared.UnsignedStateTxHash()) != sha256.Size {
		t.Fatal("prepared hashes are incomplete")
	}
	requestCopy := prepared.Request()
	requestCopy.ClaimCBOR[0] ^= 1
	if bytes.Equal(requestCopy.ClaimCBOR, prepared.Request().ClaimCBOR) {
		t.Fatal("prepared request getter was not a deep copy")
	}
	unsignedCopy := prepared.UnsignedPayment()
	unsignedCopy.RawTx[0] ^= 1
	if bytes.Equal(unsignedCopy.RawTx, prepared.UnsignedPayment().RawTx) {
		t.Fatal("prepared unsigned payment getter was not a deep copy")
	}
	response, err := workflow.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	result, err := UnmarshalResult(response.ResultCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.RequestCommitment, prepared.RequestCommitment()) || !bytes.Equal(result.ContentPayloadsHash, prepared.ContentPayloadsHash()) || !bytes.Equal(result.UnsignedStateTxHash, prepared.UnsignedStateTxHash()) {
		t.Fatal("Kind 9 result hashes changed")
	}
	resultDomain, err := ArbiterResultSigningCBOR(response.ResultCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(evidence.keys[2].PubKey().Compressed(), resultDomain, response.ArbiterResultSignature); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2 || raw[0] != 0x85 || raw[1] != 0x04 {
		t.Fatalf("Kind 9 response must be a five-element [4,...] array: %x", raw)
	}
}

func TestPrepareRejectsWrongArbiterBeforeCustody(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	wrongArbiter, err := NewWorkflow(WorkflowConfig{PrivateKey: mustKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := wrongArbiter.PreparePayment(context.Background(), evidence.request, 900000)
	if err == nil {
		t.Fatal("wrong arbiter received custody evidence")
	}
	if prepared != nil {
		t.Fatal("wrong arbiter returned prepared evidence")
	}
}

func TestLegacyV4ArbitrationShapesAndWrongKindsReject(t *testing.T) {
	legacyRequest, err := arbitrationEnc.Marshal([]any{
		uint64(4), bytes.Repeat([]byte{1}, 32), []byte{2}, []byte{3}, []byte{4}, []byte{5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRequest(legacyRequest); err == nil {
		t.Fatal("legacy six-element request decoded")
	}
	legacyResponse, err := arbitrationEnc.Marshal([]any{
		uint64(4), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 70),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResponse(legacyResponse); err == nil {
		t.Fatal("complete legacy response shape decoded")
	}
	evidence := makeArbitrationEvidence(t)
	raw, err := MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResponse(raw); err == nil {
		t.Fatal("Kind 8 body decoded as Kind 9")
	}
}

func TestArbitrationWireLimitsRejectBeforeUnboundedDecode(t *testing.T) {
	if _, err := UnmarshalRequest(bytes.Repeat([]byte{0}, MaxArbitrationRequestBytes+1)); err == nil {
		t.Fatal("oversized arbitration request was decoded")
	}
	if want := bitfs.MaxContentPayloadsCBORBytes + MaxArbitrationClaimBytes + MaxArbitrationSignatureBytes + maxArbitrationRequestEnvelopeBytes; MaxArbitrationRequestBytes != want {
		t.Fatalf("request wire limit drifted from the protocol child limits: %d", MaxArbitrationRequestBytes)
	}
	if MaxArbitrationRequestBytes != 16843609 {
		t.Fatalf("request wire limit drifted from the pinned protocol value: %d", MaxArbitrationRequestBytes)
	}
	if _, err := UnmarshalClaim(bytes.Repeat([]byte{0}, MaxArbitrationClaimBytes+1)); err == nil {
		t.Fatal("oversized arbitration Claim was decoded")
	}
	if _, err := UnmarshalResponse(bytes.Repeat([]byte{0}, MaxArbitrationResponseBytes+1)); err == nil {
		t.Fatal("oversized arbitration response was decoded")
	}
	if _, err := UnmarshalResult(bytes.Repeat([]byte{0}, MaxArbitrationResultBytes+1)); err == nil {
		t.Fatal("oversized arbitration Result was decoded")
	}

	oversizedTerms, err := arbitrationEnc.Marshal([]any{
		uint64(100000), bytes.Repeat([]byte{1}, 105), bytes.Repeat([]byte{2}, 64),
		bytes.Repeat([]byte{3}, MaxArbitrationTermsBytes+1), bytes.Repeat([]byte{4}, 70),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalClaim(oversizedTerms); err == nil {
		t.Fatal("oversized nested TermsCBOR was accepted")
	}

	invalidHash, err := arbitrationEnc.Marshal([]any{bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResult(invalidHash); err == nil {
		t.Fatal("invalid Result hash width was accepted")
	}
}

func TestPrepareRejectsPayloadMismatchBeforeSigning(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	evidence.request.ContentPayloadsCBOR, _ = bitfs.EncodeContentPayloads([][]byte{[]byte("tampered")})
	workflow, err := NewWorkflow(WorkflowConfig{PrivateKey: evidence.keys[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.PreparePayment(context.Background(), evidence.request, 900000); err == nil {
		t.Fatal("payload hash mismatch was accepted")
	}
}

func TestArbitrationRequestAcceptsFullSizePayloadBundles(t *testing.T) {
	for _, count := range []int{2, bitfs.MaxContentBatchItems} {
		payloads := make([][]byte, count)
		digests := make([][]byte, count)
		for index := range payloads {
			payload := bytes.Repeat([]byte{byte(index + 1)}, int(bitfs.BlockSize))
			payloads[index] = payload
			digest := sha256.Sum256(payload)
			digests[index] = digest[:]
		}
		evidence := makeArbitrationEvidenceWithPayloads(t, digests, payloads)
		raw, err := MarshalRequest(evidence.request)
		if err != nil {
			t.Fatalf("legal %d-payload request exceeded the wire limit: %v", count, err)
		}
		if len(raw) <= 384*1024 {
			t.Fatalf("%d-payload request regressed below the retired 384 KiB quota: %d bytes", count, len(raw))
		}
		decoded, err := UnmarshalRequest(raw)
		if err != nil {
			t.Fatalf("legal %d-payload request was rejected: %v", count, err)
		}
		if !bytes.Equal(decoded.ContentPayloadsCBOR, evidence.request.ContentPayloadsCBOR) || !bytes.Equal(decoded.ClaimCBOR, evidence.request.ClaimCBOR) {
			t.Fatalf("%d-payload request changed during round trip", count)
		}
	}
}

func TestArbitrationRejectsPayloadCountBoundaries(t *testing.T) {
	evidence := makeArbitrationEvidence(t)

	empty, err := arbitrationEnc.Marshal([]any{})
	if err != nil {
		t.Fatal(err)
	}
	rejected := cloneRequest(evidence.request)
	rejected.ContentPayloadsCBOR = empty
	if _, err := MarshalRequest(rejected); err == nil {
		t.Fatal("zero-payload bundle was accepted")
	}
	if _, err := UnmarshalRequest(mustMarshalRequest(t, rejected)); err == nil {
		t.Fatal("zero-payload request was decoded")
	}

	items := make([]any, bitfs.MaxContentBatchItems+1)
	for index := range items {
		items[index] = bytes.Repeat([]byte{byte(index + 1)}, 16)
	}
	oversized, err := arbitrationEnc.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	rejected = cloneRequest(evidence.request)
	rejected.ContentPayloadsCBOR = oversized
	if _, err := MarshalRequest(rejected); err == nil {
		t.Fatal("65-payload bundle was accepted")
	}
	if _, err := UnmarshalRequest(mustMarshalRequest(t, rejected)); err == nil {
		t.Fatal("65-payload request was decoded")
	}
}

func mustMarshalRequest(t *testing.T, request *ArbitrationRequest) []byte {
	t.Helper()
	raw, err := arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationRequest, bstr(request.ClaimCBOR), bstr(request.SellerClaimSignature), bstr(request.ContentPayloadsCBOR)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func makeArbitrationEvidence(t *testing.T) arbitrationEvidence {
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	return makeArbitrationEvidenceWithPayloads(t, [][]byte{digest[:]}, [][]byte{payload})
}

func makeArbitrationEvidenceWithPayloads(t *testing.T, digests, payloads [][]byte) arbitrationEvidence {
	t.Helper()
	keys := [3]*ec.PrivateKey{mustKey(t, "11"), mustKey(t, "22"), mustKey(t, "33")}
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPubKey: keys[0].PubKey().Compressed(), SellerPubKey: keys[1].PubKey().Compressed(), ArbiterPubKey: keys[2].PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := chainhash.NewHash(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SourceTxOutIndex: 0, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock)})
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: keys[0].PubKey().Compressed(), SellerPubKey: keys[1].PubKey().Compressed(), ArbiterPubKey: keys[2].PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := pool.NewBuyerPoolAdapter(engine, keys[0]).BuildRefundPresignRequest(context.Background(), pool.OpeningInput{FundingTx: funding.Bytes(), ExpiryLockTime: uint32(time.Now().Add(time.Hour).Unix()), MinerFeeRateSatPerKB: 1, SellerPubKey: keys[1].PubKey().Compressed(), ArbiterPubKey: keys[2].PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := pool.NewSellerPoolAdapter(engine, keys[1]).SignSellerRefund(context.Background(), presign)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(context.Background(), presign, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	refundID, err := pool.DeriveRefundTemplateTxID(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := bitfs.EncodeContentHashes(digests)
	if err != nil {
		t.Fatal(err)
	}
	terms, err := bitfs.NewSignedContentRequest(&bitfs.ContentRequestTerms{QuoteTermsHash: bytes.Repeat([]byte{1}, 32), RefundTemplateTxID: refundID[:], PaymentSequence: 3, SellerAmountAfterSat: 100, ContentHashesCBOR: hashes, DeliveryDeadlineUnix: time.Now().Add(time.Hour).Unix()}, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	details, err := pool.DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	claimCBOR, err := MarshalClaim(&ArbitrationClaim{PoolOutputSatoshis: details.PoolOutputSatoshis, PoolOutputLockingScript: details.PoolLockingScript, RefundTemplateRaw: proof.RefundTx, TermsCBOR: terms.TermsCBOR, BuyerSignature: terms.BuyerSignature})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := SellerClaimSigningCBOR(claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimSig, err := bitfs.SignMessage(keys[1], domain)
	if err != nil {
		t.Fatal(err)
	}
	payloadBundle, err := bitfs.EncodeContentPayloads(payloads)
	if err != nil {
		t.Fatal(err)
	}
	return arbitrationEvidence{request: &ArbitrationRequest{Version: MajorVersion, ClaimCBOR: claimCBOR, SellerClaimSignature: sellerClaimSig, ContentPayloadsCBOR: payloadBundle}, proof: proof, keys: keys}
}

func mustKey(t *testing.T, repeated string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(repeated), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
