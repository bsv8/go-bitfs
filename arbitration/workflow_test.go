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

const testArbitrationFeeSat uint64 = 500

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

func TestPrepareThenSignProducesCustodyReceiptAndTransactionEvidence(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow, err := NewWorkflow(WorkflowConfig{PrivateKey: evidence.keys[2]})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PreparePayment(context.Background(), evidence.request, 900000, testArbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.ClaimID()) != sha256.Size || len(prepared.PaymentAuthorizationHash()) != sha256.Size {
		t.Fatal("prepared commitments are incomplete")
	}
	if prepared.ArbiterAmountSat() != testArbitrationFeeSat {
		t.Fatalf("prepared fee drifted: %d", prepared.ArbiterAmountSat())
	}
	unsigned := prepared.UnsignedPayment()
	if unsigned.ArbiterAmountSat != testArbitrationFeeSat {
		t.Fatalf("unsigned candidate fee = %d, want %d", unsigned.ArbiterAmountSat, testArbitrationFeeSat)
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
	receipt, err := UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receipt.ClaimID, prepared.ClaimID()) || receipt.ArbiterAmountSat != prepared.ArbiterAmountSat() || !bytes.Equal(receipt.ArbiterTransactionSignature, signedTxSignature(response)) {
		t.Fatal("receipt did not preserve the frozen Claim ID, fee, and transaction signature")
	}
	receiptDomain, err := ArbiterReceiptSigningCBOR(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(evidence.keys[2].PubKey().Compressed(), receiptDomain, response.ArbiterReceiptSignature); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x84 || raw[1] != 0x04 || raw[2] != 0x09 {
		t.Fatalf("Kind 9 response must be a four-element [4,9,...] array: %x", raw)
	}
}

func signedTxSignature(response *ArbitrationResponse) []byte {
	receipt, err := UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		panic(err)
	}
	return receipt.ArbiterTransactionSignature
}

func TestArbitrationClaimIDGoldenBinding(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	claimID, err := ArbitrationClaimID(evidence.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := SellerClaimSigningCBOR(evidence.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(domain)
	if !bytes.Equal(claimID, digest[:]) {
		t.Fatal("Claim ID is not SHA-256 of the exact [4,8,claim_cbor] signing domain")
	}
	fullRequest, err := MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := sha256.Sum256(fullRequest)
	if bytes.Equal(claimID, requestHash[:]) {
		t.Fatal("Claim ID must not be the complete Kind 8 envelope hash")
	}
	// Claim ID 必须随 exact claim 字节变化，且对同一字节保持稳定。
	again, err := ArbitrationClaimID(evidence.request.ClaimCBOR)
	if err != nil || !bytes.Equal(claimID, again) {
		t.Fatal("Claim ID computation was not deterministic")
	}
}

func TestPrepareRejectsWrongArbiterBeforeCustody(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	wrongArbiter, err := NewWorkflow(WorkflowConfig{PrivateKey: mustKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := wrongArbiter.PreparePayment(context.Background(), evidence.request, 900000, testArbitrationFeeSat)
	if err == nil {
		t.Fatal("wrong arbiter received custody evidence")
	}
	if prepared != nil {
		t.Fatal("wrong arbiter returned prepared evidence")
	}
}

func TestPrepareRejectsZeroFeeBeforeAnyEvidenceWork(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow := mustArbiterWorkflow(t)
	prepared, err := workflow.PreparePayment(context.Background(), evidence.request, 900000, 0)
	if err == nil {
		t.Fatal("zero arbitration fee was accepted by PreparePayment")
	}
	if prepared != nil {
		t.Fatal("zero-fee prepare returned prepared evidence")
	}
	if _, err := workflow.PreparePayment(context.Background(), evidence.request, 900000, 1<<62); err == nil {
		t.Fatal("fee exceeding pool balance was accepted by PreparePayment")
	}
}

func TestLegacyFiveElementKind9AndWrongKindsReject(t *testing.T) {
	legacyResult, err := arbitrationEnc.Marshal([]any{
		bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	// 完整的旧五元 Kind 9 外壳：[4, 9, result_cbor, result_sig, tx_sig]。
	legacyResponse, err := arbitrationEnc.Marshal([]any{
		uint64(4), uint64(9), bstr(legacyResult), bstr(bytes.Repeat([]byte{7}, 70)), bstr(bytes.Repeat([]byte{8}, 70)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResponse(legacyResponse); err == nil {
		t.Fatal("legacy five-element Kind 9 decoded")
	}
	legacyRequest, err := arbitrationEnc.Marshal([]any{
		uint64(4), bytes.Repeat([]byte{1}, 32), []byte{2}, []byte{3}, []byte{4}, []byte{5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRequest(legacyRequest); err == nil {
		t.Fatal("legacy six-element request decoded")
	}
	evidence := makeArbitrationEvidence(t)
	raw, err := MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResponse(raw); err == nil {
		t.Fatal("Kind 8 body decoded as Kind 9")
	}
	responseRaw, err := MarshalResponse(mustSignedResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRequest(responseRaw); err == nil {
		t.Fatal("Kind 9 body decoded as Kind 8")
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
	if _, err := UnmarshalReceipt(bytes.Repeat([]byte{0}, MaxArbitrationReceiptBytes+1)); err == nil {
		t.Fatal("oversized arbitration receipt was decoded")
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

	invalidClaimID, err := arbitrationEnc.Marshal([]any{bytes.Repeat([]byte{1}, 31), uint64(1), bstr(bytes.Repeat([]byte{2}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceipt(invalidClaimID); err == nil {
		t.Fatal("31-byte Claim ID was accepted")
	}
	wideClaimID, err := arbitrationEnc.Marshal([]any{bytes.Repeat([]byte{1}, 33), uint64(1), bstr(bytes.Repeat([]byte{2}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalReceipt(wideClaimID); err == nil {
		t.Fatal("33-byte Claim ID was accepted")
	}
}

func TestReceiptWireLimitsAreDerivedFromChildLimits(t *testing.T) {
	if want := 1 + 34 + 9 + 259; MaxArbitrationReceiptBytes != want {
		t.Fatalf("receipt wire limit drifted from the derived protocol value: %d", MaxArbitrationReceiptBytes)
	}
	if MaxArbitrationReceiptBytes != 303 {
		t.Fatalf("receipt wire limit drifted from the pinned protocol value: %d", MaxArbitrationReceiptBytes)
	}
	if want := 1 + 1 + 1 + (3 + MaxArbitrationReceiptBytes) + (3 + MaxArbitrationSignatureBytes); MaxArbitrationResponseBytes != want {
		t.Fatalf("response wire limit drifted from the derived protocol value: %d", MaxArbitrationResponseBytes)
	}
	if MaxArbitrationResponseBytes != 568 {
		t.Fatalf("response wire limit drifted from the pinned protocol value: %d", MaxArbitrationResponseBytes)
	}
}

func TestReceiptRoundTripAndStrictDecoding(t *testing.T) {
	response := mustSignedResponse(t)
	raw, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ReceiptCBOR, response.ReceiptCBOR) || !bytes.Equal(decoded.ArbiterReceiptSignature, response.ArbiterReceiptSignature) || decoded.Version != MajorVersion {
		t.Fatal("response fields changed during round trip")
	}
	receiptRaw, err := MarshalReceipt(&ArbitrationReceipt{ClaimID: bytes.Repeat([]byte{1}, 32), ArbiterAmountSat: 42, ArbiterTransactionSignature: bytes.Repeat([]byte{3}, 70)})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := UnmarshalReceipt(receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	canonicalAgain, err := MarshalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receiptRaw, canonicalAgain) {
		t.Fatal("receipt canonical re-encode drifted")
	}
	if len(receiptRaw) < 3 || receiptRaw[0] != 0x83 {
		t.Fatalf("receipt must be a three-element array: %x", receiptRaw)
	}

	negativeCases := map[string][]byte{
		"trailing byte":       append(append([]byte(nil), receiptRaw...), 0),
		"tag wrapped":         append([]byte{0xc0}, receiptRaw...),
		"indefinite array":    append(append([]byte{0x9f}, receiptRaw...), 0xff),
		"two-element array":   mustEncodeReceiptParts(t, 2),
		"four-element array":  mustEncodeReceiptParts(t, 4),
		"zero amount":         mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 32), uint64(0), bytes.Repeat([]byte{3}, 70)),
		"empty tx signature":  mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 32), uint64(5), nil),
		"oversized tx sig":    mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 32), uint64(5), bytes.Repeat([]byte{3}, MaxArbitrationSignatureBytes+1)),
		"short claim id":      mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 31), uint64(5), bytes.Repeat([]byte{3}, 70)),
		"long claim id":       mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 33), uint64(5), bytes.Repeat([]byte{3}, 70)),
		"text claim id":       mustEncodeReceipt(t, "not-bytes", uint64(5), bytes.Repeat([]byte{3}, 70)),
		"negative amount":     mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 32), int64(-1), bytes.Repeat([]byte{3}, 70)),
		"non-shortest amount": mustMarshal(t, []any{bstr(bytes.Repeat([]byte{1}, 32)), cborTaggedUint(), bstr(bytes.Repeat([]byte{3}, 70))}),
	}
	for name, rawCase := range negativeCases {
		if _, err := UnmarshalReceipt(rawCase); err == nil {
			t.Fatalf("%s receipt case decoded: %x", name, rawCase)
		}
	}
	// Response-level strictness: wrong version/kind and trailing bytes.
	wrongVersion, err := arbitrationEnc.Marshal([]any{uint64(5), uint64(9), bstr(receiptRaw), bstr(bytes.Repeat([]byte{7}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResponse(wrongVersion); err == nil {
		t.Fatal("wrong response version decoded")
	}
	wrongKind, err := arbitrationEnc.Marshal([]any{uint64(4), uint64(8), bstr(receiptRaw), bstr(bytes.Repeat([]byte{7}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalResponse(wrongKind); err == nil {
		t.Fatal("wrong response kind decoded")
	}
	if _, err := UnmarshalResponse(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("response decoder accepted trailing bytes")
	}
	emptySigResponse := &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: append([]byte(nil), response.ReceiptCBOR...), ArbiterReceiptSignature: nil}
	if _, err := MarshalResponse(emptySigResponse); err == nil {
		t.Fatal("empty receipt signature was accepted")
	}
}

func cborTaggedUint() []byte {
	// 非最短整数编码（0x19 00 05 表示 5）必须被 strict decoder 拒绝。
	return []byte{0x19, 0x00, 0x05}
}

func mustEncodeReceipt(t *testing.T, claimID any, amount any, txSig any) []byte {
	t.Helper()
	raw, err := arbitrationEnc.Marshal([]any{claimID, amount, wrapBstr(txSig)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustEncodeReceiptParts(t *testing.T, count int) []byte {
	t.Helper()
	items := make([]any, count)
	for index := range items {
		items[index] = bstr(bytes.Repeat([]byte{1}, 32))
	}
	raw, err := arbitrationEnc.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustMarshal(t *testing.T, values []any) []byte {
	t.Helper()
	raw, err := arbitrationEnc.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wrapBstr(value any) any {
	if raw, ok := value.([]byte); ok {
		return bstr(raw)
	}
	return value
}

func mustSignedResponse(t *testing.T) *ArbitrationResponse {
	t.Helper()
	evidence := makeArbitrationEvidence(t)
	workflow, err := NewWorkflow(WorkflowConfig{PrivateKey: evidence.keys[2]})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PreparePayment(context.Background(), evidence.request, 900000, testArbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := workflow.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestPrepareRejectsPayloadMismatchBeforeSigning(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	evidence.request.ContentPayloadsCBOR, _ = bitfs.EncodeContentPayloads([][]byte{[]byte("tampered")})
	workflow, err := NewWorkflow(WorkflowConfig{PrivateKey: evidence.keys[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.PreparePayment(context.Background(), evidence.request, 900000, testArbitrationFeeSat); err == nil {
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
	return makeArbitrationEvidenceWithPayloadsAndExpiry(t, keys, digests, payloads, uint32(time.Now().Add(time.Hour).Unix()))
}

func makeArbitrationEvidenceWithPayloadsAndExpiry(t *testing.T, keys [3]*ec.PrivateKey, digests, payloads [][]byte, expiryLockTime uint32) arbitrationEvidence {
	t.Helper()
	// 交付截止时间不进入交易，但同样冻结，保证该 helper 完全确定。
	return makeArbitrationEvidenceWithPayloadsAndTimes(t, keys, digests, payloads, expiryLockTime, time.Now().Add(time.Hour).Unix())
}

// makeArbitrationEvidenceWithPayloadsAndTimes builds evidence with both wall
// clocks frozen by the caller. Tests that compare candidates across two
// separately built evidences MUST use this helper with one shared expiry and
// deadline; independent time.Now() calls can straddle a Unix-second boundary
// and change the refund template, txid, and candidate raw.
func makeArbitrationEvidenceWithPayloadsAndTimes(
	t *testing.T,
	keys [3]*ec.PrivateKey,
	digests, payloads [][]byte,
	expiryLockTime uint32,
	deliveryDeadlineUnix int64,
) arbitrationEvidence {
	t.Helper()
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
	presign, err := pool.NewBuyerPoolAdapter(engine, keys[0]).BuildRefundPresignRequest(context.Background(), pool.OpeningInput{FundingTx: funding.Bytes(), ExpiryLockTime: expiryLockTime, MinerFeeRateSatPerKB: 1, SellerPubKey: keys[1].PubKey().Compressed(), ArbiterPubKey: keys[2].PubKey().Compressed()})
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
	terms, err := bitfs.NewSignedContentRequest(&bitfs.ContentRequestTerms{QuoteTermsHash: bytes.Repeat([]byte{1}, 32), RefundTemplateTxID: refundID[:], PaymentSequence: 3, SellerAmountAfterSat: 100, ContentHashesCBOR: hashes, DeliveryDeadlineUnix: deliveryDeadlineUnix}, keys[0])
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
