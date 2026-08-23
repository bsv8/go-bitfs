package arbitration

// Security negative matrix required by the 007 hard-switch work order:
// tampered custody evidence, wrong signatures, payload batch attacks,
// exact deadline edges, hostile CBOR shapes, and deep-copy guarantees.
// Everything runs as pure Go tests; no cross-language vectors are involved.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

func mustArbiterWorkflow(t *testing.T) *Workflow {
	t.Helper()
	workflow, err := NewWorkflow(WorkflowConfig{PrivateKey: mustKey(t, "33")})
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func TestPrepareRejectsTamperedSellerClaimSignature(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	rejected := cloneRequest(evidence.request)
	rejected.SellerClaimSignature[len(rejected.SellerClaimSignature)-1] ^= 1
	if _, err := mustArbiterWorkflow(t).PreparePayment(context.Background(), rejected, 900000); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("tampered Seller Claim signature was not rejected as invalid evidence: %v", err)
	}
}

// TestSignPreparedRejectsTamperedCustodyEvidence mutates every stored custody
// input after PreparePayment and requires SignPreparedPayment to refuse to
// sign anything that no longer matches the persisted commitment.
func TestSignPreparedRejectsTamperedCustodyEvidence(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(prepared *PreparedPayment)
	}{
		{"request commitment", func(p *PreparedPayment) { p.requestCommitment[0] ^= 0xff }},
		{"content payloads hash", func(p *PreparedPayment) { p.payloadsHash[0] ^= 0xff }},
		{"unsigned state tx hash", func(p *PreparedPayment) { p.unsignedTxHash[0] ^= 0xff }},
		{"authorization hash", func(p *PreparedPayment) { p.authorizationHash[0] ^= 0xff }},
		{"request payload bundle", func(p *PreparedPayment) {
			p.request.ContentPayloadsCBOR[len(p.request.ContentPayloadsCBOR)-1] ^= 1
		}},
		{"request claim bytes", func(p *PreparedPayment) {
			p.request.ClaimCBOR[len(p.request.ClaimCBOR)-1] ^= 1
		}},
		{"request seller signature", func(p *PreparedPayment) {
			p.request.SellerClaimSignature[0] ^= 1
		}},
		{"unsigned candidate raw tx", func(p *PreparedPayment) {
			p.unsigned.RawTx[len(p.unsigned.RawTx)-1] ^= 1
		}},
	}
	for _, mutation := range mutations {
		evidence := makeArbitrationEvidence(t)
		workflow := mustArbiterWorkflow(t)
		prepared, err := workflow.PreparePayment(context.Background(), evidence.request, 900000)
		if err != nil {
			t.Fatal(err)
		}
		mutation.mutate(prepared)
		if _, err := workflow.SignPreparedPayment(context.Background(), prepared); !errors.Is(err, pool.ErrInvalidEvidence) {
			t.Fatalf("%s: tampered prepared evidence was accepted: %v", mutation.name, err)
		}
	}
}

// TestArbitrationResultBindingRejectsTampering proves the Kind 9 signatures
// bind the exact Result hashes and candidate: flipping any byte of the three
// committed hashes or either signature breaks a fixed verifier.
func TestArbitrationResultBindingRejectsTampering(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow := mustArbiterWorkflow(t)
	prepared, err := workflow.PreparePayment(context.Background(), evidence.request, 900000)
	if err != nil {
		t.Fatal(err)
	}
	response, err := workflow.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	result, err := UnmarshalResult(response.ResultCBOR)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := prepared.UnsignedPayment()
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(prepared.claim.PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	arbiterPubKey := evidence.keys[2].PubKey().Compressed()

	hashMutations := map[string]func(result *ArbitrationResult){
		"request commitment":     func(r *ArbitrationResult) { r.RequestCommitment[0] ^= 1 },
		"content payloads hash":  func(r *ArbitrationResult) { r.ContentPayloadsHash[0] ^= 1 },
		"unsigned state tx hash": func(r *ArbitrationResult) { r.UnsignedStateTxHash[0] ^= 1 },
	}
	for name, mutate := range hashMutations {
		tampered := cloneResult(result)
		mutate(tampered)
		tamperedCBOR, err := MarshalResult(tampered)
		if err != nil {
			t.Fatal(err)
		}
		domain, err := ArbiterResultSigningCBOR(tamperedCBOR)
		if err != nil {
			t.Fatal(err)
		}
		if err := bitfs.VerifySignature(arbiterPubKey, domain, response.ArbiterResultSignature); err == nil {
			t.Fatalf("tampered %s still verified against the frozen Arbiter result signature", name)
		}
	}

	domain, err := ArbiterResultSigningCBOR(response.ResultCBOR)
	if err != nil {
		t.Fatal(err)
	}
	flippedResultSig := append([]byte(nil), response.ArbiterResultSignature...)
	flippedResultSig[len(flippedResultSig)-1] ^= 1
	if err := bitfs.VerifySignature(arbiterPubKey, domain, flippedResultSig); err == nil {
		t.Fatal("flipped Arbiter result signature verified")
	}
	flippedTxSig := append([]byte(nil), response.ArbiterTransactionSignature...)
	flippedTxSig[len(flippedTxSig)-1] ^= 1
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, flippedTxSig); err == nil {
		t.Fatal("flipped Arbiter transaction signature verified against the candidate")
	}
	if err := engine.VerifyArbitrationSellerPayment(unsigned, flippedTxSig); err == nil {
		t.Fatal("arbiter signature slot accepted a signature for another role")
	}
}

// TestArbitrationPayloadCountMatrix covers the full legal and illegal count
// range with small payloads: only 1..MaxContentBatchItems bundles pass.
// Counts 0 and 65 are exercised by swapping the payload bundle of a legal
// request, because the terms builder itself refuses out-of-range hash counts.
func TestArbitrationPayloadCountMatrix(t *testing.T) {
	buildPayloads := func(count int) ([][]byte, [][]byte) {
		payloads := make([][]byte, count)
		digests := make([][]byte, count)
		for index := range payloads {
			payload := bytes.Repeat([]byte{byte(index + 1)}, 16)
			payloads[index] = payload
			digest := sha256.Sum256(payload)
			digests[index] = digest[:]
		}
		return digests, payloads
	}
	for count, wantAccept := range map[int]bool{0: false, 1: true, 2: true, 64: true, 65: false} {
		baseCount := count
		if baseCount < 1 {
			baseCount = 1
		}
		if baseCount > bitfs.MaxContentBatchItems {
			baseCount = bitfs.MaxContentBatchItems
		}
		digests, payloads := buildPayloads(baseCount)
		evidence := makeArbitrationEvidenceWithPayloads(t, digests, payloads)
		if count != baseCount {
			items := make([]any, count)
			for index := range items {
				items[index] = bytes.Repeat([]byte{byte(index + 1)}, 16)
			}
			bundle, err := arbitrationEnc.Marshal(items)
			if err != nil {
				t.Fatal(err)
			}
			evidence.request.ContentPayloadsCBOR = bundle
		}
		_, err := mustArbiterWorkflow(t).PreparePayment(context.Background(), evidence.request, 900000)
		if wantAccept && err != nil {
			t.Fatalf("legal %d-payload request was rejected: %v", count, err)
		}
		if !wantAccept && err == nil {
			t.Fatalf("%d-payload request was accepted", count)
		}
	}
}

// TestPrepareRejectsPayloadOrderSizeAndCountMismatch covers the remaining
// batch attacks: swapped order, empty item, oversized item, and a bundle whose
// length diverges from the authorized hash count.
func TestPrepareRejectsPayloadOrderSizeAndCountMismatch(t *testing.T) {
	workflow := mustArbiterWorkflow(t)

	first, second := []byte("payload-one"), []byte("payload-two")
	digestOne, digestTwo := sha256.Sum256(first), sha256.Sum256(second)

	swapped := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:], digestTwo[:]}, [][]byte{second, first})
	if _, err := workflow.PreparePayment(context.Background(), swapped.request, 900000); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("swapped payload order was accepted: %v", err)
	}

	emptyBundle := mustEncodeArray(t, []any{[]byte{}, second})
	empty := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:], digestTwo[:]}, [][]byte{first, second})
	empty.request.ContentPayloadsCBOR = emptyBundle
	if _, err := workflow.PreparePayment(context.Background(), empty.request, 900000); err == nil {
		t.Fatal("empty payload item was accepted")
	}

	oversizedItem := bytes.Repeat([]byte{9}, int(bitfs.BlockSize)+1)
	oversizedBundle := mustEncodeArray(t, []any{oversizedItem})
	oversized := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:]}, [][]byte{first})
	oversized.request.ContentPayloadsCBOR = oversizedBundle
	if _, err := workflow.PreparePayment(context.Background(), oversized.request, 900000); err == nil {
		t.Fatal("oversized payload item was accepted")
	}

	countMismatch := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:]}, [][]byte{first, second})
	if _, err := workflow.PreparePayment(context.Background(), countMismatch.request, 900000); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("payload/hash count mismatch was accepted: %v", err)
	}
}

func mustEncodeArray(t *testing.T, values []any) []byte {
	t.Helper()
	raw, err := arbitrationEnc.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func makeArbitrationEvidenceWithDeadline(t *testing.T, deadlineUnix int64) arbitrationEvidence {
	t.Helper()
	payload := []byte("deadline-payload")
	digest := sha256.Sum256(payload)
	evidence := makeArbitrationEvidenceWithPayloads(t, [][]byte{digest[:]}, [][]byte{payload})
	claim, err := UnmarshalClaim(evidence.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms, err := bitfs.DecodeContentRequestTerms(claim.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	terms.DeliveryDeadlineUnix = deadlineUnix
	termsCBOR, err := bitfs.EncodeContentRequestTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	buyerSignature, err := bitfs.SignMessage(evidence.keys[0], termsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimCBOR, err := MarshalClaim(&ArbitrationClaim{
		PoolOutputSatoshis:      claim.PoolOutputSatoshis,
		PoolOutputLockingScript: claim.PoolOutputLockingScript,
		RefundTemplateRaw:       claim.RefundTemplateRaw,
		TermsCBOR:               termsCBOR,
		BuyerSignature:          buyerSignature,
	})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := SellerClaimSigningCBOR(claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimSig, err := bitfs.SignMessage(evidence.keys[1], domain)
	if err != nil {
		t.Fatal(err)
	}
	evidence.request.ClaimCBOR = claimCBOR
	evidence.request.SellerClaimSignature = sellerClaimSig
	return evidence
}

// TestDeadlineBoundariesGatePrepareAndSigning pins the exact delivery-deadline
// second (inclusive rejection), acceptance before it, and expiry inside the
// persistence gap between PreparePayment and SignPreparedPayment.
func TestDeadlineBoundariesGatePrepareAndSigning(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	workflow := mustArbiterWorkflow(t)

	exactDeadline := makeArbitrationEvidenceWithDeadline(t, now.Add(time.Second).Unix()-1)
	if _, err := workflow.PreparePayment(context.Background(), exactDeadline.request, 900000); err == nil {
		t.Fatal("prepare at the exact deadline second was accepted")
	}

	beforeDeadline := makeArbitrationEvidenceWithDeadline(t, now.Add(30*time.Second).Unix())
	prepared, err := workflow.PreparePayment(context.Background(), beforeDeadline.request, 900000)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.DeadlineUnix() != now.Add(30*time.Second).Unix() {
		t.Fatalf("prepared deadline drifted: %d", prepared.DeadlineUnix())
	}

	// Sign must refuse once the delivery deadline passes inside the
	// persistence gap between Prepare and Sign. The workflow intentionally
	// owns its clock, so crossing the boundary needs a small real-time wait;
	// if a heavily loaded or racing machine burns through the window before
	// Prepare lands, rebuild the evidence with a fresh window.
	expiring := prepared
	for attempt := 0; attempt < 5; attempt++ {
		expiringSoon := makeArbitrationEvidenceWithDeadline(t, time.Now().Add(3*time.Second).Unix())
		candidate, err := workflow.PreparePayment(context.Background(), expiringSoon.request, 900000)
		if err != nil {
			if strings.Contains(err.Error(), "deadline") {
				continue
			}
			t.Fatal(err)
		}
		expiring = candidate
		break
	}
	if expiring == prepared {
		t.Fatal("could not prepare custody evidence inside its delivery deadline")
	}
	for time.Now().UTC().Before(time.Unix(expiring.deadlineUnix, 0)) {
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := workflow.SignPreparedPayment(context.Background(), expiring); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("signing after deadline expiry in the persistence gap was accepted: %v", err)
	}
}

// TestArbitrationDecodersRejectHostileCBOR pins decoder-level rejections:
// tags, indefinite lengths, non-shortest integers, and wrong field types never
// reach semantic validation; decoded outputs are isolated from source bytes.
func TestArbitrationDecodersRejectHostileCBOR(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	valid, err := MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}

	tagged := append([]byte{0xc0}, valid...)
	if _, err := UnmarshalRequest(tagged); err == nil {
		t.Fatal("tag-wrapped request was decoded")
	}

	indefinite := append([]byte{0x9f}, valid...)
	indefinite = append(indefinite, 0xff)
	if _, err := UnmarshalRequest(indefinite); err == nil {
		t.Fatal("indefinite-length array request was decoded")
	}

	// [4, 8, (_ 'a' 'b'), h'0304', h'05']: an indefinite-length bstr child.
	indefiniteBstrChild := []byte{0x85, 0x04, 0x08, 0x5f, 0x41, 0x61, 0x41, 0x62, 0xff, 0x42, 0x03, 0x04, 0x41, 0x05}
	if _, err := UnmarshalRequest(indefiniteBstrChild); err == nil {
		t.Fatal("indefinite-length bstr child was decoded")
	}

	nonShortestVersion := append([]byte{0x85, 0x19, 0x00, 0x04}, valid[2:]...)
	if _, err := UnmarshalRequest(nonShortestVersion); err == nil {
		t.Fatal("non-shortest version integer was decoded")
	}

	textClaim := append([]byte{0x85, 0x04, 0x08, 0x63, 'a', 'b', 'c'}, valid[3:]...)
	if _, err := UnmarshalRequest(textClaim); err == nil {
		t.Fatal("text-string Claim element was decoded as bstr")
	}

	negativeSatoshis, err := arbitrationEnc.Marshal([]any{-1, bstr(bytes.Repeat([]byte{1}, 105)), bstr([]byte{2}), bstr([]byte{3}), bstr([]byte{4})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalClaim(negativeSatoshis); err == nil {
		t.Fatal("negative satoshis were decoded into the Claim")
	}

	taggedResult := append([]byte{0xc1}, []byte{0x83, 0x58, 0x20}...)
	taggedResult = append(taggedResult, bytes.Repeat([]byte{1}, 97)...)
	if _, err := UnmarshalResult(taggedResult); err == nil {
		t.Fatal("tag-wrapped result was decoded")
	}

	wrongTypeResult := mustEncodeArray(t, []any{"not-a-hash", bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)})
	if _, err := UnmarshalResult(wrongTypeResult); err == nil {
		t.Fatal("text-string Result element was decoded as bstr")
	}

	// Decoded outputs must be isolated from the source bytes and from each
	// other: mutating one decode must not affect the wire bytes or a fresh
	// decode of them.
	decoded, err := UnmarshalRequest(valid)
	if err != nil {
		t.Fatal(err)
	}
	originalSignature := append([]byte(nil), decoded.SellerClaimSignature...)
	decoded.SellerClaimSignature[0] ^= 1
	fresh, err := UnmarshalRequest(valid)
	if err != nil {
		t.Fatalf("source bytes were corrupted by a prior decode and mutation: %v", err)
	}
	if !bytes.Equal(fresh.SellerClaimSignature, originalSignature) || bytes.Equal(fresh.SellerClaimSignature, decoded.SellerClaimSignature) {
		t.Fatal("a fresh decode observed a previous decode's mutation")
	}
	canonical, err := MarshalRequest(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, valid) {
		t.Fatal("canonical re-encoding drifted from the source bytes")
	}
}

// TestPreparedPaymentGettersReturnDeepCopies extends the deep-copy guarantee
// to every exported getter of PreparedPayment.
func TestPreparedPaymentGettersReturnDeepCopies(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	prepared, err := mustArbiterWorkflow(t).PreparePayment(context.Background(), evidence.request, 900000)
	if err != nil {
		t.Fatal(err)
	}

	assertDeepCopy := func(name string, get func() []byte) {
		t.Helper()
		first := get()
		if len(first) == 0 {
			t.Fatalf("%s getter returned empty data", name)
		}
		second := get()
		if len(second) != len(first) {
			t.Fatalf("%s getter changed length between calls", name)
		}
		first[len(first)-1] ^= 1
		if bytes.Equal(first, second) {
			t.Fatalf("%s getter returned an internal reference", name)
		}
	}
	assertDeepCopy("RefundTemplateTxID", prepared.RefundTemplateTxID)
	assertDeepCopy("RequestCommitment", prepared.RequestCommitment)
	assertDeepCopy("PaymentAuthorizationHash", prepared.PaymentAuthorizationHash)
	assertDeepCopy("ContentPayloadsHash", prepared.ContentPayloadsHash)
	assertDeepCopy("UnsignedStateTxHash", prepared.UnsignedStateTxHash)
	assertDeepCopy("ContentPayloadsCBOR", prepared.ContentPayloadsCBOR)

	claim := prepared.Claim()
	if claim == nil || len(claim.PoolOutputLockingScript) == 0 {
		t.Fatal("Claim getter returned empty evidence")
	}
	claim.PoolOutputLockingScript[len(claim.PoolOutputLockingScript)-1] ^= 1
	claimAgain := prepared.Claim()
	if bytes.Equal(claim.PoolOutputLockingScript, claimAgain.PoolOutputLockingScript) {
		t.Fatal("Claim getter returned an internal reference")
	}

	payloads := prepared.ContentPayloads()
	if len(payloads) == 0 || len(payloads[0]) == 0 {
		t.Fatal("ContentPayloads getter returned empty evidence")
	}
	payloads[0][len(payloads[0])-1] ^= 1
	if bytes.Equal(payloads[0], prepared.ContentPayloads()[0]) {
		t.Fatal("ContentPayloads getter returned internal references")
	}

	request := prepared.Request()
	request.ContentPayloadsCBOR[len(request.ContentPayloadsCBOR)-1] ^= 1
	if bytes.Equal(request.ContentPayloadsCBOR, prepared.Request().ContentPayloadsCBOR) {
		t.Fatal("Request getter returned internal references")
	}

	unsigned := prepared.UnsignedPayment()
	unsigned.RawTx[len(unsigned.RawTx)-1] ^= 1
	if bytes.Equal(unsigned.RawTx, prepared.UnsignedPayment().RawTx) {
		t.Fatal("UnsignedPayment getter returned internal references")
	}
}
