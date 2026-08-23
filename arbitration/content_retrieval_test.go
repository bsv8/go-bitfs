package arbitration

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

var testRetrievalNonce = bytes.Repeat([]byte{0xab}, RetrievalNonceBytes)

func mustSignedCustodyPair(t *testing.T) (arbitrationEvidence, *Workflow, *PreparedPayment, *ArbitrationResponse) {
	t.Helper()
	evidence := makeArbitrationEvidence(t)
	workflow, prepared := mustSignPrepared(t, evidence)
	response, err := workflow.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	return evidence, workflow, prepared, response
}

func mustRetrievalRequest(t *testing.T, evidence arbitrationEvidence, claimID, nonce []byte) *ContentRetrievalRequest {
	t.Helper()
	signing, err := BuyerRetrievalSigningCBOR(claimID, nonce)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := bitfs.SignMessage(evidence.keys[0], signing)
	if err != nil {
		t.Fatal(err)
	}
	request := &ContentRetrievalRequest{Version: MajorVersion, ClaimID: append([]byte(nil), claimID...), Nonce: append([]byte(nil), nonce...), BuyerSignature: signature}
	if _, err := MarshalContentRetrievalRequest(request); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestContentRetrievalRequestShapeRoundTripAndSigningDomain(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	claimID, err := ArbitrationClaimID(evidence.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	raw, err := MarshalContentRetrievalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 5 || raw[0] != 0x85 || raw[1] != 0x04 || raw[2] != 0x0a {
		t.Fatalf("Kind 10 must be the five-element [4,10,...] array: %x", raw)
	}
	decoded, err := UnmarshalContentRetrievalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ClaimID, request.ClaimID) || !bytes.Equal(decoded.Nonce, request.Nonce) || !bytes.Equal(decoded.BuyerSignature, request.BuyerSignature) || decoded.Version != MajorVersion {
		t.Fatal("Kind 10 fields changed during round trip")
	}
	again, err := MarshalContentRetrievalRequest(decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("Kind 10 canonical round trip drifted")
	}
	if _, err := UnmarshalContentRetrievalRequest(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("Kind 10 decoder accepted trailing bytes")
	}
	// 签名域严格为 [4,10,claim_id,nonce]；裸 Claim ID、裸 nonce、完整五元
	// envelope 都不能通过验证。
	domain, err := BuyerRetrievalSigningCBOR(claimID, testRetrievalNonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(domain) < 3 || domain[0] != 0x84 || domain[1] != 0x04 || domain[2] != 0x0a {
		t.Fatalf("buyer retrieval signing domain must be four-element [4,10,...]: %x", domain)
	}
	buyerPubKey := evidence.keys[0].PubKey().Compressed()
	if err := bitfs.VerifySignature(buyerPubKey, domain, request.BuyerSignature); err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(buyerPubKey, claimID, request.BuyerSignature); err == nil {
		t.Fatal("bare Claim ID was accepted as the signing domain")
	}
	if err := bitfs.VerifySignature(buyerPubKey, nonceBytes(testRetrievalNonce), request.BuyerSignature); err == nil {
		t.Fatal("bare nonce was accepted as the signing domain")
	}
	if err := bitfs.VerifySignature(buyerPubKey, raw, request.BuyerSignature); err == nil {
		t.Fatal("the complete Kind 10 envelope was accepted as the signing domain")
	}
}

func nonceBytes(value []byte) []byte { return append([]byte(nil), value...) }

func TestContentRetrievalLimitsAreDerivedFromChildLimits(t *testing.T) {
	wantRequest := 1 + 1 + 1 + maxClaimIDBstrBytes + maxClaimIDBstrBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes
	if MaxContentRetrievalRequestBytes != wantRequest {
		t.Fatalf("request wire limit drifted from the derived protocol value: %d", MaxContentRetrievalRequestBytes)
	}
	if MaxContentRetrievalRequestBytes != 330 {
		t.Fatalf("request wire limit drifted from the pinned protocol value: %d", MaxContentRetrievalRequestBytes)
	}
	wantResponse := 1 + 1 + 1 + 5 + MaxArbitrationRequestBytes + maxSignatureBstrOverhead + MaxArbitrationResponseBytes
	if MaxContentRetrievalResponseBytes != wantResponse {
		t.Fatalf("response wire limit drifted from the derived protocol value: %d", MaxContentRetrievalResponseBytes)
	}
	if MaxContentRetrievalResponseBytes != 16844188 {
		t.Fatalf("response wire limit drifted from the pinned protocol value: %d", MaxContentRetrievalResponseBytes)
	}
	if _, err := UnmarshalContentRetrievalRequest(bytes.Repeat([]byte{0}, MaxContentRetrievalRequestBytes+1)); err == nil {
		t.Fatal("oversized Kind 10 was decoded")
	}
}

func TestContentRetrievalRequestRejectsHostileShapes(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	claimID, err := ArbitrationClaimID(evidence.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	valid := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	raw, err := MarshalContentRetrievalRequest(valid)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"wrong version":       mustMarshal(t, []any{uint64(MajorVersion + 1), kindContentRetrievalRequest, bstr(claimID), bstr(testRetrievalNonce), bstr(valid.BuyerSignature)}),
		"wrong kind":          mustMarshal(t, []any{MajorVersion, uint64(9), bstr(claimID), bstr(testRetrievalNonce), bstr(valid.BuyerSignature)}),
		"four elements":       mustEncodeArray(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(testRetrievalNonce)}),
		"six elements":        mustEncodeArray(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(testRetrievalNonce), bstr(valid.BuyerSignature), bstr(claimID)}),
		"tag wrapped":         append([]byte{0xc0}, raw...),
		"indefinite array":    append(append([]byte{0x9f}, raw...), 0xff),
		"indefinite bstr":     mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, cborIndefiniteBstr(), bstr(testRetrievalNonce), bstr(valid.BuyerSignature)}),
		"non-shortest int":    append([]byte{0x85, 0x19, 0x00, 0x04}, raw[2:]...),
		"short claim id":      mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(bytes.Repeat([]byte{1}, 31)), bstr(testRetrievalNonce), bstr(valid.BuyerSignature)}),
		"long claim id":       mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(bytes.Repeat([]byte{1}, 33)), bstr(testRetrievalNonce), bstr(valid.BuyerSignature)}),
		"text claim id":       mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, "not-bytes", bstr(testRetrievalNonce), bstr(valid.BuyerSignature)}),
		"short nonce":         mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(bytes.Repeat([]byte{2}, 31)), bstr(valid.BuyerSignature)}),
		"long nonce":          mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(bytes.Repeat([]byte{2}, 33)), bstr(valid.BuyerSignature)}),
		"zero nonce":          mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(bytes.Repeat([]byte{0}, 32)), bstr(valid.BuyerSignature)}),
		"empty signature":     mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(testRetrievalNonce), bstr(nil)}),
		"oversized signature": mustMarshal(t, []any{MajorVersion, kindContentRetrievalRequest, bstr(claimID), bstr(testRetrievalNonce), bstr(bytes.Repeat([]byte{7}, MaxArbitrationSignatureBytes+1))}),
	}
	for name, rawCase := range cases {
		if _, err := UnmarshalContentRetrievalRequest(rawCase); err == nil {
			t.Fatalf("%s Kind 10 case decoded: %x", name, rawCase)
		}
	}
	structural := []*ContentRetrievalRequest{
		nil,
		{Version: MajorVersion + 1, ClaimID: claimID, Nonce: testRetrievalNonce, BuyerSignature: valid.BuyerSignature},
		{Version: MajorVersion, ClaimID: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{0}, 32), BuyerSignature: valid.BuyerSignature},
		{Version: MajorVersion, ClaimID: claimID, Nonce: nil, BuyerSignature: valid.BuyerSignature},
		{Version: MajorVersion, ClaimID: claimID, Nonce: testRetrievalNonce, BuyerSignature: nil},
	}
	for index, request := range structural {
		if err := ValidateContentRetrievalRequest(request); err == nil {
			t.Fatalf("structural Kind 10 case #%d validated", index)
		}
	}
}

func cborIndefiniteBstr() []byte {
	// (_ h'a' h'b')：不定长 bstr 子项必须被 strict decoder 拒绝。
	return []byte{0x5f, 0x41, 0x61, 0x41, 0x62, 0xff}
}

func TestContentRetrievalResponseEmbedsExactStoredBytesOnce(t *testing.T) {
	_, _, prepared, response := mustSignedCustodyPair(t)
	exactKind8, err := MarshalRequest(prepared.Request())
	if err != nil {
		t.Fatal(err)
	}
	exactKind9, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := BuildContentRetrievalResponse(exactKind8, exactKind9)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentRetrievalResponse(retrieval)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x84 || raw[1] != 0x04 || raw[2] != 0x0b {
		t.Fatalf("Kind 11 must be the four-element [4,11,...] array: %x", raw)
	}
	if !bytes.Equal(retrieval.ArbitrationRequestCBOR, exactKind8) || !bytes.Equal(retrieval.ArbitrationResponseCBOR, exactKind9) {
		t.Fatal("Kind 11 did not embed the exact persisted Kind 8/9 bytes verbatim")
	}
	decoded, err := UnmarshalContentRetrievalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ArbitrationRequestCBOR, exactKind8) || !bytes.Equal(decoded.ArbitrationResponseCBOR, exactKind9) {
		t.Fatal("embedded Kind 8/9 changed during round trip")
	}
	again, err := MarshalContentRetrievalResponse(decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("Kind 11 canonical round trip drifted")
	}
	// payload 只在内嵌 Kind 8 中出现一次，外壳不重复携带任何 payload 副本。
	payloads, err := bitfs.DecodeContentPayloads(mustKind8PayloadsCBOR(t, exactKind8))
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) == 0 {
		t.Fatal("test premise broken: bundle is empty")
	}
	if got := bytes.Count(raw, payloads[0]); got != 1 {
		t.Fatalf("payload bytes appear %d times in Kind 11, want exactly once", got)
	}
	if _, err := UnmarshalContentRetrievalResponse(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("Kind 11 decoder accepted trailing bytes")
	}
	if _, err := UnmarshalContentRetrievalResponse(bytes.Repeat([]byte{0}, MaxContentRetrievalResponseBytes+1)); err == nil {
		t.Fatal("oversized Kind 11 was decoded")
	}
}

func mustKind8PayloadsCBOR(t *testing.T, exactKind8 []byte) []byte {
	t.Helper()
	request, err := UnmarshalRequest(exactKind8)
	if err != nil {
		t.Fatal(err)
	}
	return request.ContentPayloadsCBOR
}

func TestContentRetrievalResponseRejectsHostileChildren(t *testing.T) {
	_, _, prepared, response := mustSignedCustodyPair(t)
	exactKind8, err := MarshalRequest(prepared.Request())
	if err != nil {
		t.Fatal(err)
	}
	exactKind9, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	validStruct, err := BuildContentRetrievalResponse(exactKind8, exactKind9)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := MarshalContentRetrievalResponse(validStruct)
	if err != nil {
		t.Fatal(err)
	}
	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "foreign")}, [][]byte{[]byte("foreign")})
	_, foreignPrepared := mustSignPrepared(t, other)
	foreignKind8, err := MarshalRequest(foreignPrepared.Request())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"wrong version":   mustMarshal(t, []any{uint64(MajorVersion + 1), kindContentRetrievalResponse, bstr(exactKind8), bstr(exactKind9)}),
		"wrong kind":      mustMarshal(t, []any{MajorVersion, uint64(9), bstr(exactKind8), bstr(exactKind9)}),
		"three elements":  mustEncodeArray(t, []any{MajorVersion, kindContentRetrievalResponse, bstr(exactKind8)}),
		"five elements":   mustEncodeArray(t, []any{MajorVersion, kindContentRetrievalResponse, bstr(exactKind8), bstr(exactKind9), bstr(exactKind8)}),
		"tag wrapped":     append([]byte{0xc0}, valid...),
		"indefinite arr":  append(append([]byte{0x9f}, valid...), 0xff),
		"truncated kind8": mustMarshal(t, []any{MajorVersion, kindContentRetrievalResponse, bstr(exactKind8[:len(exactKind8)-1]), bstr(exactKind9)}),
		"truncated kind9": mustMarshal(t, []any{MajorVersion, kindContentRetrievalResponse, bstr(exactKind8), bstr(exactKind9[:len(exactKind9)-1])}),
		"oversized kind8": mustMarshal(t, []any{MajorVersion, kindContentRetrievalResponse, bstr(make([]byte, MaxArbitrationRequestBytes+1)), bstr(exactKind9)}),
	}
	for name, rawCase := range cases {
		if _, err := UnmarshalContentRetrievalResponse(rawCase); err == nil {
			t.Fatalf("%s Kind 11 case decoded", name)
		}
	}
	if _, err := BuildContentRetrievalResponse(exactKind8, exactKind9[:len(exactKind9)-1]); err == nil {
		t.Fatal("builder accepted a corrupt exact Kind 9")
	}
	// 解码器只保证两份子文档各自 canonical；跨记录拼接由完整证据验证拒绝。
	if _, err := BuildContentRetrievalResponse(foreignKind8, exactKind9); err == nil {
		t.Fatal("builder accepted a Kind 8/9 pair from two different records")
	}
}

func TestVerifyCustodiedContentRejectsTamperedEvidence(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	baseRequest := prepared.Request()
	claimID, err := ArbitrationClaimID(baseRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}

	// 回执属于另一个 Claim：拼接另一条记录的 Receipt 必须失败。
	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "other")}, [][]byte{[]byte("other")})
	_, preparedOther := mustSignPrepared(t, other)
	responseOther, err := workflow.SignPreparedPayment(context.Background(), preparedOther)
	if err != nil {
		t.Fatal(err)
	}
	spliced := &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: responseOther.ReceiptCBOR, ArbiterReceiptSignature: responseOther.ArbiterReceiptSignature}
	if _, err := VerifyCustodiedContent(baseRequest, spliced); err == nil {
		t.Fatal("a foreign receipt satisfied the custody chain")
	}

	// Seller Claim 签名被篡改：完整验证在任何回执比较之前拒绝。
	badSellerSig := cloneRequest(baseRequest)
	badSellerSig.SellerClaimSignature[len(badSellerSig.SellerClaimSignature)-1] ^= 1
	if _, err := VerifyCustodiedContent(badSellerSig, response); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("tampered Seller Claim signature accepted: %v", err)
	}

	// payload 篡改：hash 链断裂必须拒绝。
	tamperedBundle, err := bitfs.EncodeContentPayloads([][]byte{[]byte("tampered")})
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload := cloneRequest(baseRequest)
	tamperedPayload.ContentPayloadsCBOR = tamperedBundle
	if _, err := VerifyCustodiedContent(tamperedPayload, response); err == nil {
		t.Fatal("tampered payload bundle satisfied the custody chain")
	}

	// 回执费用篡改（重签回执消息签名但不改交易签名）：交易签名验证必须失败。
	receipt, err := UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	arbiterKey := evidence.keys[2]
	reFee := cloneReceipt(receipt)
	reFee.ArbiterAmountSat += 7
	reFeeCBOR, err := MarshalReceipt(reFee)
	if err != nil {
		t.Fatal(err)
	}
	reFeeDomain, err := ArbiterReceiptSigningCBOR(reFeeCBOR)
	if err != nil {
		t.Fatal(err)
	}
	reFeeSig, err := bitfs.SignMessage(arbiterKey, reFeeDomain)
	if err != nil {
		t.Fatal(err)
	}
	reFeeResponse := &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: reFeeCBOR, ArbiterReceiptSignature: reFeeSig}
	if _, err := VerifyCustodiedContent(baseRequest, reFeeResponse); err == nil {
		t.Fatal("a re-signed receipt with a different fee satisfied the transaction binding")
	}

	// 交易签名翻转：候选重建后的验证必须失败。
	flipped := cloneReceipt(receipt)
	flipped.ArbiterTransactionSignature[len(flipped.ArbiterTransactionSignature)-1] ^= 1
	flippedCBOR, err := MarshalReceipt(flipped)
	if err != nil {
		t.Fatal(err)
	}
	flippedDomain, err := ArbiterReceiptSigningCBOR(flippedCBOR)
	if err != nil {
		t.Fatal(err)
	}
	flippedSig, err := bitfs.SignMessage(arbiterKey, flippedDomain)
	if err != nil {
		t.Fatal(err)
	}
	flippedResponse := &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: flippedCBOR, ArbiterReceiptSignature: flippedSig}
	if _, err := VerifyCustodiedContent(baseRequest, flippedResponse); err == nil {
		t.Fatal("a flipped transaction signature satisfied the rebuilt candidate")
	}

	// 正向基线：未篡改证据完整通过，且全部返回值是 deep copy。
	verified, err := VerifyCustodiedContent(baseRequest, response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified.ClaimID, claimID) || len(verified.Payloads) == 0 {
		t.Fatal("verified custody content is incomplete")
	}
	firstPayload := append([]byte(nil), verified.Payloads[0]...)
	verified.Payloads[0][len(verified.Payloads[0])-1] ^= 1
	second, err := VerifyCustodiedContent(baseRequest, response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.Payloads[0], firstPayload) {
		t.Fatal("VerifyCustodiedContent returned internal references")
	}
	verified.Receipt.ClaimID[0] ^= 1
	if bytes.Equal(verified.Receipt.ClaimID, second.Receipt.ClaimID) {
		t.Fatal("Receipt pointer is not deep-copied between calls")
	}
	verified.Request.SellerClaimSignature[0] ^= 1
	if bytes.Equal(verified.Request.SellerClaimSignature, second.Request.SellerClaimSignature) {
		t.Fatal("Request pointer is not deep-copied between calls")
	}
	verified.Response.ArbiterReceiptSignature[0] ^= 1
	if bytes.Equal(verified.Response.ArbiterReceiptSignature, second.Response.ArbiterReceiptSignature) {
		t.Fatal("Response pointer is not deep-copied between calls")
	}
	verified.PayloadsCBOR[len(verified.PayloadsCBOR)-1] ^= 1
	if bytes.Equal(verified.PayloadsCBOR, second.PayloadsCBOR) {
		t.Fatal("PayloadsCBOR is not deep-copied between calls")
	}
}

func TestVerifyContentRetrievalRequestAuthenticatesBuyer(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	storedRequest := prepared.Request()
	claimID, err := ArbitrationClaimID(storedRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	retrieval := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	if _, err := workflow.VerifyContentRetrievalRequest(retrieval, storedRequest, response); err != nil {
		t.Fatalf("legitimate buyer retrieval was rejected: %v", err)
	}

	// 跨 Claim ID 重放：同一签名换一个 Claim ID 必须失败。
	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "cross")}, [][]byte{[]byte("cross")})
	otherID, err := ArbitrationClaimID(other.request.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	crossClaim := &ContentRetrievalRequest{Version: MajorVersion, ClaimID: append([]byte(nil), otherID...), Nonce: append([]byte(nil), testRetrievalNonce...), BuyerSignature: append([]byte(nil), retrieval.BuyerSignature...)}
	if _, err := workflow.VerifyContentRetrievalRequest(crossClaim, storedRequest, response); err == nil {
		t.Fatal("Kind 10 signature was replayed across Claim IDs")
	}

	// 跨 nonce 重放。
	otherNonce := bytes.Repeat([]byte{0xcd}, RetrievalNonceBytes)
	crossNonce := &ContentRetrievalRequest{Version: MajorVersion, ClaimID: append([]byte(nil), claimID...), Nonce: append([]byte(nil), otherNonce...), BuyerSignature: append([]byte(nil), retrieval.BuyerSignature...)}
	if _, err := workflow.VerifyContentRetrievalRequest(crossNonce, storedRequest, response); err == nil {
		t.Fatal("Kind 10 signature was replayed across nonces")
	}

	// 错误买家密钥。
	attacker := mustKey(t, "99")
	attackerSigning, err := BuyerRetrievalSigningCBOR(claimID, testRetrievalNonce)
	if err != nil {
		t.Fatal(err)
	}
	attackerSig, err := bitfs.SignMessage(attacker, attackerSigning)
	if err != nil {
		t.Fatal(err)
	}
	forged := &ContentRetrievalRequest{Version: MajorVersion, ClaimID: append([]byte(nil), claimID...), Nonce: append([]byte(nil), testRetrievalNonce...), BuyerSignature: attackerSig}
	if _, err := workflow.VerifyContentRetrievalRequest(forged, storedRequest, response); err == nil {
		t.Fatal("a foreign buyer key authorized retrieval")
	}

	// 错误仲裁方 workflow key。
	wrongArbiter, err := NewWorkflow(WorkflowConfig{PrivateKey: mustKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongArbiter.VerifyContentRetrievalRequest(retrieval, storedRequest, response); err == nil {
		t.Fatal("another arbiter served this custody record")
	}
}

// forceSignCustodyResponse reproduces exactly what an arbiter's two-phase
// signing produced while the record was still inside its deadline/refund
// gates: the same internal time-independent core rebuilds the candidate and
// both signatures follow the fixed order. It never fakes a clock or height.
func forceSignCustodyResponse(t *testing.T, request *ArbitrationRequest, arbiterKey *ec.PrivateKey) *ArbitrationResponse {
	t.Helper()
	local := cloneRequest(request)
	claim, _, _, unsigned, claimID, _, keys, err := validateRequestEvidence(local, testArbitrationFeeSat)
	if err != nil {
		t.Fatalf("premise broken: expired evidence fails structural verification: %v", err)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	arbiterTxSig, err := engine.SignArbitrationArbiterPayment(context.Background(), unsigned, arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.ArbiterPubKey, arbiterKey.PubKey().Compressed()) {
		t.Fatal("premise broken: role keys do not match the signing arbiter")
	}
	receipt := &ArbitrationReceipt{ClaimID: append([]byte(nil), claimID...), ArbiterAmountSat: testArbitrationFeeSat, ArbiterTransactionSignature: append([]byte(nil), arbiterTxSig...)}
	receiptCBOR, err := MarshalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := ArbiterReceiptSigningCBOR(receiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bitfs.SignMessage(arbiterKey, domain)
	if err != nil {
		t.Fatal(err)
	}
	return &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: receiptCBOR, ArbiterReceiptSignature: sig}
}

// TestExpiredCustodyEvidenceRemainsVerifiable proves post-hoc recovery is
// time-independent: a custody pair the arbiter legally signed before its
// delivery deadline and refund maturity still fully verifies — and authorizes
// retrieval — long after both gates passed, with no fake clock or block height.
func TestExpiredCustodyEvidenceRemainsVerifiable(t *testing.T) {
	now := time.Now().UTC()
	expiredLock := uint32(now.Add(-time.Hour).Unix())
	expiredDeadline := now.Add(-30 * time.Minute).Unix()
	keys := [3]*ec.PrivateKey{mustKey(t, "11"), mustKey(t, "22"), mustKey(t, "33")}
	evidence := makeArbitrationEvidenceWithPayloadsAndTimes(t,
		keys, [][]byte{mustDigest(t, "expired-custody")}, [][]byte{[]byte("expired-custody")},
		expiredLock, expiredDeadline)

	// 前提确认：当前时间门禁确实拒绝这份证据。
	if _, err := mustArbiterWorkflow(t).PreparePayment(context.Background(), cloneRequest(evidence.request), 900000, testArbitrationFeeSat); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("premise broken: expired evidence still prepares: %v", err)
	}
	response := forceSignCustodyResponse(t, evidence.request, keys[2])
	verified, err := VerifyCustodiedContent(evidence.request, response)
	if err != nil {
		t.Fatalf("signed custody evidence became unverifiable after expiry: %v", err)
	}
	if len(verified.Payloads) != 1 || string(verified.Payloads[0]) != "expired-custody" {
		t.Fatal("verified payloads do not match the custodied batch")
	}
	retrieval := mustRetrievalRequest(t, evidence, verified.ClaimID, testRetrievalNonce)
	if _, err := mustArbiterWorkflow(t).VerifyContentRetrievalRequest(retrieval, evidence.request, response); err != nil {
		t.Fatalf("post-deadline retrieval of signed custody evidence failed: %v", err)
	}
}

func TestBuildContentRetrievalResponseReturnsDeepCopies(t *testing.T) {
	_, _, prepared, response := mustSignedCustodyPair(t)
	exactKind8, err := MarshalRequest(prepared.Request())
	if err != nil {
		t.Fatal(err)
	}
	exactKind9, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	inputCopy8 := append([]byte(nil), exactKind8...)
	inputCopy9 := append([]byte(nil), exactKind9...)
	first, err := BuildContentRetrievalResponse(exactKind8, exactKind9)
	if err != nil {
		t.Fatal(err)
	}
	first.ArbitrationRequestCBOR[len(first.ArbitrationRequestCBOR)-1] ^= 1
	first.ArbitrationResponseCBOR[0] ^= 1
	second, err := BuildContentRetrievalResponse(exactKind8, exactKind9)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.ArbitrationRequestCBOR, inputCopy8) || !bytes.Equal(second.ArbitrationResponseCBOR, inputCopy9) {
		t.Fatal("BuildContentRetrievalResponse exposed internal references")
	}
	if !bytes.Equal(exactKind8, inputCopy8) || !bytes.Equal(exactKind9, inputCopy9) {
		t.Fatal("input buffers were mutated by the builder")
	}
}

// TestVerifyCustodiedContentRejectsWrongVersionStructs pins shell validation
// for direct Go-struct callers: a Kind 9 struct carrying a wrong version must
// be rejected by the same truth as the wire decoder, even when its inner
// Kind 9 document is fully valid — decoding children alone is not enough.
func TestVerifyCustodiedContentRejectsWrongVersionStructs(t *testing.T) {
	_, workflow, prepared, response := mustSignedCustodyPair(t)
	baseRequest := prepared.Request()
	receiptCopy := append([]byte(nil), response.ReceiptCBOR...)
	sigCopy := append([]byte(nil), response.ArbiterReceiptSignature...)

	for version := range map[uint64]string{MajorVersion + 1: "future", 0: "zero", MajorVersion - 1: "past"} {
		badShell := &ArbitrationResponse{Version: version, ReceiptCBOR: append([]byte(nil), receiptCopy...), ArbiterReceiptSignature: append([]byte(nil), sigCopy...)}
		if _, err := VerifyCustodiedContent(baseRequest, badShell); err == nil {
			t.Fatalf("version %d Kind 9 struct was accepted", version)
		}
	}

	// 同样约束 Workflow 入口：存储响应版本错误时整个鉴权失败。
	evidence := makeArbitrationEvidence(t)
	claimID, err := ArbitrationClaimID(baseRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	retrieval := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	badShell := &ArbitrationResponse{Version: MajorVersion + 1, ReceiptCBOR: append([]byte(nil), receiptCopy...), ArbiterReceiptSignature: append([]byte(nil), sigCopy...)}
	if _, err := workflow.VerifyContentRetrievalRequest(retrieval, baseRequest, badShell); err == nil {
		t.Fatal("wrong-version stored response satisfied the retrieval authentication")
	}

	// 正向基线：正确版本的同一对证据通过。
	goodShell := &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: append([]byte(nil), receiptCopy...), ArbiterReceiptSignature: append([]byte(nil), sigCopy...)}
	if _, err := VerifyCustodiedContent(baseRequest, goodShell); err != nil {
		t.Fatalf("valid struct pair rejected: %v", err)
	}
}

// TestVerifyContentRetrievalRequestSnapshotsCallerBuffers proves the verifier
// clones the Kind 10 input before any validation work: mutating the caller's
// buffers after a successful call cannot invalidate the already-completed
// verification, and restoring them restores the original outcome.
func TestVerifyContentRetrievalRequestSnapshotsCallerBuffers(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	storedRequest := prepared.Request()
	claimID, err := ArbitrationClaimID(storedRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimIDBuf := append([]byte(nil), claimID...)
	nonceBuf := append([]byte(nil), testRetrievalNonce...)
	signing, err := BuyerRetrievalSigningCBOR(claimIDBuf, nonceBuf)
	if err != nil {
		t.Fatal(err)
	}
	sigBuf, err := bitfs.SignMessage(evidence.keys[0], signing)
	if err != nil {
		t.Fatal(err)
	}
	request := &ContentRetrievalRequest{Version: MajorVersion, ClaimID: claimIDBuf, Nonce: nonceBuf, BuyerSignature: sigBuf}
	if _, err := workflow.VerifyContentRetrievalRequest(request, storedRequest, response); err != nil {
		t.Fatal(err)
	}
	// 验证完成后原地篡改调用方缓冲区，再恢复；两次调用结果都必须与快照语义一致。
	request.Nonce[len(request.Nonce)-1] ^= 1
	request.BuyerSignature[0] ^= 1
	if _, err := workflow.VerifyContentRetrievalRequest(request, storedRequest, response); err == nil {
		t.Fatal("tampered caller buffers were accepted, verifier did not read current content")
	}
	request.Nonce[len(request.Nonce)-1] ^= 1
	request.BuyerSignature[0] ^= 1
	if _, err := workflow.VerifyContentRetrievalRequest(request, storedRequest, response); err != nil {
		t.Fatalf("restored caller buffers no longer verify: %v", err)
	}
}
