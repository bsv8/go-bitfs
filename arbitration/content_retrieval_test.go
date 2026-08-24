package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
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

func mustRetrievalRequest(t *testing.T, evidence arbitrationEvidence, claimID protocol.ArbitrationClaimID, nonce []byte) *ContentRetrievalRequest {
	t.Helper()
	request, err := NewContentRetrievalRequest(claimID, nonce, evidence.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestContentRetrievalRequestShapeRoundTripAndSigningDomain(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	claimID, err := ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	raw, err := MarshalContentRetrievalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x0a {
		t.Fatalf("Kind 10 must be the four-element [1,10,...] array: %x", raw)
	}
	decoded, err := UnmarshalContentRetrievalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ContentRetrievalRequestCBOR, request.ContentRetrievalRequestCBOR) || !bytes.Equal(decoded.BuyerContentRetrievalRequestSignature, request.BuyerContentRetrievalRequestSignature) {
		t.Fatal("Kind 10 fields changed during round trip")
	}
	again, err := MarshalContentRetrievalRequest(decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("Kind 10 canonical round trip drifted")
	}
	if _, err := UnmarshalContentRetrievalRequest(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("Kind 10 decoder accepted trailing bytes")
	}
	// 签名域严格为统一 helper 的 [domain, 1, 10, request_cbor]。
	buyerPubKey := evidence.keys[0].PubKey().Compressed()
	if err := protocol.VerifyWireDocument(buyerPubKey, protocol.WireVersion, 10, request.ContentRetrievalRequestCBOR, request.BuyerContentRetrievalRequestSignature); err != nil {
		t.Fatal(err)
	}
	decodedClaimID, decodedNonce, err := DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if decodedClaimID != claimID || !bytes.Equal(decodedNonce, testRetrievalNonce) {
		t.Fatal("request document fields changed during round trip")
	}
	if err := bitfs.VerifySignature(buyerPubKey, claimID[:], request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("bare Claim ID was accepted as the signing domain")
	}
	if err := bitfs.VerifySignature(buyerPubKey, testRetrievalNonce, request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("bare nonce was accepted as the signing domain")
	}
	if err := bitfs.VerifySignature(buyerPubKey, raw, request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("the complete Kind 10 envelope was accepted as the signing domain")
	}
	if err := protocol.VerifyWireDocument(buyerPubKey, protocol.WireVersion, 11, request.ContentRetrievalRequestCBOR, request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("Kind 10 signature verified inside the Kind 11 signing context")
	}
}

func TestContentRetrievalLimitsAreDerivedFromChildLimits(t *testing.T) {
	wantRequest := 3 + maxSignatureBstrOverhead + maxContentRetrievalRequestDocBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes
	if MaxContentRetrievalRequestBytes != wantRequest {
		t.Fatalf("request wire limit drifted from the derived protocol value: %d", MaxContentRetrievalRequestBytes)
	}
	if MaxContentRetrievalRequestBytes != 334 {
		t.Fatalf("request wire limit drifted from the pinned protocol value: %d", MaxContentRetrievalRequestBytes)
	}
	if MaxContentRetrievalResponseBytes != MaxContentRetrievalAvailableBytes {
		t.Fatalf("response pre-allocation guard must equal the available branch limit")
	}
	if _, err := UnmarshalContentRetrievalRequest(bytes.Repeat([]byte{0}, MaxContentRetrievalRequestBytes+1)); err == nil {
		t.Fatal("oversized Kind 10 was decoded")
	}
}

func retrievalRequestIDHash(t *testing.T, request *ContentRetrievalRequest) protocol.ContentRetrievalRequestID {
	t.Helper()
	digest := sha256.Sum256(request.ContentRetrievalRequestCBOR)
	return protocol.ContentRetrievalRequestID(digest)
}

func TestContentRetrievalAvailableBranchRoundTripAndBinding(t *testing.T) {
	evidence, _, _, _ := mustSignedCustodyPair(t)
	claimID, err := ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)

	payloads := [][]byte{[]byte("custody-block-0"), []byte("custody-block-1")}
	payloadsCBOR, err := bitfs.EncodeContentPayloads(payloads)
	if err != nil {
		t.Fatal(err)
	}
	response, err := BuildContentRetrievalAvailableRaw(retrievalRequestIDHash(t, request), payloadsCBOR, evidence.keys[2])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentRetrievalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x85 || raw[1] != 0x01 || raw[2] != 0x0b {
		t.Fatalf("available Kind 11 must be the five-element [1,11,...] array: %x", raw)
	}
	decoded, err := UnmarshalContentRetrievalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ContentPayloadsCBOR, payloadsCBOR) {
		t.Fatal("payload attachment changed during round trip")
	}
	result, err := VerifyContentRetrievalResponse(request, evidence.keys[2].PubKey().Compressed(), decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Available || len(result.Payloads) != 2 || !bytes.Equal(result.Payloads[0], payloads[0]) || result.ContentRetrievalRequestID != retrievalRequestIDHash(t, request) {
		t.Fatalf("verified available result = %#v", result)
	}
	// payload 替换必须被 content_payloads_id 拒绝。
	tampered := cloneRetrievalResponse(decoded)
	tampered.ContentPayloadsCBOR = append([]byte(nil), tampered.ContentPayloadsCBOR...)
	tampered.ContentPayloadsCBOR[len(tampered.ContentPayloadsCBOR)-1] ^= 1
	if _, err := VerifyContentRetrievalResponse(request, evidence.keys[2].PubKey().Compressed(), tampered); err == nil {
		t.Fatal("tampered payload attachment satisfied the signed payload ID")
	}
	if err := protocol.VerifyWireDocument(evidence.keys[2].PubKey().Compressed(), protocol.WireVersion, 10, decoded.ContentRetrievalResultCBOR, decoded.ArbiterContentRetrievalResultSignature); err == nil {
		t.Fatal("Kind 11 signature verified inside the Kind 10 signing context")
	}
}

func TestContentRetrievalUnavailableBranchRoundTripAndReasons(t *testing.T) {
	evidence, _, _, _ := mustSignedCustodyPair(t)
	claimID, err := ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	requestID := retrievalRequestIDHash(t, request)

	for reason := range map[ContentRetrievalUnavailableReason]string{
		RetrievalSellerArbitrationNotReceived: "not_received",
		RetrievalSellerArbitrationNotReady:    "not_ready",
		RetrievalCustodyGone:                  "gone",
	} {
		response, err := BuildContentRetrievalUnavailable(requestID, reason, evidence.keys[2])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalContentRetrievalResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 3 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x0b {
			t.Fatalf("unavailable Kind 11 must be the four-element [1,11,...] array: %x", raw)
		}
		decoded, err := UnmarshalContentRetrievalResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		result, err := VerifyContentRetrievalResponse(request, evidence.keys[2].PubKey().Compressed(), decoded)
		if err != nil {
			t.Fatal(err)
		}
		if result.Available || result.Payloads != nil || result.PayloadsCBOR != nil {
			t.Fatalf("unavailable branch leaked attachment data: %#v", result)
		}
		view, err := DecodeContentRetrievalResultDocument(decoded.ContentRetrievalResultCBOR)
		if err != nil {
			t.Fatal(err)
		}
		if view.UnavailableReason != reason || view.ContentRetrievalRequestID != requestID {
			t.Fatalf("unavailable round trip drifted: %+v", view)
		}
	}

	// 未知原因与未知判别值必须被拒绝。
	badReason := mustMarshal(t, []any{bstr(requestID[:]), uint64(0), uint64(9)})
	if _, err := DecodeContentRetrievalResultDocument(badReason); err == nil {
		t.Fatal("unknown unavailable reason decoded")
	}
	badDiscriminator := mustMarshal(t, []any{bstr(requestID[:]), uint64(7), uint64(0)})
	if _, err := DecodeContentRetrievalResultDocument(badDiscriminator); err == nil {
		t.Fatal("unknown discriminator decoded")
	}
	shortPayloadID := mustMarshal(t, []any{bstr(requestID[:]), uint64(1), bstr(bytes.Repeat([]byte{1}, 31))})
	if _, err := DecodeContentRetrievalResultDocument(shortPayloadID); err == nil {
		t.Fatal("short content_payloads_id decoded")
	}
}

func TestContentRetrievalResponseRejectsBranchInconsistency(t *testing.T) {
	evidence, _, _, _ := mustSignedCustodyPair(t)
	claimID, err := ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	requestID := retrievalRequestIDHash(t, request)

	unavailable, err := BuildContentRetrievalUnavailable(requestID, RetrievalSellerArbitrationNotReady, evidence.keys[2])
	if err != nil {
		t.Fatal(err)
	}
	unavailableRaw, err := MarshalContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	smuggled, err := bitfs.EncodeContentPayloads([][]byte{[]byte("smuggled")})
	if err != nil {
		t.Fatal(err)
	}
	withAttachment := mustMarshal(t, []any{
		protocol.WireVersion, wireKindContentRetrievalResponse,
		bstr(unavailable.ContentRetrievalResultCBOR), bstr(unavailable.ArbiterContentRetrievalResultSignature),
		bstr(smuggled),
	})
	if _, err := UnmarshalContentRetrievalResponse(withAttachment); err == nil {
		t.Fatal("unavailable branch with attachment decoded")
	}

	available, err := BuildContentRetrievalAvailable(requestID, [][]byte{[]byte("block")}, evidence.keys[2])
	if err != nil {
		t.Fatal(err)
	}
	withoutAttachment := mustMarshal(t, []any{
		protocol.WireVersion, wireKindContentRetrievalResponse,
		bstr(available.ContentRetrievalResultCBOR), bstr(available.ArbiterContentRetrievalResultSignature),
	})
	if _, err := UnmarshalContentRetrievalResponse(withoutAttachment); err == nil {
		t.Fatal("available branch without attachment decoded")
	}
	if _, err := UnmarshalContentRetrievalResponse(mustEncodeArray(t, []any{protocol.WireVersion, wireKindContentRetrievalResponse, bstr(available.ContentRetrievalResultCBOR)})); err == nil {
		t.Fatal("three-element Kind 11 decoded")
	}
	wrongVersion := mustMarshal(t, []any{uint64(protocol.WireVersion + 1), wireKindContentRetrievalResponse, bstr(available.ContentRetrievalResultCBOR), bstr(available.ArbiterContentRetrievalResultSignature), bstr(available.ContentPayloadsCBOR)})
	if _, err := UnmarshalContentRetrievalResponse(wrongVersion); err == nil {
		t.Fatal("wrong wire version Kind 11 decoded")
	}
	wrongKind := mustMarshal(t, []any{protocol.WireVersion, wireKindArbitrationResponse, bstr(available.ContentRetrievalResultCBOR), bstr(available.ArbiterContentRetrievalResultSignature), bstr(available.ContentPayloadsCBOR)})
	if _, err := UnmarshalContentRetrievalResponse(wrongKind); err == nil {
		t.Fatal("Kind 9 body decoded as Kind 11")
	}
	if _, err := UnmarshalContentRetrievalResponse(append(append([]byte(nil), unavailableRaw...), 0)); err == nil {
		t.Fatal("Kind 11 decoder accepted trailing bytes")
	}
	if _, err := UnmarshalContentRetrievalResponse(bytes.Repeat([]byte{0}, MaxContentRetrievalResponseBytes+1)); err == nil {
		t.Fatal("oversized Kind 11 was decoded")
	}
	// 请求绑定：响应回答另一个请求 ID 必须失败。
	otherRequest := mustRetrievalRequest(t, evidence, claimID, bytes.Repeat([]byte{0xcd}, RetrievalNonceBytes))
	if _, err := VerifyContentRetrievalResponse(otherRequest, evidence.keys[2].PubKey().Compressed(), unavailable); err == nil {
		t.Fatal("a response answered a different retrieval request")
	}
}

func TestVerifyCustodiedContentRejectsTamperedEvidence(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	baseRequest := prepared.Request()
	claimID, err := ArbitrationClaimID(baseRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}

	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "other")}, [][]byte{[]byte("other")})
	_, preparedOther := mustSignPrepared(t, other)
	responseOther, err := workflow.SignPreparedPayment(context.Background(), preparedOther)
	if err != nil {
		t.Fatal(err)
	}
	spliced := &ArbitrationResponse{ArbitrationReceiptCBOR: responseOther.ArbitrationReceiptCBOR, ArbiterArbitrationReceiptSignature: responseOther.ArbiterArbitrationReceiptSignature}
	if _, err := VerifyCustodiedContent(baseRequest, spliced); err == nil {
		t.Fatal("a foreign receipt satisfied the custody chain")
	}

	badSellerSig := cloneRequest(baseRequest)
	badSellerSig.SellerArbitrationClaimSignature[len(badSellerSig.SellerArbitrationClaimSignature)-1] ^= 1
	if _, err := VerifyCustodiedContent(badSellerSig, response); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("tampered Seller Claim signature accepted: %v", err)
	}

	tamperedBundle, err := bitfs.EncodeContentPayloads([][]byte{[]byte("tampered")})
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload := cloneRequest(baseRequest)
	tamperedPayload.ContentPayloadsCBOR = tamperedBundle
	if _, err := VerifyCustodiedContent(tamperedPayload, response); err == nil {
		t.Fatal("tampered payload bundle satisfied the custody chain")
	}

	receipt, err := UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	arbiterKey := evidence.keys[2]
	reFee := cloneReceipt(receipt)
	reFee.ArbiterAmountSatoshis += 7
	reFeeCBOR, err := MarshalReceipt(reFee)
	if err != nil {
		t.Fatal(err)
	}
	reFeeSig, err := protocol.SignWireDocument(arbiterKey, protocol.WireVersion, 9, reFeeCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCustodiedContent(baseRequest, &ArbitrationResponse{ArbitrationReceiptCBOR: reFeeCBOR, ArbiterArbitrationReceiptSignature: reFeeSig}); err == nil {
		t.Fatal("a re-signed receipt with a different fee satisfied the transaction binding")
	}

	flipped := cloneReceipt(receipt)
	flipped.ArbiterPaymentTransactionSignature[len(flipped.ArbiterPaymentTransactionSignature)-1] ^= 1
	flippedCBOR, err := MarshalReceipt(flipped)
	if err != nil {
		t.Fatal(err)
	}
	flippedSig, err := protocol.SignWireDocument(arbiterKey, protocol.WireVersion, 9, flippedCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCustodiedContent(baseRequest, &ArbitrationResponse{ArbitrationReceiptCBOR: flippedCBOR, ArbiterArbitrationReceiptSignature: flippedSig}); err == nil {
		t.Fatal("a flipped transaction signature satisfied the rebuilt candidate")
	}

	verified, err := VerifyCustodiedContent(baseRequest, response)
	if err != nil {
		t.Fatal(err)
	}
	if verified.ArbitrationClaimID != claimID || len(verified.Payloads) == 0 {
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
	verified.Request.SellerArbitrationClaimSignature[0] ^= 1
	if bytes.Equal(verified.Request.SellerArbitrationClaimSignature, second.Request.SellerArbitrationClaimSignature) {
		t.Fatal("Request pointer is not deep-copied between calls")
	}
	verified.Response.ArbiterArbitrationReceiptSignature[0] ^= 1
	if bytes.Equal(verified.Response.ArbiterArbitrationReceiptSignature, second.Response.ArbiterArbitrationReceiptSignature) {
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
	claimID, err := ArbitrationClaimID(storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	retrieval := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	if _, err := workflow.VerifyContentRetrievalRequest(retrieval, storedRequest, response); err != nil {
		t.Fatalf("legitimate buyer retrieval was rejected: %v", err)
	}

	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "cross")}, [][]byte{[]byte("cross")})
	otherID, err := ArbitrationClaimID(other.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	crossDoc, err := EncodeContentRetrievalRequestDocument(otherID, testRetrievalNonce)
	if err != nil {
		t.Fatal(err)
	}
	crossClaim := &ContentRetrievalRequest{ContentRetrievalRequestCBOR: crossDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), retrieval.BuyerContentRetrievalRequestSignature...)}
	if _, err := workflow.VerifyContentRetrievalRequest(crossClaim, storedRequest, response); err == nil {
		t.Fatal("Kind 10 signature was replayed across Claim IDs")
	}

	otherNonce := bytes.Repeat([]byte{0xcd}, RetrievalNonceBytes)
	crossNonceDoc, err := EncodeContentRetrievalRequestDocument(claimID, otherNonce)
	if err != nil {
		t.Fatal(err)
	}
	crossNonce := &ContentRetrievalRequest{ContentRetrievalRequestCBOR: crossNonceDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), retrieval.BuyerContentRetrievalRequestSignature...)}
	if _, err := workflow.VerifyContentRetrievalRequest(crossNonce, storedRequest, response); err == nil {
		t.Fatal("Kind 10 signature was replayed across nonces")
	}

	forgedRequest, err := NewContentRetrievalRequest(claimID, testRetrievalNonce, mustKey(t, "99"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.VerifyContentRetrievalRequest(forgedRequest, storedRequest, response); err == nil {
		t.Fatal("a foreign buyer key authorized retrieval")
	}

	wrongArbiter, err := NewWorkflow(WorkflowConfig{PrivateKey: mustKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongArbiter.VerifyContentRetrievalRequest(retrieval, storedRequest, response); err == nil {
		t.Fatal("another arbiter served this custody record")
	}
}

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
	arbiterTransactionSignature, err := engine.SignArbitrationArbiterPayment(context.Background(), unsigned, arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.ArbiterPublicKey, arbiterKey.PubKey().Compressed()) {
		t.Fatal("premise broken: role keys do not match the signing arbiter")
	}
	receipt := &ArbitrationReceipt{ArbitrationClaimID: claimID, ArbiterAmountSatoshis: testArbitrationFeeSat, ArbiterPaymentTransactionSignature: append([]byte(nil), arbiterTransactionSignature...)}
	receiptCBOR, err := MarshalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignWireDocument(arbiterKey, protocol.WireVersion, 9, receiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return &ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR, ArbiterArbitrationReceiptSignature: sig}
}

func TestExpiredCustodyEvidenceRemainsVerifiable(t *testing.T) {
	now := time.Now().UTC()
	expiredLock := uint32(now.Add(-time.Hour).Unix())
	expiredDeadline := now.Add(-30 * time.Minute).Unix()
	keys := [3]*ec.PrivateKey{mustKey(t, "11"), mustKey(t, "22"), mustKey(t, "33")}
	evidence := makeArbitrationEvidenceWithPayloadsAndTimes(t,
		keys, [][]byte{mustDigest(t, "expired-custody")}, [][]byte{[]byte("expired-custody")},
		expiredLock, expiredDeadline)

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
	retrieval := mustRetrievalRequest(t, evidence, verified.ArbitrationClaimID, testRetrievalNonce)
	if _, err := mustArbiterWorkflow(t).VerifyContentRetrievalRequest(retrieval, evidence.request, response); err != nil {
		t.Fatalf("post-deadline retrieval of signed custody evidence failed: %v", err)
	}
}

func TestVerifyContentRetrievalRequestSnapshotsCallerBuffers(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	storedRequest := prepared.Request()
	claimID, err := ArbitrationClaimID(storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	requestBuf, err := EncodeContentRetrievalRequestDocument(claimID, testRetrievalNonce)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.SignWireDocument(evidence.keys[0], protocol.WireVersion, 10, requestBuf)
	if err != nil {
		t.Fatal(err)
	}
	request := &ContentRetrievalRequest{ContentRetrievalRequestCBOR: requestBuf, BuyerContentRetrievalRequestSignature: signature}
	if _, err := workflow.VerifyContentRetrievalRequest(request, storedRequest, response); err != nil {
		t.Fatal(err)
	}
	request.ContentRetrievalRequestCBOR[len(request.ContentRetrievalRequestCBOR)-1] ^= 1
	request.BuyerContentRetrievalRequestSignature[0] ^= 1
	if _, err := workflow.VerifyContentRetrievalRequest(request, storedRequest, response); err == nil {
		t.Fatal("tampered caller buffers were accepted, verifier did not read current content")
	}
	request.ContentRetrievalRequestCBOR[len(request.ContentRetrievalRequestCBOR)-1] ^= 1
	request.BuyerContentRetrievalRequestSignature[0] ^= 1
	if _, err := workflow.VerifyContentRetrievalRequest(request, storedRequest, response); err != nil {
		t.Fatalf("restored caller buffers no longer verify: %v", err)
	}
}
