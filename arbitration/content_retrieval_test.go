package arbitration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/flowtest/arbiter"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

// testRetrievalNonce 是显式 nonce 的底层入口所用的固定重放键。
var testRetrievalNonce = mustNonce(bytes.Repeat([]byte{0xab}, arbitration.RetrievalNonceBytes))

func mustNonce(raw []byte) protocol.RetrievalNonce {
	nonce, err := protocol.NewRetrievalNonce(raw)
	if err != nil {
		panic(err)
	}
	return nonce
}

func mustSignedCustodyPair(t *testing.T) (arbitrationEvidence, *arbiter.Workflow, *arbiter.PreparedArbitration, *arbitration.ArbitrationResponse) {
	t.Helper()
	evidence := makeArbitrationEvidence(t)
	workflow, prepared := mustSignPrepared(t, evidence)
	response := signPrepared(t, workflow, prepared)
	return evidence, workflow, prepared, response
}

// signPrepared 完成持久化后的签名步骤，并把 Kind 9 Artifact 解码为应答 DTO。
func signPrepared(t *testing.T, workflow *arbiter.Workflow, prepared *arbiter.PreparedArbitration) *arbitration.ArbitrationResponse {
	t.Helper()
	return signPreparedWithFacts(t, workflow, testFacts(), prepared)
}

func signPreparedWithFacts(t *testing.T, workflow *arbiter.Workflow, facts protocol.Facts, prepared *arbiter.PreparedArbitration) *arbitration.ArbitrationResponse {
	t.Helper()
	artifact, err := workflow.SignPreparedArbitration(context.Background(), facts, prepared)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbitration.UnmarshalResponse(artifact.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func mustRetrievalRequest(t *testing.T, evidence arbitrationEvidence, claimID protocol.ArbitrationClaimID, nonce protocol.RetrievalNonce) *arbitration.ContentRetrievalRequest {
	t.Helper()
	request, err := arbitration.NewContentRetrievalRequest(context.Background(), claimID, nonce, mustSigner(t, evidence.keys[0]))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestContentRetrievalRequestShapeRoundTripAndSigningDomain(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	claimID, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	raw, err := arbitration.MarshalContentRetrievalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x0a {
		t.Fatalf("Kind 10 must be the four-element [1,10,...] array: %x", raw)
	}
	decoded, err := arbitration.UnmarshalContentRetrievalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ContentRetrievalRequestCBOR, request.ContentRetrievalRequestCBOR) || !bytes.Equal(decoded.BuyerContentRetrievalRequestSignature, request.BuyerContentRetrievalRequestSignature) {
		t.Fatal("Kind 10 fields changed during round trip")
	}
	again, err := arbitration.MarshalContentRetrievalRequest(decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("Kind 10 canonical round trip drifted")
	}
	if _, err := arbitration.UnmarshalContentRetrievalRequest(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("Kind 10 decoder accepted trailing bytes")
	}
	// 签名域严格为统一 helper 的 [domain, 1, 10, request_cbor]。
	buyerPubKey := evidence.keys[0].PubKey().Compressed()
	if err := protocol.VerifyWireDocument(buyerPubKey, protocol.WireVersion, 10, request.ContentRetrievalRequestCBOR, request.BuyerContentRetrievalRequestSignature); err != nil {
		t.Fatal(err)
	}
	decodedClaimID, decodedNonce, err := arbitration.DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if decodedClaimID != claimID || !bytes.Equal(decodedNonce, testRetrievalNonce.Bytes()) {
		t.Fatal("request document fields changed during round trip")
	}
	if err := protocol.VerifyMessageSignature(buyerPubKey, claimID[:], request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("bare Claim ID was accepted as the signing domain")
	}
	if err := protocol.VerifyMessageSignature(buyerPubKey, testRetrievalNonce.Bytes(), request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("bare nonce was accepted as the signing domain")
	}
	if err := protocol.VerifyMessageSignature(buyerPubKey, raw, request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("the complete Kind 10 envelope was accepted as the signing domain")
	}
	if err := protocol.VerifyWireDocument(buyerPubKey, protocol.WireVersion, 11, request.ContentRetrievalRequestCBOR, request.BuyerContentRetrievalRequestSignature); err == nil {
		t.Fatal("Kind 10 signature verified inside the Kind 11 signing context")
	}
}

func TestContentRetrievalLimitsAreDerivedFromChildLimits(t *testing.T) {
	wantRequest := 3 + arbitration.MaxSignatureBstrOverheadForTest + arbitration.MaxContentRetrievalRequestDocBytesForTest + arbitration.MaxSignatureBstrOverheadForTest + arbitration.MaxArbitrationSignatureBytes
	if arbitration.MaxContentRetrievalRequestBytes != wantRequest {
		t.Fatalf("request wire limit drifted from the derived protocol value: %d", arbitration.MaxContentRetrievalRequestBytes)
	}
	if arbitration.MaxContentRetrievalRequestBytes != 334 {
		t.Fatalf("request wire limit drifted from the pinned protocol value: %d", arbitration.MaxContentRetrievalRequestBytes)
	}
	if arbitration.MaxContentRetrievalResponseBytes != arbitration.MaxContentRetrievalAvailableBytes {
		t.Fatalf("response pre-allocation guard must equal the available branch limit")
	}
	if _, err := arbitration.UnmarshalContentRetrievalRequest(bytes.Repeat([]byte{0}, arbitration.MaxContentRetrievalRequestBytes+1)); err == nil {
		t.Fatal("oversized Kind 10 was decoded")
	}
}

func retrievalRequestIDHash(t *testing.T, request *arbitration.ContentRetrievalRequest) protocol.ContentRetrievalRequestID {
	t.Helper()
	digest := sha256.Sum256(request.ContentRetrievalRequestCBOR)
	return protocol.ContentRetrievalRequestID(digest)
}

func TestContentRetrievalAvailableBranchRoundTripAndBinding(t *testing.T) {
	evidence, _, _, _ := mustSignedCustodyPair(t)
	claimID, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)

	payloads := [][]byte{[]byte("custody-block-0"), []byte("custody-block-1")}
	payloadsCBOR, err := content.EncodeContentPayloads(payloads)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbitration.BuildContentRetrievalAvailableRaw(context.Background(), retrievalRequestIDHash(t, request), payloadsCBOR, mustSigner(t, evidence.keys[2]))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := arbitration.MarshalContentRetrievalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x85 || raw[1] != 0x01 || raw[2] != 0x0b {
		t.Fatalf("available Kind 11 must be the five-element [1,11,...] array: %x", raw)
	}
	decoded, err := arbitration.UnmarshalContentRetrievalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ContentPayloadsCBOR, payloadsCBOR) {
		t.Fatal("payload attachment changed during round trip")
	}
	result, err := arbitration.VerifyContentRetrievalResponse(request, evidence.keys[2].PubKey().Compressed(), decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Available || len(result.Payloads) != 2 || !bytes.Equal(result.Payloads[0], payloads[0]) || result.ContentRetrievalRequestID != retrievalRequestIDHash(t, request) {
		t.Fatalf("verified available result = %#v", result)
	}
	// payload 替换必须被 content_payloads_id 拒绝。
	tampered := arbitration.CloneContentRetrievalResponse(decoded)
	tampered.ContentPayloadsCBOR = append([]byte(nil), tampered.ContentPayloadsCBOR...)
	tampered.ContentPayloadsCBOR[len(tampered.ContentPayloadsCBOR)-1] ^= 1
	if _, err := arbitration.VerifyContentRetrievalResponse(request, evidence.keys[2].PubKey().Compressed(), tampered); err == nil {
		t.Fatal("tampered payload attachment satisfied the signed payload ID")
	}
	if err := protocol.VerifyWireDocument(evidence.keys[2].PubKey().Compressed(), protocol.WireVersion, 10, decoded.ContentRetrievalResultCBOR, decoded.ArbiterContentRetrievalResultSignature); err == nil {
		t.Fatal("Kind 11 signature verified inside the Kind 10 signing context")
	}
}

func TestContentRetrievalUnavailableBranchRoundTripAndReasons(t *testing.T) {
	evidence, _, _, _ := mustSignedCustodyPair(t)
	claimID, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	requestID := retrievalRequestIDHash(t, request)

	for reason := range map[arbitration.ContentRetrievalUnavailableReason]string{
		arbitration.RetrievalSellerArbitrationNotReceived: "not_received",
		arbitration.RetrievalSellerArbitrationNotReady:    "not_ready",
		arbitration.RetrievalCustodyGone:                  "gone",
	} {
		response, err := arbitration.BuildContentRetrievalUnavailable(context.Background(), requestID, reason, mustSigner(t, evidence.keys[2]))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := arbitration.MarshalContentRetrievalResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 3 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x0b {
			t.Fatalf("unavailable Kind 11 must be the four-element [1,11,...] array: %x", raw)
		}
		decoded, err := arbitration.UnmarshalContentRetrievalResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		// valid unavailable 是已验签的协议结果：不返回 error，返回 typed result。
		result, err := arbitration.VerifyContentRetrievalResponse(request, evidence.keys[2].PubKey().Compressed(), decoded)
		if err != nil {
			t.Fatalf("valid unavailable branch returned an error: %v", err)
		}
		if result.Available || result.Payloads != nil || result.PayloadsCBOR != nil {
			t.Fatalf("unavailable branch leaked attachment data: %#v", result)
		}
		if result.UnavailableReason != reason {
			t.Fatalf("unavailable reason drifted: got %d, want %d", result.UnavailableReason, reason)
		}
		view, err := arbitration.DecodeContentRetrievalResultDocument(decoded.ContentRetrievalResultCBOR)
		if err != nil {
			t.Fatal(err)
		}
		if view.UnavailableReason != reason || view.ContentRetrievalRequestID != requestID {
			t.Fatalf("unavailable round trip drifted: %+v", view)
		}
	}

	// 未知原因与未知判别值必须被拒绝。
	badReason := mustMarshal(t, []any{arbitration.BstrForTest(requestID[:]), uint64(0), uint64(9)})
	if _, err := arbitration.DecodeContentRetrievalResultDocument(badReason); err == nil {
		t.Fatal("unknown unavailable reason decoded")
	}
	badDiscriminator := mustMarshal(t, []any{arbitration.BstrForTest(requestID[:]), uint64(7), uint64(0)})
	if _, err := arbitration.DecodeContentRetrievalResultDocument(badDiscriminator); err == nil {
		t.Fatal("unknown discriminator decoded")
	}
	shortPayloadID := mustMarshal(t, []any{arbitration.BstrForTest(requestID[:]), uint64(1), arbitration.BstrForTest(bytes.Repeat([]byte{1}, 31))})
	if _, err := arbitration.DecodeContentRetrievalResultDocument(shortPayloadID); err == nil {
		t.Fatal("short content_payloads_id decoded")
	}
}

func TestContentRetrievalResponseRejectsBranchInconsistency(t *testing.T) {
	evidence, _, _, _ := mustSignedCustodyPair(t)
	claimID, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	requestID := retrievalRequestIDHash(t, request)

	unavailable, err := arbitration.BuildContentRetrievalUnavailable(context.Background(), requestID, arbitration.RetrievalSellerArbitrationNotReady, mustSigner(t, evidence.keys[2]))
	if err != nil {
		t.Fatal(err)
	}
	unavailableRaw, err := arbitration.MarshalContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	smuggled, err := content.EncodeContentPayloads([][]byte{[]byte("smuggled")})
	if err != nil {
		t.Fatal(err)
	}
	withAttachment := mustMarshal(t, []any{
		protocol.WireVersion, uint64(11),
		arbitration.BstrForTest(unavailable.ContentRetrievalResultCBOR), arbitration.BstrForTest(unavailable.ArbiterContentRetrievalResultSignature),
		arbitration.BstrForTest(smuggled),
	})
	if _, err := arbitration.UnmarshalContentRetrievalResponse(withAttachment); err == nil {
		t.Fatal("unavailable branch with attachment decoded")
	}

	available, err := arbitration.BuildContentRetrievalAvailable(context.Background(), requestID, [][]byte{[]byte("block")}, mustSigner(t, evidence.keys[2]))
	if err != nil {
		t.Fatal(err)
	}
	withoutAttachment := mustMarshal(t, []any{
		protocol.WireVersion, uint64(11),
		arbitration.BstrForTest(available.ContentRetrievalResultCBOR), arbitration.BstrForTest(available.ArbiterContentRetrievalResultSignature),
	})
	if _, err := arbitration.UnmarshalContentRetrievalResponse(withoutAttachment); err == nil {
		t.Fatal("available branch without attachment decoded")
	}
	if _, err := arbitration.UnmarshalContentRetrievalResponse(mustEncodeArray(t, []any{protocol.WireVersion, uint64(11), arbitration.BstrForTest(available.ContentRetrievalResultCBOR)})); err == nil {
		t.Fatal("three-element Kind 11 decoded")
	}
	wrongVersion := mustMarshal(t, []any{uint64(protocol.WireVersion + 1), uint64(11), arbitration.BstrForTest(available.ContentRetrievalResultCBOR), arbitration.BstrForTest(available.ArbiterContentRetrievalResultSignature), arbitration.BstrForTest(available.ContentPayloadsCBOR)})
	if _, err := arbitration.UnmarshalContentRetrievalResponse(wrongVersion); err == nil {
		t.Fatal("wrong wire version Kind 11 decoded")
	}
	wrongKind := mustMarshal(t, []any{protocol.WireVersion, uint64(9), arbitration.BstrForTest(available.ContentRetrievalResultCBOR), arbitration.BstrForTest(available.ArbiterContentRetrievalResultSignature), arbitration.BstrForTest(available.ContentPayloadsCBOR)})
	if _, err := arbitration.UnmarshalContentRetrievalResponse(wrongKind); err == nil {
		t.Fatal("Kind 9 body decoded as Kind 11")
	}
	if _, err := arbitration.UnmarshalContentRetrievalResponse(append(append([]byte(nil), unavailableRaw...), 0)); err == nil {
		t.Fatal("Kind 11 decoder accepted trailing bytes")
	}
	if _, err := arbitration.UnmarshalContentRetrievalResponse(bytes.Repeat([]byte{0}, arbitration.MaxContentRetrievalResponseBytes+1)); err == nil {
		t.Fatal("oversized Kind 11 was decoded")
	}
	// 请求绑定：响应回答另一个请求 ID 必须失败。
	otherRequest := mustRetrievalRequest(t, evidence, claimID, mustNonce(bytes.Repeat([]byte{0xcd}, arbitration.RetrievalNonceBytes)))
	if _, err := arbitration.VerifyContentRetrievalResponse(otherRequest, evidence.keys[2].PubKey().Compressed(), unavailable); err == nil {
		t.Fatal("a response answered a different retrieval request")
	}
}

func TestVerifyCustodiedContentRejectsTamperedEvidence(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	baseRequest := prepared.Request()
	claimID, err := arbitration.ArbitrationClaimID(baseRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}

	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "other")}, [][]byte{[]byte("other")})
	_, preparedOther := mustSignPrepared(t, other)
	responseOther := signPrepared(t, workflow, preparedOther)
	spliced := &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: responseOther.ArbitrationReceiptCBOR, ArbiterArbitrationReceiptSignature: responseOther.ArbiterArbitrationReceiptSignature}
	if _, err := arbitration.VerifyCustodiedContent(baseRequest, spliced); err == nil {
		t.Fatal("a foreign receipt satisfied the custody chain")
	}

	badSellerSig := arbitration.CloneRequest(baseRequest)
	badSellerSig.SellerArbitrationClaimSignature[len(badSellerSig.SellerArbitrationClaimSignature)-1] ^= 1
	if _, err := arbitration.VerifyCustodiedContent(badSellerSig, response); !protocol.IsCode(err, protocol.CodeInvalidSignature) {
		t.Fatalf("tampered Seller Claim signature accepted: %v", err)
	}

	tamperedBundle, err := content.EncodeContentPayloads([][]byte{[]byte("tampered")})
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload := arbitration.CloneRequest(baseRequest)
	tamperedPayload.ContentPayloadsCBOR = tamperedBundle
	if _, err := arbitration.VerifyCustodiedContent(tamperedPayload, response); err == nil {
		t.Fatal("tampered payload bundle satisfied the custody chain")
	}

	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	arbiterKey := evidence.keys[2]
	reFee := cloneReceiptForTest(receipt)
	reFee.ArbiterAmountSatoshis += 7
	reFeeCBOR, err := arbitration.MarshalReceipt(reFee)
	if err != nil {
		t.Fatal(err)
	}
	reFeeSig, err := protocol.SignWireDocument(context.Background(), mustSigner(t, arbiterKey), protocol.WireVersion, 9, reFeeCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.VerifyCustodiedContent(baseRequest, &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: reFeeCBOR, ArbiterArbitrationReceiptSignature: reFeeSig}); err == nil {
		t.Fatal("a re-signed receipt with a different fee satisfied the transaction binding")
	}

	flipped := cloneReceiptForTest(receipt)
	flipped.ArbiterPaymentTransactionSignature[len(flipped.ArbiterPaymentTransactionSignature)-1] ^= 1
	flippedCBOR, err := arbitration.MarshalReceipt(flipped)
	if err != nil {
		t.Fatal(err)
	}
	flippedSig, err := protocol.SignWireDocument(context.Background(), mustSigner(t, arbiterKey), protocol.WireVersion, 9, flippedCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.VerifyCustodiedContent(baseRequest, &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: flippedCBOR, ArbiterArbitrationReceiptSignature: flippedSig}); err == nil {
		t.Fatal("a flipped transaction signature satisfied the rebuilt candidate")
	}

	verified, err := arbitration.VerifyCustodiedContent(baseRequest, response)
	if err != nil {
		t.Fatal(err)
	}
	if verified.ArbitrationClaimID != claimID || len(verified.Payloads) == 0 {
		t.Fatal("verified custody content is incomplete")
	}
	firstPayload := append([]byte(nil), verified.Payloads[0]...)
	verified.Payloads[0][len(verified.Payloads[0])-1] ^= 1
	second, err := arbitration.VerifyCustodiedContent(baseRequest, response)
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

func TestAuthenticateContentRetrievalRequestAuthenticatesBuyer(t *testing.T) {
	evidence, workflow, prepared, response := mustSignedCustodyPair(t)
	storedRequest := prepared.Request()
	claimID, err := arbitration.ArbitrationClaimID(storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	retrieval := mustRetrievalRequest(t, evidence, claimID, testRetrievalNonce)
	arbiterPublicKey := evidence.keys[2].PubKey().Compressed()
	if err := arbitration.AuthenticateContentRetrievalRequest(retrieval, storedRequest, arbiterPublicKey); err != nil {
		t.Fatalf("legitimate buyer retrieval was rejected: %v", err)
	}
	// 角色级全链入口（含已签 Kind 9 托管证据）同样通过。
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrieval)
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := arbitration.MarshalRequest(storedRequest)
	if err != nil {
		t.Fatal(err)
	}
	rawKind9, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.VerifyRetrievableCustody(rawKind10, rawKind8, rawKind9); err != nil {
		t.Fatalf("full custody verification rejected a legitimate buyer: %v", err)
	}

	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "cross")}, [][]byte{[]byte("cross")})
	otherID, err := arbitration.ArbitrationClaimID(other.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	crossDoc, err := arbitration.EncodeContentRetrievalRequestDocument(otherID, testRetrievalNonce.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	crossClaim := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: crossDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), retrieval.BuyerContentRetrievalRequestSignature...)}
	if err := arbitration.AuthenticateContentRetrievalRequest(crossClaim, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("Kind 10 signature was replayed across Claim IDs")
	}

	otherNonce := bytes.Repeat([]byte{0xcd}, arbitration.RetrievalNonceBytes)
	crossNonceDoc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, otherNonce)
	if err != nil {
		t.Fatal(err)
	}
	crossNonce := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: crossNonceDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), retrieval.BuyerContentRetrievalRequestSignature...)}
	if err := arbitration.AuthenticateContentRetrievalRequest(crossNonce, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("Kind 10 signature was replayed across nonces")
	}

	forgedRequest, err := arbitration.NewContentRetrievalRequest(context.Background(), claimID, testRetrievalNonce, mustSigner(t, mustKey(t, "99")))
	if err != nil {
		t.Fatal(err)
	}
	if err := arbitration.AuthenticateContentRetrievalRequest(forgedRequest, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("a foreign buyer key authorized retrieval")
	}

	wrongArbiter := mustArbiterWorkflowWithKey(t, "44")
	if err := arbitration.AuthenticateContentRetrievalRequest(retrieval, storedRequest, wrongArbiter.PublicKey()); err == nil {
		t.Fatal("another arbiter served this custody record")
	}
	if _, err := wrongArbiter.VerifyRetrievableCustody(rawKind10, rawKind8, rawKind9); err == nil {
		t.Fatal("another arbiter verified this custody record through the role API")
	}
}

func forceSignCustodyResponse(t *testing.T, request *arbitration.ArbitrationRequest, arbiterKey *ec.PrivateKey) *arbitration.ArbitrationResponse {
	t.Helper()
	local := arbitration.CloneRequest(request)
	claim, _, _, unsigned, claimID, _, keys, err := arbitration.ValidateRequestEvidence(local, testArbitrationFeeSat)
	if err != nil {
		t.Fatalf("premise broken: expired evidence fails structural verification: %v", err)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	arbiterTransactionSignature, err := engine.SignArbitrationArbiterPayment(context.Background(), unsigned, mustSigner(t, arbiterKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.ArbiterPublicKey, arbiterKey.PubKey().Compressed()) {
		t.Fatal("premise broken: role keys do not match the signing arbiter")
	}
	receipt := &arbitration.ArbitrationReceipt{ArbitrationClaimID: claimID, ArbiterAmountSatoshis: testArbitrationFeeSat, ArbiterPaymentTransactionSignature: append([]byte(nil), arbiterTransactionSignature...)}
	receiptCBOR, err := arbitration.MarshalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignWireDocument(context.Background(), mustSigner(t, arbiterKey), protocol.WireVersion, 9, receiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR, ArbiterArbitrationReceiptSignature: sig}
}

func TestExpiredCustodyEvidenceRemainsVerifiable(t *testing.T) {
	now := time.Now().UTC()
	expiredLock := uint32(now.Add(-time.Hour).Unix())
	expiredDeadline := now.Add(-30 * time.Minute).Unix()
	keys := [3]*ec.PrivateKey{mustKey(t, "11"), mustKey(t, "22"), mustKey(t, "33")}
	evidence := makeArbitrationEvidenceWithPayloadsAndTimes(t,
		keys, [][]byte{mustDigest(t, "expired-custody")}, [][]byte{[]byte("expired-custody")},
		expiredLock, expiredDeadline)

	rawKind8, err := arbitration.MarshalRequest(cloneExpiredEvidence(t, evidence))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mustArbiterWorkflow(t).PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("premise broken: expired evidence still prepares (want expired): %v", err)
	}
	response := forceSignCustodyResponse(t, evidence.request, keys[2])
	verified, err := arbitration.VerifyCustodiedContent(evidence.request, response)
	if err != nil {
		t.Fatalf("signed custody evidence became unverifiable after expiry: %v", err)
	}
	if len(verified.Payloads) != 1 || string(verified.Payloads[0]) != "expired-custody" {
		t.Fatal("verified payloads do not match the custodied batch")
	}
	retrieval := mustRetrievalRequest(t, evidence, verified.ArbitrationClaimID, testRetrievalNonce)
	if err := arbitration.AuthenticateContentRetrievalRequest(retrieval, evidence.request, keys[2].PubKey().Compressed()); err != nil {
		t.Fatalf("post-deadline retrieval of signed custody evidence failed: %v", err)
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrieval)
	if err != nil {
		t.Fatal(err)
	}
	if err := mustArbiterWorkflow(t).AuthenticateRetrieval(rawKind10, rawKind8); err != nil {
		t.Fatalf("role-level post-deadline authentication failed: %v", err)
	}
}

// cloneExpiredEvidence 深拷贝过期证据，避免共享缓冲被 Prepare 内部克隆边界掩盖问题。
func cloneExpiredEvidence(t *testing.T, evidence arbitrationEvidence) *arbitration.ArbitrationRequest {
	t.Helper()
	cloned := arbitration.CloneRequest(evidence.request)
	if cloned == nil {
		t.Fatal("clone of expired evidence failed")
	}
	return cloned
}

func TestAuthenticateContentRetrievalRequestSnapshotsCallerBuffers(t *testing.T) {
	evidence, _, prepared, _ := mustSignedCustodyPair(t)
	storedRequest := prepared.Request()
	claimID, err := arbitration.ArbitrationClaimID(storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	requestBuf, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, testRetrievalNonce.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.SignWireDocument(context.Background(), mustSigner(t, evidence.keys[0]), protocol.WireVersion, 10, requestBuf)
	if err != nil {
		t.Fatal(err)
	}
	request := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: requestBuf, BuyerContentRetrievalRequestSignature: signature}
	arbiterPublicKey := evidence.keys[2].PubKey().Compressed()
	if err := arbitration.AuthenticateContentRetrievalRequest(request, storedRequest, arbiterPublicKey); err != nil {
		t.Fatal(err)
	}
	request.ContentRetrievalRequestCBOR[len(request.ContentRetrievalRequestCBOR)-1] ^= 1
	request.BuyerContentRetrievalRequestSignature[0] ^= 1
	if err := arbitration.AuthenticateContentRetrievalRequest(request, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("tampered caller buffers were accepted, verifier did not read current content")
	}
	request.ContentRetrievalRequestCBOR[len(request.ContentRetrievalRequestCBOR)-1] ^= 1
	request.BuyerContentRetrievalRequestSignature[0] ^= 1
	if err := arbitration.AuthenticateContentRetrievalRequest(request, storedRequest, arbiterPublicKey); err != nil {
		t.Fatalf("restored caller buffers no longer verify: %v", err)
	}
}
