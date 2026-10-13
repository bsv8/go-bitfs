package arbitration_test

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
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/flowtest/arbiter"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

const testArbitrationFeeSat uint64 = 500

// testFacts 返回满足托管门控的显式事实：Now 必须早于证据默认的一小时后交付
// 截止时间；BlockHeight 非零以满足退款模板到期比较所需的高度事实。
func testFacts() protocol.Facts {
	return protocol.Facts{Now: time.Now(), BlockHeight: 900000}
}

// mustSigner 把测试私钥包装成受约束 protocol.Signer（所有签名入口统一收 Signer）。
func mustSigner(t *testing.T, key *ec.PrivateKey) protocol.Signer {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// mustArbiterWorkflowWithKey 用指定重复字节私钥构造 Arbiter 角色工作流。
func mustArbiterWorkflowWithKey(t *testing.T, repeated string) *arbiter.Workflow {
	t.Helper()
	workflow, err := arbiter.NewWorkflow(mustSigner(t, mustKey(t, repeated)))
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

type arbitrationEvidence struct {
	request *arbitration.ArbitrationRequest
	proof   *pool.OpeningProof
	keys    [3]*ec.PrivateKey
}

func TestV1ArbitrationWireShapeAndSigningDomains(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	raw, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x85 || raw[1] != 0x01 || raw[2] != 0x08 {
		t.Fatalf("Kind 8 request must be a five-element [1,8,...] array: %x", raw)
	}
	decoded, err := arbitration.UnmarshalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ArbitrationClaimCBOR, evidence.request.ArbitrationClaimCBOR) || !bytes.Equal(decoded.ContentPayloadsCBOR, evidence.request.ContentPayloadsCBOR) {
		t.Fatal("request evidence changed during round trip")
	}
	if _, err := arbitration.UnmarshalRequest(append(raw, 0)); err == nil {
		t.Fatal("request decoder accepted trailing bytes")
	}
	if err := protocol.VerifyWireDocument(evidence.keys[1].PubKey().Compressed(), protocol.WireVersion, 8, evidence.request.ArbitrationClaimCBOR, evidence.request.SellerArbitrationClaimSignature); err != nil {
		t.Fatal(err)
	}
	// 裸 Claim 文档不是签名预映像：统一域签名不能通过普通消息验证。
	if err := protocol.VerifyMessageSignature(evidence.keys[1].PubKey().Compressed(), evidence.request.ArbitrationClaimCBOR, evidence.request.SellerArbitrationClaimSignature); err == nil {
		t.Fatal("Seller Claim signature verified over the bare Claim document")
	}
	// 跨 Kind 换壳必须失败。
	if err := protocol.VerifyWireDocument(evidence.keys[1].PubKey().Compressed(), protocol.WireVersion, 9, evidence.request.ArbitrationClaimCBOR, evidence.request.SellerArbitrationClaimSignature); err == nil {
		t.Fatal("Kind 8 signature verified inside the Kind 9 signing context")
	}
}

func TestPrepareThenSignProducesCustodyReceiptAndTransactionEvidence(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow := mustArbiterWorkflow(t)
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	facts := testFacts()
	prepared, err := workflow.PrepareArbitration(facts, rawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.ArbitrationClaimID()) != sha256.Size || len(prepared.PaymentAuthorizationID()) != sha256.Size {
		t.Fatal("prepared commitments are incomplete")
	}
	if prepared.FeeSatoshis() != protocol.Satoshis(testArbitrationFeeSat) {
		t.Fatalf("prepared fee drifted: %d", prepared.FeeSatoshis())
	}
	unsigned := mustUnsignedForPrepared(t, prepared)
	if unsigned.ArbiterAmountSatoshis != testArbitrationFeeSat {
		t.Fatalf("unsigned candidate fee = %d, want %d", unsigned.ArbiterAmountSatoshis, testArbitrationFeeSat)
	}
	requestCopy := prepared.Request()
	requestCopy.ArbitrationClaimCBOR[0] ^= 1
	if bytes.Equal(requestCopy.ArbitrationClaimCBOR, prepared.Request().ArbitrationClaimCBOR) {
		t.Fatal("prepared request getter was not a deep copy")
	}
	unsignedCopy := mustUnsignedForPrepared(t, prepared)
	unsignedCopy.RawTx[0] ^= 1
	if bytes.Equal(unsignedCopy.RawTx, mustUnsignedForPrepared(t, prepared).RawTx) {
		t.Fatal("rebuilt unsigned candidate was not isolated from prior mutations")
	}
	response := signPreparedWithFacts(t, workflow, facts, prepared)
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbitrationClaimID != prepared.ArbitrationClaimID() || receipt.ArbiterAmountSatoshis != uint64(prepared.FeeSatoshis()) || !bytes.Equal(receipt.ArbiterPaymentTransactionSignature, signedTxSignature(response)) {
		t.Fatal("receipt did not preserve the frozen Claim ID, fee, and transaction signature")
	}
	if err := protocol.VerifyWireDocument(evidence.keys[2].PubKey().Compressed(), protocol.WireVersion, 9, response.ArbitrationReceiptCBOR, response.ArbiterArbitrationReceiptSignature); err != nil {
		t.Fatal(err)
	}
	raw, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x09 {
		t.Fatalf("Kind 9 response must be a four-element [1,9,...] array: %x", raw)
	}
}

// mustUnsignedForPrepared 从 prepared 的 exact Kind 8 视图按冻结费用独立重建
// 未签名 candidate（UnsignedPayment getter 已删除，重建是唯一只读入口）。
func mustUnsignedForPrepared(t *testing.T, prepared *arbiter.PreparedArbitration) *pool.UnsignedPayment {
	t.Helper()
	_, _, _, unsigned, _, _, _, err := arbitration.ValidateRequestEvidence(prepared.Request(), uint64(prepared.FeeSatoshis()))
	if err != nil {
		t.Fatal(err)
	}
	return unsigned
}

func signedTxSignature(response *arbitration.ArbitrationResponse) []byte {
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		panic(err)
	}
	return receipt.ArbiterPaymentTransactionSignature
}

func TestArbitrationClaimIDGoldenBinding(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	claimID, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(evidence.request.ArbitrationClaimCBOR)
	if claimID != protocol.ArbitrationClaimID(digest) {
		t.Fatal("Claim ID is not SHA-256 of the exact claim document")
	}
	fullRequest, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	requestID := sha256.Sum256(fullRequest)
	if claimID == protocol.ArbitrationClaimID(requestID) {
		t.Fatal("Claim ID must not be the complete Kind 8 envelope hash")
	}
	// Claim ID 必须随 exact claim 字节变化，且对同一字节保持稳定。
	again, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil || claimID != again {
		t.Fatal("Claim ID computation was not deterministic")
	}
}

func TestPrepareRejectsWrongArbiterBeforeCustody(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	wrongArbiter := mustArbiterWorkflowWithKey(t, "44")
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := wrongArbiter.PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err == nil {
		t.Fatal("wrong arbiter received custody evidence")
	}
	if !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong arbiter error = %v, want unauthorized", err)
	}
	if prepared != nil {
		t.Fatal("wrong arbiter returned prepared evidence")
	}
}

func TestPrepareRejectsZeroFeeBeforeAnyEvidenceWork(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow := mustArbiterWorkflow(t)
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PrepareArbitration(testFacts(), rawKind8, 0)
	if err == nil {
		t.Fatal("zero arbitration fee was accepted by PrepareArbitration")
	}
	if !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("zero-fee error = %v, want invalid_evidence", err)
	}
	if prepared != nil {
		t.Fatal("zero-fee prepare returned prepared evidence")
	}
	if _, err := workflow.PrepareArbitration(testFacts(), rawKind8, 1<<62); !protocol.IsCode(err, protocol.CodeInsufficientBalance) {
		t.Fatalf("fee exceeding pool balance error = %v, want insufficient_balance", err)
	}
}

func TestLegacyFiveElementKind9AndWrongKindsReject(t *testing.T) {
	legacyResult, err := arbitration.DeterministicEncForTest().Marshal([]any{
		bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	// 完整的旧五元 Kind 9 外壳：[4, 9, result_cbor, result_sig, tx_sig]。
	legacyResponse, err := arbitration.DeterministicEncForTest().Marshal([]any{
		uint64(4), uint64(9), arbitration.BstrForTest(legacyResult), arbitration.BstrForTest(bytes.Repeat([]byte{7}, 70)), arbitration.BstrForTest(bytes.Repeat([]byte{8}, 70)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalResponse(legacyResponse); err == nil {
		t.Fatal("legacy five-element Kind 9 decoded")
	}
	legacyRequest, err := arbitration.DeterministicEncForTest().Marshal([]any{
		uint64(4), bytes.Repeat([]byte{1}, 32), []byte{2}, []byte{3}, []byte{4}, []byte{5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalRequest(legacyRequest); err == nil {
		t.Fatal("legacy six-element request decoded")
	}
	evidence := makeArbitrationEvidence(t)
	raw, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalResponse(raw); err == nil {
		t.Fatal("Kind 8 body decoded as Kind 9")
	}
	responseRaw, err := arbitration.MarshalResponse(mustSignedResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalRequest(responseRaw); err == nil {
		t.Fatal("Kind 9 body decoded as Kind 8")
	}
}

func TestArbitrationWireLimitsRejectBeforeUnboundedDecode(t *testing.T) {
	limit := arbitration.MaxArbitrationRequestBytes
	if _, err := arbitration.UnmarshalRequest(bytes.Repeat([]byte{0}, limit+1)); err == nil {
		t.Fatal("oversized arbitration request was decoded")
	}
	want := content.MaxContentPayloadsCBORBytes + arbitration.MaxArbitrationClaimBytes + arbitration.MaxArbitrationSignatureBytes + arbitration.MaxArbitrationRequestEnvelopeBytesForTest
	if limit != want {
		t.Fatalf("request wire limit drifted from the protocol child limits: %d", limit)
	}
	if limit != 16843609 {
		t.Fatalf("request wire limit drifted from the pinned protocol value: %d", limit)
	}
	if _, err := arbitration.UnmarshalClaim(bytes.Repeat([]byte{0}, arbitration.MaxArbitrationClaimBytes+1)); err == nil {
		t.Fatal("oversized arbitration Claim was decoded")
	}
	if _, err := arbitration.UnmarshalResponse(bytes.Repeat([]byte{0}, arbitration.MaxArbitrationResponseBytes+1)); err == nil {
		t.Fatal("oversized arbitration response was decoded")
	}
	if _, err := arbitration.UnmarshalReceipt(bytes.Repeat([]byte{0}, arbitration.MaxArbitrationReceiptBytes+1)); err == nil {
		t.Fatal("oversized arbitration receipt was decoded")
	}

	oversizedTerms, err := arbitration.DeterministicEncForTest().Marshal([]any{
		uint64(100000), bytes.Repeat([]byte{1}, 105), bytes.Repeat([]byte{2}, 64),
		bytes.Repeat([]byte{3}, arbitration.MaxArbitrationAuthorizationBytes+1), bytes.Repeat([]byte{4}, 70),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalClaim(oversizedTerms); err == nil {
		t.Fatal("oversized nested FileQuoteTermsCBOR was accepted")
	}

	invalidClaimID, err := arbitration.DeterministicEncForTest().Marshal([]any{bytes.Repeat([]byte{1}, 31), uint64(1), arbitration.BstrForTest(bytes.Repeat([]byte{2}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalReceipt(invalidClaimID); err == nil {
		t.Fatal("31-byte Claim ID was accepted")
	}
	wideClaimID, err := arbitration.DeterministicEncForTest().Marshal([]any{bytes.Repeat([]byte{1}, 33), uint64(1), arbitration.BstrForTest(bytes.Repeat([]byte{2}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalReceipt(wideClaimID); err == nil {
		t.Fatal("33-byte Claim ID was accepted")
	}
}

func TestReceiptWireLimitsAreDerivedFromChildLimits(t *testing.T) {
	if want := 1 + 34 + 9 + 259; arbitration.MaxArbitrationReceiptBytes != want {
		t.Fatalf("receipt wire limit drifted from the derived protocol value: %d", arbitration.MaxArbitrationReceiptBytes)
	}
	if arbitration.MaxArbitrationReceiptBytes != 303 {
		t.Fatalf("receipt wire limit drifted from the pinned protocol value: %d", arbitration.MaxArbitrationReceiptBytes)
	}
	if want := 1 + 1 + 1 + (3 + arbitration.MaxArbitrationReceiptBytes) + (3 + arbitration.MaxArbitrationSignatureBytes); arbitration.MaxArbitrationResponseBytes != want {
		t.Fatalf("response wire limit drifted from the derived protocol value: %d", arbitration.MaxArbitrationResponseBytes)
	}
	if arbitration.MaxArbitrationResponseBytes != 568 {
		t.Fatalf("response wire limit drifted from the pinned protocol value: %d", arbitration.MaxArbitrationResponseBytes)
	}
}

func TestReceiptRoundTripAndStrictDecoding(t *testing.T) {
	response := mustSignedResponse(t)
	raw, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := arbitration.UnmarshalResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ArbitrationReceiptCBOR, response.ArbitrationReceiptCBOR) || !bytes.Equal(decoded.ArbiterArbitrationReceiptSignature, response.ArbiterArbitrationReceiptSignature) {
		t.Fatal("response fields changed during round trip")
	}
	receiptRaw, err := arbitration.MarshalReceipt(&arbitration.ArbitrationReceipt{ArbitrationClaimID: protocol.ArbitrationClaimID(bytes.Repeat([]byte{1}, 32)), ArbiterAmountSatoshis: 42, ArbiterPaymentTransactionSignature: bytes.Repeat([]byte{3}, 70)})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	canonicalAgain, err := arbitration.MarshalReceipt(receipt)
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
		"oversized tx sig":    mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 32), uint64(5), bytes.Repeat([]byte{3}, arbitration.MaxArbitrationSignatureBytes+1)),
		"short claim id":      mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 31), uint64(5), bytes.Repeat([]byte{3}, 70)),
		"long claim id":       mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 33), uint64(5), bytes.Repeat([]byte{3}, 70)),
		"text claim id":       mustEncodeReceipt(t, "not-bytes", uint64(5), bytes.Repeat([]byte{3}, 70)),
		"negative amount":     mustEncodeReceipt(t, bytes.Repeat([]byte{1}, 32), int64(-1), bytes.Repeat([]byte{3}, 70)),
		"non-shortest amount": mustMarshal(t, []any{arbitration.BstrForTest(bytes.Repeat([]byte{1}, 32)), cborTaggedUint(), arbitration.BstrForTest(bytes.Repeat([]byte{3}, 70))}),
	}
	for name, rawCase := range negativeCases {
		if _, err := arbitration.UnmarshalReceipt(rawCase); err == nil {
			t.Fatalf("%s receipt case decoded: %x", name, rawCase)
		}
	}
	// Response-level strictness: wrong version/kind and trailing bytes.
	wrongVersion, err := arbitration.DeterministicEncForTest().Marshal([]any{uint64(2), uint64(9), arbitration.BstrForTest(receiptRaw), arbitration.BstrForTest(bytes.Repeat([]byte{7}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalResponse(wrongVersion); err == nil {
		t.Fatal("wrong response version decoded")
	}
	wrongKind, err := arbitration.DeterministicEncForTest().Marshal([]any{protocol.WireVersion, uint64(8), arbitration.BstrForTest(receiptRaw), arbitration.BstrForTest(bytes.Repeat([]byte{7}, 70))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalResponse(wrongKind); err == nil {
		t.Fatal("wrong response kind decoded")
	}
	if _, err := arbitration.UnmarshalResponse(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatal("response decoder accepted trailing bytes")
	}
	emptySigResponse := &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: append([]byte(nil), response.ArbitrationReceiptCBOR...), ArbiterArbitrationReceiptSignature: nil}
	if _, err := arbitration.MarshalResponse(emptySigResponse); err == nil {
		t.Fatal("empty receipt signature was accepted")
	}
}

func cborTaggedUint() []byte {
	// 非最短整数编码（0x19 00 05 表示 5）必须被 strict decoder 拒绝。
	return []byte{0x19, 0x00, 0x05}
}

func mustEncodeReceipt(t *testing.T, claimID any, amount any, txSig any) []byte {
	t.Helper()
	raw, err := arbitration.DeterministicEncForTest().Marshal([]any{claimID, amount, wrapBstr(txSig)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustEncodeReceiptParts(t *testing.T, count int) []byte {
	t.Helper()
	items := make([]any, count)
	for index := range items {
		items[index] = arbitration.BstrForTest(bytes.Repeat([]byte{1}, 32))
	}
	raw, err := arbitration.DeterministicEncForTest().Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustMarshal(t *testing.T, values []any) []byte {
	t.Helper()
	raw, err := arbitration.DeterministicEncForTest().Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wrapBstr(value any) any {
	if raw, ok := value.([]byte); ok {
		return arbitration.BstrForTest(raw)
	}
	return value
}

func mustSignedResponse(t *testing.T) *arbitration.ArbitrationResponse {
	t.Helper()
	evidence := makeArbitrationEvidence(t)
	workflow := mustArbiterWorkflow(t)
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	return signPreparedWithFacts(t, workflow, testFacts(), prepared)
}

func TestPrepareRejectsPayloadMismatchBeforeSigning(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	tamperedBundle, err := content.EncodeContentPayloads([][]byte{[]byte("tampered")})
	if err != nil {
		t.Fatal(err)
	}
	evidence.request.ContentPayloadsCBOR = tamperedBundle
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mustArbiterWorkflow(t).PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("payload hash mismatch was accepted: %v", err)
	}
}

func TestArbitrationRequestAcceptsFullSizePayloadBundles(t *testing.T) {
	for _, count := range []int{2, content.MaxContentBatchItems} {
		payloads := make([][]byte, count)
		digests := make([][]byte, count)
		for index := range payloads {
			payload := bytes.Repeat([]byte{byte(index + 1)}, int(content.BlockSize))
			payloads[index] = payload
			digest := sha256.Sum256(payload)
			digests[index] = digest[:]
		}
		evidence := makeArbitrationEvidenceWithPayloads(t, digests, payloads)
		raw, err := arbitration.MarshalRequest(evidence.request)
		if err != nil {
			t.Fatalf("legal %d-payload request exceeded the wire limit: %v", count, err)
		}
		if len(raw) <= 384*1024 {
			t.Fatalf("%d-payload request regressed below the retired 384 KiB quota: %d bytes", count, len(raw))
		}
		decoded, err := arbitration.UnmarshalRequest(raw)
		if err != nil {
			t.Fatalf("legal %d-payload request was rejected: %v", count, err)
		}
		if !bytes.Equal(decoded.ContentPayloadsCBOR, evidence.request.ContentPayloadsCBOR) || !bytes.Equal(decoded.ArbitrationClaimCBOR, evidence.request.ArbitrationClaimCBOR) {
			t.Fatalf("%d-payload request changed during round trip", count)
		}
		if len(raw) > arbitration.MaxArbitrationRequestBytes || arbitration.MaxArbitrationRequestBytes > 16+arbitration.MaxArbitrationClaimBytes+arbitration.MaxArbitrationSignatureBytes+content.MaxContentPayloadsCBORBytes {
			t.Fatalf("%d-payload request length %d violates the derived limit %d", count, len(raw), arbitration.MaxArbitrationRequestBytes)
		}
		if count != content.MaxContentBatchItems {
			continue
		}
		// wire 层边界：合法满载 Kind 8 必须能通过全局解析上限进入 typed
		// decoder；超限 1 字节必须在 ParseAs 阶段被拒绝。
		if _, err = wire.ParseAs(wire.ArbitrationRequest, raw); err != nil {
			t.Fatalf("legal full-size kind8 rejected by wire.ParseAs: %v", err)
		}
		if _, err = wire.ParseAs(wire.ArbitrationRequest, append(append([]byte(nil), raw...), 0)); err == nil {
			t.Fatal("wire.ParseAs accepted a kind8 one byte beyond the limit")
		}
	}
}

func TestArbitrationRejectsPayloadCountBoundaries(t *testing.T) {
	evidence := makeArbitrationEvidence(t)

	empty, err := arbitration.DeterministicEncForTest().Marshal([]any{})
	if err != nil {
		t.Fatal(err)
	}
	rejected := arbitration.CloneRequest(evidence.request)
	rejected.ContentPayloadsCBOR = empty
	if _, err := arbitration.MarshalRequest(rejected); err == nil {
		t.Fatal("zero-payload bundle was accepted")
	}
	if _, err := arbitration.UnmarshalRequest(mustMarshalRequest(t, rejected)); err == nil {
		t.Fatal("zero-payload request was decoded")
	}

	items := make([]any, content.MaxContentBatchItems+1)
	for index := range items {
		items[index] = bytes.Repeat([]byte{byte(index + 1)}, 16)
	}
	oversized, err := arbitration.DeterministicEncForTest().Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	rejected = arbitration.CloneRequest(evidence.request)
	rejected.ContentPayloadsCBOR = oversized
	if _, err := arbitration.MarshalRequest(rejected); err == nil {
		t.Fatal("65-payload bundle was accepted")
	}
	if _, err := arbitration.UnmarshalRequest(mustMarshalRequest(t, rejected)); err == nil {
		t.Fatal("65-payload request was decoded")
	}
}

func mustMarshalRequest(t *testing.T, request *arbitration.ArbitrationRequest) []byte {
	t.Helper()
	raw, err := arbitration.DeterministicEncForTest().Marshal([]any{protocol.WireVersion, uint64(8), arbitration.BstrForTest(request.ArbitrationClaimCBOR), arbitration.BstrForTest(request.SellerArbitrationClaimSignature), arbitration.BstrForTest(request.ContentPayloadsCBOR)})
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
	ctx := context.Background()
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPublicKey: keys[0].PubKey().Compressed(), SellerPublicKey: keys[1].PubKey().Compressed(), ArbiterPublicKey: keys[2].PubKey().Compressed()})
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
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: keys[0].PubKey().Compressed(), SellerPublicKey: keys[1].PubKey().Compressed(), ArbiterPublicKey: keys[2].PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := pool.NewBuyerPoolAdapter(engine, mustSigner(t, keys[0])).BuildRefundPresignRequest(ctx, pool.OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: expiryLockTime, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: keys[1].PubKey().Compressed(), ArbiterPublicKey: keys[2].PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := pool.NewSellerPoolAdapter(engine, mustSigner(t, keys[1])).SignSellerRefund(ctx, presign)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(presign, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	refundID, err := pool.DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := content.EncodeContentHashes(digests)
	if err != nil {
		t.Fatal(err)
	}
	signedAuthorization, err := content.NewSignedContentRequest(ctx, &content.PaymentAuthorization{FileQuoteTermsID: protocol.FileQuoteTermsID(bytes.Repeat([]byte{1}, 32)), RefundTemplateTxID: refundID[:], PaymentSequence: 3, SellerAmountAfterSatoshis: 100, ContentHashesCBOR: hashes, DeliveryDeadlineUnixSeconds: deliveryDeadlineUnix}, mustSigner(t, keys[0]))
	if err != nil {
		t.Fatal(err)
	}
	details, err := pool.DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	claimCBOR, err := arbitration.MarshalClaim(&arbitration.ArbitrationClaim{PoolOutputSatoshis: details.PoolOutputSatoshis, PoolOutputLockingScript: details.PoolLockingScript, RefundTemplateRaw: proof.RefundTemplateRaw, PaymentAuthorizationCBOR: signedAuthorization.PaymentAuthorizationCBOR, BuyerPaymentAuthorizationSignature: signedAuthorization.BuyerPaymentAuthorizationSignature})
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimSig, err := protocol.SignWireDocument(ctx, mustSigner(t, keys[1]), protocol.WireVersion, 8, claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	payloadBundle, err := content.EncodeContentPayloads(payloads)
	if err != nil {
		t.Fatal(err)
	}
	return arbitrationEvidence{request: &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: claimCBOR, SellerArbitrationClaimSignature: sellerClaimSig, ContentPayloadsCBOR: payloadBundle}, proof: proof, keys: keys}
}

func mustKey(t *testing.T, repeated string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(repeated), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// cloneReceiptForTest 深拷贝回执：负向用例需要改写副本而不触碰原回执。
func cloneReceiptForTest(receipt *arbitration.ArbitrationReceipt) *arbitration.ArbitrationReceipt {
	return &arbitration.ArbitrationReceipt{
		ArbitrationClaimID:                 receipt.ArbitrationClaimID,
		ArbiterAmountSatoshis:              receipt.ArbiterAmountSatoshis,
		ArbiterPaymentTransactionSignature: append([]byte(nil), receipt.ArbiterPaymentTransactionSignature...),
	}
}
