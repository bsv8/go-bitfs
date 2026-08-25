package arbitration_test

// Security negative matrix required by the 007 hard-switch work order:
// tampered custody evidence, tampered receipts, wrong signatures, payload
// batch attacks, exact deadline edges, hostile CBOR shapes, cross-Claim
// signature reuse, idempotent replay byte stability, and deep-copy
// guarantees. Everything runs as pure Go tests; no cross-language vectors are
// involved.
//
// 硬切换说明：原 arbitration.Workflow 已拆到 arbiter 角色包。Prepare/Sign 全部
// 走显式 Facts（时间与区块高度由测试注入，SDK 不再读系统时钟）；错误断言从
// sentinel(errors.Is) 改为 protocol 分类码（protocol.IsCode）。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

func mustArbiterWorkflow(t *testing.T) *arbiter.Workflow {
	t.Helper()
	return mustArbiterWorkflowWithKey(t, "33")
}

func TestPrepareRejectsTamperedSellerArbitrationClaimSignature(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	rejected := arbitration.CloneRequest(evidence.request)
	rejected.SellerArbitrationClaimSignature[len(rejected.SellerArbitrationClaimSignature)-1] ^= 1
	rawKind8, err := arbitration.MarshalRequest(rejected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mustArbiterWorkflow(t).PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeInvalidSignature) {
		t.Fatalf("tampered Seller Claim signature was not rejected as invalid signature: %v", err)
	}
}

func TestPrepareRejectsWrongArbiterAndExpiredRefund(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	rawKind8, err := arbitration.MarshalRequest(arbitration.CloneRequest(evidence.request))
	if err != nil {
		t.Fatal(err)
	}
	wrongWorkflow := mustArbiterWorkflowWithKey(t, "44")
	if _, err := wrongWorkflow.PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("Claim naming another arbiter key error = %v, want unauthorized", err)
	}
	expired := makeArbitrationEvidenceWithExpiry(t, uint32(time.Now().UTC().Add(-time.Hour).Unix()))
	expiredRawKind8, err := arbitration.MarshalRequest(expired.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mustArbiterWorkflow(t).PrepareArbitration(testFacts(), expiredRawKind8, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("refund template already at its arbitral maturity height error = %v, want expired", err)
	}
}

func mustSignPrepared(t *testing.T, evidence arbitrationEvidence) (*arbiter.Workflow, *arbiter.PreparedArbitration) {
	t.Helper()
	workflow := mustArbiterWorkflow(t)
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	return workflow, prepared
}

// TestSignPreparedRejectsTamperedCustodyEvidence 保留原九行篡改矩阵：新 API 下
// PreparedArbitration 不透明且全部 getter 均为深拷贝，持久化间隙内调用方只能拿
// 到冻结状态的副本视图。每一行对对应 getter 视图施加与旧行相同的字节篡改，再
// 要求签名结果与未篡改基线逐字节一致——即调用方篡改无法影响签署输出。随后
// 追加两个外部可触发的拒签路径：他人 prepared 证据跨工作流签署（unauthorized）、
// 持久化间隙内交付截止已过（expired）。
func TestSignPreparedRejectsTamperedCustodyEvidence(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(prepared *arbiter.PreparedArbitration)
	}{
		{"frozen claim id", func(p *arbiter.PreparedArbitration) {
			view := p.ArbitrationClaimID()
			view[0] ^= 0xff
		}},
		{"frozen fee", func(p *arbiter.PreparedArbitration) {
			fee := p.FeeSatoshis()
			fee += 1
			_ = fee
		}},
		{"third output amount", func(p *arbiter.PreparedArbitration) {
			unsigned := mustUnsignedForPrepared(t, p)
			unsigned.ArbiterAmountSatoshis += 1
		}},
		{"authorization ID", func(p *arbiter.PreparedArbitration) {
			view := p.PaymentAuthorizationID()
			view[0] ^= 0xff
		}},
		{"evidence commitment", func(p *arbiter.PreparedArbitration) {
			view, err := p.RequestCBOR()
			if err != nil {
				t.Fatal(err)
			}
			view[0] ^= 0xff
		}},
		{"request payload bundle", func(p *arbiter.PreparedArbitration) {
			request := p.Request()
			request.ContentPayloadsCBOR[len(request.ContentPayloadsCBOR)-1] ^= 1
		}},
		{"request claim bytes", func(p *arbiter.PreparedArbitration) {
			request := p.Request()
			request.ArbitrationClaimCBOR[len(request.ArbitrationClaimCBOR)-1] ^= 1
		}},
		{"request seller signature", func(p *arbiter.PreparedArbitration) {
			request := p.Request()
			request.SellerArbitrationClaimSignature[0] ^= 1
		}},
		{"unsigned candidate raw tx", func(p *arbiter.PreparedArbitration) {
			unsigned := mustUnsignedForPrepared(t, p)
			unsigned.RawTx[len(unsigned.RawTx)-1] ^= 1
		}},
	}
	for _, mutation := range mutations {
		evidence := makeArbitrationEvidence(t)
		workflow, prepared := mustSignPrepared(t, evidence)
		baseline, err := workflow.SignPreparedArbitration(context.Background(), testFacts(), prepared)
		if err != nil {
			t.Fatal(err)
		}
		mutation.mutate(prepared)
		again, err := workflow.SignPreparedArbitration(context.Background(), testFacts(), prepared)
		if err != nil {
			t.Fatalf("%s: tampered caller-side views changed signing: %v", mutation.name, err)
		}
		if !bytes.Equal(baseline.Bytes(), again.Bytes()) {
			t.Fatalf("%s: tampered prepared evidence changed the canonical response bytes", mutation.name)
		}
	}

	// 外部可触发的拒签路径一：他人工作流不得签署别人的 prepared 托管证据。
	evidence := makeArbitrationEvidence(t)
	workflow, prepared := mustSignPrepared(t, evidence)
	stranger := mustArbiterWorkflowWithKey(t, "44")
	if _, err := stranger.SignPreparedArbitration(context.Background(), testFacts(), prepared); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("foreign workflow signed another arbiter's prepared evidence: %v", err)
	}
	// 外部可触发的拒签路径二：签名时刻的显式 Facts.Now 越过交付截止秒。
	expiredSignFacts := protocol.Facts{Now: time.Unix(int64(prepared.DeadlineUnixSeconds()), 0).UTC(), BlockHeight: 900000}
	if _, err := workflow.SignPreparedArbitration(context.Background(), expiredSignFacts, prepared); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("signing after deadline expiry in the persistence gap was accepted: %v", err)
	}
}

// TestReceiptBindingRejectsAnyByteChange proves the Kind 9 signatures bind the
// exact receipt: flipping any byte of the Claim ID, the frozen amount, either
// signature breaks a fixed verifier.
func TestReceiptBindingRejectsAnyByteChange(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow, prepared := mustSignPrepared(t, evidence)
	response := signPrepared(t, workflow, prepared)
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := mustUnsignedForPrepared(t, prepared)
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(prepared.Claim().PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	arbiterPubKey := evidence.keys[2].PubKey().Compressed()

	receiptMutations := map[string]func(receipt *arbitration.ArbitrationReceipt){
		"claim id":       func(r *arbitration.ArbitrationReceipt) { r.ArbitrationClaimID[0] ^= 1 },
		"arbiter amount": func(r *arbitration.ArbitrationReceipt) { r.ArbiterAmountSatoshis += 1 },
		"transaction sig": func(r *arbitration.ArbitrationReceipt) {
			r.ArbiterPaymentTransactionSignature[len(r.ArbiterPaymentTransactionSignature)-1] ^= 1
		},
	}
	for name, mutate := range receiptMutations {
		tampered := cloneReceiptForTest(receipt)
		mutate(tampered)
		tamperedCBOR, err := arbitration.MarshalReceipt(tampered)
		if err != nil {
			t.Fatalf("%s: marshal tampered receipt: %v", name, err)
		}
		domain, err := protocol.WireSignatureInput(protocol.WireVersion, 9, tamperedCBOR)
		if err != nil {
			t.Fatalf("%s: tampered child rejected by signing domain: %v", name, err)
		}
		if err := protocol.VerifyMessageSignature(arbiterPubKey, domain, response.ArbiterArbitrationReceiptSignature); err == nil {
			t.Fatalf("tampered %s still verified against the frozen Arbiter receipt signature", name)
		}
	}

	domain, err := protocol.WireSignatureInput(protocol.WireVersion, 9, response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	flippedReceiptSig := append([]byte(nil), response.ArbiterArbitrationReceiptSignature...)
	flippedReceiptSig[len(flippedReceiptSig)-1] ^= 1
	if err := protocol.VerifyMessageSignature(arbiterPubKey, domain, flippedReceiptSig); err == nil {
		t.Fatal("flipped Arbiter receipt signature verified")
	}
	flippedTxSig := append([]byte(nil), receipt.ArbiterPaymentTransactionSignature...)
	flippedTxSig[len(flippedTxSig)-1] ^= 1
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, flippedTxSig); err == nil {
		t.Fatal("flipped Arbiter transaction signature verified against the candidate")
	}
	if err := engine.VerifyArbitrationSellerPayment(unsigned, flippedTxSig); err == nil {
		t.Fatal("arbiter signature slot accepted a signature for another role")
	}
}

// TestReceiptSignatureCannotBeReusedAcrossClaims proves two Claims that share
// pool, sequence, seller amount — hence an identical financial candidate —
// still produce different Claim IDs when their authorized content hashes
// differ, and a Receipt signed for one Claim cannot be transplanted onto the
// other. Both evidences are built with one frozen clock pair (refund expiry
// and delivery deadline) so the refund template, txid, and candidate raw stay
// byte-identical regardless of Unix-second boundaries.
func TestReceiptSignatureCannotBeReusedAcrossClaims(t *testing.T) {
	now := time.Now().UTC()
	expiry := uint32(now.Add(time.Hour).Unix())
	deadline := now.Add(30 * time.Minute).Unix()
	keys := [3]*ec.PrivateKey{mustKey(t, "11"), mustKey(t, "22"), mustKey(t, "33")}
	first := makeArbitrationEvidenceWithPayloadsAndTimes(t, keys,
		[][]byte{mustDigest(t, "payload-one")}, [][]byte{[]byte("payload-one")},
		expiry, deadline)
	second := makeArbitrationEvidenceWithPayloadsAndTimes(t, keys,
		[][]byte{mustDigest(t, "payload-two")}, [][]byte{[]byte("payload-two")},
		expiry, deadline)

	firstID, err := arbitration.ArbitrationClaimID(first.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := arbitration.ArbitrationClaimID(second.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatal("two Claims with different content hashes produced one Claim ID")
	}

	workflow := mustArbiterWorkflow(t)
	firstRawKind8, err := arbitration.MarshalRequest(first.request)
	if err != nil {
		t.Fatal(err)
	}
	preparedFirst, err := workflow.PrepareArbitration(testFacts(), firstRawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	secondRawKind8, err := arbitration.MarshalRequest(second.request)
	if err != nil {
		t.Fatal(err)
	}
	preparedSecond, err := workflow.PrepareArbitration(testFacts(), secondRawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	unsignedFirst := mustUnsignedForPrepared(t, preparedFirst)
	unsignedSecond := mustUnsignedForPrepared(t, preparedSecond)
	if !bytes.Equal(unsignedFirst.RawTx, unsignedSecond.RawTx) {
		t.Fatal("test premise broken: identical finances should rebuild one candidate")
	}
	response := signPrepared(t, workflow, preparedFirst)
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	// The same candidate bytes plus the other Claim's ID cannot carry the
	// first Claim's receipt: the unified message signature covers only
	// WireSignatureInput(1, 9, arbitration_receipt_cbor), so any Claim ID
	// swap breaks it.
	transplanted := cloneReceiptForTest(receipt)
	transplanted.ArbitrationClaimID = secondID
	transplantedCBOR, err := arbitration.MarshalReceipt(transplanted)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := protocol.WireSignatureInput(protocol.WireVersion, 9, transplantedCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyMessageSignature(second.keys[2].PubKey().Compressed(), domain, response.ArbiterArbitrationReceiptSignature); err == nil {
		t.Fatal("receipt signature was reused across two different Claim IDs")
	}
}

// TestSameClaimIdempotentReplayIsByteStable proves that signing the same
// persisted evidence twice yields byte-identical canonical Kind 9 responses,
// so a send failure can be retried with the exact saved bytes.
func TestSameClaimIdempotentReplayIsByteStable(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow, prepared := mustSignPrepared(t, evidence)
	facts := testFacts()
	first, err := workflow.SignPreparedArbitration(context.Background(), facts, prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := workflow.SignPreparedArbitration(context.Background(), facts, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("re-signing the same frozen custody state changed the canonical response bytes")
	}
}

func mustDigest(t *testing.T, value string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

// makeArbitrationEvidenceWithExpiry builds a full evidence set whose pool
// refund template already matured at the given wall-clock lock time.
func makeArbitrationEvidenceWithExpiry(t *testing.T, expiryLockTime uint32) arbitrationEvidence {
	t.Helper()
	keys := [3]*ec.PrivateKey{mustKey(t, "11"), mustKey(t, "22"), mustKey(t, "33")}
	evidence := makeArbitrationEvidenceWithPayloadsAndExpiry(t, keys, [][]byte{mustDigest(t, "expired-payload")}, [][]byte{[]byte("expired-payload")}, expiryLockTime)
	return evidence
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
		if baseCount > content.MaxContentBatchItems {
			baseCount = content.MaxContentBatchItems
		}
		digests, payloads := buildPayloads(baseCount)
		evidence := makeArbitrationEvidenceWithPayloads(t, digests, payloads)
		if count != baseCount {
			items := make([]any, count)
			for index := range items {
				items[index] = bytes.Repeat([]byte{byte(index + 1)}, 16)
			}
			bundle, err := arbitration.DeterministicEncForTest().Marshal(items)
			if err != nil {
				t.Fatal(err)
			}
			evidence.request.ContentPayloadsCBOR = bundle
		}
		rawKind8, err := arbitration.MarshalRequest(evidence.request)
		if err != nil {
			if wantAccept {
				t.Fatalf("legal %d-payload request exceeded the wire limit: %v", count, err)
			}
			continue
		}
		_, err = mustArbiterWorkflow(t).PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat))
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
	rawSwapped, err := arbitration.MarshalRequest(swapped.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.PrepareArbitration(testFacts(), rawSwapped, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("swapped payload order was accepted: %v", err)
	}

	emptyBundle := mustEncodeArray(t, []any{[]byte{}, second})
	empty := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:], digestTwo[:]}, [][]byte{first, second})
	empty.request.ContentPayloadsCBOR = emptyBundle
	// 非法 bundle 无法通过严格 MarshalRequest，需按外壳手工拼装 exact 字节。
	rawEmpty := mustMarshalRequest(t, empty.request)
	if _, err := workflow.PrepareArbitration(testFacts(), rawEmpty, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("empty payload item was accepted: %v", err)
	}

	oversizedItem := bytes.Repeat([]byte{9}, int(content.BlockSize)+1)
	oversizedBundle := mustEncodeArray(t, []any{oversizedItem})
	oversized := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:]}, [][]byte{first})
	oversized.request.ContentPayloadsCBOR = oversizedBundle
	rawOversized := mustMarshalRequest(t, oversized.request)
	if _, err := workflow.PrepareArbitration(testFacts(), rawOversized, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("oversized payload item was accepted: %v", err)
	}

	countMismatch := makeArbitrationEvidenceWithPayloads(t, [][]byte{digestOne[:]}, [][]byte{first, second})
	rawMismatch, err := arbitration.MarshalRequest(countMismatch.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.PrepareArbitration(testFacts(), rawMismatch, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("payload/hash count mismatch was accepted: %v", err)
	}
}

func mustEncodeArray(t *testing.T, values []any) []byte {
	t.Helper()
	raw, err := arbitration.DeterministicEncForTest().Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// makeArbitrationEvidenceWithDeadline 用调用方指定的交付截止秒重签买方授权与
// 卖方 Claim 签名，其余证据保持不变。
func makeArbitrationEvidenceWithDeadline(t *testing.T, deadlineUnix int64) arbitrationEvidence {
	t.Helper()
	ctx := context.Background()
	payload := []byte("deadline-payload")
	digest := sha256.Sum256(payload)
	evidence := makeArbitrationEvidenceWithPayloads(t, [][]byte{digest[:]}, [][]byte{payload})
	claim, err := arbitration.UnmarshalClaim(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := content.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	authorization.DeliveryDeadlineUnixSeconds = deadlineUnix
	authorizationCBOR, err := content.EncodePaymentAuthorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	buyerSignature, err := protocol.SignWireDocument(ctx, mustSigner(t, evidence.keys[0]), protocol.WireVersion, 5, authorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claimCBOR, err := arbitration.MarshalClaim(&arbitration.ArbitrationClaim{
		PoolOutputSatoshis:                 claim.PoolOutputSatoshis,
		PoolOutputLockingScript:            claim.PoolOutputLockingScript,
		RefundTemplateRaw:                  claim.RefundTemplateRaw,
		PaymentAuthorizationCBOR:           authorizationCBOR,
		BuyerPaymentAuthorizationSignature: buyerSignature,
	})
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimSig, err := protocol.SignWireDocument(ctx, mustSigner(t, evidence.keys[1]), protocol.WireVersion, 8, claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	evidence.request.ArbitrationClaimCBOR = claimCBOR
	evidence.request.SellerArbitrationClaimSignature = sellerClaimSig
	return evidence
}

// TestDeadlineBoundariesGatePrepareAndSigning pins the exact delivery-deadline
// second (inclusive rejection), acceptance before it, and expiry inside the
// persistence gap between PrepareArbitration and SignPreparedArbitration.
// 新模型下时间全部来自显式 Facts，无需真实等待即可跨越边界。
func TestDeadlineBoundariesGatePrepareAndSigning(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	workflow := mustArbiterWorkflow(t)
	prepareFacts := protocol.Facts{Now: base, BlockHeight: 900000}

	exactDeadline := makeArbitrationEvidenceWithDeadline(t, base.Add(time.Second).Unix()-1)
	exactRawKind8, err := arbitration.MarshalRequest(exactDeadline.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.PrepareArbitration(prepareFacts, exactRawKind8, protocol.Satoshis(testArbitrationFeeSat)); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("prepare at the exact deadline second was accepted: %v", err)
	}

	beforeDeadline := makeArbitrationEvidenceWithDeadline(t, base.Add(30*time.Second).Unix())
	beforeRawKind8, err := arbitration.MarshalRequest(beforeDeadline.request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := workflow.PrepareArbitration(prepareFacts, beforeRawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	if prepared.DeadlineUnixSeconds() != content.UnixSeconds(base.Add(30*time.Second).Unix()) {
		t.Fatalf("prepared deadline drifted: %d", int64(prepared.DeadlineUnixSeconds()))
	}
	if !prepared.PreparedAt().Equal(base) {
		t.Fatalf("prepared.at drifted from facts.now: %v", prepared.PreparedAt())
	}

	// 持久化间隙过期：把签名时的 Facts.Now 推到截止秒（含），必须拒签。
	gapFacts := protocol.Facts{Now: time.Unix(int64(prepared.DeadlineUnixSeconds()), 0).UTC(), BlockHeight: 900000}
	if _, err := workflow.SignPreparedArbitration(context.Background(), gapFacts, prepared); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("signing after deadline expiry in the persistence gap was accepted: %v", err)
	}
	// 对照基线：截止前一秒仍可正常签署。
	okFacts := protocol.Facts{Now: time.Unix(int64(prepared.DeadlineUnixSeconds())-1, 0).UTC(), BlockHeight: 900000}
	if _, err := workflow.SignPreparedArbitration(context.Background(), okFacts, prepared); err != nil {
		t.Fatalf("signing one second before the deadline failed: %v", err)
	}
}

// TestArbitrationDecodersRejectHostileCBOR pins decoder-level rejections:
// tags, indefinite lengths, non-shortest integers, and wrong field types never
// reach semantic validation; decoded outputs are isolated from source bytes.
func TestArbitrationDecodersRejectHostileCBOR(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	valid, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}

	tagged := append([]byte{0xc0}, valid...)
	if _, err := arbitration.UnmarshalRequest(tagged); err == nil {
		t.Fatal("tag-wrapped request was decoded")
	}

	indefinite := append([]byte{0x9f}, valid...)
	indefinite = append(indefinite, 0xff)
	if _, err := arbitration.UnmarshalRequest(indefinite); err == nil {
		t.Fatal("indefinite-length array request was decoded")
	}

	// [4, 8, (_ 'a' 'b'), h'0304', h'05']: an indefinite-length bstr child.
	indefiniteBstrChild := []byte{0x85, 0x04, 0x08, 0x5f, 0x41, 0x61, 0x41, 0x62, 0xff, 0x42, 0x03, 0x04, 0x41, 0x05}
	if _, err := arbitration.UnmarshalRequest(indefiniteBstrChild); err == nil {
		t.Fatal("indefinite-length bstr child was decoded")
	}

	nonShortestVersion := append([]byte{0x85, 0x19, 0x00, 0x04}, valid[2:]...)
	if _, err := arbitration.UnmarshalRequest(nonShortestVersion); err == nil {
		t.Fatal("non-shortest version integer was decoded")
	}

	textClaim := append([]byte{0x85, 0x04, 0x08, 0x63, 'a', 'b', 'c'}, valid[3:]...)
	if _, err := arbitration.UnmarshalRequest(textClaim); err == nil {
		t.Fatal("text-string Claim element was decoded as bstr")
	}

	negativeSatoshis, err := arbitration.DeterministicEncForTest().Marshal([]any{-1, arbitration.BstrForTest(bytes.Repeat([]byte{1}, 105)), arbitration.BstrForTest([]byte{2}), arbitration.BstrForTest([]byte{3}), arbitration.BstrForTest([]byte{4})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbitration.UnmarshalClaim(negativeSatoshis); err == nil {
		t.Fatal("negative satoshis were decoded into the Claim")
	}

	taggedReceipt := append([]byte{0xc1}, []byte{0x83, 0x58, 0x20}...)
	taggedReceipt = append(taggedReceipt, bytes.Repeat([]byte{1}, 97)...)
	if _, err := arbitration.UnmarshalReceipt(taggedReceipt); err == nil {
		t.Fatal("tag-wrapped receipt was decoded")
	}

	wrongTypeReceipt := mustEncodeArray(t, []any{"not-a-hash", uint64(1), arbitration.BstrForTest(bytes.Repeat([]byte{2}, 70))})
	if _, err := arbitration.UnmarshalReceipt(wrongTypeReceipt); err == nil {
		t.Fatal("text-string Claim ID element was decoded as bstr")
	}

	// Decoded outputs must be isolated from the source bytes and from each
	// other: mutating one decode must not affect the wire bytes or a fresh
	// decode of them.
	decoded, err := arbitration.UnmarshalRequest(valid)
	if err != nil {
		t.Fatal(err)
	}
	originalSignature := append([]byte(nil), decoded.SellerArbitrationClaimSignature...)
	decoded.SellerArbitrationClaimSignature[0] ^= 1
	fresh, err := arbitration.UnmarshalRequest(valid)
	if err != nil {
		t.Fatalf("source bytes were corrupted by a prior decode and mutation: %v", err)
	}
	if !bytes.Equal(fresh.SellerArbitrationClaimSignature, originalSignature) || bytes.Equal(fresh.SellerArbitrationClaimSignature, decoded.SellerArbitrationClaimSignature) {
		t.Fatal("a fresh decode observed a previous decode's mutation")
	}
	canonical, err := arbitration.MarshalRequest(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, valid) {
		t.Fatal("canonical re-encoding drifted from the source bytes")

	}
	receiptSource := mustSignedResponse(t)
	receiptRaw, err := arbitration.MarshalResponse(receiptSource)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := arbitration.UnmarshalResponse(receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse.ArbiterArbitrationReceiptSignature[0] ^= 1
	freshResponse, err := arbitration.UnmarshalResponse(receiptRaw)
	if err != nil {
		t.Fatalf("response source bytes were corrupted by a prior decode and mutation: %v", err)
	}
	if bytes.Equal(freshResponse.ArbiterArbitrationReceiptSignature, decodedResponse.ArbiterArbitrationReceiptSignature) {
		t.Fatal("a fresh response decode observed a previous decode's mutation")
	}
}

// TestPreparedArbitrationGettersReturnDeepCopies extends the deep-copy guarantee
// to every exported getter of PreparedArbitration.
func TestPreparedArbitrationGettersReturnDeepCopies(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	rawKind8, err := arbitration.MarshalRequest(evidence.request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := mustArbiterWorkflow(t).PrepareArbitration(testFacts(), rawKind8, protocol.Satoshis(testArbitrationFeeSat))
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
	// ClaimID / PaymentAuthorizationID 现在是值类型数组，天然按值返回。
	assertDeepCopy("ContentPayloadsCBOR", prepared.ContentPayloadsCBOR)
	assertDeepCopy("ArbiterPublicKey", prepared.ArbiterPublicKey)

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

	// UnsignedPayment getter 已删除：未签名 candidate 只能从 Request() 视图独立
	// 重建，两次重建必须互不影响。
	unsigned := mustUnsignedForPrepared(t, prepared)
	unsigned.RawTx[len(unsigned.RawTx)-1] ^= 1
	if bytes.Equal(unsigned.RawTx, mustUnsignedForPrepared(t, prepared).RawTx) {
		t.Fatal("rebuilt unsigned candidate returned internal references")
	}
}

// TestContentRetrievalSignatureReplayMatrix pins the Kind 10 authorization
// boundary: a buyer signature over the exact Kind 10 request document authorizes exactly
// one Claim ID with exactly one nonce under kind 10 — the same bytes signed
// for a different Claim, a different nonce, or any other signing domain are
// all rejected by the fixed verifier.
func TestContentRetrievalSignatureReplayMatrix(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	workflow := mustArbiterWorkflow(t)
	_, prepared := mustSignPrepared(t, evidence)
	response := signPrepared(t, workflow, prepared)
	storedRequest := prepared.Request()
	claimID, err := arbitration.ArbitrationClaimID(storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	arbiterPublicKey := evidence.keys[2].PubKey().Compressed()
	requestDoc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, testRetrievalNonce.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	buyerSignature, err := protocol.SignWireDocument(context.Background(), mustSigner(t, evidence.keys[0]), protocol.WireVersion, 10, requestDoc)
	if err != nil {
		t.Fatal(err)
	}

	// 同一签名贴到另一个 Claim ID。
	other := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "matrix-other")}, [][]byte{[]byte("matrix-other")})
	_, preparedOther := mustSignPrepared(t, other)
	responseOther := signPrepared(t, workflow, preparedOther)
	storedOther := preparedOther.Request()
	otherID, err := arbitration.ArbitrationClaimID(storedOther.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}

	otherDoc, err := arbitration.EncodeContentRetrievalRequestDocument(otherID, testRetrievalNonce.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	reusedForOther := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: otherDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), buyerSignature...)}
	if err := arbitration.AuthenticateContentRetrievalRequest(reusedForOther, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("Kind 10 signature authorized a different Claim ID")
	}
	// 贴到对方自己的完整托管记录上（含其已签 Kind 9）也必须失败。
	rawReusedKind10, err := arbitration.MarshalContentRetrievalRequest(reusedForOther)
	if err != nil {
		t.Fatal(err)
	}
	rawOtherKind8, err := arbitration.MarshalRequest(storedOther)
	if err != nil {
		t.Fatal(err)
	}
	rawOtherKind9, err := arbitration.MarshalResponse(responseOther)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.VerifyRetrievableCustody(rawReusedKind10, rawOtherKind8, rawOtherKind9); err == nil {
		t.Fatal("Kind 10 signature signed over another claim's domain verified elsewhere")
	}

	// 同一签名贴到不同 nonce。
	freshNonce := bytes.Repeat([]byte{0x5a}, arbitration.RetrievalNonceBytes)
	reusedNonceDoc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, freshNonce)
	if err != nil {
		t.Fatal(err)
	}
	reusedNonce := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: reusedNonceDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), buyerSignature...)}
	if err := arbitration.AuthenticateContentRetrievalRequest(reusedNonce, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("Kind 10 signature authorized a different nonce")
	}

	// Kind 混淆：把 Kind 8/9 域下的签名当作 Kind 10 签名使用，都必须失败。
	kind8Signed, err := protocol.SignWireDocument(context.Background(), mustSigner(t, evidence.keys[0]), protocol.WireVersion, 8, storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	crossKindDoc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, testRetrievalNonce.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	crossKind := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: crossKindDoc, BuyerContentRetrievalRequestSignature: kind8Signed}
	if err := arbitration.AuthenticateContentRetrievalRequest(crossKind, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("a Kind 8-domain signature authorized retrieval")
	}
	kind9Signed, err := protocol.SignWireDocument(context.Background(), mustSigner(t, evidence.keys[0]), protocol.WireVersion, 9, response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	crossKind2 := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: crossKindDoc, BuyerContentRetrievalRequestSignature: kind9Signed}
	if err := arbitration.AuthenticateContentRetrievalRequest(crossKind2, storedRequest, arbiterPublicKey); err == nil {
		t.Fatal("a Kind 9-domain signature authorized retrieval")
	}

	// 正向基线：精确 (ClaimID, nonce) 组合通过。
	validRequest := &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: requestDoc, BuyerContentRetrievalRequestSignature: append([]byte(nil), buyerSignature...)}
	if err := arbitration.AuthenticateContentRetrievalRequest(validRequest, storedRequest, arbiterPublicKey); err != nil {
		t.Fatalf("exact replay-key request was rejected: %v", err)
	}
	rawValidKind10, err := arbitration.MarshalContentRetrievalRequest(validRequest)
	if err != nil {
		t.Fatal(err)
	}
	rawStoredKind8, err := arbitration.MarshalRequest(storedRequest)
	if err != nil {
		t.Fatal(err)
	}
	rawResponseKind9, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.VerifyRetrievableCustody(rawValidKind10, rawStoredKind8, rawResponseKind9); err != nil {
		t.Fatalf("exact replay-key request failed full custody verification: %v", err)
	}
}

// TestStoredCustodyPairCrossSplicingIsRejected covers record-level attacks:
// one record's exact Kind 8 paired with another record's Kind 9, and a
// receipt transplanted onto foreign claim bytes, must both fail even though
// every individual document is internally valid.
func TestStoredCustodyPairCrossSplicingIsRejected(t *testing.T) {
	first := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "splice-one")}, [][]byte{[]byte("splice-one")})
	second := makeArbitrationEvidenceWithPayloads(t, [][]byte{mustDigest(t, "splice-two")}, [][]byte{[]byte("splice-two")})
	workflow := mustArbiterWorkflow(t)
	firstRawKind8, err := arbitration.MarshalRequest(first.request)
	if err != nil {
		t.Fatal(err)
	}
	preparedFirst, err := workflow.PrepareArbitration(testFacts(), firstRawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	secondRawKind8, err := arbitration.MarshalRequest(second.request)
	if err != nil {
		t.Fatal(err)
	}
	preparedSecond, err := workflow.PrepareArbitration(testFacts(), secondRawKind8, protocol.Satoshis(testArbitrationFeeSat))
	if err != nil {
		t.Fatal(err)
	}
	responseFirst := signPrepared(t, workflow, preparedFirst)
	responseSecond := signPrepared(t, workflow, preparedSecond)
	splicedA := &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: responseSecond.ArbitrationReceiptCBOR, ArbiterArbitrationReceiptSignature: responseSecond.ArbiterArbitrationReceiptSignature}
	if _, err := arbitration.VerifyCustodiedContent(first.request, splicedA); err == nil {
		t.Fatal("record A accepted record B's receipt response")
	}
	splicedB := &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: responseFirst.ArbitrationReceiptCBOR, ArbiterArbitrationReceiptSignature: responseFirst.ArbiterArbitrationReceiptSignature}
	if _, err := arbitration.VerifyCustodiedContent(second.request, splicedB); err == nil {
		t.Fatal("record B accepted record A's receipt response")
	}
}

// TestBuyerDerivesSameClaimIDWithoutSellerEvidence proves the retrieval-side
// property that makes Claim-ID routing work offline: from only the
// OpeningProof plus the exact signed 003 — no Seller Claim signature, no
// payload bundle, no Kind 9 — the shared builder produces byte-identical
// ArbitrationClaimCBOR and therefore the identical ArbitrationClaimID.
func TestBuyerDerivesSameClaimIDWithoutSellerEvidence(t *testing.T) {
	evidence := makeArbitrationEvidence(t)
	sellerClaimID, err := arbitration.ArbitrationClaimID(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := arbitration.UnmarshalClaim(evidence.request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	authorization := &content.SignedContentRequest{PaymentAuthorizationCBOR: append([]byte(nil), claim.PaymentAuthorizationCBOR...), BuyerPaymentAuthorizationSignature: append([]byte(nil), claim.BuyerPaymentAuthorizationSignature...)}
	built, err := arbitration.BuildClaimFromAuthorization(evidence.proof, authorization)
	if err != nil {
		t.Fatalf("buyer-side shared builder failed without seller evidence: %v", err)
	}
	if !bytes.Equal(built.ArbitrationClaimCBOR, evidence.request.ArbitrationClaimCBOR) {
		t.Fatal("shared builder produced different ArbitrationClaimCBOR than the seller path")
	}
	if built.ArbitrationClaimID != sellerClaimID {
		t.Fatal("buyer-derived Claim ID differs from the seller/arbiter Claim ID")
	}
	// 输入克隆证明：调用方缓冲区被篡改后再次构建仍得到原始结果。
	authorization.PaymentAuthorizationCBOR[len(authorization.PaymentAuthorizationCBOR)-1] ^= 1
	if _, err := arbitration.BuildClaimFromAuthorization(evidence.proof, authorization); err == nil {
		t.Fatal("tampered authorization was accepted by the shared builder")
	}
}
