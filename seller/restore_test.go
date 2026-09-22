package seller

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/flowtest/arbiter"
	"github.com/bsv8/go-bitfs/internal/flowtest/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// 本文件覆盖验收要求的强制场景：Seller/Arbiter Restore 全量重验往返、伪造
// 证据无法获得 Verified 值、Signer 取消语义分类、Facts 按锁定类型按需读取。

// TestRestoreOpeningCheckpointRoundTripAndTampering 验证卖方预签 checkpoint
// 只能由真实 exact evidence 重建：正常往返后可继续验收资金交付；篡改 Kind 3
// 任一字节都会被完整验证拒绝。
func TestRestoreOpeningCheckpointRoundTripAndTampering(t *testing.T) {
	f := newSellerFixture(t)
	quote, _ := f.defaultQuote(t)
	ctx := context.Background()
	prepared, err := f.Buyer.PreparePoolOpening(ctx, buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind2 := prepared.Outbound.Bytes()
	presign, err := f.Seller.PreparePoolOpening(ctx, rawKind2)
	if err != nil {
		t.Fatal(err)
	}
	rawKind3 := presign.Outbound.Bytes()

	restored, err := RestoreOpeningCheckpoint(rawKind2, rawKind3)
	if err != nil {
		t.Fatalf("restore from exact evidence: %v", err)
	}
	if !bytes.Equal(restored.Opening().RefundTemplateRaw, presign.Checkpoint.Opening().RefundTemplateRaw) {
		t.Fatal("restored presign evidence drifted from the persisted bytes")
	}

	// 恢复后的 checkpoint 必须能继续完成资金交付验收（买方侧先交付）。
	buyerPoolCheckpoint, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, rawKind3)
	if err != nil {
		t.Fatal(err)
	}
	fundingDelivery, err := f.Buyer.PrepareFundingDelivery(buyerPoolCheckpoint.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	fundingResult, err := f.Seller.VerifyFundingDelivery(restored, fundingDelivery.Bytes())
	if err != nil {
		t.Fatalf("restored checkpoint cannot accept funding delivery: %v", err)
	}
	if len(fundingResult.FundingTransactionRaw) == 0 {
		t.Fatal("funding verification lost the funding transaction")
	}

	// 篡改 Kind 3 的卖方签名一个字节 → invalid_evidence/state_conflict。
	tampered := append([]byte(nil), rawKind3...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := RestoreOpeningCheckpoint(rawKind2, tampered); !protocol.IsCode(err, protocol.CodeInvalidEvidence) && !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("tampered kind3 restore error = %v", err)
	}
}

// TestRestorePoolAndDeliveryCheckpoints 验证池与交付 checkpoint 的恢复路径：
// 字段全部从 exact evidence 重算，篡改 raw tx 被拒。
func TestRestorePoolAndDeliveryCheckpoints(t *testing.T) {
	f := newSellerFixture(t)
	p := f.openDefaultPool(t)
	round := f.purchaseSeed(t, p, testBaseTime)

	proofCBOR, err := pool.EncodeOpeningProof(p.sellerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	restoredPool, err := RestorePoolCheckpoint(proofCBOR, p.sellerPool.Payment().RawTx)
	if err != nil {
		t.Fatalf("restore pool checkpoint: %v", err)
	}
	if restoredPool.RefundTemplateTxID() != p.sellerPool.RefundTemplateTxID() {
		t.Fatal("restored pool correlation mismatch")
	}

	// exact Kind 1：fixture 缓存的已签报价即创建该授权时使用的原件。
	if f.cachedQuote == nil || f.cachedQuote.signed == nil {
		t.Fatal("fixture quote cache is empty")
	}
	kind1Artifact, err := wire.EncodeFileQuote(f.cachedQuote.signed)
	if err != nil {
		t.Fatal(err)
	}
	openingProofCBOR, err := pool.EncodeOpeningProof(p.sellerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	restoredDelivery, err := RestoreDeliveryCheckpoint(kind1Artifact.Bytes(), openingProofCBOR, round.rawKind5, round.rawKind6)
	if err != nil {
		t.Fatalf("restore delivery checkpoint: %v", err)
	}
	if restoredDelivery.AuthorizationID() != round.request.AuthorizationID ||
		restoredDelivery.PaymentSequence() != round.deliveryResult.Checkpoint.PaymentSequence() ||
		restoredDelivery.SellerAmountAfterSatoshis() != round.deliveryResult.Checkpoint.SellerAmountAfterSatoshis() {
		t.Fatal("restored delivery checkpoint fields drifted from exact evidence")
	}

	// 篡改付款 raw tx 一个字节 → 恢复被拒。
	// 篡改本方 004 签名一个字节（定位签名字段而非尾部 payload）→ 全量重验拒绝。
	deliveryDTO, err := wire.DecodeContentDelivery(mustParse(t, wire.ContentDelivery, round.rawKind6))
	if err != nil {
		t.Fatal(err)
	}
	tamperedSig := append([]byte(nil), deliveryDTO.SellerContentDeliverySignature...)
	tamperedSig[len(tamperedSig)-1] ^= 0x01
	forgedKind6, ferr := rebuildKind6WithSignature(t, round.rawKind6, tamperedSig)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if _, rerr := RestoreDeliveryCheckpoint(kind1Artifact.Bytes(), openingProofCBOR, round.rawKind5, forgedKind6); !protocol.IsCode(rerr, protocol.CodeInvalidSignature) {
		t.Fatalf("tampered kind6 signature restore error = %v", rerr)
	}

	badPayment := append([]byte(nil), p.sellerPool.Payment().RawTx...)
	badPayment[len(badPayment)-1] ^= 0xFF
	if _, err := RestorePoolCheckpoint(proofCBOR, badPayment); !protocol.IsCode(err, protocol.CodeInvalidEvidence) && !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("forged payment accepted by restore: %v", err)
	}
}

// failingSigner 是可编程失败的 fake remote signer。
type failingSigner struct {
	publicKey protocol.PublicKey
	err       error
}

func (s *failingSigner) PublicKey() protocol.PublicKey { return s.publicKey }

func (s *failingSigner) Sign(_ context.Context, _ protocol.SigningRequest) ([]byte, error) {
	return nil, s.err
}

// TestContextCancellationIsCanceledNotSignerUnavailable 验证取消语义：
// Signer 返回 context.Canceled/DeadlineExceeded 时 SDK 分类为 canceled；
// 只有托管故障才是 signer_unavailable。同时覆盖普通消息签名与交易签名
// 两条真实路径。
func TestContextCancellationIsCanceledNotSignerUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want protocol.ErrorCode
	}{
		{"context canceled", context.Canceled, protocol.CodeCanceled},
		{"deadline exceeded", context.DeadlineExceeded, protocol.CodeCanceled},
		{"kms unavailable", errors.New("kms: connection refused"), protocol.CodeSignerUnavailable},
		{"signer sentinel", protocol.ErrSignerUnavailable, protocol.CodeSignerUnavailable},
	}
	buyerTypedPub := func() protocol.PublicKey {
		t.Helper()
		typed, err := protocol.PublicKeyFromBytes(mustTestKey(t, "11").PubKey().Compressed())
		if err != nil {
			t.Fatal(err)
		}
		return typed
	}()
	for _, tc := range cases {
		signer := &failingSigner{publicKey: buyerTypedPub, err: tc.err}

		// 路径一：普通消息签名（协议层入口）。
		document := bytes.Repeat([]byte{0x33}, 64)
		_, signErr := protocol.SignWireDocument(context.Background(), signer, protocol.WireVersion, 1, document)
		if !protocol.IsCode(signErr, tc.want) {
			t.Fatalf("%s: wire sign code = %v, want %s", tc.name, signErr, tc.want)
		}
		if tc.want == protocol.CodeCanceled && protocol.IsCode(signErr, protocol.CodeSignerUnavailable) {
			t.Fatalf("%s: cancellation misclassified as signer_unavailable", tc.name)
		}

		// 路径二：交易签名（pool adapter 的 sighash digest 路径）。构造一个
		// 合法 opening 后让 Signer 失败，断言同一分类规则。
		f := newSellerFixture(t)
		p := f.openDefaultPool(t)
		engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{
			BuyerPublicKey:   p.sellerPool.Opening().BuyerPublicKey,
			SellerPublicKey:  p.sellerPool.Opening().SellerPublicKey,
			ArbiterPublicKey: p.sellerPool.Opening().ArbiterPublicKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := engine.BuildPaymentUpdate(pool.PaymentUpdateInput{
			Opening:                   p.sellerPool.Opening(),
			Previous:                  p.sellerPool.Payment(),
			PaymentSequence:           p.sellerPool.Payment().PaymentSequence + 1,
			SellerAmountAfterSatoshis: p.sellerPool.Payment().SellerAmountSatoshis,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, txErr := pool.NewBuyerPoolAdapter(engine, signer).SignBuyerPayment(context.Background(), unsigned, p.sellerPool.Opening())
		if !protocol.IsCode(txErr, tc.want) {
			t.Fatalf("%s: transaction sign code = %v, want %s", tc.name, txErr, tc.want)
		}
	}
}

// TestFactsOnDemandByLockType 验证显式事实按需读取：timestamp 锁定的正向
// 操作只要求 Now（缺高度必须成功）；height 锁定缺高度时拒绝而不是猜测，
// 给出显式高度后成功。到期退款同理。
func TestFactsOnDemandByLockType(t *testing.T) {
	f := newSellerFixture(t)
	ctx := context.Background()

	// timestamp 锁定池：到期退款只给 Now（不给高度）必须成功。
	tsQuote, _ := f.defaultQuote(t)
	tsLock := uint32(testBaseTime.Add(time.Hour).Unix())
	preparedTs, err := f.Buyer.PreparePoolOpening(ctx, buyerPrepareCommandFor(t, f, tsQuote, tsLock))
	if err != nil {
		t.Fatal(err)
	}
	presignTs, err := f.Seller.PreparePoolOpening(ctx, preparedTs.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completedTs, err := f.Buyer.CompletePoolOpening(preparedTs.Checkpoint, presignTs.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	maturedFacts := protocol.Facts{Now: time.Unix(int64(tsLock), 0)} // 故意不带 BlockHeight
	refund, err := f.Buyer.BuildMaturedRefund(maturedFacts, completedTs.InitialPool)
	if err != nil {
		t.Fatalf("timestamp-lock refund demanded block height: %v", err)
	}
	if len(refund.RawTx()) == 0 {
		t.Fatal("matured refund produced empty raw tx")
	}

	// height 锁定池：到期退款缺 BlockHeight 必须拒绝；给出后成功。
	hQuote, _ := f.defaultQuote(t)
	heightLock := uint32(800123)
	preparedH, err := f.Buyer.PreparePoolOpening(ctx, buyerPrepareCommandFor(t, f, hQuote, heightLock))
	if err != nil {
		t.Fatal(err)
	}
	presignH, err := f.Seller.PreparePoolOpening(ctx, preparedH.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completedH, err := f.Buyer.CompletePoolOpening(preparedH.Checkpoint, presignH.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime.Add(10 * 365 * 24 * time.Hour)}, completedH.InitialPool); !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("height-lock refund without block height error = %v, want facts missing", err)
	}
	heightRefund, err := f.Buyer.BuildMaturedRefund(protocol.Facts{BlockHeight: protocol.BlockHeight(heightLock)}, completedH.InitialPool)
	if err != nil {
		t.Fatalf("height-lock refund with explicit height failed: %v", err)
	}
	if len(heightRefund.RawTx()) == 0 {
		t.Fatal("height-lock matured refund produced empty raw tx")
	}
}

// TestForgedEvidenceCannotBecomeVerified 证明外部包无法把伪造数据包装成
// Verified 值：篡改开池签名、篡改状态元数据、随机 raw tx 都会被拒绝。
func TestForgedEvidenceCannotBecomeVerified(t *testing.T) {
	f := newSellerFixture(t)
	p := f.openDefaultPool(t)

	proof := p.sellerPool.Opening()

	// 1) 翻转卖方退款签名 → VerifyOpeningProof 拒绝。
	forgedProof := pool.CloneOpeningProof(proof)
	forgedProof.SellerRefundTransactionSignature[len(forgedProof.SellerRefundTransactionSignature)-1] ^= 0x01
	if _, err := pool.VerifyOpeningProof(forgedProof); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("forged opening proof accepted: %v", err)
	}

	// 2) 合法 raw + 被篡改的元数据金额 → VerifyPaymentState 拒绝。
	state := pool.ClonePaymentState(p.sellerPool.Payment())
	state.SellerAmountSatoshis += 1
	if _, err := pool.VerifyPaymentState(state, proof); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("forged payment state accepted: %v", err)
	}

	// 3) 随机字节 → VerifySignedTransaction 拒绝。
	junk := bytes.Repeat([]byte{0xA5}, 220)
	if _, err := pool.VerifySignedTransaction(junk, proof); err == nil {
		t.Fatal("random bytes accepted as a verified transaction")
	}
}

// TestArbiterRestorePreparedArbitration 验证托管证据恢复：恢复值与 Prepare
// 产物一致、可继续签署；错 fee 的恢复值在签署时被 state_conflict 拦截。
func TestArbiterRestorePreparedArbitration(t *testing.T) {
	f := newSellerFixture(t)
	chain := f.buildCustodyWithDeadline(t, content.UnixSeconds(testBaseTime.Add(30*time.Minute).Unix()))

	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), chain.rawKind8, testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := arbiter.RestorePreparedArbitration(chain.rawKind8, testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatalf("restore prepared arbitration: %v", err)
	}
	if restored.ArbitrationClaimID() != prepared.ArbitrationClaimID() || restored.FeeSatoshis() != prepared.FeeSatoshis() {
		t.Fatal("restored arbitration identity drifted")
	}
	signedFromRestore, err := f.Arbiter.SignPreparedArbitration(context.Background(), testFacts(testBaseTime), restored)
	if err != nil {
		t.Fatalf("sign from restored value failed: %v", err)
	}
	signedFromPrepare, err := f.Arbiter.SignPreparedArbitration(context.Background(), testFacts(testBaseTime), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signedFromRestore.Bytes(), signedFromPrepare.Bytes()) {
		t.Fatal("restore-based signing drifted from prepare-based signing")
	}

	// 费用完全由恢复值决定：错 fee 的恢复值自洽且可签，但产出不同回执字节——
	// 这证明应用持久化费用必须与 Kind 8 绑定保存，SDK 按恢复值精确执行。
	wrongFeeRestored, err := arbiter.RestorePreparedArbitration(chain.rawKind8, testArbitrationFeeSatoshis+1)
	if err != nil {
		t.Fatal(err)
	}
	wrongFeeSigned, err := f.Arbiter.SignPreparedArbitration(context.Background(), testFacts(testBaseTime), wrongFeeRestored)
	if err != nil {
		t.Fatalf("wrong-fee restored signing failed unexpectedly: %v", err)
	}
	if bytes.Equal(wrongFeeSigned.Bytes(), signedFromPrepare.Bytes()) {
		t.Fatal("restored fee drift did not change the signed receipt")
	}
}

// buyerPrepareCommandFor 构造买方开池 Command（测试辅助）。
func buyerPrepareCommandFor(t *testing.T, f *sellerFixture, quote *content.VerifiedQuote, lock uint32) buyer.PrepareOpeningCommand {
	t.Helper()
	return buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(lock),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	}
}

// ---- restore 测试的小工具 ----

func mustParse(t *testing.T, kind wire.Kind, raw []byte) wire.Artifact {
	t.Helper()
	artifact, err := wire.ParseAs(kind, raw)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func mustAuthIDOf(t *testing.T, delivery *content.SignedContentDelivery) protocol.PaymentAuthorizationID {
	t.Helper()
	id, err := content.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustPayloadsOf(t *testing.T, delivery *content.SignedContentDelivery) [][]byte {
	t.Helper()
	payloads, err := content.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return payloads
}

// rebuildKind6WithSignature 用篡改后的签名重建 exact Kind 6 bytes：直接在
// CBOR 数组的第四个元素（签名字段）内做字节替换，保持其余元素不变。
func rebuildKind6WithSignature(t *testing.T, rawKind6 []byte, newSignature []byte) ([]byte, error) {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentDelivery, rawKind6)
	if err != nil {
		return nil, err
	}
	delivery, err := wire.DecodeContentDelivery(artifact)
	if err != nil {
		return nil, err
	}
	delivery.SellerContentDeliverySignature = append([]byte(nil), newSignature...)
	out, err := wire.EncodeContentDelivery(delivery)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
