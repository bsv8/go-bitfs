package seller

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/protocol"
	wire "github.com/bsv8/go-bitfs/wire"
)

// 本文件锁定两项安全契约：
//  1. Prepare→Sign 间隙的退款锁重检：托管在持久化期间成熟时，签署必须以
//     expired 拒绝（Field=refund_template_raw），且 Signer 调用次数增量为 0；
//     timestamp 与 height 两种锁定、prepared 与 restored 两类产物都覆盖。
//  2. Workflow 绑定公钥：底层 Signer 在生命周期内轮换私钥后，所有 Kind 的
//     签名路径统一 invalid_signature/unauthorized，绝不能静默写入新身份。

// countingSigner 记录 Sign 调用次数；可注入错误。
type countingSigner struct {
	delegate protocol.Signer
	mu       sync.Mutex
	calls    int
}

func (s *countingSigner) PublicKey() protocol.PublicKey { return s.delegate.PublicKey() }

func (s *countingSigner) callsSnapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *countingSigner) Sign(ctx context.Context, request protocol.SigningRequest) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.delegate.Sign(ctx, request)
}

// rotatableSigner 允许测试中途替换私钥：模拟远程 HSM 密钥轮换。
type rotatableSigner struct {
	mu  sync.Mutex
	key *ec.PrivateKey
}

func newRotatableSigner(t *testing.T, key *ec.PrivateKey) *rotatableSigner {
	t.Helper()
	return &rotatableSigner{key: key}
}

func (s *rotatableSigner) PublicKey() protocol.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	typed, err := protocol.PublicKeyFromBytes(s.key.PubKey().Compressed())
	if err != nil {
		return protocol.PublicKey{}
	}
	return typed
}

func (s *rotatableSigner) rotate(t *testing.T, key *ec.PrivateKey) {
	t.Helper()
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
}

func (s *rotatableSigner) Sign(_ context.Context, request protocol.SigningRequest) ([]byte, error) {
	s.mu.Lock()
	key := s.key
	s.mu.Unlock()
	signature, err := key.Sign(request.Digest.Bytes())
	if err != nil {
		return nil, err
	}
	return signature.ToDER()
}

// refundLockBoundaryCase 描述一次 Prepare→(成熟跨越)→Sign 的边界场景。
type refundLockBoundaryCase struct {
	name string
	// lockTime 是退款模板 nLockTime（timestamp 或 height）。
	lockTime uint32
	// deadline 必须晚于退款锁，保证跨边界时先撞 refund 门禁而非 deadline。
	deadline content.UnixSeconds
	// prepareFacts / signFacts 是两次操作各自唯一的显式事实。
	prepareFacts protocol.Facts
	signFacts    protocol.Facts
}

func refundLockBoundaryCases() []refundLockBoundaryCase {
	// 退款锁必须早于报价有效期（base+1h），deadline 又晚于退款锁，
	// 保证跨边界时先撞 refund 门禁而不是 deadline。
	tsLock := uint32(testBaseTime.Add(30 * time.Minute).Unix())
	heightLock := uint32(800_321)
	return []refundLockBoundaryCase{
		{
			name:         "timestamp lock: sign exactly at locktime",
			lockTime:     tsLock,
			deadline:     content.UnixSeconds(testBaseTime.Add(45 * time.Minute).Unix()), // 锁 < deadline < 报价有效期
			prepareFacts: protocol.Facts{Now: testBaseTime},
			signFacts:    protocol.Facts{Now: time.Unix(int64(tsLock), 0)}, // 恰到锁时刻 → 成熟
		},
		{
			name:         "height lock: sign at maturity height",
			lockTime:     heightLock,
			deadline:     content.UnixSeconds(testBaseTime.Add(time.Hour).Unix()),
			prepareFacts: protocol.Facts{Now: testBaseTime, BlockHeight: protocol.BlockHeight(heightLock - 1)},
			signFacts:    protocol.Facts{Now: testBaseTime.Add(30 * time.Minute), BlockHeight: protocol.BlockHeight(heightLock)},
		},
	}
}

// buildCustodyKind8ForBoundary 以显式锁定/截止构造 exact Kind 8 bytes：
// 开池 → 购买 seed → 卖方 PrepareArbitration。所有时间判断使用显式事实。
func (f *sellerFixture) buildCustodyKind8ForBoundary(t *testing.T, tc refundLockBoundaryCase) []byte {
	t.Helper()
	ctx := context.Background()

	quote, signedQuote := f.defaultQuote(t)
	prepared, err := f.Buyer.PreparePoolOpening(ctx, buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(tc.lockTime),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := f.Seller.PreparePoolOpening(ctx, prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, presign.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := f.Buyer.PrepareFundingDelivery(completed.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	funding, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, deliveryArtifact.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	poolCheckpoint := &PoolCheckpoint{opening: funding.Opening.Proof(), payment: funding.InitialPool.Payment()}

	request, err := f.Buyer.RequestContent(ctx, tc.prepareFacts, buyer.RequestContentCommand{
		Quote:            quote,
		Pool:             completed.InitialPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: tc.deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.Seller.DeliverContent(ctx, tc.prepareFacts, DeliveryCommand{
		Quote:           signedQuote,
		Pool:            poolCheckpoint,
		RequestRaw:      request.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
		Seed:            append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatal(err)
	}
	kind8, err := f.Seller.PrepareArbitration(ctx, tc.prepareFacts, ArbitrationCommand{
		Pool:        poolCheckpoint,
		Request:     request.Checkpoint.Request(),
		DeliveryRaw: delivery.Outbound.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return kind8.Bytes()
}

// TestSignPreparedArbitrationRechecksRefundLockAfterPrepare 覆盖两种锁定类型
// 的 Prepare→Sign 成熟跨越：签署必须 expired 且 Field=refund_template_raw，
// Signer 调用增量必须为 0；prepared 与 restored 产物走同一门禁。
func TestSignPreparedArbitrationRechecksRefundLockAfterPrepare(t *testing.T) {
	for _, tc := range refundLockBoundaryCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newSellerFixture(t)
			rawKind8 := f.buildCustodyKind8ForBoundary(t, tc)

			counter := &countingSigner{delegate: mustSigner(t, f.arbiterKey)}
			wf, err := arbiter.NewWorkflow(counter)
			if err != nil {
				t.Fatal(err)
			}

			assertRefundGateRefusal := func(what string, prepared *arbiter.PreparedArbitration) {
				t.Helper()
				before := counter.callsSnapshot()
				_, err = wf.SignPreparedArbitration(context.Background(), tc.signFacts, prepared)
				after := counter.callsSnapshot()
				if !protocol.IsCode(err, protocol.CodeExpired) {
					t.Fatalf("%s: error = %v, want expired", what, err)
				}
				var perr *protocol.Error
				if !errors.As(err, &perr) || perr.Field != "refund_template_raw" {
					t.Fatalf("%s: field = %v (err=%v), want refund_template_raw", what, perr, err)
				}
				if after-before != 0 {
					t.Fatalf("%s: signer delta = %d, want 0", what, after-before)
				}
			}

			// Prepare（未成熟）应成功。
			prepared, err := wf.PrepareArbitration(tc.prepareFacts, rawKind8, testArbitrationFeeSatoshis)
			if err != nil {
				t.Fatalf("prepare before maturity failed: %v", err)
			}
			assertRefundGateRefusal("prepared", prepared)

			// Restore 产物走同一门禁。
			restored, err := arbiter.RestorePreparedArbitration(rawKind8, testArbitrationFeeSatoshis)
			if err != nil {
				t.Fatal(err)
			}
			assertRefundGateRefusal("restored", restored)

			// 未跨越边界的事实下仍可正常签署（证明门禁没有误伤成功路径）。
			if _, err := wf.SignPreparedArbitration(context.Background(), tc.prepareFacts, prepared); err != nil {
				t.Fatalf("sign with valid facts failed: %v", err)
			}
		})
	}
}

// requireGateClassification 断言错误经 protocol.CodeOf 精确命中 want，
// 且 ErrFactsMissing 哨兵仍可穿透——调用层包装绝不能覆盖稳定分类。
func requireGateClassification(t *testing.T, err error, want protocol.ErrorCode, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error, got nil", what)
	}
	code, ok := protocol.CodeOf(err)
	if !ok || code != want {
		t.Fatalf("%s: error code = %v (err=%v), want exactly %s", what, code, err, want)
	}
	if !errors.Is(err, protocol.ErrFactsMissing) && want == protocol.CodeInvalidEvidence {
		t.Fatalf("%s: invalid_evidence lost ErrFactsMissing sentinel: %v", what, err)
	}
}

// TestSellerDeliverContentMissingHeightFactStaysInvalidEvidence 高度锁池上
// 卖方正向入口缺少 BlockHeight：必须保持事实缺失的 invalid_evidence，
// 绝不能被门禁包装误报成 expired（应用按稳定 Code 分支会得出错误的
// "退款已到期"结论并放弃正常交付）。
func TestSellerDeliverContentMissingHeightFactStaysInvalidEvidence(t *testing.T) {
	f := newSellerFixture(t)
	ctx := context.Background()

	quote, signedQuote := f.defaultQuote(t)
	heightLock := uint32(800_321)
	prepared, err := f.Buyer.PreparePoolOpening(ctx, buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(heightLock),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := f.Seller.PreparePoolOpening(ctx, prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, presign.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := f.Buyer.PrepareFundingDelivery(completed.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	funding, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, deliveryArtifact.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	poolCheckpoint := &PoolCheckpoint{opening: funding.Opening.Proof(), payment: funding.InitialPool.Payment()}
	requestFacts := protocol.Facts{Now: testBaseTime, BlockHeight: protocol.BlockHeight(heightLock - 1)}
	request, err := f.Buyer.RequestContent(ctx, requestFacts, buyer.RequestContentCommand{
		Quote:            quote,
		Pool:             completed.InitialPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Add(time.Hour).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 只有 Now：refund 门禁缺高度必须以 invalid_evidence 拒绝。
	_, err = f.Seller.DeliverContent(ctx, protocol.Facts{Now: testBaseTime}, DeliveryCommand{
		Quote:           signedQuote,
		Pool:            poolCheckpoint,
		RequestRaw:      request.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
		Seed:            append([]byte(nil), f.Seed...),
	})
	requireGateClassification(t, err, protocol.CodeInvalidEvidence, "seller.DeliverContent without block height")
}

// TestSignPreparedArbitrationMissingFactKeepsInvalidEvidence 托管签署入口的
// 事实缺失分类矩阵：timestamp 锁缺 Now 与 height 锁缺 BlockHeight 都必须
// 保持 invalid_evidence，且 Signer 调用增量为 0（不产生任何部分签名）。
func TestSignPreparedArbitrationMissingFactKeepsInvalidEvidence(t *testing.T) {
	tsLock := uint32(testBaseTime.Add(30 * time.Minute).Unix())
	for _, tc := range []struct {
		name         string
		lockTime     uint32
		deadline     content.UnixSeconds
		prepareFacts protocol.Facts
		signFacts    protocol.Facts // 故意缺失当前锁定类型需要的那一份事实
	}{
		{
			name:         "timestamp lock missing Now",
			lockTime:     tsLock,
			deadline:     content.UnixSeconds(testBaseTime.Add(45 * time.Minute).Unix()),
			prepareFacts: protocol.Facts{Now: testBaseTime},
			signFacts:    protocol.Facts{},
		},
		{
			name:         "height lock missing BlockHeight",
			lockTime:     800_321,
			deadline:     content.UnixSeconds(testBaseTime.Add(time.Hour).Unix()),
			prepareFacts: protocol.Facts{Now: testBaseTime, BlockHeight: protocol.BlockHeight(800_320)},
			signFacts:    protocol.Facts{Now: testBaseTime.Add(30 * time.Minute)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSellerFixture(t)
			rawKind8 := f.buildCustodyKind8ForBoundary(t, refundLockBoundaryCase{
				name: tc.name, lockTime: tc.lockTime, deadline: tc.deadline,
				prepareFacts: tc.prepareFacts, signFacts: tc.signFacts,
			})

			counter := &countingSigner{delegate: mustSigner(t, f.arbiterKey)}
			wf, err := arbiter.NewWorkflow(counter)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := wf.PrepareArbitration(tc.prepareFacts, rawKind8, testArbitrationFeeSatoshis)
			if err != nil {
				t.Fatal(err)
			}

			before := counter.callsSnapshot()
			_, err = wf.SignPreparedArbitration(context.Background(), tc.signFacts, prepared)
			after := counter.callsSnapshot()
			requireGateClassification(t, err, protocol.CodeInvalidEvidence, tc.name)
			if after-before != 0 {
				t.Fatalf("%s: signer delta = %d, want 0", tc.name, after-before)
			}
		})
	}
}

func assertInvalidSignatureOrUnauthorized(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded after key rotation", what)
	}
	if !isSignatureFamilyError(err) {
		t.Fatalf("%s error = %v, want invalid_signature/unauthorized", what, err)
	}
}

func isSignatureFamilyError(err error) bool {
	return protocol.IsCode(err, protocol.CodeInvalidSignature) ||
		protocol.IsCode(err, protocol.CodeUnauthorized) ||
		errors.Is(err, protocol.ErrHighSSignature)
}

// TestWorkflowBindsSignerPublicKeyAcrossKinds 远程 Signer 中途轮换私钥：
// 所有 Kind 的签名返回必须统一 invalid_signature/unauthorized，
// Kind 1 绝不能把新公钥写进报价；轮换前的历史 Artifact 保持有效。
func TestWorkflowBindsSignerPublicKeyAcrossKinds(t *testing.T) {
	f := newSellerFixture(t)
	ctx := context.Background()

	buyerRotating := newRotatableSigner(t, mustTestKey(t, "11"))
	sellerRotating := newRotatableSigner(t, mustTestKey(t, "22"))
	arbRotating := newRotatableSigner(t, mustTestKey(t, "33"))

	buyerWf, err := buyer.NewWorkflow(buyerRotating)
	if err != nil {
		t.Fatal(err)
	}
	sellerWf, err := NewWorkflow(sellerRotating)
	if err != nil {
		t.Fatal(err)
	}
	arbWf, err := arbiter.NewWorkflow(arbRotating)
	if err != nil {
		t.Fatal(err)
	}
	f.Buyer = buyerWf
	f.Seller = sellerWf
	f.Arbiter = arbWf

	quoteResult, err := sellerWf.CreateQuote(ctx, testFacts(testBaseTime), QuoteDraft{
		SeedHash:                   f.SeedHash,
		BuyerPublicKey:             f.buyerPubKey,
		SeedPriceSatoshis:          protocol.Satoshis(100),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(f.FileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(testBaseTime.Add(time.Hour).Unix()),
		SupportedArbiterPublicKeys: []protocol.PublicKey{f.arbiterPubKey},
		RecommendedFilename:        "rotate.bin",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 轮换前：开池全链成功。
	p := f.openDefaultPoolWithQuoteAndWorkflows(t, quoteResult.Outbound.Bytes())

	verifiedQuote, err := buyerWf.AcceptQuote(testFacts(testBaseTime), quoteResult.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// ---- Kind 5（轮换前成功，保留 checkpoint 供 Kind 10 使用）----
	request, err := buyerWf.RequestContent(ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote:            verifiedQuote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Add(30 * time.Minute).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}

	// ---- Kind 11（轮换前成功）----
	requestID := protocol.ContentRetrievalRequestID(bytes32ForTest(0xA7))
	if _, err := arbWf.BuildUnavailableRetrieval(ctx, requestID, arbitration.RetrievalSellerArbitrationNotReady); err != nil {
		t.Fatalf("pre-rotation unavailable build failed: %v", err)
	}

	// ===== 轮换阶段：三把钥全部换成无关新钥 =====
	buyerRotating.rotate(t, mustTestKey(t, "88"))
	sellerRotating.rotate(t, mustTestKey(t, "99"))
	arbRotating.rotate(t, mustTestKey(t, "66"))

	// ---- Kind 1：绝不能静默写入新身份 ----
	_, err = sellerWf.CreateQuote(ctx, testFacts(testBaseTime.Add(time.Minute)), QuoteDraft{
		SeedHash:                   f.SeedHash,
		BuyerPublicKey:             f.buyerPubKey,
		SeedPriceSatoshis:          protocol.Satoshis(100),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(f.FileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(testBaseTime.Add(2 * time.Hour).Unix()),
		SupportedArbiterPublicKeys: []protocol.PublicKey{f.arbiterPubKey},
		RecommendedFilename:        "rotate2.bin",
	})
	assertInvalidSignatureOrUnauthorized(t, err, "seller.CreateQuote after key rotation")

	// ---- Kind 5 ----
	_, err = buyerWf.RequestContent(ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote:            verifiedQuote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Add(30 * time.Minute).Unix()),
	})
	assertInvalidSignatureOrUnauthorized(t, err, "buyer.RequestContent after rotation")

	// ---- Kind 10：Workflow 默认入口（SDK 生成 nonce 的路径）----
	_, err = buyerWf.RequestArbitratedContent(ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          p.buyerPool,
		Authorization: request.Checkpoint,
	})
	assertInvalidSignatureOrUnauthorized(t, err, "buyer.RequestArbitratedContent after rotation")

	// ---- Kind 6：同一份授权，交付签署必须失败 ----
	signedQuoteForDelivery, err := wire.DecodeFileQuote(quoteResult.Outbound)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sellerWf.DeliverContent(ctx, testFacts(testBaseTime), DeliveryCommand{
		Quote:           signedQuoteForDelivery,
		Pool:            p.sellerPool,
		RequestRaw:      request.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	})
	assertInvalidSignatureOrUnauthorized(t, err, "seller.DeliverContent after rotation")

	// ---- Kind 11 ----
	_, err = arbWf.BuildUnavailableRetrieval(ctx, requestID, arbitration.RetrievalSellerArbitrationNotReady)
	assertInvalidSignatureOrUnauthorized(t, err, "arbiter.BuildUnavailableRetrieval after rotation")

	// ---- Workflow 交易签名路径（PrepareClose 内部经 adapter 签署）----
	_, err = buyerWf.PrepareClose(ctx, testFacts(testBaseTime), buyer.PrepareCloseCommand{
		Pool:                       p.buyerPool,
		Base:                       p.buyerPool.Payment(),
		TargetSellerAmountSatoshis: protocol.Satoshis(p.buyerPool.Payment().SellerAmountSatoshis),
	})
	assertInvalidSignatureOrUnauthorized(t, err, "buyer.PrepareClose after rotation")
}

func bytes32ForTest(fill byte) [32]byte {
	return [32]byte(bytes.Repeat([]byte{fill}, 32))
}

// openDefaultPoolWithQuoteAndWorkflows 以指定报价 bytes 驱动开池（测试辅助）：
// 使用 fixture 的三方 workflow 完成 002→0203→0204→0205 全链。
func (f *sellerFixture) openDefaultPoolWithQuoteAndWorkflows(t *testing.T, quoteRaw []byte) *openedPool {
	t.Helper()
	ctx := context.Background()
	verified, err := f.Buyer.AcceptQuote(testFacts(testBaseTime), quoteRaw)
	if err != nil {
		t.Fatal(err)
	}
	command := buyer.PrepareOpeningCommand{
		Quote:                           verified,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	}
	prepared, err := f.Buyer.PreparePoolOpening(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	presign, err := f.Seller.PreparePoolOpening(ctx, prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, presign.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := f.Buyer.PrepareFundingDelivery(completed.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	funding, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, deliveryArtifact.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return &openedPool{
		buyerOpening:  prepared.Checkpoint,
		buyerPool:     completed.InitialPool,
		sellerOpening: presign.Checkpoint,
		sellerPool:    funding.InitialPool,
		rawKind2:      prepared.Outbound.Bytes(),
		rawKind3:      presign.Outbound.Bytes(),
		rawKind4:      deliveryArtifact.Bytes(),
	}
}
