// Package integration exercises the complete BitFS v1 protocol lifecycle
// 001–008 through the new role APIs (buyer/seller/arbiter Workflow)。测试本身
// 扮演调用方应用：报价、checkpoint（开池/池/授权/交付）、付款状态与 exact
// wire 字节全部保存在本地变量并显式传入每个 SDK 调用；SDK 不持有任何存储。
// 时间一律使用固定 UTC Facts{Now, BlockHeight}，错误断言使用协议分类码。
package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

const (
	testBlockHeight            protocol.BlockHeight = 900000
	testArbitrationFeeSatoshis protocol.Satoshis    = 500
	testMinerFeeRateSatPerKB   uint64               = 1
	testPoolOutputSatoshis     uint64               = 100000
	testSeedPriceSatoshis      uint64               = 100
)

// testBaseTime 是全部测试共用的固定时间事实来源；时间敏感断言通过相对它
// 加减偏移表达"过期前一秒/到期当刻/之后一秒"。
var testBaseTime = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func testFacts(at time.Time) protocol.Facts {
	return protocol.Facts{Now: at, BlockHeight: testBlockHeight}
}

func testKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testSigner(t *testing.T, key *ec.PrivateKey) *protocol.PrivateKeySigner {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testPublicKey(t *testing.T, key *ec.PrivateKey) protocol.PublicKey {
	t.Helper()
	publicKey, err := protocol.PublicKeyFromBytes(key.PubKey().Compressed())
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func requireCode(t *testing.T, err error, want protocol.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	if !protocol.IsCode(err, want) {
		code, _ := protocol.CodeOf(err)
		t.Fatalf("error code = %v (err=%v), want %s", code, err, want)
	}
}

// requireAnyCode 断言错误稳定落在给定的分类码集合内（用于底层验证路径可能
// 在多个等价分类之间选择的场景）。
func requireAnyCode(t *testing.T, err error, allowed ...protocol.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected classified error in %v, got nil", allowed)
	}
	for _, code := range allowed {
		if protocol.IsCode(err, code) {
			return
		}
	}
	got, _ := protocol.CodeOf(err)
	t.Fatalf("error code = %v (err=%v), want one of %v", got, err, allowed)
}

// buildTestFundingTx 构造一笔只含 2-of-3 池输出的资金交易：输入为零哈希
// 占位符，不代表真实可花费 UTXO；SDK 只验证输出与退款模板的关系。
func buildTestFundingTx(t *testing.T, satoshis uint64, keys pool.MultisigPoolPublicKeys) []byte {
	t.Helper()
	lock, err := pool.Build2of3LockingScript(keys)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: satoshis, LockingScript: script.NewFromBytes(lock)})
	return funding.Bytes()
}

func samePaymentState(left, right *pool.PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID &&
		left.PaymentSequence == right.PaymentSequence &&
		left.SellerAmountSatoshis == right.SellerAmountSatoshis &&
		left.ArbiterAmountSatoshis == right.ArbiterAmountSatoshis &&
		bytes.Equal(left.RawTx, right.RawTx)
}

func mergedSignedPayment(vt *pool.VerifiedSignedTransaction) *pool.SignedPayment {
	return &pool.SignedPayment{State: *vt.State(), RawTx: vt.RawTx()}
}

// retrievalRequestIDOf 从 exact Kind 10 bytes 派生请求 ID：
// SHA-256(exact content_retrieval_request_cbor)。
func retrievalRequestIDOf(t *testing.T, rawKind10 []byte) protocol.ContentRetrievalRequestID {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentRetrievalRequest, rawKind10)
	if err != nil {
		t.Fatal(err)
	}
	requestDTO, err := wire.DecodeContentRetrievalRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(requestDTO.ContentRetrievalRequestCBOR)
	return protocol.ContentRetrievalRequestID(digest)
}

// protocolFixture 是三方固定密钥下的应用侧状态容器：001 报价与 002 开池在
// New 时完成，后续场景复用同一套 checkpoint。
type protocolFixture struct {
	ctx        context.Context
	buyerKey   *ec.PrivateKey
	sellerKey  *ec.PrivateKey
	arbiterKey *ec.PrivateKey

	Buyer   *buyer.Workflow
	Seller  *seller.Workflow
	Arbiter *arbiter.Workflow

	buyerPubKey   protocol.PublicKey
	sellerPubKey  protocol.PublicKey
	arbiterPubKey protocol.PublicKey

	Seed      []byte
	SeedHash  []byte
	FileBytes []byte

	FundingTransactionRaw []byte
	Expiry                uint32 // 时间戳型退款锁：base + 1h
	QuoteExpiresAt        int64
	DeliveryDeadline      content.UnixSeconds

	// 001 双侧各自保存 exact Kind 1 bytes 与自己的验证快照。
	quoteRaw    []byte
	buyerQuote  *content.VerifiedQuote
	sellerQuote *content.SignedFileQuote

	opened *openedPool
}

func newProtocolFixture(t *testing.T) *protocolFixture {
	t.Helper()
	f := &protocolFixture{
		ctx:        context.Background(),
		buyerKey:   testKey(t, "11"),
		sellerKey:  testKey(t, "22"),
		arbiterKey: testKey(t, "33"),
	}
	var err error
	f.Buyer, err = buyer.NewWorkflow(testSigner(t, f.buyerKey))
	if err != nil {
		t.Fatal(err)
	}
	f.Seller, err = seller.NewWorkflow(testSigner(t, f.sellerKey))
	if err != nil {
		t.Fatal(err)
	}
	f.Arbiter, err = arbiter.NewWorkflow(testSigner(t, f.arbiterKey))
	if err != nil {
		t.Fatal(err)
	}
	f.buyerPubKey = testPublicKey(t, f.buyerKey)
	f.sellerPubKey = testPublicKey(t, f.sellerKey)
	f.arbiterPubKey = testPublicKey(t, f.arbiterKey)

	source := bytes.Repeat([]byte{7}, 4096)
	f.FileBytes = source
	var seedBuffer bytes.Buffer
	if _, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(source), &seedBuffer); err != nil {
		t.Fatal(err)
	}
	f.Seed = seedBuffer.Bytes()
	f.SeedHash = masterseed.Sum256(f.Seed).Bytes()

	keys := pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerPubKey[:], SellerPublicKey: f.sellerPubKey[:], ArbiterPublicKey: f.arbiterPubKey[:]}
	f.FundingTransactionRaw = buildTestFundingTx(t, testPoolOutputSatoshis, keys)
	f.Expiry = uint32(testBaseTime.Add(time.Hour).Unix())
	f.QuoteExpiresAt = testBaseTime.Add(time.Hour).Unix()
	f.DeliveryDeadline = content.UnixSeconds(testBaseTime.Add(30 * time.Minute).Unix())

	// ---- 001：卖方创建报价并持久化 exact bytes，买方从字节验收。----
	qr, err := f.Seller.CreateQuote(f.ctx, testFacts(testBaseTime), seller.QuoteDraft{
		SeedHash:                   f.SeedHash,
		BuyerPublicKey:             f.buyerPubKey,
		SeedPriceSatoshis:          protocol.Satoshis(testSeedPriceSatoshis),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(f.FileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(f.QuoteExpiresAt),
		SupportedArbiterPublicKeys: []protocol.PublicKey{mustTypedPublicKey(t, f.arbiterPubKey[:])},
		RecommendedFilename:        "file.bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.quoteRaw = qr.Outbound.Bytes() // 应用先保存 exact Artifact 字节再发送
	// 卖方侧持有 exact 已签报价（DeliverContent 需要）；买方从持久化字节验收。
	sellerQuoteArtifact, err := wire.ParseAs(wire.FileQuote, f.quoteRaw)
	if err != nil {
		t.Fatal(err)
	}
	f.sellerQuote, err = wire.DecodeFileQuote(sellerQuoteArtifact)
	if err != nil {
		t.Fatal(err)
	}
	f.buyerQuote = f.mustAcceptQuote(t, testBaseTime, f.quoteRaw)
	return f
}

func (f *protocolFixture) mustAcceptQuote(t *testing.T, at time.Time, raw []byte) *content.VerifiedQuote {
	t.Helper()
	verified, err := f.Buyer.AcceptQuote(testFacts(at), raw)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

// openedPool 保存一次 002 开池往返的双侧 checkpoint 与 exact 报文字节。
type openedPool struct {
	buyerOpening  *buyer.OpeningCheckpoint
	buyerPool     *buyer.PoolCheckpoint
	sellerOpening *seller.OpeningCheckpoint
	sellerPool    *seller.PoolCheckpoint
	rawKind2      []byte
	rawKind3      []byte
	rawKind4      []byte
}

// openPool 走完 0201→0205：每一步都先持久化 exact wire bytes / checkpoint，
// 再把字节交给对端角色 API。
func (f *protocolFixture) openPool(t *testing.T, fundingRaw []byte) *openedPool {
	t.Helper()
	prepared, err := f.Buyer.PreparePoolOpening(f.ctx, buyer.PrepareOpeningCommand{
		Quote:                           f.buyerQuote,
		FundingTransactionRaw:           fundingRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind2 := prepared.Outbound.Bytes() // 应用先持久化 checkpoint 与 bytes 再发送

	presign, err := f.Seller.PreparePoolOpening(f.ctx, rawKind2)
	if err != nil {
		t.Fatal(err)
	}
	rawKind3 := presign.Outbound.Bytes()

	completed, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, rawKind3)
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := f.Buyer.PrepareFundingDelivery(completed.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	rawKind4 := deliveryArtifact.Bytes()

	funding, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, rawKind4)
	if err != nil {
		t.Fatal(err)
	}
	return &openedPool{
		buyerOpening:  prepared.Checkpoint,
		buyerPool:     completed.InitialPool,
		sellerOpening: presign.Checkpoint,
		sellerPool:    funding.InitialPool,
		rawKind2:      rawKind2,
		rawKind3:      rawKind3,
		rawKind4:      rawKind4,
	}
}

func (f *protocolFixture) openMainPool(t *testing.T) *openedPool {
	t.Helper()
	p := f.openPool(t, f.FundingTransactionRaw)
	f.opened = p
	return p
}

// purchaseRound 是一轮 003→004→005 的双侧产物。
type purchaseRound struct {
	pool         *openedPool
	request      *buyer.RequestContentResult
	rawKind5     []byte
	delivery     *seller.DeliveryCheckpoint
	rawKind6     []byte
	payment      *buyer.PaymentPreparationResult
	rawKind7     []byte
	completedPay *seller.CompletePaymentResult // 可为 nil：仲裁批次不完成 005
}

// runPurchaseWithDeadline 从指定池状态执行一轮 seed 购买；completePayment
// 控制是否执行 005 完成步（仲裁/取回场景保持"已交付未支付"状态）。
func (f *protocolFixture) runPurchaseWithDeadline(t *testing.T, quote *content.VerifiedQuote, p *openedPool, at time.Time, deadline content.UnixSeconds, completePayment bool) *purchaseRound {
	t.Helper()
	rc, err := f.Buyer.RequestContent(f.ctx, testFacts(at), buyer.RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind5 := rc.Outbound.Bytes()

	delivery, err := f.Seller.DeliverContent(f.ctx, testFacts(at), seller.DeliveryCommand{
		Quote:           f.sellerQuote,
		Pool:            p.sellerPool,
		RequestRaw:      rawKind5,
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind6 := delivery.Outbound.Bytes()

	payment, err := f.Buyer.VerifyDeliveryAndPreparePayment(f.ctx, testFacts(at), buyer.VerifyDeliveryCommand{
		Quote:       quote,
		Pool:        p.buyerPool,
		Request:     rc.Checkpoint,
		DeliveryRaw: rawKind6,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind7 := payment.Outbound.Bytes()

	round := &purchaseRound{pool: p, request: rc, rawKind5: rawKind5, delivery: delivery.Checkpoint, rawKind6: rawKind6, payment: payment, rawKind7: rawKind7}
	if !completePayment {
		return round
	}
	completedPay, err := f.Seller.CompletePayment(f.ctx, testFacts(at), seller.PaymentCommand{
		Pool:       p.sellerPool,
		Request:    rc.Checkpoint.Request(),
		UpdateRaw:  rawKind7,
		Checkpoint: delivery.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	round.completedPay = completedPay
	// 应用作为协调方共享合并后的最新状态：卖方直接持有 NextPool；买方用
	// RestorePoolCheckpoint 从 canonical opening proof + 完整付款 raw tx 恢复。
	p.sellerPool = completedPay.NextPool
	proofCBOR, err := pool.EncodeOpeningProof(p.buyerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	nextBuyerPool, err := buyer.RestorePoolCheckpoint(proofCBOR, completedPay.Transaction.RawTx())
	if err != nil {
		t.Fatal(err)
	}
	p.buyerPool = nextBuyerPool
	return round
}

func (f *protocolFixture) purchaseSeed(t *testing.T, p *openedPool, at time.Time) *purchaseRound {
	t.Helper()
	return f.runPurchaseWithDeadline(t, f.buyerQuote, p, at, f.DeliveryDeadline, true)
}

// buildCustodyChain 在指定池上完成 003→004→007：返回 exact Kind 8/9 bytes。
func (f *protocolFixture) buildCustodyChain(t *testing.T, p *openedPool) ([]byte, []byte, *purchaseRound) {
	t.Helper()
	round := f.runPurchaseWithDeadline(t, f.buyerQuote, p, testBaseTime, f.DeliveryDeadline, false)
	rawKind8, err := f.Seller.PrepareArbitration(f.ctx, testFacts(testBaseTime), seller.ArbitrationCommand{
		Pool:        p.sellerPool,
		Request:     round.request.Checkpoint.Request(),
		DeliveryRaw: round.rawKind6,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), rawKind8.Bytes(), testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	responseArtifact, err := f.Arbiter.SignPreparedArbitration(f.ctx, testFacts(testBaseTime), prepared)
	if err != nil {
		t.Fatal(err)
	}
	return rawKind8.Bytes(), responseArtifact.Bytes(), round
}

// ---- 完整 001→008 端到端：close / refund / arbitration / retrieval 全覆盖 ----

func TestFullLifecycle001Through008WithRoleAPIs(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)

	// 初始池状态：sequence=2、卖方与仲裁金额为零。
	initial := p.buyerPool.Payment()
	if initial.PaymentSequence != 2 || initial.SellerAmountSatoshis != 0 || initial.ArbiterAmountSatoshis != 0 {
		t.Fatalf("initial state = seq %d seller %d arbiter %d", initial.PaymentSequence, initial.SellerAmountSatoshis, initial.ArbiterAmountSatoshis)
	}

	// ---- 003→004→005 第一轮 seed 购买，双方推进到同一确认状态。----
	round1 := f.purchaseSeed(t, p, testBaseTime)
	if len(round1.payment.Payloads) != 1 || !bytes.Equal(round1.payment.Payloads[0], f.Seed) {
		t.Fatal("verified payload batch does not match delivered seed content")
	}
	latest := p.sellerPool.Payment()
	if latest.PaymentSequence != 3 || latest.SellerAmountSatoshis != testSeedPriceSatoshis {
		t.Fatalf("after round one = seq %d amount %d", latest.PaymentSequence, latest.SellerAmountSatoshis)
	}
	if !samePaymentState(latest, p.buyerPool.Payment()) {
		t.Fatal("buyer and seller diverged after the first cumulative payment")
	}

	// ---- 006 close：从共享最新状态立即关闭并由买方验证最终交易。----
	closePrep, err := f.Buyer.PrepareClose(f.ctx, testFacts(testBaseTime), buyer.PrepareCloseCommand{
		Pool:                       p.buyerPool,
		Base:                       latest,
		TargetSellerAmountSatoshis: protocol.Satoshis(latest.SellerAmountSatoshis),
	})
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.Seller.CompleteClose(f.ctx, testFacts(testBaseTime), seller.CloseCommand{
		Pool:           p.sellerPool,
		Unsigned:       closePrep.Unsigned,
		BuyerSignature: closePrep.BuyerSignature,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedClose, err := f.Buyer.VerifyCompletedClose(buyer.VerifyCloseCommand{Pool: p.buyerPool, Close: mergedSignedPayment(closed)})
	if err != nil {
		t.Fatal(err)
	}
	if verifiedClose.PaymentSequence() != protocol.PaymentSequence(^uint32(0)) || verifiedClose.SellerAmountSatoshis() != protocol.Satoshis(latest.SellerAmountSatoshis) {
		t.Fatalf("final close = seq %d amount %d", verifiedClose.PaymentSequence(), verifiedClose.SellerAmountSatoshis())
	}

	// ---- refund：锁定未到 → not_matured；到期事实到达后可构造可广播退款。----
	if _, err := f.Buyer.BuildMaturedRefund(testFacts(testBaseTime), p.buyerPool); !protocol.IsCode(err, protocol.CodeNotMatured) {
		t.Fatalf("pre-maturity refund error = %v, want not_matured", err)
	}
	maturedFacts := protocol.Facts{Now: time.Unix(int64(f.Expiry), 0).UTC(), BlockHeight: testBlockHeight}
	refund, err := f.Buyer.BuildMaturedRefund(maturedFacts, p.buyerPool)
	if err != nil {
		t.Fatal(err)
	}
	if len(refund.RawTx()) == 0 || refund.State().PaymentSequence != 2 || refund.State().SellerAmountSatoshis != 0 {
		t.Fatalf("matured refund state = %+v", refund.State())
	}
	if refund.RefundTemplateTxID() != p.buyerPool.RefundTemplateTxID() {
		t.Fatal("refund transaction does not match the pool correlation ID")
	}

	// ---- 007 arbitration：第二批交付后走托管收款全链。----
	kind8, kind9, round2 := f.buildCustodyChain(t, p)
	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), kind8, testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.FeeSatoshis() != testArbitrationFeeSatoshis || prepared.ArbitrationClaimID().IsZero() {
		t.Fatalf("prepared arbitration audit fields incomplete: fee=%d claimID zero=%t", prepared.FeeSatoshis(), prepared.ArbitrationClaimID().IsZero())
	}
	response9, err := f.Arbiter.SignPreparedArbitration(f.ctx, testFacts(testBaseTime), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if response9.Kind() != wire.ArbitrationResponse {
		t.Fatalf("kind 9 artifact kind = %d", response9.Kind())
	}
	// 卖方把自己保存的 exact payload bundle 一并交给 SDK 做逐字节比对。
	kind6Artifact, err := wire.ParseAs(wire.ContentDelivery, round2.rawKind6)
	if err != nil {
		t.Fatal(err)
	}
	deliveryDTO, err := wire.DecodeContentDelivery(kind6Artifact)
	if err != nil {
		t.Fatal(err)
	}
	arbitratedTx, err := f.Seller.CompleteArbitratedPayment(f.ctx, testFacts(testBaseTime), seller.ArbitratedPaymentCommand{
		RequestRaw:           kind8,
		ResponseRaw:          response9.Bytes(),
		DeliveryPayloadsCBOR: deliveryDTO.ContentPayloadsCBOR,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := arbitratedTx.State()
	if state.ArbiterAmountSatoshis != uint64(testArbitrationFeeSatoshis) {
		t.Fatalf("arbitrated arbiter amount = %d, want %d", state.ArbiterAmountSatoshis, testArbitrationFeeSatoshis)
	}

	// ---- 008 retrieval：买方独立构造 Kind 10，仲裁方验证托管并回答。----
	k10, err := f.Buyer.RequestArbitratedContent(f.ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          round2.pool.buyerPool,
		Authorization: round2.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if k10.Kind() != wire.ContentRetrievalRequest {
		t.Fatalf("kind 10 artifact kind = %d", k10.Kind())
	}
	// 重试必须原样重放已持久化的 Kind 10；SDK 每次调用生成新 nonce。
	k10Again, err := f.Buyer.RequestArbitratedContent(f.ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          round2.pool.buyerPool,
		Authorization: round2.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k10.Bytes(), k10Again.Bytes()) {
		t.Fatal("two retrieval requests reused one nonce")
	}

	requestID := retrievalRequestIDOf(t, k10.Bytes())
	if !strings.HasPrefix(requestID.String(), "cr_") {
		t.Fatalf("typed request id prefix missing: %s", requestID.String())
	}

	custody, err := f.Arbiter.VerifyRetrievableCustody(k10.Bytes(), kind8, kind9)
	if err != nil {
		t.Fatal(err)
	}
	before := pool.ClonePaymentState(round2.pool.buyerPool.Payment())

	available, err := f.Arbiter.BuildAvailableRetrieval(f.ctx, requestID, custody)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := f.Buyer.VerifyArbitratedContent(f.ctx, buyer.ArbitratedContentCommand{
		Quote:                f.buyerQuote,
		Pool:                 round2.pool.buyerPool,
		Request:              round2.request.Checkpoint,
		RetrievalRequestRaw:  k10.Bytes(),
		RetrievalResponseRaw: available.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Available || len(outcome.Payloads) != 1 || !bytes.Equal(outcome.Payloads[0], f.Seed) {
		t.Fatalf("available outcome mismatch: available=%t payloads=%d", outcome.Available, len(outcome.Payloads))
	}
	if outcome.ContentRetrievalRequestID != requestID || outcome.ArbitrationClaimID != prepared.ArbitrationClaimID() {
		t.Fatal("audit binding does not tie the answer to the exact request and custody claim")
	}
	if !samePaymentState(before, round2.pool.buyerPool.Payment()) {
		t.Fatal("retrieval mutated the previous payment state")
	}

	// valid unavailable 是 typed 结果而不是 error：旧 nonce 永远不会升级为
	// 下载授权，买方必须换新 nonce 重试。
	unavailable, err := f.Arbiter.BuildUnavailableRetrieval(f.ctx, requestID, arbitration.RetrievalSellerArbitrationNotReady)
	if err != nil {
		t.Fatal(err)
	}
	unavailableOutcome, err := f.Buyer.VerifyArbitratedContent(f.ctx, buyer.ArbitratedContentCommand{
		Quote:                f.buyerQuote,
		Pool:                 round2.pool.buyerPool,
		Request:              round2.request.Checkpoint,
		RetrievalRequestRaw:  k10.Bytes(),
		RetrievalResponseRaw: unavailable.Bytes(),
	})
	if err != nil {
		t.Fatalf("valid unavailable must not be an error: %v", err)
	}
	if unavailableOutcome.Available || unavailableOutcome.UnavailableReason != arbitration.RetrievalSellerArbitrationNotReady || len(unavailableOutcome.Payloads) != 0 {
		t.Fatalf("unavailable outcome mismatch: %+v", unavailableOutcome)
	}
	if !samePaymentState(before, round2.pool.buyerPool.Payment()) {
		t.Fatal("unavailable answer mutated the previous payment state")
	}
}

// ---- 连续累计付款轮次 ----

// TestConsecutiveCumulativeRoundsShareConfirmedState runs two full
// 003→004→005 rounds; the second must consume the first round's confirmed
// state so sequence and cumulative amount keep advancing.
func TestConsecutiveCumulativeRoundsShareConfirmedState(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)

	round1 := f.purchaseSeed(t, p, testBaseTime)
	latest := p.sellerPool.Payment()
	if !samePaymentState(latest, p.buyerPool.Payment()) {
		t.Fatal("round-one confirmed states diverged between roles")
	}
	if round1.completedPay.Transaction.State().PaymentSequence != latest.PaymentSequence {
		t.Fatal("merged transaction state does not match the shared checkpoint")
	}

	round2 := f.purchaseSeed(t, p, testBaseTime.Add(time.Minute))
	final := p.sellerPool.Payment()
	if final.PaymentSequence != latest.PaymentSequence+1 {
		t.Fatalf("round-two sequence = %d, want %d", final.PaymentSequence, latest.PaymentSequence+1)
	}
	if final.SellerAmountSatoshis != latest.SellerAmountSatoshis+testSeedPriceSatoshis {
		t.Fatalf("round-two amount = %d, want %d", final.SellerAmountSatoshis, latest.SellerAmountSatoshis+testSeedPriceSatoshis)
	}
	if !bytes.Equal(final.RawTx, round2.completedPay.Transaction.RawTx()) {
		t.Fatal("round-two merged transaction does not match its parsed state")
	}

	// 买方日志仍停在第一轮时无法开启下一轮：陈旧序号必须被拒绝。
	// （用第一轮的 exact Kind 5 对已推进的卖方状态重新交付。）
	if _, err := f.Seller.DeliverContent(f.ctx, testFacts(testBaseTime), seller.DeliveryCommand{
		Quote:           f.sellerQuote,
		Pool:            p.sellerPool,
		RequestRaw:      round1.rawKind5,
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	}); err == nil {
		t.Fatal("replayed round-one authorization was accepted for a new delivery")
	} else {
		requireCode(t, err, protocol.CodeStateConflict)
	}
}

// ---- 角色错配与显式事实门禁 ----

func TestWrongRolesAndExpiredFactsAreClassified(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)

	wrongBuyer, err := buyer.NewWorkflow(testSigner(t, testKey(t, "44")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongBuyer.PrepareFundingDelivery(p.buyerPool); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong buyer funding delivery error = %v, want unauthorized", err)
	}

	wrongSeller, err := seller.NewWorkflow(testSigner(t, testKey(t, "44")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongSeller.PreparePoolOpening(f.ctx, p.rawKind2); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong seller presign error = %v, want unauthorized", err)
	}

	// 退款未到期时不能构造退款，但正向操作仍可用；到期后正向门禁关闭。
	expiredFacts := protocol.Facts{Now: time.Unix(int64(f.Expiry)+1, 0).UTC(), BlockHeight: testBlockHeight}
	if _, err := f.Buyer.RequestContent(f.ctx, expiredFacts, buyer.RequestContentCommand{
		Quote:            f.buyerQuote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(expiredFacts.Now.Add(30 * time.Minute).Unix()),
	}); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("request after refund expiry error = %v, want expired", err)
	}
	refund, err := f.Buyer.BuildMaturedRefund(expiredFacts, p.buyerPool)
	if err != nil {
		t.Fatal(err)
	}
	if refund.RefundTemplateTxID() != p.buyerPool.RefundTemplateTxID() {
		t.Fatal("refund correlation mismatch under expired facts")
	}

	// 缺失时间事实直接拒绝，绝不回退系统时钟。
	if _, err := f.Buyer.AcceptQuote(protocol.Facts{}, f.quoteRaw); err == nil {
		t.Fatal("zero facts accepted for a time-sensitive operation")
	}
}

// mustTypedPublicKey 把压缩公钥字节转换为强类型公钥（测试辅助）。
func mustTypedPublicKey(t *testing.T, raw []byte) protocol.PublicKey {
	t.Helper()
	typed, err := protocol.PublicKeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return typed
}
