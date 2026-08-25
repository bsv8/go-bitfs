// Cross-pool isolation tests: two pools' state is held explicitly by the
// test application in separate variables; any evidence swap between the pools
// — checkpoint、角色、序号错配 —— 必须稳定返回 state_conflict / invalid_evidence
// 分类错误，绝不允许静默合并两条资金池状态。
package integration

import (
	"bytes"
	"testing"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
)

func openNamedPool(t *testing.T, f *protocolFixture, satoshis uint64) *openedPool {
	t.Helper()
	keys := pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerPubKey[:], SellerPublicKey: f.sellerPubKey[:], ArbiterPublicKey: f.arbiterPubKey[:]}
	return f.openPool(t, buildTestFundingTx(t, satoshis, keys))
}

func TestTwoPoolsKeepTheirExplicitStatesSeparate(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := openNamedPool(t, f, 100000)
	poolB := openNamedPool(t, f, 110000)
	if poolA.buyerPool.RefundTemplateTxID() == poolB.buyerPool.RefundTemplateTxID() {
		t.Fatal("distinct pools produced identical correlation IDs")
	}
	if poolA.buyerPool.Payment().PaymentSequence != 2 || poolB.sellerPool.Payment().PaymentSequence != 2 {
		t.Fatal("initial states missing or wrong sequence")
	}
	if bytes.Equal(poolA.rawKind2, poolB.rawKind2) {
		t.Fatal("distinct funding transactions produced identical presign requests")
	}
}

func TestCrossPoolPresignResponseIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := openNamedPool(t, f, 100000)
	preparedB, err := f.Buyer.PreparePoolOpening(f.ctx, buyer.PrepareOpeningCommand{
		Quote:                           f.buyerQuote,
		FundingTransactionRaw:           buildTestFundingTx(t, 120000, pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerPubKey[:], SellerPublicKey: f.sellerPubKey[:], ArbiterPublicKey: f.arbiterPubKey[:]}),
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	presignB, err := f.Seller.PreparePoolOpening(f.ctx, preparedB.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// Pool B 的响应不能通过 pool A 已持久化的本地状态校验 → state_conflict。
	_, err = f.Buyer.CompletePoolOpening(poolA.buyerOpening, presignB.Outbound.Bytes())
	requireCode(t, err, protocol.CodeStateConflict)
}

func TestCrossPoolFundingDeliveryIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := openNamedPool(t, f, 100000)
	poolB := openNamedPool(t, f, 110000)
	// 把 pool A 的资金交付对到 pool B 的预签证据上：关联 ID 先行冲突。
	_, err := f.Seller.VerifyFundingDelivery(poolB.sellerOpening, poolA.rawKind4)
	requireCode(t, err, protocol.CodeStateConflict)
}

func TestCrossPoolContentAndArbitrationEvidenceAreRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := openNamedPool(t, f, 100000)
	poolB := openNamedPool(t, f, 110000)

	requestA, err := f.Buyer.RequestContent(f.ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote:            f.buyerQuote,
		Pool:             poolA.buyerPool,
		ContentHashes:    [][]byte{masterseed.Sum256(f.Seed).Bytes()},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 绑定 pool A 的授权不能对 pool B 的状态交付：池身份/序号错配必须落在
	// state_conflict 或 invalid_evidence 分类内，绝不静默成功。
	_, err = f.Seller.DeliverContent(f.ctx, testFacts(testBaseTime), seller.DeliveryCommand{
		Quote:           f.sellerQuote,
		Pool:            poolB.sellerPool,
		RequestRaw:      requestA.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	})
	requireAnyCode(t, err, protocol.CodeStateConflict, protocol.CodeInvalidEvidence)

	// 池 A 内正常交付后构造的仲裁请求必须绑定池 A 的退款模板，
	// 与池 B 的退款模板逐字节不同。
	deliveryA, err := f.Seller.DeliverContent(f.ctx, testFacts(testBaseTime), seller.DeliveryCommand{
		Quote:           f.sellerQuote,
		Pool:            poolA.sellerPool,
		RequestRaw:      requestA.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := f.Seller.PrepareArbitration(f.ctx, testFacts(testBaseTime), seller.ArbitrationCommand{
		Pool:        poolA.sellerPool,
		Request:     requestA.Checkpoint.Request(),
		DeliveryRaw: deliveryA.Outbound.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), rawKind8.Bytes(), testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prepared.RefundTemplateTxID(), mustRefundTemplateTxIDBytes(t, poolA)) {
		t.Fatal("arbitration custody did not bind pool A's refund template")
	}
	if bytes.Equal(prepared.RefundTemplateTxID(), mustRefundTemplateTxIDBytes(t, poolB)) {
		t.Fatal("arbitration request bound to pool B's refund template")
	}
}

func mustRefundTemplateTxIDBytes(t *testing.T, p *openedPool) []byte {
	t.Helper()
	details, err := pool.DeriveOpeningDetails(p.sellerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), details.RefundTemplateTxID[:]...)
}

// 最小 005 凭证不携带池 ID，路由完全依赖 PaymentAuthorizationID → exact 003
// → RefundTemplateTxID。把一个池的凭证与另一个池的授权组合必须在签名验证
// 前被拒绝；同一参与方、同一内容价格在两个池中产生不同的授权哈希。
func TestCrossPoolAuthorizationLookupIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := openNamedPool(t, f, 100000)
	poolB := openNamedPool(t, f, 110000)

	requestA, err := f.Buyer.RequestContent(f.ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote:            f.buyerQuote,
		Pool:             poolA.buyerPool,
		ContentHashes:    [][]byte{masterseed.Sum256(f.Seed).Bytes()},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	deliveryA, err := f.Seller.DeliverContent(f.ctx, testFacts(testBaseTime), seller.DeliveryCommand{
		Quote:           f.sellerQuote,
		Pool:            poolA.sellerPool,
		RequestRaw:      requestA.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	})
	if err != nil {
		t.Fatal(err)
	}
	paymentA, err := f.Buyer.VerifyDeliveryAndPreparePayment(f.ctx, testFacts(testBaseTime), buyer.VerifyDeliveryCommand{
		Quote:       f.buyerQuote,
		Pool:        poolA.buyerPool,
		Request:     requestA.Checkpoint,
		DeliveryRaw: deliveryA.Outbound.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}

	requestB, err := f.Buyer.RequestContent(f.ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote:            f.buyerQuote,
		Pool:             poolB.buyerPool,
		ContentHashes:    [][]byte{masterseed.Sum256(f.Seed).Bytes()},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	hashA := requestA.AuthorizationID
	hashB := requestB.AuthorizationID
	if hashA == hashB {
		t.Fatal("distinct pools produced identical payment authorization hashes")
	}

	// pool A 的凭证 + pool B 的授权 → 授权 ID 冲突（state_conflict）。
	_, err = f.Seller.CompletePayment(f.ctx, testFacts(testBaseTime), seller.PaymentCommand{
		Pool:       poolB.sellerPool,
		Request:    requestB.Checkpoint.Request(),
		UpdateRaw:  paymentA.Outbound.Bytes(),
		Checkpoint: deliveryA.Checkpoint,
	})
	requireCode(t, err, protocol.CodeStateConflict)

	// pool A 的凭证 + pool A 的授权但 pool B 的池 checkpoint：
	// 授权与 opening 绑定校验拒绝（unauthorized/state_conflict/invalid_evidence 分类稳定）。
	_, err = f.Seller.CompletePayment(f.ctx, testFacts(testBaseTime), seller.PaymentCommand{
		Pool:       poolB.sellerPool,
		Request:    requestA.Checkpoint.Request(),
		UpdateRaw:  paymentA.Outbound.Bytes(),
		Checkpoint: deliveryA.Checkpoint,
	})
	requireAnyCode(t, err, protocol.CodeUnauthorized, protocol.CodeStateConflict, protocol.CodeInvalidEvidence)
}

// TestCrossPoolArbitrationRetrievalIsRefused extends cross-pool isolation to
// 008: 只有 (opening, authorization, Claim ID) 完全匹配的组合才能验收托管
// payload；pool B 的上下文配 pool A 的托管证据整批拒绝（invalid_evidence）。
func TestCrossPoolArbitrationRetrievalIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := openNamedPool(t, f, 100000)
	poolB := openNamedPool(t, f, 110000)

	buildChainFor := func(p *openedPool) (*purchaseRound, []byte, []byte) {
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
		response9, err := f.Arbiter.SignPreparedArbitration(f.ctx, testFacts(testBaseTime), prepared)
		if err != nil {
			t.Fatal(err)
		}
		return round, rawKind8.Bytes(), response9.Bytes()
	}

	roundA, kind8A, kind9A := buildChainFor(poolA)
	roundB, kind8B, kind9B := buildChainFor(poolB)
	k10A, err := f.Buyer.RequestArbitratedContent(f.ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          poolA.buyerPool,
		Authorization: roundA.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	k10B, err := f.Buyer.RequestArbitratedContent(f.ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          poolB.buyerPool,
		Authorization: roundB.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 正向：完全匹配的组合各自验证自己的托管记录。
	if _, err := f.Arbiter.VerifyRetrievableCustody(k10A.Bytes(), kind8A, kind9A); err != nil {
		t.Fatalf("pool A retrieval failed against its own custody: %v", err)
	}
	custodyB, err := f.Arbiter.VerifyRetrievableCustody(k10B.Bytes(), kind8B, kind9B)
	if err != nil {
		t.Fatalf("pool B retrieval failed against its own custody: %v", err)
	}
	availableB, err := f.Arbiter.BuildAvailableRetrieval(f.ctx, retrievalRequestIDOf(t, k10B.Bytes()), custodyB)
	if err != nil {
		t.Fatal(err)
	}

	// 交叉验收：pool B 的池上下文 + pool A 的授权 + pool A 的托管证据 →
	// 本地重建 Claim 与 Kind 10 路由 ID 错配 → invalid_evidence。
	_, err = f.Buyer.VerifyArbitratedContent(f.ctx, buyer.ArbitratedContentCommand{
		Quote:                f.buyerQuote,
		Pool:                 poolB.buyerPool,
		Request:              roundA.request.Checkpoint,
		RetrievalRequestRaw:  k10A.Bytes(),
		RetrievalResponseRaw: availableB.Bytes(),
	})
	requireCode(t, err, protocol.CodeInvalidEvidence)
}
