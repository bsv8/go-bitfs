// Documented API smoke test: 本文件镜像 README 风格的新公开入口片段——
// NewPrivateKeySigner → NewWorkflow → 显式 Facts → CreateQuote → AcceptQuote
// 主路径，以及一条完整的购买链路。若公开签名变化，文档示例与本测试会一起
// 编译失败，指南永远不会悄悄漂移。
package integration

import (
	"bytes"
	"context"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/flowtest/arbiter"
	"github.com/bsv8/go-bitfs/internal/flowtest/buyer"
	"github.com/bsv8/go-bitfs/internal/flowtest/seller"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// TestDocumentedMainPathSignerWorkflowQuoteAccept mirrors the README quick
// start: three signers, three role workflows, one explicit Facts value, then
// CreateQuote → wire.Parse → AcceptQuote.
func TestDocumentedMainPathSignerWorkflowQuoteAccept(t *testing.T) {
	ctx := context.Background()

	// ---- 步骤 1：三方密钥 → 受约束 Signer。----
	buyerKey := testKey(t, "11")
	sellerKey := testKey(t, "22")
	arbiterKey := testKey(t, "33")
	signerBuyer, err := protocol.NewPrivateKeySigner(buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	signerSeller, err := protocol.NewPrivateKeySigner(sellerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arbiter.NewWorkflow(mustArbiterSigner(t, arbiterKey)); err != nil {
		t.Fatal(err)
	}

	// ---- 步骤 2：角色 workflow 只持有 Signer；无存储、无时钟、无网络。----
	sellerWf, err := seller.NewWorkflow(signerSeller)
	if err != nil {
		t.Fatal(err)
	}
	buyerWf, err := buyer.NewWorkflow(signerBuyer)
	if err != nil {
		t.Fatal(err)
	}
	_ = buyerWf

	// ---- 步骤 3：显式事实（时间 + 高度）由调用方观测并传入。----
	facts := protocol.Facts{Now: testBaseTime, BlockHeight: 900000}

	// ---- 步骤 4：卖方创建报价；应用先持久化 exact Artifact 字节再发送。----
	source := bytes.Repeat([]byte{7}, 4096)
	var seedBuffer bytes.Buffer
	if _, err := masterseed.CreateSeed(ctx, bytes.NewReader(source), &seedBuffer); err != nil {
		t.Fatal(err)
	}
	seedHash := masterseed.Sum256(seedBuffer.Bytes()).Bytes()
	arbiterPubKey := testPublicKey(t, arbiterKey)
	typedArbiter, err := protocol.PublicKeyFromBytes(arbiterPubKey[:])
	if err != nil {
		t.Fatal(err)
	}
	qr, err := sellerWf.CreateQuote(ctx, facts, seller.QuoteDraft{
		SeedHash:                   seedHash,
		BuyerPublicKey:             testPublicKey(t, buyerKey),
		SeedPriceSatoshis:          protocol.Satoshis(100),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(source)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(facts.Now.Add(time.Hour).Unix()),
		SupportedArbiterPublicKeys: []protocol.PublicKey{typedArbiter},
		RecommendedFilename:        "file.bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	rawKind1 := qr.Outbound.Bytes() // 应用保存 exact bytes
	if qr.Outbound.Kind() != wire.FileQuote {
		t.Fatalf("quote artifact kind = %d", qr.Outbound.Kind())
	}
	if qr.Terms == nil || qr.Terms.RecommendedFilename != "file.bin" {
		t.Fatalf("finalized terms lost the sanitized filename: %+v", qr.Terms)
	}

	// ---- 步骤 5（展示层）：wire.Parse 自读版本与 Kind 并分派严格 decoder。----
	artifact, err := wire.Parse(rawKind1)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Kind() != wire.FileQuote || !bytes.Equal(artifact.Bytes(), rawKind1) {
		t.Fatal("wire.Parse did not preserve the exact quote bytes")
	}

	// ---- 步骤 6：买方从 exact bytes 验收，得到不可变 VerifiedQuote。----
	vq, err := buyerWf.AcceptQuote(facts, rawKind1)
	if err != nil {
		t.Fatal(err)
	}
	terms := vq.Terms()
	if terms.SeedPriceSatoshis != 100 || terms.FullBlockPriceSatoshis != 1000 || terms.FileSizeBytes != uint64(len(source)) {
		t.Fatalf("verified terms mismatch: %+v", terms)
	}
	if !bytes.Equal(vq.SeedHash(), seedHash) || !vq.AllowsArbiter(arbiterPubKey[:]) {
		t.Fatal("verified quote identity binding mismatch")
	}
	if vq.ID().IsZero() {
		t.Fatal("verified quote id is zero")
	}
	// 过期判断只依赖 facts.Now：到期当刻拒绝。
	_, err = buyerWf.AcceptQuote(protocol.Facts{Now: time.Unix(int64(terms.QuoteExpiresAtUnixSeconds), 0).UTC(), BlockHeight: facts.BlockHeight}, rawKind1)
	requireCode(t, err, protocol.CodeExpired)
}

// TestDocumentedPurchaseAndRetrievalSmokeCompileAndRun walks the documented
// purchase chain (open pool → request → deliver → verify+pay) and the 008
// retrieval snippet with the same public entries as the guide.
func TestDocumentedPurchaseAndRetrievalSmokeCompileAndRun(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)

	round := f.runPurchaseWithDeadline(t, f.buyerQuote, p, testBaseTime, f.DeliveryDeadline, true)
	if round.completedPay == nil || len(round.completedPay.Transaction.RawTx()) == 0 {
		t.Fatal("documented purchase chain produced no merged transaction")
	}
	latest := p.sellerPool.Payment()
	if latest.SellerAmountSatoshis != 100 || !samePaymentState(latest, p.buyerPool.Payment()) {
		t.Fatalf("shared confirmed state mismatch: seller=%+v", latest)
	}

	// 008 片段：托管 + 取回的公开入口组合。
	kind8, kind9, round2 := f.buildCustodyChain(t, p)
	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), kind8, testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Arbiter.SignPreparedArbitration(f.ctx, testFacts(testBaseTime), prepared); err != nil {
		t.Fatal(err)
	}
	k10, err := f.Buyer.RequestArbitratedContent(f.ctx, buyer.ArbitrationRetrievalCommand{
		Pool:          round2.pool.buyerPool,
		Authorization: round2.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	custody, err := f.Arbiter.VerifyRetrievableCustody(k10.Bytes(), kind8, kind9)
	if err != nil {
		t.Fatal(err)
	}
	available, err := f.Arbiter.BuildAvailableRetrieval(f.ctx, retrievalRequestIDOf(t, k10.Bytes()), custody)
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
		t.Fatalf("documented retrieval outcome mismatch: %+v", outcome)
	}
}

// mustArbiterSigner 构造仲裁方受约束 Signer（README 步骤 1 的第三个角色）。
func mustArbiterSigner(t *testing.T, key *ec.PrivateKey) *protocol.PrivateKeySigner {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
