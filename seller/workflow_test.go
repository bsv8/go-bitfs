// Seller workflow 测试把测试本身当作调用方应用：报价、预签证据、开池证明、
// 付款状态与交付 checkpoint 全部保存在本地变量并显式传入每个 SDK 调用。
// 没有 fake store、租约或后端；这里只断言纯协议拒绝（错哈希、错角色、错证据、
// 陈旧序号）与显式事实门禁。时间一律使用固定 UTC facts。
package seller

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/bsv8/go-bitfs/wire"
)

const (
	testBlockHeight            protocol.BlockHeight = 900000
	testArbitrationFeeSatoshis protocol.Satoshis    = 500
	testMinerFeeRateSatPerKB   uint64               = 1
	testPoolOutputSatoshis     uint64               = 100000
)

var testBaseTime = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func testFacts(at time.Time) protocol.Facts {
	return protocol.Facts{Now: at, BlockHeight: testBlockHeight}
}

func mustTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustSigner(t *testing.T, key *ec.PrivateKey) *protocol.PrivateKeySigner {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func mustPublicKey(t *testing.T, key *ec.PrivateKey) protocol.PublicKey {
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

// sellerFixture 是三方固定密钥下的应用侧状态容器（买方 workflow 仅用于驱动协议链）。
type sellerFixture struct {
	buyerKey   *ec.PrivateKey
	sellerKey  *ec.PrivateKey
	arbiterKey *ec.PrivateKey

	Buyer         *buyer.Workflow
	Seller        *Workflow
	OtherSeller   *Workflow
	Arbiter       *arbiter.Workflow
	arbiterSigner *protocol.PrivateKeySigner

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

	cachedQuote *quoteBox
}

// quoteBox 同时保存 Verified 快照与 exact Kind 1 解码结果，供买卖两侧复用。
type quoteBox struct {
	verified *content.VerifiedQuote
	signed   *content.SignedFileQuote
}

func newSellerFixture(t *testing.T) *sellerFixture {
	t.Helper()
	f := &sellerFixture{
		buyerKey:   mustTestKey(t, "11"),
		sellerKey:  mustTestKey(t, "22"),
		arbiterKey: mustTestKey(t, "33"),
	}
	var err error
	f.Buyer, err = buyer.NewWorkflow(mustSigner(t, f.buyerKey))
	if err != nil {
		t.Fatal(err)
	}
	f.Seller, err = NewWorkflow(mustSigner(t, f.sellerKey))
	if err != nil {
		t.Fatal(err)
	}
	f.OtherSeller, err = NewWorkflow(mustSigner(t, mustTestKey(t, "44")))
	if err != nil {
		t.Fatal(err)
	}
	f.Arbiter, err = arbiter.NewWorkflow(mustSigner(t, f.arbiterKey))
	if err != nil {
		t.Fatal(err)
	}
	f.arbiterSigner = mustSigner(t, f.arbiterKey)
	f.buyerPubKey = mustPublicKey(t, f.buyerKey)
	f.sellerPubKey = mustPublicKey(t, f.sellerKey)
	f.arbiterPubKey = mustPublicKey(t, f.arbiterKey)

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
	return f
}

func (f *sellerFixture) createQuoteRaw(t *testing.T, mutate func(*QuoteDraft)) []byte {
	t.Helper()
	draft := QuoteDraft{
		SeedHash:                   f.SeedHash,
		BuyerPublicKey:             f.buyerPubKey,
		SeedPriceSatoshis:          protocol.Satoshis(100),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(f.FileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(f.QuoteExpiresAt),
		SupportedArbiterPublicKeys: mustTypedArbiterKeys(t, [][]byte{f.arbiterPubKey[:]}),
		RecommendedFilename:        "file.bin",
	}
	if mutate != nil {
		mutate(&draft)
	}
	quoteResult, err := f.Seller.CreateQuote(context.Background(), testFacts(testBaseTime), draft)
	if err != nil {
		t.Fatal(err)
	}
	raw := quoteResult.Outbound.Bytes()
	quoteArtifact, err := wire.ParseAs(wire.FileQuote, raw)
	if err != nil {
		t.Fatal(err)
	}
	signedQuote, err := wire.DecodeFileQuote(quoteArtifact)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptQuote(testFacts(testBaseTime), raw)
	if err != nil {
		t.Fatal(err)
	}
	f.cachedQuote = &quoteBox{verified: verified, signed: signedQuote}
	return raw
}

func (f *sellerFixture) defaultQuote(t *testing.T) (*content.VerifiedQuote, *content.SignedFileQuote) {
	t.Helper()
	if f.cachedQuote == nil {
		f.createQuoteRaw(t, nil)
	}
	return f.cachedQuote.verified, f.cachedQuote.signed
}

// openedPool 保存一次完整 002 开池往返的双侧 checkpoint 与 exact 报文。
type openedPool struct {
	buyerOpening  *buyer.OpeningCheckpoint
	buyerPool     *buyer.PoolCheckpoint
	sellerOpening *OpeningCheckpoint
	sellerPool    *PoolCheckpoint
	rawKind2      []byte
	rawKind3      []byte
	rawKind4      []byte
	presignResult *OpeningPreparationResult
}

func (f *sellerFixture) openPoolWith(t *testing.T, quote *content.VerifiedQuote, expiry uint32, feeRate uint64, fundingRaw []byte) *openedPool {
	t.Helper()
	ctx := context.Background()
	prepared, err := f.Buyer.PreparePoolOpening(ctx, testFacts(testBaseTime), buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           fundingRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(feeRate),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := f.Seller.PreparePoolOpening(ctx, testFacts(testBaseTime), prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(ctx, prepared.Checkpoint, presign.Outbound.Bytes())
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
		presignResult: presign,
	}
}

func (f *sellerFixture) openDefaultPool(t *testing.T) *openedPool {
	t.Helper()
	quote, _ := f.defaultQuote(t)
	return f.openPoolWith(t, quote, f.Expiry, testMinerFeeRateSatPerKB, f.FundingTransactionRaw)
}

// seedPurchase 保存一次 003→004→006 往返的全部协议产物（双侧视角）。
type seedPurchase struct {
	pool             *openedPool
	request          *buyer.RequestContentResult
	rawKind5         []byte
	deliveryResult   *DeliveryResult
	rawKind6         []byte
	payment          *buyer.PaymentPreparationResult
	completedPayment *CompletePaymentResult
}

func (f *sellerFixture) purchaseSeedWithDeadline(t *testing.T, p *openedPool, at time.Time, deadline content.UnixSeconds) *seedPurchase {
	t.Helper()
	ctx := context.Background()
	quote, signedQuote := f.defaultQuote(t)
	request, err := f.Buyer.RequestContent(ctx, testFacts(at), buyer.RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.Seller.DeliverContent(ctx, testFacts(at), DeliveryCommand{
		Quote:           signedQuote,
		Pool:            p.sellerPool,
		RequestRaw:      request.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
		Seed:            append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatal(err)
	}
	payment, err := f.Buyer.VerifyDeliveryAndPreparePayment(ctx, testFacts(at), buyer.VerifyDeliveryCommand{
		Quote:       quote,
		Pool:        p.buyerPool,
		Request:     request.Checkpoint,
		DeliveryRaw: delivery.Outbound.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Seller.CompletePayment(ctx, testFacts(at), PaymentCommand{
		Pool:       p.sellerPool,
		Request:    request.Checkpoint.Request(),
		UpdateRaw:  payment.Outbound.Bytes(),
		Checkpoint: delivery.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &seedPurchase{
		pool:             p,
		request:          request,
		rawKind5:         request.Outbound.Bytes(),
		deliveryResult:   delivery,
		rawKind6:         delivery.Outbound.Bytes(),
		payment:          payment,
		completedPayment: completed,
	}
}

func (f *sellerFixture) purchaseSeed(t *testing.T, p *openedPool, at time.Time) *seedPurchase {
	t.Helper()
	return f.purchaseSeedWithDeadline(t, p, at, f.DeliveryDeadline)
}

// ---- 001 创建报价 ----

func TestCreateQuoteSignsDraftAndSanitizesFilename(t *testing.T) {
	f := newSellerFixture(t)
	draft := QuoteDraft{
		SeedHash:                   f.SeedHash,
		BuyerPublicKey:             f.buyerPubKey,
		SeedPriceSatoshis:          protocol.Satoshis(100),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(f.FileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(f.QuoteExpiresAt),
		SupportedArbiterPublicKeys: mustTypedArbiterKeys(t, [][]byte{f.arbiterPubKey[:]}),
		RecommendedFilename:        "../../evil name.bin",
	}
	quoteResult, err := f.Seller.CreateQuote(context.Background(), testFacts(testBaseTime), draft)
	if err != nil {
		t.Fatal(err)
	}
	// 文件名唯一来源：sanitize 后进入签名条款快照。
	if quoteResult.Terms.RecommendedFilename != "evil name.bin" {
		t.Fatalf("terms filename = %q", quoteResult.Terms.RecommendedFilename)
	}
	if quoteResult.Outbound.Kind() != wire.FileQuote {
		t.Fatalf("quote kind = %d", quoteResult.Outbound.Kind())
	}
	artifact, err := wire.ParseAs(wire.FileQuote, quoteResult.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	signedQuote, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		t.Fatal(err)
	}
	terms, err := content.VerifySignedFileQuote(signedQuote, testBaseTime)
	if err != nil {
		t.Fatalf("returned quote does not verify: %v", err)
	}
	if terms.SeedPriceSatoshis != 100 || !bytes.Equal(terms.BuyerPublicKey, f.buyerPubKey[:]) || terms.QuoteExpiresAtUnixSeconds != f.QuoteExpiresAt {
		t.Fatalf("signed terms mismatch: %+v", terms)
	}
	// exact Kind 1 可被买方验收且看到同一 sanitize 结果。
	verified, err := f.Buyer.AcceptQuote(testFacts(testBaseTime), quoteResult.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Terms().RecommendedFilename != "evil name.bin" {
		t.Fatalf("buyer saw filename %q", verified.Terms().RecommendedFilename)
	}

	// 到期草稿在 facts.Now 拒绝：到期前一秒可签，当秒与之后一秒拒绝。
	expiredDraft := draft
	expiredDraft.QuoteExpiresAtUnixSeconds = content.UnixSeconds(testBaseTime.Add(time.Minute).Unix())
	expiryAt := time.Unix(int64(expiredDraft.QuoteExpiresAtUnixSeconds), 0)
	if _, err := f.Seller.CreateQuote(context.Background(), testFacts(expiryAt.Add(-time.Second)), expiredDraft); err != nil {
		t.Fatalf("quote one second before expiry rejected: %v", err)
	}
	for _, at := range []time.Time{expiryAt, expiryAt.Add(time.Second)} {
		_, err := f.Seller.CreateQuote(context.Background(), testFacts(at), expiredDraft)
		requireCode(t, err, protocol.CodeExpired)
	}

	// 缺失时间事实直接拒绝。
	if _, err := f.Seller.CreateQuote(context.Background(), protocol.Facts{}, draft); !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("zero facts accepted: %v", err)
	}

	// 重复仲裁公钥 → invalid_evidence。
	duplicate := draft
	dup, err := protocol.PublicKeyFromBytes(f.arbiterPubKey[:])
	if err != nil {
		t.Fatal(err)
	}
	duplicate.SupportedArbiterPublicKeys = []protocol.PublicKey{dup, dup}
	_, err = f.Seller.CreateQuote(context.Background(), testFacts(testBaseTime), duplicate)
	requireCode(t, err, protocol.CodeInvalidEvidence)
}

// ---- 002 预签 ----

func requestFromProof(proof *pool.OpeningProof) *pool.RefundPresignRequest {
	return &pool.RefundPresignRequest{
		RefundTemplateRaw:               append([]byte(nil), proof.RefundTemplateRaw...),
		BuyerPublicKey:                  append([]byte(nil), proof.BuyerPublicKey...),
		SellerPublicKey:                 append([]byte(nil), proof.SellerPublicKey...),
		ArbiterPublicKey:                append([]byte(nil), proof.ArbiterPublicKey...),
		MinerFeeRateSatoshisPerKilobyte: proof.MinerFeeRateSatoshisPerKilobyte,
		BuyerRefundTransactionSignature: append([]byte(nil), proof.BuyerRefundTransactionSignature...),
	}
}

func TestPreparePoolOpeningCorrelatesPresignEvidence(t *testing.T) {
	f := newSellerFixture(t)
	quote, _ := f.defaultQuote(t)
	ctx := context.Background()

	prepared, err := f.Buyer.PreparePoolOpening(ctx, testFacts(testBaseTime), buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 预签请求指定其他卖方 → unauthorized。
	_, err = f.OtherSeller.PreparePoolOpening(ctx, testFacts(testBaseTime), prepared.Outbound.Bytes())
	requireCode(t, err, protocol.CodeUnauthorized)

	// 篡改买方退款签名 → 卖方验证失败。
	requestArtifact, err := wire.ParseAs(wire.RefundPresignRequest, prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := wire.DecodeRefundPresignRequest(requestArtifact)
	if err != nil {
		t.Fatal(err)
	}
	tampered.BuyerRefundTransactionSignature[0] ^= 0xff
	tamperedRaw, err := wire.EncodeRefundPresignRequest(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.PreparePoolOpening(ctx, testFacts(testBaseTime), tamperedRaw.Bytes()); err == nil {
		t.Fatal("tampered refund presign request was accepted")
	}

	// 畸形字节 → malformed_wire。
	if _, err := f.Seller.PreparePoolOpening(ctx, testFacts(testBaseTime), []byte{0x01}); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("garbage request accepted: %v", err)
	}

	// 正常预签：响应关联 ID 与本地重派生一致，退款签名可独立验证。
	result, err := f.Seller.PreparePoolOpening(ctx, testFacts(testBaseTime), prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outbound.Kind() != wire.RefundPresignResponse {
		t.Fatalf("presign outbound kind = %d", result.Outbound.Kind())
	}
	responseArtifact, err := wire.ParseAs(wire.RefundPresignResponse, result.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	response, err := wire.DecodeRefundPresignResponse(responseArtifact)
	if err != nil {
		t.Fatal(err)
	}
	proof := result.Checkpoint.Opening()
	if proof == nil {
		t.Fatal("presign checkpoint lost the opening proof")
	}
	derived, err := pool.DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatal(err)
	}
	if derived != response.RefundTemplateTxID || derived != prepared.Checkpoint.RefundTemplateTxID() {
		t.Fatalf("correlation mismatch: proof %x response %x state %x", derived, response.RefundTemplateTxID, prepared.Checkpoint.RefundTemplateTxID())
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifySellerRefundSignature(requestFromProof(proof), response.SellerRefundTransactionSignature); err != nil {
		t.Fatalf("seller refund signature invalid: %v", err)
	}
}

// ---- 0204/0205 资金交付验收 ----

func decodeFundingDelivery(t *testing.T, raw []byte) *pool.FundingTransactionDelivery {
	t.Helper()
	artifact, err := wire.ParseAs(wire.FundingTransactionDelivery, raw)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := wire.DecodeFundingTransactionDelivery(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func encodeFundingDelivery(t *testing.T, delivery *pool.FundingTransactionDelivery) []byte {
	t.Helper()
	raw, err := wire.EncodeFundingTransactionDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func TestVerifyFundingDeliveryCompletesProofAndInitialPool(t *testing.T) {
	f := newSellerFixture(t)
	quote, _ := f.defaultQuote(t)
	ctx := context.Background()

	prepared, err := f.Buyer.PreparePoolOpening(ctx, testFacts(testBaseTime), buyer.PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := f.Seller.PreparePoolOpening(ctx, testFacts(testBaseTime), prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompletePoolOpening(ctx, prepared.Checkpoint, presign.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := f.Buyer.PrepareFundingDelivery(completed.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	goodRaw := deliveryArtifact.Bytes()

	// 关联 ID 错配 → state_conflict。
	foreign := decodeFundingDelivery(t, goodRaw)
	foreign.RefundTemplateTxID[0] ^= 0xff
	_, err = f.Seller.VerifyFundingDelivery(presign.Checkpoint, encodeFundingDelivery(t, foreign))
	requireCode(t, err, protocol.CodeStateConflict)

	// 其他卖方的 signer 不能验收本池资金。
	if _, err := f.OtherSeller.VerifyFundingDelivery(presign.Checkpoint, goodRaw); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong seller signer was accepted: %v", err)
	}

	// 资金交易被篡改 → 验证失败。
	corrupted := decodeFundingDelivery(t, goodRaw)
	corrupted.FundingTransactionRaw[len(corrupted.FundingTransactionRaw)-1] ^= 1
	if _, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, encodeFundingDelivery(t, corrupted)); err == nil {
		t.Fatal("tampered funding transaction was accepted")
	}

	// 正常验收：完整证据 + 初始池状态 + 可广播原文回执。
	funding, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, goodRaw)
	if err != nil {
		t.Fatal(err)
	}
	opening := funding.Opening
	if !opening.MatchesBuyer(f.buyerPubKey[:]) || !opening.MatchesSeller(f.sellerPubKey[:]) || len(opening.FundingTransactionRaw()) == 0 {
		t.Fatal("funding verification lost the complete opening evidence")
	}
	if !bytes.Equal(funding.FundingTransactionRaw, f.FundingTransactionRaw) {
		t.Fatal("funding verification did not echo the verified funding transaction")
	}
	initial := funding.InitialPool.Payment()
	if initial.PaymentSequence != 2 || initial.SellerAmountSatoshis != 0 || initial.ArbiterAmountSatoshis != 0 {
		t.Fatalf("initial state = seq %d seller %d arbiter %d", initial.PaymentSequence, initial.SellerAmountSatoshis, initial.ArbiterAmountSatoshis)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey(), SellerPublicKey: opening.SellerPublicKey(), ArbiterPublicKey: opening.ArbiterPublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(initial, funding.InitialPool.Opening()); err != nil {
		t.Fatalf("initial payment invalid: %v", err)
	}
}

// ---- 003/004/005 交付与付款完成 ----

func TestDeliverContentThenCompletePaymentAdvancesPool(t *testing.T) {
	f := newSellerFixture(t)
	p := f.openDefaultPool(t)
	purchase := f.purchaseSeed(t, p, testBaseTime)
	ctx := context.Background()
	delivery := purchase.deliveryResult
	if delivery.Outbound.Kind() != wire.ContentDelivery {
		t.Fatalf("delivery kind = %d", delivery.Outbound.Kind())
	}
	authID := purchase.request.AuthorizationID
	checkpoint := delivery.Checkpoint
	if checkpoint.PaymentSequence() != 3 || checkpoint.SellerAmountAfterSatoshis() != 100 {
		t.Fatalf("delivery checkpoint = seq %d amount %d", checkpoint.PaymentSequence(), checkpoint.SellerAmountAfterSatoshis())
	}
	if checkpoint.AuthorizationID() != authID || checkpoint.RefundTemplateTxID() != p.sellerPool.RefundTemplateTxID() {
		t.Fatal("delivery checkpoint does not bind authorization and pool")
	}

	completed := purchase.completedPayment
	if completed.Transaction.PaymentSequence() != 3 || completed.Transaction.SellerAmountSatoshis() != protocol.Satoshis(100) {
		t.Fatalf("completed payment = %+v", completed.Transaction.State())
	}
	next := completed.NextPool.Payment()
	if next.PaymentSequence != 3 || next.SellerAmountSatoshis != 100 {
		t.Fatalf("next pool state = seq %d amount %d", next.PaymentSequence, next.SellerAmountSatoshis)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: p.sellerPool.Opening().BuyerPublicKey, SellerPublicKey: p.sellerPool.Opening().SellerPublicKey, ArbiterPublicKey: p.sellerPool.Opening().ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(next, p.sellerPool.Opening()); err != nil {
		t.Fatalf("merged accepted state invalid: %v", err)
	}

	// 错误角色不能代表本卖方交付。
	_, signedQuote := f.defaultQuote(t)
	if _, err := f.OtherSeller.DeliverContent(ctx, testFacts(testBaseTime), DeliveryCommand{
		Quote: signedQuote, Pool: p.sellerPool,
		RequestRaw: purchase.rawKind5, ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
	}); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong seller signer delivered content: %v", err)
	}

	// 缺少原始 003 无法完成付款：SDK 不扫描池、不从裸哈希猜上下文。
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: nil,
		UpdateRaw: purchase.payment.Outbound.Bytes(), Checkpoint: checkpoint,
	}); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("missing signed content request was accepted: %v", err)
	}

	// 另一张 003 的哈希与 005 引用不一致 → state_conflict。
	otherRequest, err := f.Buyer.RequestContent(ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote: f.cachedQuote.verified, Pool: p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline + 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: otherRequest.Checkpoint.Request(),
		UpdateRaw: purchase.payment.Outbound.Bytes(), Checkpoint: checkpoint,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("authorization hash mismatch was accepted: %v", err)
	}

	// 缺失 checkpoint 与跨池 checkpoint → state_conflict。
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: purchase.request.Checkpoint.Request(),
		UpdateRaw: purchase.payment.Outbound.Bytes(), Checkpoint: nil,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("missing delivery checkpoint was accepted: %v", err)
	}
	foreignCheckpoint := &DeliveryCheckpoint{refundTemplateTxID: pool.RefundTemplateTxID(bytes.Repeat([]byte{7}, 32)), authorizationID: authID, paymentSequence: checkpoint.PaymentSequence(), sellerAmountAfterSatoshis: checkpoint.SellerAmountAfterSatoshis()}
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: purchase.request.Checkpoint.Request(),
		UpdateRaw: purchase.payment.Outbound.Bytes(), Checkpoint: foreignCheckpoint,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("cross-pool delivery checkpoint was accepted: %v", err)
	}

	// checkpoint 记录的授权哈希被替换 → state_conflict。
	wrongHashCheckpoint := &DeliveryCheckpoint{refundTemplateTxID: checkpoint.refundTemplateTxID, authorizationID: protocol.PaymentAuthorizationID(bytes.Repeat([]byte{9}, 32)), paymentSequence: checkpoint.PaymentSequence(), sellerAmountAfterSatoshis: checkpoint.SellerAmountAfterSatoshis()}
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: purchase.request.Checkpoint.Request(),
		UpdateRaw: purchase.payment.Outbound.Bytes(), Checkpoint: wrongHashCheckpoint,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("checkpoint hash mismatch was accepted: %v", err)
	}

	// 只有字段壳的 previous 无法通过状态验证。
	shell := &pool.PaymentState{RefundTemplateTxID: p.sellerPool.Payment().RefundTemplateTxID, PaymentSequence: p.sellerPool.Payment().PaymentSequence, SellerAmountSatoshis: p.sellerPool.Payment().SellerAmountSatoshis}
	shellPool := &PoolCheckpoint{opening: p.sellerPool.Opening(), payment: shell}
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: shellPool, Request: purchase.request.Checkpoint.Request(),
		UpdateRaw: purchase.payment.Outbound.Bytes(), Checkpoint: checkpoint,
	}); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("shell-only previous state was accepted: %v", err)
	}

	// 买方对另一笔交易（关闭 candidate）的签名不能通过重建交易验证。
	closePrep, err := f.Buyer.PrepareClose(ctx, testFacts(testBaseTime), buyer.PrepareCloseCommand{
		Pool: p.buyerPool, Base: p.buyerPool.Payment(), TargetSellerAmountSatoshis: protocol.Satoshis(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	mismatchedUpdate, err := wire.EncodePaymentUpdate(&pool.PaymentUpdate{PaymentAuthorizationID: authID, BuyerPaymentTransactionSignature: closePrep.BuyerSignature})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: purchase.request.Checkpoint.Request(),
		UpdateRaw: mismatchedUpdate.Bytes(), Checkpoint: checkpoint,
	}); err == nil {
		t.Fatal("buyer signature over another transaction was accepted")
	}

	// 篡改 005 哈希破坏与原始 003 的绑定 → state_conflict。
	updateArtifact, err := wire.ParseAs(wire.PaymentUpdate, purchase.payment.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tamperedUpdate, err := wire.DecodePaymentUpdate(updateArtifact)
	if err != nil {
		t.Fatal(err)
	}
	tamperedUpdate.PaymentAuthorizationID[0] ^= 0xff
	tamperedRaw, err := wire.EncodePaymentUpdate(tamperedUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), PaymentCommand{
		Pool: p.sellerPool, Request: purchase.request.Checkpoint.Request(),
		UpdateRaw: tamperedRaw.Bytes(), Checkpoint: checkpoint,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("tampered authorization hash was accepted: %v", err)
	}

	// 深拷贝边界：成功后原地篡改输入不影响已返回结果。
	rawTxBefore := completed.Transaction.RawTx()
	purchase.payment.Outbound.Bytes()[0] ^= 0xff
	if !bytes.Equal(rawTxBefore, completed.Transaction.RawTx()) {
		t.Fatal("completed transaction exposed internal references")
	}
}

// ---- 立即关闭 ----

func mergedSignedPayment(vt *pool.VerifiedSignedTransaction) *pool.SignedPayment {
	return &pool.SignedPayment{State: *vt.State(), RawTx: vt.RawTx()}
}

func TestCompleteCloseGuardsFinalSequenceExpiryAndRoles(t *testing.T) {
	f := newSellerFixture(t)
	p := f.openDefaultPool(t)
	purchase := f.purchaseSeed(t, p, testBaseTime)
	ctx := context.Background()
	latest := purchase.completedPayment.NextPool.Payment()
	target := latest.SellerAmountSatoshis

	// 非 final 序号的 candidate 直接拒绝。
	if _, err := f.Seller.CompleteClose(ctx, testFacts(testBaseTime), CloseCommand{
		Pool: p.sellerPool, Unsigned: purchase.payment.NextCandidate, BuyerSignature: purchase.payment.Outbound.Bytes(),
	}); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("non-final close candidate was accepted: %v", err)
	}

	// 退款已到期后不能再补签关闭。
	closePrep, err := f.Buyer.PrepareClose(ctx, testFacts(testBaseTime), buyer.PrepareCloseCommand{
		Pool: p.buyerPool, Base: latest, TargetSellerAmountSatoshis: protocol.Satoshis(target),
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredFacts := protocol.Facts{Now: time.Unix(int64(f.Expiry), 0), BlockHeight: testBlockHeight}
	if _, err := f.Seller.CompleteClose(ctx, expiredFacts, CloseCommand{
		Pool: p.sellerPool, Unsigned: closePrep.Unsigned, BuyerSignature: closePrep.BuyerSignature,
	}); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("close completed after refund expiry: %v", err)
	}

	// 其他卖方 signer 不能补签本池关闭。
	if _, err := f.OtherSeller.CompleteClose(ctx, testFacts(testBaseTime), CloseCommand{
		Pool: p.sellerPool, Unsigned: closePrep.Unsigned, BuyerSignature: closePrep.BuyerSignature,
	}); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong seller signer completed the close: %v", err)
	}

	// 正常关闭：合并后的最终交易通过买方完成验收。
	closed, err := f.Seller.CompleteClose(ctx, testFacts(testBaseTime), CloseCommand{
		Pool: p.sellerPool, Unsigned: closePrep.Unsigned, BuyerSignature: closePrep.BuyerSignature,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closed.PaymentSequence() != protocol.PaymentSequence(^uint32(0)) || closed.SellerAmountSatoshis() != protocol.Satoshis(target) {
		t.Fatalf("closed final = seq %d amount %d", closed.PaymentSequence(), closed.SellerAmountSatoshis())
	}
	verifiedClose, err := f.Buyer.VerifyCompletedClose(buyer.VerifyCloseCommand{Pool: p.buyerPool, Close: mergedSignedPayment(closed)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifiedClose.RawTx(), closed.RawTx()) {
		t.Fatal("verified close diverged from the seller merge output")
	}
}

// ---- 007 仲裁托管收款 ----

type custodyChain struct {
	pool         *openedPool
	purchase     *seedPurchase
	rawKind8     []byte
	rawKind9     []byte
	payloadsCBOR []byte
	receipt      *arbitration.ArbitrationReceipt
}

func (f *sellerFixture) buildCustodyWithDeadline(t *testing.T, deadline content.UnixSeconds) *custodyChain {
	t.Helper()
	ctx := context.Background()
	p := f.openDefaultPool(t)
	purchase := f.purchaseSeedWithDeadline(t, p, testBaseTime, deadline)

	// 从 exact Kind 6 提取 payload attachment，供 CompleteArbitratedPayment 比对。
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, purchase.rawKind6)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		t.Fatal(err)
	}

	kind8, err := f.Seller.PrepareArbitration(ctx, testFacts(testBaseTime), ArbitrationCommand{
		Pool:        p.sellerPool,
		Request:     purchase.request.Checkpoint.Request(),
		DeliveryRaw: purchase.rawKind6,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), kind8.Bytes(), testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	kind9, err := f.Arbiter.SignPreparedArbitration(ctx, testFacts(testBaseTime), prepared)
	if err != nil {
		t.Fatal(err)
	}
	kind9Artifact, err := wire.ParseAs(wire.ArbitrationResponse, kind9.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kind9Response, err := wire.DecodeArbitrationResponse(kind9Artifact)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(kind9Response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return &custodyChain{
		pool:         p,
		purchase:     purchase,
		rawKind8:     kind8.Bytes(),
		rawKind9:     kind9.Bytes(),
		payloadsCBOR: delivery.ContentPayloadsCBOR,
		receipt:      receipt,
	}
}

func marshalArbitrationResponse(t *testing.T, response *arbitration.ArbitrationResponse) []byte {
	t.Helper()
	raw, err := arbitration.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCompleteArbitratedPaymentCompletesCustodiedClaim(t *testing.T) {
	f := newSellerFixture(t)
	chain := f.buildCustodyWithDeadline(t, f.DeliveryDeadline)
	ctx := context.Background()

	signed, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), ArbitratedPaymentCommand{
		RequestRaw: chain.rawKind8, ResponseRaw: chain.rawKind9, DeliveryPayloadsCBOR: chain.payloadsCBOR,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 回执费用、买方授权金额与序号必须逐项落进合并结果。
	if signed.State().ArbiterAmountSatoshis != uint64(testArbitrationFeeSatoshis) || signed.SellerAmountSatoshis() != protocol.Satoshis(100) || signed.PaymentSequence() != 3 {
		t.Fatalf("merged arbitration state = %+v", signed.State())
	}
	stateTx, err := pool.ParseCanonicalTransaction(signed.RawTx())
	if err != nil {
		t.Fatal(err)
	}
	if stateTx.Outputs[2].Satoshis != uint64(testArbitrationFeeSatoshis) {
		t.Fatalf("third output = %d, want receipt fee %d", stateTx.Outputs[2].Satoshis, testArbitrationFeeSatoshis)
	}

	// 本地保存的 payload bundle 与托管附件不一致 → state_conflict。
	otherBundle, err := content.EncodeContentPayloads([][]byte{[]byte("other")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), ArbitratedPaymentCommand{
		RequestRaw: chain.rawKind8, ResponseRaw: chain.rawKind9,
		DeliveryPayloadsCBOR: otherBundle,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("mismatched stored payload bundle was accepted: %v", err)
	}
}

func TestCompleteArbitratedPaymentRejectsTamperedKind9Evidence(t *testing.T) {
	f := newSellerFixture(t)
	chain := f.buildCustodyWithDeadline(t, f.DeliveryDeadline)
	ctx := context.Background()
	command := func(responseRaw []byte) ArbitratedPaymentCommand {
		return ArbitratedPaymentCommand{RequestRaw: chain.rawKind8, ResponseRaw: responseRaw, DeliveryPayloadsCBOR: chain.payloadsCBOR}
	}

	decodeResponse := func(t *testing.T) *arbitration.ArbitrationResponse {
		t.Helper()
		artifact, err := wire.ParseAs(wire.ArbitrationResponse, chain.rawKind9)
		if err != nil {
			t.Fatal(err)
		}
		response, err := wire.DecodeArbitrationResponse(artifact)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	// 保持外层回执签名不变、只改内部字段的对抗组合必然破坏内层一致性。
	tamperReceipt := func(mutate func(receipt *arbitration.ArbitrationReceipt)) []byte {
		receipt, err := arbitration.UnmarshalReceipt(decodeResponse(t).ArbitrationReceiptCBOR)
		if err != nil {
			t.Fatal(err)
		}
		mutate(receipt)
		tamperedCBOR, err := arbitration.MarshalReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		return marshalArbitrationResponse(t, &arbitration.ArbitrationResponse{
			ArbitrationReceiptCBOR:             tamperedCBOR,
			ArbiterArbitrationReceiptSignature: append([]byte(nil), decodeResponse(t).ArbiterArbitrationReceiptSignature...),
		})
	}
	flipLastByte := func(value []byte) []byte {
		flipped := append([]byte(nil), value...)
		flipped[len(flipped)-1] ^= 1
		return flipped
	}

	cases := []struct {
		name        string
		responseRaw []byte
	}{
		{"claim id", tamperReceipt(func(r *arbitration.ArbitrationReceipt) { r.ArbitrationClaimID[0] ^= 1 })},
		{"receipt fee", tamperReceipt(func(r *arbitration.ArbitrationReceipt) { r.ArbiterAmountSatoshis += 1 })},
		{"inner transaction signature", tamperReceipt(func(r *arbitration.ArbitrationReceipt) {
			r.ArbiterPaymentTransactionSignature = flipLastByte(r.ArbiterPaymentTransactionSignature)
		})},
		{"outer receipt signature", marshalArbitrationResponse(t, &arbitration.ArbitrationResponse{
			ArbitrationReceiptCBOR:             append([]byte(nil), decodeResponse(t).ArbitrationReceiptCBOR...),
			ArbiterArbitrationReceiptSignature: flipLastByte(decodeResponse(t).ArbiterArbitrationReceiptSignature),
		})},
	}
	for _, testCase := range cases {
		signed, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), command(testCase.responseRaw))
		if err == nil {
			t.Fatalf("tampered %s was accepted by CompleteArbitratedPayment", testCase.name)
		}
		if signed != nil {
			t.Fatalf("tampered %s still produced a merged transaction", testCase.name)
		}
	}

	// 测试持有仲裁方私钥：可以伪造外层签名一致的回执，用于证明卖方的独立
	// 重建会拒绝内部不一致组合（费用字段与交易签名互相矛盾）。
	forgeSignedReceipt := func(receipt *arbitration.ArbitrationReceipt) []byte {
		receiptCBOR, err := arbitration.MarshalReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := protocol.SignWireDocument(ctx, f.arbiterSigner, protocol.WireVersion, 9, receiptCBOR)
		if err != nil {
			t.Fatal(err)
		}
		return marshalArbitrationResponse(t, &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR, ArbiterArbitrationReceiptSignature: signature})
	}

	// 另一费用的准备材料：交易签名覆盖更高费用的 candidate。
	otherFeePrepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), chain.rawKind8, testArbitrationFeeSatoshis+1)
	if err != nil {
		t.Fatal(err)
	}
	otherFeeKind9, err := f.Arbiter.SignPreparedArbitration(ctx, testFacts(testBaseTime), otherFeePrepared)
	if err != nil {
		t.Fatal(err)
	}
	otherFeeArtifact, err := wire.ParseAs(wire.ArbitrationResponse, otherFeeKind9.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	otherFeeResponse, err := wire.DecodeArbitrationResponse(otherFeeArtifact)
	if err != nil {
		t.Fatal(err)
	}
	otherFeeReceipt, err := arbitration.UnmarshalReceipt(otherFeeResponse.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	// 费用字段写原值、交易签名属于另一费用。
	mixedFee := forgeSignedReceipt(&arbitration.ArbitrationReceipt{
		ArbitrationClaimID:                 chain.receipt.ArbitrationClaimID,
		ArbiterAmountSatoshis:              chain.receipt.ArbiterAmountSatoshis,
		ArbiterPaymentTransactionSignature: append([]byte(nil), otherFeeReceipt.ArbiterPaymentTransactionSignature...),
	})
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), command(mixedFee)); err == nil {
		t.Fatal("a transaction signature priced for another fee completed the claim")
	}
	// 费用字段抬高但保留原费用的交易签名。
	inflatedFee := forgeSignedReceipt(&arbitration.ArbitrationReceipt{
		ArbitrationClaimID:                 chain.receipt.ArbitrationClaimID,
		ArbiterAmountSatoshis:              chain.receipt.ArbiterAmountSatoshis + 1,
		ArbiterPaymentTransactionSignature: append([]byte(nil), chain.receipt.ArbiterPaymentTransactionSignature...),
	})
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), command(inflatedFee)); err == nil {
		t.Fatal("an inflated receipt fee inconsistent with its transaction signature was accepted")
	}

	// 属于另一 Claim 的回执不能完成本 Claim：第二个授权使用相同资金池与序号，
	// 仅交付截止不同，因此 Claim ID 不同。
	otherChain := f.buildCustodyWithDeadline(t, f.DeliveryDeadline+600)
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), ArbitratedPaymentCommand{
		RequestRaw: chain.rawKind8, ResponseRaw: otherChain.rawKind9, DeliveryPayloadsCBOR: chain.payloadsCBOR,
	}); err == nil {
		t.Fatal("a receipt signed for another Claim completed this claim")
	}

	// 未篡改的组合仍然可以完成（证明拒绝来自篡改而非 harness 断裂）。
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, testFacts(testBaseTime), command(chain.rawKind9))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(chain.pool.sellerPool.Payment().PoolLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(signed.State(), chain.pool.sellerPool.Opening()); err != nil {
		t.Fatalf("arbitrated state invalid after untampered completion: %v", err)
	}
}

// ---- 共享 Claim 构造器 ----

func TestSharedClaimBuilderMatchesSellerKind8(t *testing.T) {
	f := newSellerFixture(t)
	chain := f.buildCustodyWithDeadline(t, f.DeliveryDeadline)

	kind8Artifact, err := wire.ParseAs(wire.ArbitrationRequest, chain.rawKind8)
	if err != nil {
		t.Fatal(err)
	}
	kind8Decoded, err := wire.DecodeArbitrationRequest(kind8Artifact)
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimID, err := arbitration.ArbitrationClaimID(kind8Decoded.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}

	// 买方侧共享构造器仅凭 opening + 精确签名 003 复现同一 Claim 字节。
	built, err := arbitration.BuildClaimFromAuthorization(chain.pool.sellerPool.Opening(), chain.purchase.request.Checkpoint.Request())
	if err != nil {
		t.Fatalf("buyer-side shared builder failed: %v", err)
	}
	if !bytes.Equal(built.ArbitrationClaimCBOR, kind8Decoded.ArbitrationClaimCBOR) {
		t.Fatal("shared builder produced different ArbitrationClaimCBOR than the seller Kind 8")
	}
	if built.ArbitrationClaimID != sellerClaimID {
		t.Fatal("shared builder produced a different Claim ID than the seller path")
	}

	// Kind 8 golden 外层形状保持 [1, 8, ...] 五元数组。
	rawKind8 := chain.rawKind8
	if len(rawKind8) < 3 || rawKind8[0] != 0x85 || rawKind8[1] != 0x01 || rawKind8[2] != 0x08 {
		t.Fatalf("seller Kind 8 shape drifted: %x", rawKind8[:3])
	}
}

// mustTypedArbiterKeys 把压缩公钥字节列表转换为强类型公钥列表（测试辅助）。
func mustTypedArbiterKeys(t *testing.T, raws [][]byte) []protocol.PublicKey {
	t.Helper()
	keys := make([]protocol.PublicKey, 0, len(raws))
	for _, raw := range raws {
		typed, err := protocol.PublicKeyFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, typed)
	}
	return keys
}
