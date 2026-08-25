// Buyer workflow 测试把测试本身当作调用方应用：报价、开池证据、付款状态与
// checkpoint 全部保存在本地变量并显式传入每个 SDK 调用。没有 fake store 或
// 后端；相同显式输入必须产生相同结果。时间一律使用固定 UTC facts。
package buyer

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

const (
	testBlockHeight              protocol.BlockHeight = 900000
	testArbitrationFeeSatoshis   protocol.Satoshis    = 500
	testMinerFeeRateSatPerKB     uint64               = 1
	testPoolOutputSatoshis       uint64               = 100000
	tinyPoolOutputSatoshis       uint64               = 20000
	expensiveSeedPriceSatoshis   uint64               = 999999
	testHeightLockRefundLockTime uint32               = 900500
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

func samePaymentState(left, right *pool.PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID &&
		left.PaymentSequence == right.PaymentSequence &&
		left.BuyerAmountSatoshis == right.BuyerAmountSatoshis &&
		left.SellerAmountSatoshis == right.SellerAmountSatoshis &&
		left.ArbiterAmountSatoshis == right.ArbiterAmountSatoshis &&
		left.PoolOutputSatoshis == right.PoolOutputSatoshis &&
		bytes.Equal(left.RawTx, right.RawTx) &&
		bytes.Equal(left.PoolLockingScript, right.PoolLockingScript)
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// buyerFixture 是三方固定密钥下的应用侧状态容器。
type buyerFixture struct {
	buyerKey   *ec.PrivateKey
	sellerKey  *ec.PrivateKey
	arbiterKey *ec.PrivateKey

	Buyer   *Workflow
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

	cachedQuote      *content.VerifiedQuote
	cachedQuoteBytes []byte
}

func newBuyerFixture(t *testing.T) *buyerFixture {
	t.Helper()
	f := &buyerFixture{
		buyerKey:   mustTestKey(t, "11"),
		sellerKey:  mustTestKey(t, "22"),
		arbiterKey: mustTestKey(t, "33"),
	}
	var err error
	f.Buyer, err = NewWorkflow(mustSigner(t, f.buyerKey))
	if err != nil {
		t.Fatal(err)
	}
	f.Seller, err = seller.NewWorkflow(mustSigner(t, f.sellerKey))
	if err != nil {
		t.Fatal(err)
	}
	f.Arbiter, err = arbiter.NewWorkflow(mustSigner(t, f.arbiterKey))
	if err != nil {
		t.Fatal(err)
	}
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

// createQuoteRaw 用可变草稿生成 exact Kind 1 bytes。
func (f *buyerFixture) createQuoteRaw(t *testing.T, mutate func(*seller.QuoteDraft)) []byte {
	t.Helper()
	draft := seller.QuoteDraft{
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
	return quoteResult.Outbound.Bytes()
}

func mustAcceptQuote(t *testing.T, wf *Workflow, at time.Time, raw []byte) *content.VerifiedQuote {
	t.Helper()
	verified, err := wf.AcceptQuote(testFacts(at), raw)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

// defaultQuote 返回缓存的标准报价（Verified + exact Kind 1 解码结果）。
func (f *buyerFixture) defaultQuote(t *testing.T) (*content.VerifiedQuote, *content.SignedFileQuote) {
	t.Helper()
	if f.cachedQuote == nil {
		raw := f.createQuoteRaw(t, nil)
		f.cachedQuote = mustAcceptQuote(t, f.Buyer, testBaseTime, raw)
		f.cachedQuoteBytes = raw
	}
	return f.cachedQuote, f.cachedQuote.Quote()
}

// openedPool 保存一次 002 开池往返的双侧 checkpoint 与 exact 报文。
type openedPool struct {
	buyerOpening  *OpeningCheckpoint
	buyerPool     *PoolCheckpoint
	sellerOpening *seller.OpeningCheckpoint
	sellerPool    *seller.PoolCheckpoint
	rawKind2      []byte
	rawKind3      []byte
	rawKind4      []byte
}

func (f *buyerFixture) openPoolWith(t *testing.T, quote *content.VerifiedQuote, expiry uint32, feeRate uint64, fundingRaw []byte) *openedPool {
	t.Helper()
	prepared, err := f.Buyer.PreparePoolOpening(context.Background(), PrepareOpeningCommand{
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
	presign, err := f.Seller.PreparePoolOpening(context.Background(), prepared.Outbound.Bytes())
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

func (f *buyerFixture) openDefaultPool(t *testing.T) *openedPool {
	t.Helper()
	quote, _ := f.defaultQuote(t)
	return f.openPoolWith(t, quote, f.Expiry, testMinerFeeRateSatPerKB, f.FundingTransactionRaw)
}

// seedPurchase 保存一次 003→004→006 往返的全部协议产物。
type seedPurchase struct {
	pool     *openedPool
	quoteRaw []byte
	request  *RequestContentResult
	rawKind5 []byte
	rawKind6 []byte
	delivery *seller.DeliveryCheckpoint
	payment  *PaymentPreparationResult
}

func (f *buyerFixture) purchaseSeedWithDeadline(t *testing.T, p *openedPool, at time.Time, deadline content.UnixSeconds) *seedPurchase {
	t.Helper()
	ctx := context.Background()
	quote, signedQuote := f.defaultQuote(t)
	request, err := f.Buyer.RequestContent(ctx, testFacts(at), RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.Seller.DeliverContent(ctx, testFacts(at), seller.DeliveryCommand{
		Quote:           signedQuote,
		Pool:            p.sellerPool,
		RequestRaw:      request.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
		Seed:            append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatal(err)
	}
	payment, err := f.Buyer.VerifyDeliveryAndPreparePayment(ctx, testFacts(at), VerifyDeliveryCommand{
		Quote:       quote,
		Pool:        p.buyerPool,
		Request:     request.Checkpoint,
		DeliveryRaw: delivery.Outbound.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &seedPurchase{
		pool:     p,
		quoteRaw: signedQuoteBytes(signedQuote),
		request:  request,
		rawKind5: request.Outbound.Bytes(),
		rawKind6: delivery.Outbound.Bytes(),
		delivery: delivery.Checkpoint,
		payment:  payment,
	}
}

func (f *buyerFixture) purchaseSeed(t *testing.T, p *openedPool, at time.Time) *seedPurchase {
	t.Helper()
	return f.purchaseSeedWithDeadline(t, p, at, f.DeliveryDeadline)
}

// ---- 001 接受报价 ----

func TestAcceptQuoteReturnsVerifiedSnapshotAndRejectsBadInputs(t *testing.T) {
	f := newBuyerFixture(t)
	raw := f.createQuoteRaw(t, nil)

	verified := mustAcceptQuote(t, f.Buyer, testBaseTime, raw)
	terms := verified.Terms()
	if terms == nil || terms.SeedPriceSatoshis != 100 || terms.FullBlockPriceSatoshis != 1000 || terms.FileSizeBytes != uint64(len(f.FileBytes)) || terms.RecommendedFilename != "file.bin" {
		t.Fatalf("verified terms mismatch: %+v", terms)
	}
	if !bytes.Equal(verified.SeedHash(), f.SeedHash) ||
		!bytes.Equal(verified.BuyerPublicKey(), f.buyerPubKey[:]) ||
		!bytes.Equal(verified.SellerPublicKey(), f.sellerPubKey[:]) {
		t.Fatal("verified quote identity binding mismatch")
	}
	if !verified.ExpiresAt().Equal(time.Unix(f.QuoteExpiresAt, 0)) {
		t.Fatalf("expires at = %v", verified.ExpiresAt())
	}
	otherPubKey := mustPublicKey(t, mustTestKey(t, "44"))
	if !verified.AllowsArbiter(f.arbiterPubKey[:]) || verified.AllowsArbiter(otherPubKey[:]) {
		t.Fatal("arbiter allow-list check is wrong")
	}

	// 过期判断只依赖 facts.Now：到期前一秒接受，到期时刻与之后一秒拒绝。
	expiryAt := time.Unix(f.QuoteExpiresAt, 0)
	mustAcceptQuote(t, f.Buyer, expiryAt.Add(-time.Second), raw)
	for _, at := range []time.Time{expiryAt, expiryAt.Add(time.Second)} {
		_, err := f.Buyer.AcceptQuote(testFacts(at), raw)
		requireCode(t, err, protocol.CodeExpired)
	}

	// 缺失时间事实直接拒绝，绝不回退系统时钟。
	if _, err := f.Buyer.AcceptQuote(protocol.Facts{}, raw); !errors.Is(err, protocol.ErrFactsMissing) {
		t.Fatalf("zero facts accepted: %v", err)
	}

	// 报价指定其他买方 → unauthorized。
	otherQuote := f.createQuoteRaw(t, func(draft *seller.QuoteDraft) { draft.BuyerPublicKey = otherPubKey })
	_, err := f.Buyer.AcceptQuote(testFacts(testBaseTime), otherQuote)
	requireCode(t, err, protocol.CodeUnauthorized)

	// 畸形字节 → malformed_wire。
	_, err = f.Buyer.AcceptQuote(testFacts(testBaseTime), []byte{0x01})
	requireCode(t, err, protocol.CodeMalformedWire)

	// 路由声明 Kind 与报文自描述 Kind 错配 → unsupported_kind。
	prepared, err := f.Buyer.PreparePoolOpening(context.Background(), PrepareOpeningCommand{
		Quote:                           verified,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Buyer.AcceptQuote(testFacts(testBaseTime), prepared.Outbound.Bytes())
	requireCode(t, err, protocol.CodeUnsupportedKind)
}

// ---- 002 开池往返 ----

func TestPreparePoolOpeningProducesDeterministicWireAndPrivateCheckpoint(t *testing.T) {
	f := newBuyerFixture(t)
	quote, _ := f.defaultQuote(t)
	command := PrepareOpeningCommand{
		Quote:                           quote,
		FundingTransactionRaw:           f.FundingTransactionRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(f.Expiry),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(testMinerFeeRateSatPerKB),
		SellerPublicKey:                 f.sellerPubKey,
		ArbiterPublicKey:                f.arbiterPubKey,
	}
	prepared, err := f.Buyer.PreparePoolOpening(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Outbound.Kind() != wire.RefundPresignRequest {
		t.Fatalf("outbound kind = %d", prepared.Outbound.Kind())
	}

	requestArtifact, err := wire.ParseAs(wire.RefundPresignRequest, prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeRefundPresignRequest(requestArtifact)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Checkpoint == nil || prepared.Checkpoint.Request() == nil || prepared.Checkpoint.RefundTemplateTxID() != derived {
		t.Fatal("checkpoint does not bind the canonical request hash")
	}
	if !bytes.Equal(prepared.Checkpoint.FundingTransactionRaw(), f.FundingTransactionRaw) {
		t.Fatal("checkpoint lost the private funding transaction")
	}
	// 隐私边界：Kind 2 wire 绝不携带资金交易原文。
	if bytes.Contains(prepared.Outbound.Bytes(), f.FundingTransactionRaw) {
		t.Fatal("wire request leaked the private funding transaction")
	}

	// 纯函数性质：相同输入产生逐字节相同的请求。
	repeat, err := f.Buyer.PreparePoolOpening(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prepared.Outbound.Bytes(), repeat.Outbound.Bytes()) {
		t.Fatal("identical inputs produced different requests")
	}

	// checkpoint getter 深拷贝：篡改返回值不影响内部状态。
	fundingCopy := prepared.Checkpoint.FundingTransactionRaw()
	fundingCopy[0] ^= 0xff
	if bytes.Equal(prepared.Checkpoint.FundingTransactionRaw(), fundingCopy) {
		t.Fatal("funding transaction getter returned an internal reference")
	}
}

func decodePresignResponse(t *testing.T, raw []byte) *pool.RefundPresignResponse {
	t.Helper()
	artifact, err := wire.ParseAs(wire.RefundPresignResponse, raw)
	if err != nil {
		t.Fatal(err)
	}
	response, err := wire.DecodeRefundPresignResponse(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestCompletePoolOpeningRoundTripAndRejectsTampering(t *testing.T) {
	f := newBuyerFixture(t)
	quote, _ := f.defaultQuote(t)

	prepared, err := f.Buyer.PreparePoolOpening(context.Background(), PrepareOpeningCommand{
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
	presign, err := f.Seller.PreparePoolOpening(context.Background(), prepared.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// 缺失 checkpoint → state_conflict。
	_, err = f.Buyer.CompletePoolOpening(nil, presign.Outbound.Bytes())
	requireCode(t, err, protocol.CodeStateConflict)

	// 卖方退款签名被翻转 → invalid_evidence。
	tamperedSignature := decodePresignResponse(t, presign.Outbound.Bytes())
	tamperedSignature.SellerRefundTransactionSignature[0] ^= 0xff
	tamperedRaw, err := wire.EncodeRefundPresignResponse(tamperedSignature)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Buyer.CompletePoolOpening(prepared.Checkpoint, tamperedRaw.Bytes())
	requireCode(t, err, protocol.CodeInvalidEvidence)

	// 响应关联 ID 指向另一个池 → state_conflict。
	foreign := decodePresignResponse(t, presign.Outbound.Bytes())
	foreign.RefundTemplateTxID = pool.RefundTemplateTxID(bytes.Repeat([]byte{9}, 32))
	foreignRaw, err := wire.EncodeRefundPresignResponse(foreign)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Buyer.CompletePoolOpening(prepared.Checkpoint, foreignRaw.Bytes())
	requireCode(t, err, protocol.CodeStateConflict)

	// 正常往返：verified opening + 初始池状态。
	completed, err := f.Buyer.CompletePoolOpening(prepared.Checkpoint, presign.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	opening := completed.Opening
	if !opening.MatchesBuyer(f.buyerPubKey[:]) || !opening.MatchesSeller(f.sellerPubKey[:]) {
		t.Fatal("opening role binding mismatch")
	}
	if !bytes.Equal(opening.FundingTransactionRaw(), f.FundingTransactionRaw) {
		t.Fatal("opening proof lost the funding transaction")
	}
	initial := completed.InitialPool.Payment()
	if initial.PaymentSequence != 2 || initial.SellerAmountSatoshis != 0 || initial.ArbiterAmountSatoshis != 0 {
		t.Fatalf("initial state = seq %d seller %d arbiter %d", initial.PaymentSequence, initial.SellerAmountSatoshis, initial.ArbiterAmountSatoshis)
	}
	if completed.InitialPool.RefundTemplateTxID() != prepared.Checkpoint.RefundTemplateTxID() {
		t.Fatal("initial pool correlation mismatch")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey(), SellerPublicKey: opening.SellerPublicKey(), ArbiterPublicKey: opening.ArbiterPublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyOpening(completed.InitialPool.Opening()); err != nil {
		t.Fatalf("returned opening proof is invalid: %v", err)
	}

	// 0204/0205：资金交付往返后卖方也持有完整证据。
	deliveryArtifact, err := f.Buyer.PrepareFundingDelivery(completed.InitialPool)
	if err != nil {
		t.Fatal(err)
	}
	if deliveryArtifact.Kind() != wire.FundingTransactionDelivery {
		t.Fatalf("delivery kind = %d", deliveryArtifact.Kind())
	}
	funding, err := f.Seller.VerifyFundingDelivery(presign.Checkpoint, deliveryArtifact.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(funding.FundingTransactionRaw, f.FundingTransactionRaw) {
		t.Fatal("funding verification lost the verified funding transaction")
	}

	// 另一个买方的 signer 不能交付本池资金交易。
	otherWf, err := NewWorkflow(mustSigner(t, mustTestKey(t, "44")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherWf.PrepareFundingDelivery(completed.InitialPool); !protocol.IsCode(err, protocol.CodeUnauthorized) {
		t.Fatalf("wrong buyer signer was accepted for delivery: %v", err)
	}
}

// ---- 003 授权：定价 / 截止 / 余额 ----

func TestRequestContentPricesBatchAndEnforcesDeadlinesAndBalance(t *testing.T) {
	f := newBuyerFixture(t)
	quote, _ := f.defaultQuote(t)
	p := f.openDefaultPool(t)
	ctx := context.Background()

	// 纯 seed 批次定价 = SeedPriceSatoshis；授权字段逐项正确。
	request, err := f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, err := wire.ParseAs(wire.ContentRequest, request.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	signedRequest, err := wire.DecodeContentRequest(requestArtifact)
	if err != nil {
		t.Fatal(err)
	}
	recomputedID, err := content.PaymentAuthorizationID(signedRequest.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if request.AuthorizationID != recomputedID || request.AuthorizationID != request.Checkpoint.AuthorizationID() {
		t.Fatal("authorization id does not bind SHA-256(payment_authorization_cbor)")
	}
	if !strings.HasPrefix(request.AuthorizationID.String(), "pa_") {
		t.Fatalf("typed id prefix missing: %s", request.AuthorizationID.String())
	}
	terms, err := content.DecodePaymentAuthorization(signedRequest.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if terms.SellerAmountAfterSatoshis != 100 || terms.PaymentSequence != 3 || int64(terms.DeliveryDeadlineUnixSeconds) != int64(f.DeliveryDeadline) {
		t.Fatalf("authorization terms mismatch: %+v", terms)
	}
	poolID := p.buyerPool.RefundTemplateTxID()
	if terms.FileQuoteTermsID != quote.ID() || !bytes.Equal(terms.RefundTemplateTxID, poolID[:]) {
		t.Fatal("authorization does not bind quote and pool")
	}

	// 块批次定价与聚合函数一致（尾块按比例 + 10% 让利）。
	blockHash := masterseed.Sum256(f.FileBytes).Bytes()
	blockBatch, err := f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote:            quote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{blockHash},
		DeliveryDeadline: f.DeliveryDeadline,
		Seed:             append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatal(err)
	}
	blockArtifact, _ := wire.ParseAs(wire.ContentRequest, blockBatch.Outbound.Bytes())
	blockRequest, err := wire.DecodeContentRequest(blockArtifact)
	if err != nil {
		t.Fatal(err)
	}
	blockTerms, err := content.DecodePaymentAuthorization(blockRequest.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	expectedBlockPrice, err := content.ContentHashesPriceSatoshis(context.Background(), quote.Terms(), [][]byte{blockHash}, f.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if blockTerms.SellerAmountAfterSatoshis != expectedBlockPrice {
		t.Fatalf("block batch amount %d != aggregate price %d", blockTerms.SellerAmountAfterSatoshis, expectedBlockPrice)
	}

	// 截止不晚于 now → expired。
	_, err = f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote: quote, Pool: p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(testBaseTime.Unix()),
	})
	requireCode(t, err, protocol.CodeExpired)

	// 截止超出报价有效期 → invalid_evidence。
	_, err = f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote: quote, Pool: p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(f.QuoteExpiresAt + 60),
	})
	requireCode(t, err, protocol.CodeInvalidEvidence)

	// 报价在请求时刻已过期 → expired。
	_, err = f.Buyer.RequestContent(ctx, testFacts(time.Unix(f.QuoteExpiresAt, 0)), RequestContentCommand{
		Quote: quote, Pool: p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	requireCode(t, err, protocol.CodeExpired)

	// 陈旧 previous（关联 ID 不属于本池）→ state_conflict。
	stale := pool.ClonePaymentState(p.buyerPool.Payment())
	stale.RefundTemplateTxID[0] ^= 0xff
	_, err = f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote:            quote,
		Pool:             &PoolCheckpoint{opening: p.buyerPool.Opening(), payment: stale},
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	requireCode(t, err, protocol.CodeStateConflict)

	// 退款锁已到期的池拒绝继续授权 → expired。
	expiredQuoteRaw := f.createQuoteRaw(t, func(draft *seller.QuoteDraft) { draft.SeedPriceSatoshis += 1 })
	expiredQuote := mustAcceptQuote(t, f.Buyer, testBaseTime, expiredQuoteRaw)
	expiredPool := f.openPoolWith(t, expiredQuote, uint32(testBaseTime.Add(-time.Hour).Unix()), testMinerFeeRateSatPerKB, f.FundingTransactionRaw)
	_, err = f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote:            expiredQuote,
		Pool:             expiredPool.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	requireCode(t, err, protocol.CodeExpired)

	// 余额不足：小池配高价 seed → insufficient_balance。
	expensiveQuoteRaw := f.createQuoteRaw(t, func(draft *seller.QuoteDraft) {
		draft.SeedPriceSatoshis = protocol.Satoshis(expensiveSeedPriceSatoshis)
	})
	expensiveQuote := mustAcceptQuote(t, f.Buyer, testBaseTime, expensiveQuoteRaw)
	tinyKeys := pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerPubKey[:], SellerPublicKey: f.sellerPubKey[:], ArbiterPublicKey: f.arbiterPubKey[:]}
	tinyFunding := buildTestFundingTx(t, tinyPoolOutputSatoshis, tinyKeys)
	tinyPool := f.openPoolWith(t, expensiveQuote, f.Expiry, testMinerFeeRateSatPerKB, tinyFunding)
	_, err = f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote:            expensiveQuote,
		Pool:             tinyPool.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline,
	})
	requireCode(t, err, protocol.CodeInsufficientBalance)
}

// ---- 004 验收 + 005 支付链 ----

func TestVerifyDeliveryAndPreparePaymentProducesMinimalCredential(t *testing.T) {
	f := newBuyerFixture(t)
	quote, _ := f.defaultQuote(t)
	p := f.openDefaultPool(t)
	purchase := f.purchaseSeed(t, p, testBaseTime)
	ctx := context.Background()

	payment := purchase.payment
	if len(payment.Payloads) != 1 || !bytes.Equal(payment.Payloads[0], f.Seed) {
		t.Fatal("verified payload batch does not match delivered seed content")
	}
	if payment.Outbound.Kind() != wire.PaymentUpdate {
		t.Fatalf("credential kind = %d", payment.Outbound.Kind())
	}
	updateArtifact, err := wire.ParseAs(wire.PaymentUpdate, payment.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	update, err := wire.DecodePaymentUpdate(updateArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if update.PaymentAuthorizationID != purchase.request.AuthorizationID {
		t.Fatal("005 credential does not carry SHA-256(payment_authorization_cbor)")
	}
	if len(update.BuyerPaymentTransactionSignature) == 0 {
		t.Fatal("005 credential carries no buyer signature")
	}

	// 最小凭证必须对本方独立重建的交易可验；重建必须确定。
	authArtifact, _ := wire.ParseAs(wire.ContentRequest, purchase.rawKind5)
	authRequest, err := wire.DecodeContentRequest(authArtifact)
	if err != nil {
		t.Fatal(err)
	}
	authTerms, err := content.DecodePaymentAuthorization(authRequest.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	opening := p.buyerPool.Opening()
	previous := p.buyerPool.Payment()
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := engine.BuildPaymentUpdate(pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: authTerms.PaymentSequence, SellerAmountAfterSatoshis: authTerms.SellerAmountAfterSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.RawTx, payment.NextCandidate.RawTx) {
		t.Fatal("NextCandidate diverges from the independent rebuild")
	}
	if err := engine.VerifyBuyerPayment(rebuilt, update.BuyerPaymentTransactionSignature, opening); err != nil {
		t.Fatalf("buyer credential does not verify over the rebuilt transaction: %v", err)
	}
	rebuiltAgain, err := engine.BuildPaymentUpdate(pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: authTerms.PaymentSequence, SellerAmountAfterSatoshis: authTerms.SellerAmountAfterSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.RawTx, rebuiltAgain.RawTx) {
		t.Fatal("payment state rebuild is not deterministic")
	}

	// 陈旧 previous（序号回退）→ state_conflict。
	stale := pool.ClonePaymentState(previous)
	stale.PaymentSequence--
	_, err = f.Buyer.VerifyDeliveryAndPreparePayment(ctx, testFacts(testBaseTime), VerifyDeliveryCommand{
		Quote: quote, Pool: &PoolCheckpoint{opening: opening, payment: stale},
		Request: purchase.request.Checkpoint, DeliveryRaw: purchase.rawKind6,
	})
	requireCode(t, err, protocol.CodeStateConflict)

	// 交付截止已过 → expired（时间事实唯一来自调用方）。
	deadlinePassed := time.Unix(int64(f.DeliveryDeadline), 0).Add(time.Second)
	_, err = f.Buyer.VerifyDeliveryAndPreparePayment(ctx, testFacts(deadlinePassed), VerifyDeliveryCommand{
		Quote: quote, Pool: p.buyerPool,
		Request: purchase.request.Checkpoint, DeliveryRaw: purchase.rawKind6,
	})
	requireCode(t, err, protocol.CodeExpired)

	// payload attachment 被篡改 → invalid_evidence。
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, purchase.rawKind6)
	if err != nil {
		t.Fatal(err)
	}
	tamperedDelivery, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		t.Fatal(err)
	}
	tamperedDelivery.ContentPayloadsCBOR[len(tamperedDelivery.ContentPayloadsCBOR)-1] ^= 1
	tamperedRaw, err := wire.EncodeContentDelivery(tamperedDelivery)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Buyer.VerifyDeliveryAndPreparePayment(ctx, testFacts(testBaseTime), VerifyDeliveryCommand{
		Quote: quote, Pool: p.buyerPool,
		Request: purchase.request.Checkpoint, DeliveryRaw: tamperedRaw.Bytes(),
	})
	requireCode(t, err, protocol.CodeInvalidEvidence)

	// 交付绑定的是另一张 003 → invalid_evidence。
	otherRequest, err := f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote: quote, Pool: p.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline + 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, signedQuote := f.defaultQuote(t)
	otherDelivery, err := f.Seller.DeliverContent(ctx, testFacts(testBaseTime), seller.DeliveryCommand{
		Quote:           signedQuote,
		Pool:            p.sellerPool,
		RequestRaw:      otherRequest.Outbound.Bytes(),
		ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)},
		Seed:            append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Buyer.VerifyDeliveryAndPreparePayment(ctx, testFacts(testBaseTime), VerifyDeliveryCommand{
		Quote: quote, Pool: p.buyerPool,
		Request: purchase.request.Checkpoint, DeliveryRaw: otherDelivery.Outbound.Bytes(),
	})
	requireCode(t, err, protocol.CodeInvalidEvidence)
}

// ---- 关闭 / 到期退款 ----

func mergedSignedPayment(vt *pool.VerifiedSignedTransaction) *pool.SignedPayment {
	return &pool.SignedPayment{State: *vt.State(), RawTx: vt.RawTx()}
}

func TestCloseLifecycleVerifiesFinalSettlement(t *testing.T) {
	f := newBuyerFixture(t)
	p := f.openDefaultPool(t)
	purchase := f.purchaseSeed(t, p, testBaseTime)
	ctx := context.Background()

	// 卖方完成 005 得到合并后的最新状态，测试作为协调方共享给双方。
	completedPayment, err := f.Seller.CompletePayment(ctx, testFacts(testBaseTime), seller.PaymentCommand{
		Pool:       p.sellerPool,
		Request:    purchase.request.Checkpoint.Request(),
		UpdateRaw:  purchase.payment.Outbound.Bytes(),
		Checkpoint: purchase.delivery,
	})
	if err != nil {
		t.Fatal(err)
	}
	latest := completedPayment.NextPool.Payment()
	target := latest.SellerAmountSatoshis

	// 退款未到期时不能构造到期退款。
	_, err = f.Buyer.BuildMaturedRefund(testFacts(testBaseTime), p.buyerPool)
	requireCode(t, err, protocol.CodeNotMatured)
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{Now: time.Unix(int64(f.Expiry)-1, 0), BlockHeight: testBlockHeight}, p.buyerPool)
	requireCode(t, err, protocol.CodeNotMatured)

	// 退款已到期时不能再准备关闭。
	_, err = f.Buyer.PrepareClose(ctx, protocol.Facts{Now: time.Unix(int64(f.Expiry), 0), BlockHeight: testBlockHeight}, PrepareCloseCommand{
		Pool: p.buyerPool, Base: latest, TargetSellerAmountSatoshis: protocol.Satoshis(target),
	})
	requireCode(t, err, protocol.CodeExpired)

	// 正常关闭链路：买方预备 → 卖方补签合并 → 买方验证最终交易。
	closePrep, err := f.Buyer.PrepareClose(ctx, testFacts(testBaseTime), PrepareCloseCommand{
		Pool: p.buyerPool, Base: latest, TargetSellerAmountSatoshis: protocol.Satoshis(target),
	})
	if err != nil {
		t.Fatal(err)
	}
	if closePrep.Unsigned.PaymentSequence != ^uint32(0) || len(closePrep.BuyerSignature) == 0 {
		t.Fatal("immediate close candidate is not a signed final candidate")
	}
	closed, err := f.Seller.CompleteClose(ctx, testFacts(testBaseTime), seller.CloseCommand{
		Pool: p.sellerPool, Unsigned: closePrep.Unsigned, BuyerSignature: closePrep.BuyerSignature,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedClose, err := f.Buyer.VerifyCompletedClose(VerifyCloseCommand{Pool: p.buyerPool, Close: mergedSignedPayment(closed)})
	if err != nil {
		t.Fatal(err)
	}
	if verifiedClose.PaymentSequence() != protocol.PaymentSequence(^uint32(0)) || verifiedClose.SellerAmountSatoshis() != protocol.Satoshis(target) {
		t.Fatalf("final close = seq %d amount %d", verifiedClose.PaymentSequence(), verifiedClose.SellerAmountSatoshis())
	}
	if !bytes.Equal(verifiedClose.RawTx(), closed.RawTx()) {
		t.Fatal("verified close raw tx mismatch")
	}

	// 未到 final 序号的合并付款不能通过完成关闭验收。
	requireCode(t, func() error {
		_, err := f.Buyer.VerifyCompletedClose(VerifyCloseCommand{Pool: p.buyerPool, Close: mergedSignedPayment(completedPayment.Transaction)})
		return err
	}(), protocol.CodeInvalidEvidence)
}

func TestBuildMaturedRefundHonorsExplicitLocktimeFacts(t *testing.T) {
	f := newBuyerFixture(t)
	p := f.openDefaultPool(t)

	// 时间戳锁：到期时刻（含当秒）起可执行退款。
	refund, err := f.Buyer.BuildMaturedRefund(protocol.Facts{Now: time.Unix(int64(f.Expiry), 0), BlockHeight: testBlockHeight}, p.buyerPool)
	if err != nil {
		t.Fatal(err)
	}
	if len(refund.RawTx()) == 0 {
		t.Fatal("matured refund produced no broadcastable transaction")
	}
	state := refund.State()
	if state == nil || state.PaymentSequence != 2 || state.SellerAmountSatoshis != 0 {
		t.Fatalf("refund state = %+v", state)
	}
	if refund.RefundTemplateTxID() != p.buyerPool.RefundTemplateTxID() {
		t.Fatal("refund transaction does not match the pool correlation ID")
	}

	// 区块高度锁：高度未到 → not_matured；到达即可执行。
	heightQuoteRaw := f.createQuoteRaw(t, func(draft *seller.QuoteDraft) { draft.SeedPriceSatoshis += 2 })
	heightQuote := mustAcceptQuote(t, f.Buyer, testBaseTime, heightQuoteRaw)
	heightPool := f.openPoolWith(t, heightQuote, testHeightLockRefundLockTime, testMinerFeeRateSatPerKB, f.FundingTransactionRaw)
	_, err = f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime, BlockHeight: testBlockHeight - 1}, heightPool.buyerPool)
	requireCode(t, err, protocol.CodeNotMatured)
	heightRefund, err := f.Buyer.BuildMaturedRefund(protocol.Facts{Now: testBaseTime, BlockHeight: protocol.BlockHeight(testHeightLockRefundLockTime)}, heightPool.buyerPool)
	if err != nil {
		t.Fatal(err)
	}
	if heightRefund.RefundTemplateTxID() != heightPool.buyerPool.RefundTemplateTxID() {
		t.Fatal("height-lock refund correlation mismatch")
	}
}

// ---- checkpoint restore 与状态错配 ----

func TestCheckpointRestoreRoundTripAndConflicts(t *testing.T) {
	f := newBuyerFixture(t)
	p := f.openDefaultPool(t)

	// OpeningCheckpoint restore：重派生关联 ID 并保留私有资金交易。
	restoredOpening, err := RestoreOpeningCheckpoint(p.rawKind2, f.FundingTransactionRaw)
	if err != nil {
		t.Fatal(err)
	}
	if restoredOpening.RefundTemplateTxID() != p.buyerOpening.RefundTemplateTxID() {
		t.Fatal("restored opening checkpoint correlation mismatch")
	}
	if !bytes.Equal(restoredOpening.FundingTransactionRaw(), f.FundingTransactionRaw) {
		t.Fatal("restored opening checkpoint lost the funding transaction")
	}
	if restoredOpening.Request() == nil {
		t.Fatal("restored opening checkpoint lost the signed request")
	}
	recompleted, err := f.Buyer.CompletePoolOpening(restoredOpening, p.rawKind3)
	if err != nil {
		t.Fatalf("restored checkpoint cannot complete the round trip: %v", err)
	}
	if recompleted.InitialPool.RefundTemplateTxID() != p.buyerPool.RefundTemplateTxID() {
		t.Fatal("recompleted pool correlation mismatch")
	}

	// AuthorizationCheckpoint restore：三份 exact evidence 全链重验 + 重算 typed ID。
	purchase := f.purchaseSeed(t, p, testBaseTime)
	openingProofCBOR, err := pool.EncodeOpeningProof(p.buyerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	restoredAuth, err := RestoreAuthorizationCheckpoint(purchase.quoteRaw, purchase.rawKind5, openingProofCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if restoredAuth.AuthorizationID() != purchase.request.AuthorizationID {
		t.Fatal("restored authorization id mismatch")
	}
	if restoredAuth.Request() == nil {
		t.Fatal("restored authorization lost the signed 003")
	}

	// PoolCheckpoint restore：canonical opening proof 编码 + 完整付款 raw tx。
	proofCBOR, err := pool.EncodeOpeningProof(p.buyerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	restoredPool, err := RestorePoolCheckpoint(proofCBOR, p.buyerPool.Payment().RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if !samePaymentState(restoredPool.Payment(), p.buyerPool.Payment()) {
		t.Fatal("restored payment state mismatch")
	}
	if restoredPool.RefundTemplateTxID() != p.buyerPool.RefundTemplateTxID() {
		t.Fatal("restored pool correlation mismatch")
	}

	// 状态错配：付款 raw 被篡改后在 opening 下无法通过全量重验 → invalid_evidence。
	tamperedPaymentRaw := append([]byte(nil), p.buyerPool.Payment().RawTx...)
	tamperedPaymentRaw[len(tamperedPaymentRaw)-1] ^= 1
	_, err = RestorePoolCheckpoint(proofCBOR, tamperedPaymentRaw)
	requireCode(t, err, protocol.CodeInvalidEvidence)
}

// ---- 008 仲裁取回 ----

type custodyChain struct {
	pool     *openedPool
	purchase *seedPurchase
	rawKind8 []byte
	rawKind9 []byte
}

func (f *buyerFixture) buildCustodyWithDeadline(t *testing.T, deadline content.UnixSeconds) *custodyChain {
	t.Helper()
	ctx := context.Background()
	p := f.openDefaultPool(t)
	purchase := f.purchaseSeedWithDeadline(t, p, testBaseTime, deadline)
	kind8, err := f.Seller.PrepareArbitration(ctx, testFacts(testBaseTime), seller.ArbitrationCommand{
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
	return &custodyChain{pool: p, purchase: purchase, rawKind8: kind8.Bytes(), rawKind9: kind9.Bytes()}
}

func (f *buyerFixture) buildCustody(t *testing.T) *custodyChain {
	t.Helper()
	return f.buildCustodyWithDeadline(t, f.DeliveryDeadline)
}

func decodeRetrievalRequest(t *testing.T, raw []byte) (*arbitration.ContentRetrievalRequest, protocol.ArbitrationClaimID) {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentRetrievalRequest, raw)
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeContentRetrievalRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	claimID, _, err := arbitration.DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return request, claimID
}

func retrievalRequestIDOf(request *arbitration.ContentRetrievalRequest) protocol.ContentRetrievalRequestID {
	return protocol.ContentRetrievalRequestID(sha256.Sum256(request.ContentRetrievalRequestCBOR))
}

func TestRequestArbitratedContentSharesClaimIdentity(t *testing.T) {
	f := newBuyerFixture(t)
	chain := f.buildCustody(t)
	ctx := context.Background()

	kind8Artifact, err := wire.ParseAs(wire.ArbitrationRequest, chain.rawKind8)
	if err != nil {
		t.Fatal(err)
	}
	kind8Request, err := wire.DecodeArbitrationRequest(kind8Artifact)
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimID, err := arbitration.ArbitrationClaimID(kind8Request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}

	k10, err := f.Buyer.RequestArbitratedContent(ctx, ArbitrationRetrievalCommand{
		Pool:          chain.pool.buyerPool,
		Authorization: chain.purchase.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if k10.Kind() != wire.ContentRetrievalRequest {
		t.Fatalf("retrieval kind = %d", k10.Kind())
	}
	request, claimID := decodeRetrievalRequest(t, k10.Bytes())
	if claimID != sellerClaimID {
		t.Fatal("buyer-derived claim id differs from the seller Kind 8 claim id")
	}
	_, nonce, err := arbitration.DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != arbitration.RetrievalNonceBytes || allZero(nonce) {
		t.Fatal("SDK-generated nonce is missing or zero")
	}
	if err := protocol.VerifyWireDocument(f.buyerPubKey[:], protocol.WireVersion, 10, request.ContentRetrievalRequestCBOR, request.BuyerContentRetrievalRequestSignature); err != nil {
		t.Fatalf("Kind 10 signature does not verify under the buyer key: %v", err)
	}
	// SDK 内部随机 nonce：两次请求字节必然不同（重试必须原样重放）。
	again, err := f.Buyer.RequestArbitratedContent(ctx, ArbitrationRetrievalCommand{
		Pool:          chain.pool.buyerPool,
		Authorization: chain.purchase.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k10.Bytes(), again.Bytes()) {
		t.Fatal("two retrieval requests reused one nonce")
	}
}

func TestVerifyArbitratedContentReturnsPayloadsWithoutPaymentChange(t *testing.T) {
	f := newBuyerFixture(t)
	chain := f.buildCustody(t)
	ctx := context.Background()
	quote, _ := f.defaultQuote(t)

	k10, err := f.Buyer.RequestArbitratedContent(ctx, ArbitrationRetrievalCommand{
		Pool:          chain.pool.buyerPool,
		Authorization: chain.purchase.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := decodeRetrievalRequest(t, k10.Bytes())
	custody, err := f.Arbiter.VerifyRetrievableCustody(k10.Bytes(), chain.rawKind8, chain.rawKind9)
	if err != nil {
		t.Fatal(err)
	}
	available, err := f.Arbiter.BuildAvailableRetrieval(ctx, retrievalRequestIDOf(request), custody)
	if err != nil {
		t.Fatal(err)
	}

	before := pool.ClonePaymentState(chain.pool.buyerPool.Payment())
	outcome, err := f.Buyer.VerifyArbitratedContent(ctx, ArbitratedContentCommand{
		Quote:                quote,
		Pool:                 chain.pool.buyerPool,
		Request:              chain.purchase.request.Checkpoint,
		RetrievalRequestRaw:  k10.Bytes(),
		RetrievalResponseRaw: available.Bytes(),
		Seed:                 append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Available || len(outcome.Payloads) != 1 || !bytes.Equal(outcome.Payloads[0], f.Seed) {
		t.Fatalf("available outcome mismatch: %+v", outcome)
	}
	if outcome.ArbitrationClaimID == (protocol.ArbitrationClaimID{}) || outcome.ContentRetrievalRequestID != retrievalRequestIDOf(request) {
		t.Fatalf("audit binding incomplete: %+v", outcome)
	}
	if !samePaymentState(before, chain.pool.buyerPool.Payment()) {
		t.Fatal("retrieval mutated the previous payment state")
	}
	// 返回 payload 是深拷贝。
	outcome.Payloads[0][0] ^= 1
	if bytes.Equal(outcome.Payloads[0], f.Seed) {
		t.Fatal("payloads share internal references")
	}

	// valid unavailable 是 typed 结果而不是 error。
	unavailable, err := f.Arbiter.BuildUnavailableRetrieval(ctx, retrievalRequestIDOf(request), arbitration.RetrievalSellerArbitrationNotReady)
	if err != nil {
		t.Fatal(err)
	}
	unavailableOutcome, err := f.Buyer.VerifyArbitratedContent(ctx, ArbitratedContentCommand{
		Quote:                quote,
		Pool:                 chain.pool.buyerPool,
		Request:              chain.purchase.request.Checkpoint,
		RetrievalRequestRaw:  k10.Bytes(),
		RetrievalResponseRaw: unavailable.Bytes(),
		Seed:                 append([]byte(nil), f.Seed...),
	})
	if err != nil {
		t.Fatalf("valid unavailable must not be an error: %v", err)
	}
	if unavailableOutcome.Available || unavailableOutcome.UnavailableReason != arbitration.RetrievalSellerArbitrationNotReady || len(unavailableOutcome.Payloads) != 0 {
		t.Fatalf("unavailable outcome mismatch: %+v", unavailableOutcome)
	}
	if !samePaymentState(before, chain.pool.buyerPool.Payment()) {
		t.Fatal("unavailable answer mutated the previous payment state")
	}
}

func TestVerifyArbitratedContentRejectsMismatchedInputs(t *testing.T) {
	f := newBuyerFixture(t)
	chain := f.buildCustody(t)
	ctx := context.Background()
	quote, _ := f.defaultQuote(t)

	goodK10, err := f.Buyer.RequestArbitratedContent(ctx, ArbitrationRetrievalCommand{
		Pool:          chain.pool.buyerPool,
		Authorization: chain.purchase.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	goodRequest, _ := decodeRetrievalRequest(t, goodK10.Bytes())
	custody, err := f.Arbiter.VerifyRetrievableCustody(goodK10.Bytes(), chain.rawKind8, chain.rawKind9)
	if err != nil {
		t.Fatal(err)
	}
	goodAvailable, err := f.Arbiter.BuildAvailableRetrieval(ctx, retrievalRequestIDOf(goodRequest), custody)
	if err != nil {
		t.Fatal(err)
	}
	base := func() ArbitratedContentCommand {
		return ArbitratedContentCommand{
			Quote:                quote,
			Pool:                 chain.pool.buyerPool,
			Request:              chain.purchase.request.Checkpoint,
			RetrievalRequestRaw:  goodK10.Bytes(),
			RetrievalResponseRaw: goodAvailable.Bytes(),
			Seed:                 append([]byte(nil), f.Seed...),
		}
	}

	// 错误报价（改价重签）→ invalid_evidence。
	resignedQuote := mustAcceptQuote(t, f.Buyer, testBaseTime, f.createQuoteRaw(t, func(draft *seller.QuoteDraft) { draft.SeedPriceSatoshis += 7 }))
	wrongQuoteCmd := base()
	wrongQuoteCmd.Quote = resignedQuote
	_, err = f.Buyer.VerifyArbitratedContent(ctx, wrongQuoteCmd)
	requireCode(t, err, protocol.CodeInvalidEvidence)

	// 外来授权（另一张 003 的 Claim 不同）→ invalid_evidence。
	otherAuth, err := f.Buyer.RequestContent(ctx, testFacts(testBaseTime), RequestContentCommand{
		Quote: quote, Pool: chain.pool.buyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: f.DeliveryDeadline + 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignAuthCmd := base()
	foreignAuthCmd.Request = otherAuth.Checkpoint
	_, err = f.Buyer.VerifyArbitratedContent(ctx, foreignAuthCmd)
	requireCode(t, err, protocol.CodeInvalidEvidence)

	// 陈旧 previous（序号回退）→ state_conflict。
	stale := pool.ClonePaymentState(chain.pool.buyerPool.Payment())
	stale.PaymentSequence--
	staleCmd := base()
	staleCmd.Pool = &PoolCheckpoint{opening: chain.pool.buyerPool.Opening(), payment: stale}
	_, err = f.Buyer.VerifyArbitratedContent(ctx, staleCmd)
	requireCode(t, err, protocol.CodeStateConflict)

	// 外来托管应答：应答的是另一个 nonce 的请求 → invalid_evidence。
	otherK10, err := f.Buyer.RequestArbitratedContent(ctx, ArbitrationRetrievalCommand{
		Pool:          chain.pool.buyerPool,
		Authorization: chain.purchase.request.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, _ := decodeRetrievalRequest(t, otherK10.Bytes())
	otherCustody, err := f.Arbiter.VerifyRetrievableCustody(otherK10.Bytes(), chain.rawKind8, chain.rawKind9)
	if err != nil {
		t.Fatal(err)
	}
	otherAvailable, err := f.Arbiter.BuildAvailableRetrieval(ctx, retrievalRequestIDOf(otherRequest), otherCustody)
	if err != nil {
		t.Fatal(err)
	}
	foreignResponseCmd := base()
	foreignResponseCmd.RetrievalResponseRaw = otherAvailable.Bytes()
	_, err = f.Buyer.VerifyArbitratedContent(ctx, foreignResponseCmd)
	requireCode(t, err, protocol.CodeInvalidEvidence)

	// 篡改 Kind 11 结果文档 → 仲裁签名失效。
	tamperedDoc, err := arbitration.UnmarshalContentRetrievalResponse(goodAvailable.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tamperedDoc.ContentRetrievalResultCBOR[len(tamperedDoc.ContentRetrievalResultCBOR)-1] ^= 1
	tamperedDocRaw, err := arbitration.MarshalContentRetrievalResponse(tamperedDoc)
	if err != nil {
		t.Fatal(err)
	}
	docCmd := base()
	docCmd.RetrievalResponseRaw = tamperedDocRaw
	_, err = f.Buyer.VerifyArbitratedContent(ctx, docCmd)
	requireCode(t, err, protocol.CodeInvalidSignature)

	// 篡改仲裁签名字段同样拒绝。
	tamperedSig, err := arbitration.UnmarshalContentRetrievalResponse(goodAvailable.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tamperedSig.ArbiterContentRetrievalResultSignature[0] ^= 1
	tamperedSigRaw, err := arbitration.MarshalContentRetrievalResponse(tamperedSig)
	if err != nil {
		t.Fatal(err)
	}
	sigCmd := base()
	sigCmd.RetrievalResponseRaw = tamperedSigRaw
	_, err = f.Buyer.VerifyArbitratedContent(ctx, sigCmd)
	requireCode(t, err, protocol.CodeInvalidSignature)

	// 正常组合仍然可用（证明拒绝来自篡改而非 harness 断裂）。
	okOutcome, err := f.Buyer.VerifyArbitratedContent(ctx, base())
	if err != nil {
		t.Fatal(err)
	}
	if !okOutcome.Available || !bytes.Equal(okOutcome.Payloads[0], f.Seed) {
		t.Fatal("untampered retrieval regressed")
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

// signedQuoteBytes 返回 exact Kind 1 bytes（测试辅助）。
func signedQuoteBytes(quote *content.SignedFileQuote) []byte {
	artifact, err := wire.EncodeFileQuote(quote)
	if err != nil {
		panic(err)
	}
	return artifact.Bytes()
}
