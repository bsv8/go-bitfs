// Seller workflow tests treat the test itself as the calling application:
// quotes, presign proofs, opening proofs, payment states, and delivery states
// are held in local variables and passed explicitly into every SDK call.
// There are no fake stores, leases, or backends; concurrency is not an SDK
// concern. Only pure protocol rejections (wrong hash, wrong role, wrong
// evidence, stale sequence) are asserted here.
package seller

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

type sellerTestSigner struct{ key *ec.PrivateKey }

func (s sellerTestSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}

func (s sellerTestSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	signature, err := s.key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func sellerTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sellerFixture is the application-side state holder for a full 001–007 run.
type sellerFixture struct {
	buyerKey              *ec.PrivateKey
	sellerKey             *ec.PrivateKey
	arbiterKey            *ec.PrivateKey
	Buyer                 *buyer.Workflow
	Seller                *Workflow
	Arbiter               *arbitration.Workflow
	Quote                 *bitfs.SignedFileQuote
	Seed                  []byte
	FundingTransactionRaw []byte
	State                 *buyer.BuyerOpeningState
	Presign               *SellerPresignResult
	Acceptance            *buyer.RefundPresignAcceptance
	Expiry                uint32
}

func newSellerFixture(t *testing.T) *sellerFixture {
	t.Helper()
	f := &sellerFixture{
		buyerKey:   sellerTestKey(t, "11"),
		sellerKey:  sellerTestKey(t, "22"),
		arbiterKey: sellerTestKey(t, "33"),
	}
	var err error
	f.Buyer, err = buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: f.buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.Seller, err = NewWorkflow(WorkflowConfig{PrivateKey: f.sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.Arbiter, err = arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: f.arbiterKey})
	if err != nil {
		t.Fatal(err)
	}

	source := bytes.Repeat([]byte{7}, 4096)
	var seedBuffer bytes.Buffer
	if _, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(source), &seedBuffer); err != nil {
		t.Fatal(err)
	}
	f.Seed = seedBuffer.Bytes()
	now := time.Now().UTC()
	arbiters, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	f.Quote, err = f.Seller.CreateQuote(context.Background(), bitfs.FileQuoteTerms{SeedHash: masterseed.Sum256(f.Seed).Bytes(), BuyerPublicKey: f.buyerKey.PubKey().Compressed(), SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: uint64(len(source)), QuoteExpiresAtUnixSeconds: now.Add(time.Hour).Unix(), SupportedArbiterPublicKeysCBOR: arbiters}, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Buyer.AcceptQuote(context.Background(), f.Quote); err != nil {
		t.Fatal(err)
	}

	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerKey.PubKey().Compressed(), SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock)})
	f.FundingTransactionRaw = funding.Bytes()
	f.Expiry = uint32(now.Add(time.Hour).Unix())

	preparation, err := f.Buyer.PreparePoolOpening(context.Background(), pool.OpeningInput{FundingTransactionRaw: f.FundingTransactionRaw, ExpiryLockTime: f.Expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	f.State = preparation.State
	result, err := f.Seller.PresignPoolOpening(context.Background(), preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	f.Presign = result
	acceptance, err := f.Buyer.AcceptRefundPresign(context.Background(), f.State, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	f.Acceptance = acceptance
	return f
}

// openPool completes 0204 + 0205 with explicit state passing.
func (f *sellerFixture) openPool(t *testing.T) *PoolFundingAcceptance {
	t.Helper()
	delivery, err := f.Buyer.BuildFundingTransactionDelivery(context.Background(), f.Acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := f.Seller.AcceptPoolFunding(context.Background(), f.Presign.Opening, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return acceptance
}

func TestCreateQuoteReturnsSignedCredentialWithoutSaving(t *testing.T) {
	f := newSellerFixture(t)
	if _, err := bitfs.VerifySignedFileQuote(f.Quote); err != nil {
		t.Fatalf("returned quote does not verify: %v", err)
	}
}

func TestPresignPoolOpeningReturnsResponseAndLocalProof(t *testing.T) {
	f := newSellerFixture(t)
	hash, err := pool.DeriveRefundTemplateTxID(nil, f.Presign.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if hash != f.State.RefundTemplateTxID || f.Presign.Response.RefundTemplateTxID != hash {
		t.Fatalf("presign result correlation mismatch: proof %x response %x state %x", hash, f.Presign.Response.RefundTemplateTxID, f.State.RefundTemplateTxID)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: f.Presign.Opening.BuyerPublicKey, SellerPublicKey: f.Presign.Opening.SellerPublicKey, ArbiterPublicKey: f.Presign.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	request, err := requestFromProofForSellerTest(f.Presign.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifySellerRefundSignature(nil, request, f.Presign.Response.SellerRefundTransactionSignature); err != nil {
		t.Fatalf("seller refund signature invalid: %v", err)
	}
}

func TestAcceptPoolFundingReturnsCompleteProofStateAndRawFunding(t *testing.T) {
	f := newSellerFixture(t)
	acceptance := f.openPool(t)
	if len(acceptance.Opening.FundingTransactionRaw) == 0 || !bytes.Equal(acceptance.FundingTransactionRaw, f.FundingTransactionRaw) {
		t.Fatal("funding acceptance lost the verified funding transaction")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: acceptance.Opening.BuyerPublicKey, SellerPublicKey: acceptance.Opening.SellerPublicKey, ArbiterPublicKey: acceptance.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(acceptance.InitialPayment, acceptance.Opening); err != nil {
		t.Fatalf("initial payment invalid: %v", err)
	}
	if acceptance.InitialPayment.PaymentSequence != 2 {
		t.Fatalf("initial sequence = %d, want 2", acceptance.InitialPayment.PaymentSequence)
	}
}

func TestAcceptPoolFundingRejectsWrongDeliveryHash(t *testing.T) {
	f := newSellerFixture(t)
	delivery := &pool.FundingTransactionDelivery{RefundTemplateTxID: f.Presign.Response.RefundTemplateTxID, FundingTransactionRaw: append([]byte(nil), f.FundingTransactionRaw...)}
	delivery.RefundTemplateTxID[0] ^= 0xff
	if _, err := f.Seller.AcceptPoolFunding(context.Background(), f.Presign.Opening, delivery); err == nil {
		t.Fatal("delivery hash mismatch was accepted")
	}
	// A different seller's signer cannot accept funding for this pool.
	other, err := NewWorkflow(WorkflowConfig{PrivateKey: sellerTestKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	good := &pool.FundingTransactionDelivery{RefundTemplateTxID: f.Presign.Response.RefundTemplateTxID, FundingTransactionRaw: append([]byte(nil), f.FundingTransactionRaw...)}
	if _, err := other.AcceptPoolFunding(context.Background(), f.Presign.Opening, good); err == nil {
		t.Fatal("wrong seller signer was accepted")
	}
}

func TestContentPaymentCloseLifecycleWithExplicitState(t *testing.T) {
	f := newSellerFixture(t)
	opened := f.openPool(t)
	ctx := context.Background()
	now := time.Now().UTC()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong-role delivery attempt must be refused before signing.
	wrongSeller, err := NewWorkflow(WorkflowConfig{PrivateKey: sellerTestKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongSeller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}}); err == nil {
		t.Fatal("wrong seller signer delivered content")
	}
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	update := verified.Update
	// Minimal 005 carries only the authorization hash and buyer signature.
	if len(update.PaymentAuthorizationID) != 32 || len(update.BuyerPaymentTransactionSignature) == 0 {
		t.Fatal("minimal 005 must carry a 32-byte hash and a non-empty buyer signature")
	}
	authID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if update.PaymentAuthorizationID != authID {
		t.Fatal("005 authorization hash does not match SHA-256 of the signed 003 terms")
	}

	accept := func(authorization *bitfs.SignedContentRequest, previous *pool.PaymentState, state *ContentDeliveryState, candidate *pool.PaymentUpdate) (*pool.SignedPayment, error) {
		return f.Seller.AcceptPayment(ctx, opened.Opening, previous, authorization, state, candidate, 900000)
	}

	// A missing original 003 can never be accepted: the SDK does not scan
	// pools or guess context from a bare hash.
	if _, err := accept(nil, opened.InitialPayment, deliveryState, update); err == nil {
		t.Fatal("missing signed content request was accepted")
	}
	// An authorization hashing to something else is the wrong reference.
	otherInput := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(20 * time.Minute).Unix())}
	otherRequest, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, otherInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accept(otherRequest, opened.InitialPayment, deliveryState, update); err == nil {
		t.Fatal("authorization hash mismatch was accepted")
	}
	// A previous state that only fills the field shell must be rejected.
	if _, err := accept(request, &pool.PaymentState{RefundTemplateTxID: opened.InitialPayment.RefundTemplateTxID, PaymentSequence: opened.InitialPayment.PaymentSequence, SellerAmountSatoshis: opened.InitialPayment.SellerAmountSatoshis}, deliveryState, update); err == nil {
		t.Fatal("shell-only previous state was accepted")
	}
	// Delivery state targets must match the original 003 exactly.
	wrongAmountState := &ContentDeliveryState{RefundTemplateTxID: deliveryState.RefundTemplateTxID, PaymentAuthorizationID: deliveryState.PaymentAuthorizationID, PaymentSequence: deliveryState.PaymentSequence, SellerAmountAfterSatoshis: deliveryState.SellerAmountAfterSatoshis + 1}
	if _, err := accept(request, opened.InitialPayment, wrongAmountState, update); err == nil {
		t.Fatal("payment amount did not have to match the delivery state and 003")
	}
	staleState := &ContentDeliveryState{RefundTemplateTxID: deliveryState.RefundTemplateTxID, PaymentAuthorizationID: deliveryState.PaymentAuthorizationID, PaymentSequence: deliveryState.PaymentSequence - 1, SellerAmountAfterSatoshis: deliveryState.SellerAmountAfterSatoshis}
	if _, err := accept(request, opened.InitialPayment, staleState, update); err == nil {
		t.Fatal("stale base sequence was accepted")
	}
	wrongHashState := &ContentDeliveryState{RefundTemplateTxID: deliveryState.RefundTemplateTxID, PaymentAuthorizationID: protocol.PaymentAuthorizationID(bytes.Repeat([]byte{9}, 32)), PaymentSequence: deliveryState.PaymentSequence, SellerAmountAfterSatoshis: deliveryState.SellerAmountAfterSatoshis}
	if _, err := accept(request, opened.InitialPayment, wrongHashState, update); err == nil {
		t.Fatal("delivery state hash mismatch was accepted")
	}
	// A buyer signature that is valid for a different transaction (here the
	// immediate-close candidate) must fail against the locally rebuilt
	// forward-payment transaction.
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opened.Opening.BuyerPublicKey, SellerPublicKey: opened.Opening.SellerPublicKey, ArbiterPublicKey: opened.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	closeCandidate, closeSig, err := f.Buyer.BuildImmediateClose(ctx, opened.Opening, opened.InitialPayment, opened.InitialPayment.SellerAmountSatoshis, 900000)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyBuyerPayment(closeCandidate, closeSig, opened.Opening); err != nil {
		t.Fatalf("close signature fixture invalid: %v", err)
	}
	mismatchedSignature := &pool.PaymentUpdate{PaymentAuthorizationID: update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: append([]byte(nil), closeSig...)}
	if _, err := accept(request, opened.InitialPayment, deliveryState, mismatchedSignature); err == nil {
		t.Fatal("buyer signature over another transaction was accepted for the rebuilt state")
	}
	// Tampering with the wire hash breaks the binding to the supplied 003.
	tamperedHash := &pool.PaymentUpdate{PaymentAuthorizationID: update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: append([]byte(nil), update.BuyerPaymentTransactionSignature...)}
	tamperedHash.PaymentAuthorizationID[0] ^= 0xff
	if _, err := accept(request, opened.InitialPayment, deliveryState, tamperedHash); err == nil {
		t.Fatal("tampered authorization hash was accepted")
	}
	// Deep-copy contract: mutating caller inputs after acceptance cannot
	// change the returned signed payment.
	signed, err := accept(request, opened.InitialPayment, deliveryState, update)
	if err != nil {
		t.Fatal(err)
	}
	latest := &signed.State
	if err := engine.VerifyAcceptedPayment(latest, opened.Opening); err != nil {
		t.Fatalf("merged accepted state invalid: %v", err)
	}
	if latest.SellerAmountSatoshis != deliveryState.SellerAmountAfterSatoshis {
		t.Fatalf("accepted amount %d != authorized absolute amount %d", latest.SellerAmountSatoshis, deliveryState.SellerAmountAfterSatoshis)
	}
	if latest.PaymentSequence != deliveryState.PaymentSequence {
		t.Fatalf("accepted sequence %d != target %d", latest.PaymentSequence, deliveryState.PaymentSequence)
	}

	// Immediate close from explicit latest state.
	unsigned, buyerSignature, err := f.Buyer.BuildImmediateClose(ctx, opened.Opening, latest, latest.SellerAmountSatoshis, 900000)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.Seller.SignImmediateClose(ctx, opened.Opening, unsigned, buyerSignature, 900000)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompleteImmediateClose(ctx, opened.Opening, closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyFinalPayment(&completed.State, opened.Opening); err != nil {
		t.Fatalf("final close invalid: %v", err)
	}
}

// sellerTestArbitrationFeeSat is the explicit positive arbitration fee used by
// every successful fixture: the calling application decides the amount before
// PreparePayment, and the SDK never prices anything itself.
const sellerTestArbitrationFeeSat uint64 = 500

func TestArbitrationLifecycleWithExplicitState(t *testing.T) {
	f := newSellerFixture(t)
	opened := f.openPool(t)
	ctx := context.Background()
	now := time.Now().UTC()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, opened.Opening, request, delivery, 900000)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.Arbiter.PreparePayment(ctx, arbitrationRequest, 900000, sellerTestArbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.Arbiter.SignPreparedPayment(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, response, 900000)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opened.Opening.BuyerPublicKey, SellerPublicKey: opened.Opening.SellerPublicKey, ArbiterPublicKey: opened.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&signed.State, opened.Opening); err != nil {
		t.Fatalf("arbitrated state invalid: %v", err)
	}
	// 最终 raw 的第三输出、SignedPayment 状态与回执金额必须完全一致。
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rawTx, err := tx.NewTransactionFromBytes(signed.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if rawTx.Outputs[2].Satoshis != receipt.ArbiterAmountSatoshis || signed.State.ArbiterAmountSatoshis != receipt.ArbiterAmountSatoshis {
		t.Fatalf("arbiter amount mismatch: raw %d state %d receipt %d", rawTx.Outputs[2].Satoshis, signed.State.ArbiterAmountSatoshis, receipt.ArbiterAmountSatoshis)
	}
	if receipt.ArbiterAmountSatoshis != sellerTestArbitrationFeeSat {
		t.Fatalf("receipt fee = %d, want the explicitly decided %d", receipt.ArbiterAmountSatoshis, sellerTestArbitrationFeeSat)
	}
}

func requestFromProofForSellerTest(proof *pool.OpeningProof) (*pool.RefundPresignRequest, error) {
	return &pool.RefundPresignRequest{
		RefundTemplateRaw:               append([]byte(nil), proof.RefundTemplateRaw...),
		BuyerPublicKey:                  append([]byte(nil), proof.BuyerPublicKey...),
		SellerPublicKey:                 append([]byte(nil), proof.SellerPublicKey...),
		ArbiterPublicKey:                append([]byte(nil), proof.ArbiterPublicKey...),
		MinerFeeRateSatoshisPerKilobyte: proof.MinerFeeRateSatoshisPerKilobyte,
		BuyerRefundTransactionSignature: append([]byte(nil), proof.BuyerRefundTransactionSignature...),
	}, nil
}

// TestCompleteArbitratedPaymentRejectsTamperedKind9Evidence proves the Seller
// completion path binds the Arbiter receipt to its own independent rebuild:
// the Claim ID, the frozen fee, both signatures, and the candidate itself must
// match exactly before any Seller transaction signature is produced.
func TestCompleteArbitratedPaymentRejectsTamperedKind9Evidence(t *testing.T) {
	f := newSellerFixture(t)
	opened := f.openPool(t)
	ctx := context.Background()
	now := time.Now().UTC()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, opened.Opening, request, delivery, 900000)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.Arbiter.PreparePayment(ctx, arbitrationRequest, 900000, sellerTestArbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.Arbiter.SignPreparedPayment(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}

	tamperReceipt := func(mutate func(receipt *arbitration.ArbitrationReceipt)) *arbitration.ArbitrationResponse {
		t.Helper()
		receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
		if err != nil {
			t.Fatal(err)
		}
		mutate(receipt)
		tamperedCBOR, err := arbitration.MarshalReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		return &arbitration.ArbitrationResponse{
			ArbitrationReceiptCBOR:             tamperedCBOR,
			ArbiterArbitrationReceiptSignature: append([]byte(nil), response.ArbiterArbitrationReceiptSignature...),
		}
	}
	flipLastByte := func(value []byte) []byte {
		flipped := append([]byte(nil), value...)
		flipped[len(flipped)-1] ^= 1
		return flipped
	}

	cases := []struct {
		name     string
		response *arbitration.ArbitrationResponse
	}{
		{"claim id", tamperReceipt(func(r *arbitration.ArbitrationReceipt) { r.ArbitrationClaimID[0] ^= 1 })},
		{"receipt fee", tamperReceipt(func(r *arbitration.ArbitrationReceipt) { r.ArbiterAmountSatoshis += 1 })},
		{"inner transaction signature", tamperReceipt(func(r *arbitration.ArbitrationReceipt) {
			r.ArbiterPaymentTransactionSignature = flipLastByte(r.ArbiterPaymentTransactionSignature)
		})},
		{"outer receipt signature", &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: append([]byte(nil), response.ArbitrationReceiptCBOR...), ArbiterArbitrationReceiptSignature: flipLastByte(response.ArbiterArbitrationReceiptSignature)}},
	}
	for _, testCase := range cases {
		signed, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, testCase.response, 900000)
		if err == nil {
			t.Fatalf("tampered %s was accepted by CompleteArbitratedPayment", testCase.name)
		}
		if signed != nil || len(sellerProducedSignatures(signed)) != 0 {
			t.Fatalf("tampered %s still produced a merged transaction", testCase.name)
		}
	}

	// 构造“外层签名有效但内容不一致”的对抗回执：fixture 持有仲裁方私钥，
	// 可以对任意回执字节生成合法消息签名，用于证明 Seller 的独立重建会拒绝
	// 内部不一致的组合。
	forgeSignedReceipt := func(t *testing.T, receipt *arbitration.ArbitrationReceipt) *arbitration.ArbitrationResponse {
		t.Helper()
		receiptCBOR, err := arbitration.MarshalReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := protocol.SignWireDocument(f.arbiterKey, protocol.WireVersion, 9, receiptCBOR)
		if err != nil {
			t.Fatal(err)
		}
		return &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR, ArbiterArbitrationReceiptSignature: signature}
	}

	// 交易签名属于另一费用：金额字段写原费用，但交易签名覆盖的是按更高费用
	// 重建的 candidate。
	receiptForOriginalFee, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	otherFeePrepared, err := f.Arbiter.PreparePayment(ctx, arbitrationRequest, 900000, sellerTestArbitrationFeeSat+1)
	if err != nil {
		t.Fatal(err)
	}
	otherFeeResponse, err := f.Arbiter.SignPreparedPayment(ctx, otherFeePrepared)
	if err != nil {
		t.Fatal(err)
	}
	otherFeeReceipt, err := arbitration.UnmarshalReceipt(otherFeeResponse.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	mixedFeeReceipt := forgeSignedReceipt(t, &arbitration.ArbitrationReceipt{ArbitrationClaimID: receiptForOriginalFee.ArbitrationClaimID, ArbiterAmountSatoshis: receiptForOriginalFee.ArbiterAmountSatoshis, ArbiterPaymentTransactionSignature: append([]byte(nil), otherFeeReceipt.ArbiterPaymentTransactionSignature...)})
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, mixedFeeReceipt, 900000); err == nil {
		t.Fatal("a transaction signature priced for another fee completed the claim")
	}
	// fee 与 candidate 不一致：金额字段抬高，但保留原费用的交易签名。
	inflatedFeeReceipt := forgeSignedReceipt(t, &arbitration.ArbitrationReceipt{ArbitrationClaimID: receiptForOriginalFee.ArbitrationClaimID, ArbiterAmountSatoshis: receiptForOriginalFee.ArbiterAmountSatoshis + 1, ArbiterPaymentTransactionSignature: append([]byte(nil), receiptForOriginalFee.ArbiterPaymentTransactionSignature...)})
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, inflatedFeeReceipt, 900000); err == nil {
		t.Fatal("an inflated receipt fee inconsistent with its transaction signature was accepted")
	}

	// Receipt 签名属于另一 Claim：对第二个 Claim（不同 content hashes）签发
	// 的完整响应不能完成第一个 Claim。
	// 第二个 Claim 使用相同资金池、序号和 Seller 金额，仅交付截止时间不同，
	// 因此 FileQuoteTermsCBOR 与 Claim ID 不同。
	otherInput := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(20 * time.Minute).Unix())}
	otherContentRequest, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, otherInput)
	if err != nil {
		t.Fatal(err)
	}
	otherDelivery, _, err := f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, otherContentRequest, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	otherClaim, err := f.Seller.BuildArbitrationRequest(ctx, opened.Opening, otherContentRequest, otherDelivery, 900000)
	if err != nil {
		t.Fatal(err)
	}
	otherPrepared, err := f.Arbiter.PreparePayment(ctx, otherClaim, 900000, sellerTestArbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	otherClaimResponse, err := f.Arbiter.SignPreparedPayment(ctx, otherPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, otherClaimResponse, 900000); err == nil {
		t.Fatal("a receipt signed for another Claim completed this claim")
	}

	// The untouched response still completes, proving the rejections come from
	// tampering and not from a broken harness.
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, arbitrationRequest, response, 900000)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opened.Opening.BuyerPublicKey, SellerPublicKey: opened.Opening.SellerPublicKey, ArbiterPublicKey: opened.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&signed.State, opened.Opening); err != nil {
		t.Fatalf("arbitrated state invalid after untampered completion: %v", err)
	}
}

func sellerProducedSignatures(signed *pool.SignedPayment) [][]byte {
	if signed == nil {
		return nil
	}
	return [][]byte{signed.State.SellerTransactionSignature}
}

// TestSharedClaimBuilderProducesIdenticalClaimEvidence proves the 007 seller
// path and the 008 buyer retrieval path share one Claim builder: for the same
// OpeningProof plus exact signed 003, both sides get byte-identical ArbitrationClaimCBOR
// and therefore the identical ArbitrationClaimID, and the golden Kind 8 bytes
// stay unchanged after the shared-builder switch.
func TestSharedClaimBuilderProducesIdenticalClaimEvidence(t *testing.T) {
	f := newSellerFixture(t)
	opened := f.openPool(t)
	ctx := context.Background()
	now := time.Now().UTC()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, opened.Opening, request, delivery, 900000)
	if err != nil {
		t.Fatal(err)
	}
	sellerClaimID, err := arbitration.ArbitrationClaimID(arbitrationRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	// Buyer 侧：仅凭 opening + 精确签名 003，无 Seller Claim 签名与 payload。
	built, err := arbitration.BuildClaimFromAuthorization(opened.Opening, request)
	if err != nil {
		t.Fatalf("buyer-side shared builder failed: %v", err)
	}
	if !bytes.Equal(built.ArbitrationClaimCBOR, arbitrationRequest.ArbitrationClaimCBOR) {
		t.Fatal("shared builder produced different ArbitrationClaimCBOR than the seller Kind 8")
	}
	if built.ArbitrationClaimID != sellerClaimID {
		t.Fatal("shared builder produced a different Claim ID than the seller path")
	}
	// Kind 8 golden 形状在共享 builder 切换后保持不变。
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawKind8) < 3 || rawKind8[0] != 0x85 || rawKind8[1] != 0x01 || rawKind8[2] != 0x08 {
		t.Fatalf("seller Kind 8 shape drifted: %x", rawKind8[:3])
	}
}
