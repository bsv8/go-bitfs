// Cross-pool isolation tests: two pools' state is held explicitly by the
// test application in separate variables, and any evidence swap between the
// pools must be refused by the SDK.
package integration

import (
	"bytes"
	"errors"
	"testing"
	"time"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

// poolState holds one pool's explicit local state for both roles.
type poolState struct {
	funding    []byte
	buyerState *buyer.BuyerOpeningState
	presign    *pool.OpeningProof
	buyerAcc   *buyer.RefundPresignAcceptance
	sellerAcc  *seller.PoolFundingAcceptance
}

func (f *protocolFixture) openNamedPool(t *testing.T, satoshis uint64) *poolState {
	t.Helper()
	state := &poolState{funding: f.buildFunding(t, satoshis)}
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTransactionRaw: state.funding, ExpiryLockTime: f.expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	state.buyerState = preparation.State // app saves per pool
	result, err := f.seller.PresignPoolOpening(f.ctx, preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	state.presign = result.Opening // app saves per pool
	state.buyerAcc, err = f.buyer.AcceptRefundPresign(f.ctx, state.buyerState, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.buyer.BuildFundingTransactionDelivery(f.ctx, state.buyerAcc.Opening)
	if err != nil {
		t.Fatal(err)
	}
	state.sellerAcc, err = f.seller.AcceptPoolFunding(f.ctx, state.presign, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestTwoPoolsKeepTheirExplicitStatesSeparate(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	if poolA.buyerAcc.Reference.RefundTemplateTxID == poolB.buyerAcc.Reference.RefundTemplateTxID {
		t.Fatal("distinct pools produced identical correlation IDs")
	}
	if poolA.sellerAcc.InitialPayment.RawTx == nil || poolB.sellerAcc.InitialPayment.RawTx == nil {
		t.Fatal("initial states missing")
	}
}

func TestCrossPoolResponseHashMismatchIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	preparationB, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTransactionRaw: f.buildFunding(t, 120000), ExpiryLockTime: f.expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := f.seller.PresignPoolOpening(f.ctx, preparationB.Request)
	if err != nil {
		t.Fatal(err)
	}
	// Pool B's response must not satisfy pool A's saved local state.
	if _, err := f.buyer.AcceptRefundPresign(f.ctx, poolA.buyerState, resultB.Response); err == nil {
		t.Fatal("cross-pool response was accepted")
	}
}

func TestCrossPoolFundingDeliveryIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	// Deliver pool A's proof against pool B's presign evidence.
	delivery, err := f.buyer.BuildFundingTransactionDelivery(f.ctx, poolA.buyerAcc.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.seller.AcceptPoolFunding(f.ctx, poolB.presign, delivery); err == nil {
		t.Fatal("cross-pool funding delivery was accepted")
	}
}

func TestCrossPoolContentAndArbitrationEvidenceAreRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	requestA, err := f.buyer.BuildContentRequest(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	// A request bound to pool A must not be delivered against pool B's state.
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, poolB.sellerAcc.Opening, poolB.sellerAcc.InitialPayment, requestA, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("content request crossed pools")
	}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, requestA, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatalf("in-pool delivery failed: %v", err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, poolA.sellerAcc.Opening, requestA, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	claim, err := arbitration.UnmarshalClaim(arbitrationRequest.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(claim.RefundTemplateRaw, poolB.sellerAcc.Opening.RefundTemplateRaw) {
		t.Fatal("arbitration request bound to the wrong pool")
	}
}

// Minimal 005 credentials carry no pool ID, so routing is hash-based: the
// application looks up the exact saved 003 by PaymentAuthorizationID and
// only the 003's RefundTemplateTxID selects the opening. Supplying a
// credential from one pool together with another pool's authorization must
// never merge.
func TestCrossPoolAuthorizationLookupIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	requestA, err := f.buyer.BuildContentRequest(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	_, deliveryStateA, err := f.seller.BuildContentDelivery(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, requestA, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verifiedA, err := f.buyer.AcceptDelivery(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, requestA, mustDeliveryForTwoPools(t, f, poolA, requestA), buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	// The same participants and the same content price in pool B produce a
	// different authorization hash; pool B's original 003 can never satisfy
	// pool A's credential.
	requestB, err := f.buyer.BuildContentRequest(f.ctx, f.quote, poolB.sellerAcc.Opening, poolB.sellerAcc.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	hashA, err := bitfs.PaymentAuthorizationID(requestA.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := bitfs.PaymentAuthorizationID(requestB.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hashA[:], hashB[:]) {
		t.Fatal("distinct pools produced identical payment authorization hashes")
	}
	// Hash lookup first: the found 003's pool ID selects the opening. Passing
	// pool A's credential with pool B's authorization is refused before any
	// signature check.
	if _, err := f.seller.AcceptPayment(f.ctx, poolB.sellerAcc.Opening, poolB.sellerAcc.InitialPayment, requestB, deliveryStateA, verifiedA.Update, f.facts()); err == nil {
		t.Fatal("cross-pool delivery state was accepted for pool B")
	}
	if _, err := f.seller.AcceptPayment(f.ctx, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, requestB, deliveryStateA, verifiedA.Update, f.facts()); err == nil {
		t.Fatal("credential from pool A was accepted against pool B's authorization")
	}
}

func mustDeliveryForTwoPools(t *testing.T, f *protocolFixture, target *poolState, request *bitfs.SignedContentRequest) *bitfs.SignedContentDelivery {
	t.Helper()
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, target.sellerAcc.Opening, target.sellerAcc.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

// TestCrossPoolArbitrationRetrievalIsRefused extends cross-pool isolation to
// 008: only the exact (Claim ID, opening, authorization, Buyer key) tuple can
// retrieve its own payload. Pool B's opening or authorization combined with
// pool A's custody record — or vice versa — is refused, and the matching
// combination succeeds.
func TestCrossPoolArbitrationRetrievalIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	store := newMemoryArbitrationCustodyStore()

	buildChainFor := func(state *poolState) (*bitfs.SignedContentRequest, []byte) {
		input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
		request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, state.buyerAcc.Opening, state.sellerAcc.InitialPayment, input)
		if err != nil {
			t.Fatal(err)
		}
		delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, state.sellerAcc.Opening, state.sellerAcc.InitialPayment, request003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
		if err != nil {
			t.Fatal(err)
		}
		arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, state.sellerAcc.Opening, request003, delivery, f.facts())
		if err != nil {
			t.Fatal(err)
		}
		rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
		if err != nil {
			t.Fatal(err)
		}
		return request003, rawKind8
	}

	requestA, rawKind8A := buildChainFor(poolA)
	requestB, rawKind8B := buildChainFor(poolB)
	for _, raw := range [][]byte{rawKind8A, rawKind8B} {
		if _, err := store.handleArbitrationRequest(raw, f.arbiter, f.facts()); err != nil {
			t.Fatal(err)
		}
	}
	claimIDA := mustClaimIDOf(t, rawKind8A)
	recordAPayloads := mustDecodeKind8(t, store.recordOf(mustHex(t, claimIDA[:])).requestBytes).ContentPayloadsCBOR

	nonceA := bytes.Repeat([]byte{0x61}, 32)
	nonceB := bytes.Repeat([]byte{0x62}, 32)
	request10A, err := f.buyer.BuildArbitrationContentRequest(f.ctx, poolA.buyerAcc.Opening, requestA, nonceA)
	if err != nil {
		t.Fatal(err)
	}
	request10B, err := f.buyer.BuildArbitrationContentRequest(f.ctx, poolB.buyerAcc.Opening, requestB, nonceB)
	if err != nil {
		t.Fatal(err)
	}
	raw10A, err := arbitration.MarshalContentRetrievalRequest(request10A)
	if err != nil {
		t.Fatal(err)
	}
	raw10B, err := arbitration.MarshalContentRetrievalRequest(request10B)
	if err != nil {
		t.Fatal(err)
	}

	// 正向：完全匹配的组合各自取回自己的记录。
	first11, err := store.handleContentRetrieval(raw10A, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	second11, err := store.handleContentRetrieval(raw10B, f.arbiter, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first11, second11) {
		t.Fatal("two pools returned one identical custody record")
	}
	firstParsed, parseErr := arbitration.UnmarshalContentRetrievalResponse(first11)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	firstVerified, verifyErr := arbitration.VerifyContentRetrievalResponse(request10A, poolA.buyerAcc.Opening.ArbiterPublicKey, firstParsed)
	if verifyErr != nil {
		t.Fatalf("pool A Kind 11 failed verification: %v", verifyErr)
	}
	if !bytes.Equal(firstVerified.PayloadsCBOR, recordAPayloads) {
		t.Fatal("pool A retrieval does not bind pool A's custody payload bundle")
	}

	// 交叉：pool A 的 Kind 10 用 pool B 的 opening/authorization 构造必须失败。
	crossAuth, err := f.buyer.BuildArbitrationContentRequest(f.ctx, poolB.buyerAcc.Opening, requestA, bytes.Repeat([]byte{0x63}, 32))
	if err == nil {
		// 不同池的 Claim 不同：若该 Claim 没有托管记录，Arbiter 返回签名的
		// seller_arbitration_not_received（nil error）；只有鉴权失败才报错。
		rawKind11Cross, retrievalErr := store.handleContentRetrieval(mustMarshalKind10(t, crossAuth), f.arbiter, f.arbiterKey)
		if retrievalErr != nil {
			if !errors.Is(retrievalErr, errRetrievalUnauthorized) {
				t.Fatalf("cross-pool constructed request error = %v", retrievalErr)
			}
		} else {
			parsedCross, parseErr := arbitration.UnmarshalContentRetrievalResponse(rawKind11Cross)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if parsedCross.ContentPayloadsCBOR != nil {
				t.Fatal("cross-pool request unexpectedly received payloads")
			}
			decodedCross, decodeErr := arbitration.DecodeContentRetrievalResultDocument(parsedCross.ContentRetrievalResultCBOR)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if decodedCross.UnavailableReason != arbitration.RetrievalSellerArbitrationNotReceived {
				t.Fatalf("cross-pool reason = %d, want seller_arbitration_not_received", decodedCross.UnavailableReason)
			}
		}
	}

	// 验收侧交叉：pool B 的 opening/previous 配 pool A 的托管证据整批拒绝。
	response11A, err := arbitration.UnmarshalContentRetrievalResponse(first11)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.AcceptArbitratedContent(f.ctx, f.quote, poolB.buyerAcc.Opening, poolB.sellerAcc.InitialPayment, requestA, request10A, response11A, buyer.ArbitratedContentInput{}); err == nil {
		t.Fatal("pool A custody record accepted against pool B context")
	}
}
