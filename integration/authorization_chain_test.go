// 授权链一致性测试：同一张 003 在 004、005、007 中必须携带完全相同的授权哈希
// （SHA-256(TermsCBOR)），并且买方在任何未通过完整证据验证的 003 上绝不产生 005。
package integration

import (
	"bytes"
	"crypto/sha256"
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

func chainSeedRequestInput(f *protocolFixture) buyer.ContentRequestInput {
	return buyer.ContentRequestInput{
		ContentHashes:    [][]byte{masterseed.Sum256(f.seed).Bytes()},
		DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix()),
	}
}

// 同一授权在 004 交付包、005 更新与 007 响应中的哈希必须逐字节相等，且都等于
// SHA-256(003 TermsCBOR)；完整 003 外壳的哈希不是授权哈希。
func TestAuthorizationHashIdenticalAcross004005And007(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	opening := f.completed.Opening
	previous := f.completed.InitialPayment

	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, opening, previous, chainSeedRequestInput(f))
	if err != nil {
		t.Fatal(err)
	}
	delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, opening, previous, request,
		seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, opening, previous, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	signedPayment, err := f.seller.AcceptPayment(f.ctx, opening, previous, request, deliveryState, verified.Update, f.facts())
	if err != nil {
		t.Fatal(err)
	}

	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, opening, request, delivery, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.arbiter.PreparePayment(f.ctx, arbitrationRequest, f.facts(), arbitrationFeeSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.arbiter.SignPreparedPayment(f.ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}

	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(delivery.PaymentAuthorizationHash, authHash[:]) {
		t.Fatal("004 carries an authorization hash other than SHA-256(TermsCBOR)")
	}
	if !bytes.Equal(verified.Update.PaymentAuthorizationHash, authHash[:]) {
		t.Fatal("005 carries an authorization hash other than SHA-256(TermsCBOR)")
	}
	rawUpdate, err := pool.EncodePaymentUpdate(verified.Update)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawUpdate) == 0 || rawUpdate[0] != 0x83 {
		t.Fatalf("minimal 005 must be a three-element array without pool ID or raw transaction: %x", rawUpdate)
	}
	if signedPayment.State.PaymentAuthorizationHash != pool.Hash32(authHash) {
		t.Fatal("accepted payment state carries a foreign authorization hash")
	}
	// Claim ID 是 Kind 9 的身份绑定：它必须等于 SHA-256([4,8,exact_claim_cbor])
	// 且绝不冒充 003 授权哈希 SHA-256(TermsCBOR)。
	localClaimID, err := arbitration.ArbitrationClaimID(arbitrationRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	preparedClaimID := prepared.ClaimID()
	if !bytes.Equal(preparedClaimID, localClaimID) {
		t.Fatal("prepared payment Claim ID does not match the independently computed Claim ID")
	}
	if bytes.Equal(preparedClaimID, authHash[:]) {
		t.Fatal("Claim ID must never impersonate the payment authorization hash")
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receipt.ClaimID, localClaimID) || receipt.ArbiterAmountSat != arbitrationFeeSat {
		t.Fatal("007 receipt does not bind the exact Claim ID and the frozen positive fee")
	}
	shellHash := sha256.Sum256(mustEncodeChainRequest(t, request))
	if bytes.Equal(localClaimID, shellHash[:]) {
		t.Fatal("007 used the full SignedContentRequest shell hash as the Claim ID")
	}
}

// 买方在未通过完整证据验证的 003 上绝不能生成 005：篡改买方签名、攻击者自签
// 授权、伪造报价（错误 QuoteTermsHash）与不在白名单内的仲裁人都必须在 payload
// 校验之前被拒绝。
func TestAcceptDeliveryRejectsUnverifiedAuthorizationWithoutProducingUpdate(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	opening := f.completed.Opening
	previous := f.completed.InitialPayment

	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, opening, previous, chainSeedRequestInput(f))
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, opening, previous, request,
		seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}

	tampered := &bitfs.SignedContentRequest{
		TermsCBOR:      append([]byte(nil), request.TermsCBOR...),
		BuyerSignature: append([]byte(nil), request.BuyerSignature...),
	}
	tampered.BuyerSignature[0] ^= 0xff
	forge := forgeChainAuthorization(t, f, opening, previous)

	wrongPriceQuote := mustResignedQuote(t, f, func(terms *bitfs.FileQuoteTerms) { terms.SeedPriceSat += 7 })
	noArbiterQuote := mustResignedQuote(t, f, func(terms *bitfs.FileQuoteTerms) {
		arbiters, err := bitfs.EncodeSupportedArbiterPubkeys(nil)
		if err != nil {
			t.Fatal(err)
		}
		terms.SupportedArbiterPubkeysCBOR = arbiters
	})

	cases := []struct {
		name    string
		request *bitfs.SignedContentRequest
		quote   *bitfs.SignedFileQuote
	}{
		{"tampered buyer signature", tampered, f.quote},
		{"authorization not signed by this buyer", forge, f.quote},
		{"forged quote with foreign terms hash", request, wrongPriceQuote},
		{"arbiter outside the resigned whitelist", request, noArbiterQuote},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified, err := f.buyer.AcceptDelivery(f.ctx, tc.quote, opening, previous, tc.request, delivery, buyer.ContentDeliveryInput{})
			if err == nil {
				t.Fatal("unverified authorization was accepted")
			}
			if verified != nil {
				t.Fatal("a payment update was produced for unverified authorization")
			}
		})
	}
}

// 买方不得签署已过期报价或交付截止晚于报价有效期的 003。
func TestBuildContentRequestRejectsExpiredQuoteAndDeadlineBeyondExpiry(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)

	expiredQuote := mustResignedQuote(t, f, func(terms *bitfs.FileQuoteTerms) {
		terms.QuoteExpiresAtUnix = time.Now().UTC().Add(-time.Hour).Unix()
	})
	input := chainSeedRequestInput(f)
	if _, err := f.buyer.BuildContentRequest(f.ctx, expiredQuote, f.completed.Opening, f.completed.InitialPayment, input); !errors.Is(err, bitfs.ErrQuoteExpired) {
		t.Fatalf("expired quote error = %v, want ErrQuoteExpired", err)
	}

	lateInput := buyer.ContentRequestInput{
		ContentHashes:    [][]byte{masterseed.Sum256(f.seed).Bytes()},
		DeliveryDeadline: bitfs.UnixSeconds(time.Now().UTC().Add(2 * time.Hour).Unix()),
	}
	if _, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, lateInput); !errors.Is(err, bitfs.ErrDeliveryDeadline) {
		t.Fatalf("deadline beyond expiry error = %v, want ErrDeliveryDeadline", err)
	}
}

func forgeChainAuthorization(t *testing.T, f *protocolFixture, opening *pool.OpeningProof, previous *pool.PaymentState) *bitfs.SignedContentRequest {
	t.Helper()
	quoteHash, err := bitfs.FileQuoteTermsHash(f.quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		t.Fatal(err)
	}
	hashesCBOR, err := bitfs.EncodeContentHashes([][]byte{masterseed.Sum256(f.seed).Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	terms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:       quoteHash[:],
		RefundTemplateTxID:   details.RefundTemplateTxID[:],
		PaymentSequence:      previous.PaymentSequence + 1,
		SellerAmountAfterSat: previous.SellerAmountSat + 100,
		ContentHashesCBOR:    hashesCBOR,
		DeliveryDeadlineUnix: f.now.Add(30 * time.Minute).Unix(),
	}
	attackerKey := integrationKey(t, "99")
	forged, err := bitfs.NewSignedContentRequest(terms, attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	return forged
}

func mustResignedQuote(t *testing.T, f *protocolFixture, mutate func(*bitfs.FileQuoteTerms)) *bitfs.SignedFileQuote {
	t.Helper()
	terms, err := bitfs.DecodeFileQuoteTerms(f.quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	mutate(terms)
	quote, err := bitfs.NewSignedFileQuote(terms, f.sellerKey, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

func mustEncodeChainRequest(t *testing.T, request *bitfs.SignedContentRequest) []byte {
	t.Helper()
	raw, err := bitfs.EncodeSignedContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestClaimIDBindsSeller007AndBuyer008ButIsNotTheAuthHash proves one Claim ID
// simultaneously routes the Seller's Kind 8 custody record and the Buyer's
// Kind 10 retrieval, while never impersonating PaymentAuthorizationHash.
// The Kind 10 signature authorizes exactly one Claim ID + nonce pair.
func TestClaimIDBindsSeller007AndBuyer008ButIsNotTheAuthHash(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	store := newMemoryArbitrationCustodyStore()

	request003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, chainSeedRequestInput(f))
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, _ := store.runCustodyThroughKind9(t, f, request003)
	claimID := mustClaimIDOf(t, rawKind8)

	authHash, err := bitfs.PaymentAuthorizationHash(request003.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(claimID, authHash[:]) {
		t.Fatal("Claim ID must not equal the payment authorization hash")
	}

	retrievalRequest, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, request003, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retrievalRequest.ClaimID, claimID) {
		t.Fatal("Buyer 008 routing ID differs from the Seller 007 Claim ID")
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	rawKind11, err := store.handleContentRetrieval(rawKind10, f.arbiter)
	if err != nil {
		t.Fatal(err)
	}

	// Kind 10 签名只授权一个 (ClaimID, Nonce)：跨 nonce 重放被拒绝。
	sameSigOtherNonce := &arbitration.ContentRetrievalRequest{Version: arbitration.MajorVersion, ClaimID: append([]byte(nil), retrievalRequest.ClaimID...), Nonce: bytes.Repeat([]byte{0x32}, 32), BuyerSignature: append([]byte(nil), retrievalRequest.BuyerSignature...)}
	if _, err := store.handleContentRetrieval(mustMarshalKind10(t, sameSigOtherNonce), f.arbiter); !errors.Is(err, errRetrievalUnauthorized) {
		t.Fatalf("cross-nonce replay error = %v", err)
	}

	// Kind 11 payload 绑定链：Claim ID -> TermsCBOR -> ordered hashes ->
	// payload SHA-256 必须完整成立。
	response11, err := arbitration.UnmarshalContentRetrievalResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	storedRequest, err := arbitration.UnmarshalRequest(response11.ArbitrationRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	storedResponse, err := arbitration.UnmarshalResponse(response11.ArbitrationResponseCBOR)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := arbitration.VerifyCustodiedContent(storedRequest, storedResponse)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified.ClaimID, claimID) {
		t.Fatal("verified chain does not terminate at the routed Claim ID")
	}
	decodedClaim, err := arbitration.UnmarshalClaim(storedRequest.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentTerms, err := bitfs.DecodeContentRequestTerms(decodedClaim.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := bitfs.DecodeContentHashes(contentTerms.ContentHashesCBOR)
	if err != nil {
		t.Fatal(err)
	}
	for index := range verified.Payloads {
		digest := sha256.Sum256(verified.Payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			t.Fatalf("payload binding broken at item #%d", index+1)
		}
	}
}

// TestKind10CannotReplayAcrossClaims proves a valid Kind 10 signature bound to
// one Claim ID can never retrieve another claim's custody record even when
// both records belong to the same buyer and pool.
func TestKind10CannotReplayAcrossClaims(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	store := newMemoryArbitrationCustodyStore()

	first003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, chainSeedRequestInput(f))
	if err != nil {
		t.Fatal(err)
	}
	secondInput := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(20 * time.Minute).Unix())}
	second003, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, secondInput)
	if err != nil {
		t.Fatal(err)
	}
	rawFirst, _ := store.runCustodyThroughKind9(t, f, first003)
	rawSecond, _ := store.runCustodyThroughKind9(t, f, second003)
	claimIDA, claimIDB := mustClaimIDOf(t, rawFirst), mustClaimIDOf(t, rawSecond)
	if bytes.Equal(claimIDA, claimIDB) {
		t.Fatal("test premise broken: two claims share one ID")
	}

	nonce := bytes.Repeat([]byte{0x41}, 32)
	requestForA, err := f.buyer.BuildArbitrationContentRequest(f.ctx, f.completed.Opening, first003, nonce)
	if err != nil {
		t.Fatal(err)
	}
	crossClaim := &arbitration.ContentRetrievalRequest{Version: arbitration.MajorVersion, ClaimID: append([]byte(nil), claimIDB...), Nonce: append([]byte(nil), nonce...), BuyerSignature: append([]byte(nil), requestForA.BuyerSignature...)}
	if _, err := store.handleContentRetrieval(mustMarshalKind10(t, crossClaim), f.arbiter); !errors.Is(err, errRetrievalUnauthorized) {
		t.Fatalf("cross-claim replay error = %v", err)
	}
}
