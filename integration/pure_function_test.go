package integration

// 本文件是新纯函数公开面的验收测试：每个入口都有成功路径或稳定的同码拒绝，
// 并证明验证失败时 Signer 调用次数为 0、同一输入重复调用结果一致。测试直接
// 消费根 fixtures/role-v1.json，不依赖任何跨步骤 SDK 对象。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/conformance"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

type roleFixtureView struct {
	FactsNowUnix       int64  `json:"facts_now_unix_seconds"`
	FactsBlockHeight   uint32 `json:"facts_block_height"`
	DeliveryDeadline   int64  `json:"delivery_deadline_unix_seconds"`
	ExpiryLockTime     uint32 `json:"expiry_lock_time"`
	PoolOutputSatoshis uint64 `json:"pool_output_satoshis"`
	Quote              struct {
		Kind1Hex    string `json:"kind1_hex"`
		SeedHashHex string `json:"seed_hash_hex"`
		SeedHex     string `json:"seed_hex"`
		TermsID     string `json:"terms_id"`
	} `json:"quote"`
	SellerOpening struct {
		Hex string `json:"hex"`
	} `json:"seller_opening_kind2"`
	SellerPresign struct {
		Hex string `json:"hex"`
	} `json:"seller_presign_kind3"`
	FundingDelivery struct {
		Hex string `json:"hex"`
	} `json:"funding_delivery_kind4"`
	BuyerRequest struct {
		Kind5Hex        string `json:"kind5_hex"`
		AuthorizationID string `json:"authorization_id"`
	} `json:"buyer_request_kind5"`
	SellerDelivery struct {
		Hex string `json:"hex"`
	} `json:"seller_delivery_kind6"`
	Arbitration struct {
		Kind8Hex string `json:"kind8_hex"`
		Kind9Hex string `json:"kind9_hex"`
		ClaimID  string `json:"claim_id"`
	} `json:"arbitration"`
}

type countingSigner struct {
	delegate protocol.Signer
	calls    int
}

func (s *countingSigner) PublicKey() protocol.PublicKey { return s.delegate.PublicKey() }

func (s *countingSigner) Sign(ctx context.Context, request protocol.SigningRequest) ([]byte, error) {
	s.calls++
	return s.delegate.Sign(ctx, request)
}

func loadRoleFixture(t *testing.T) (*roleFixtureView, protocol.Facts) {
	t.Helper()
	path, err := conformance.FixturePath(".", "role_manifest")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var view roleFixtureView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	facts := protocol.Facts{Now: time.Unix(view.FactsNowUnix, 0).UTC(), BlockHeight: protocol.BlockHeight(view.FactsBlockHeight)}
	return &view, facts
}

func fixedSigner(t *testing.T, repeat string) *countingSigner {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(repeat, 64))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return &countingSigner{delegate: signer}
}

func fixtureHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func tamperKind2(t *testing.T, rawKind2 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.RefundPresignRequest, rawKind2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	request.BuyerRefundTransactionSignature[len(request.BuyerRefundTransactionSignature)-1] ^= 0x01
	tampered, err := wire.EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return tampered.Bytes()
}

func tamperKind6Payload(t *testing.T, rawKind6 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentDelivery, rawKind6)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := wire.DecodeContentDelivery(artifact)
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := content.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	payloads[0][0] ^= 0x01
	delivery.ContentPayloadsCBOR, err = content.EncodeContentPayloads(payloads)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := wire.EncodeContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	return tampered.Bytes()
}

func TestPureFunctionBoundaryRejectsBeforeSigning(t *testing.T) {
	view, facts := loadRoleFixture(t)
	ctx := context.Background()
	kind1 := fixtureHex(t, view.Quote.Kind1Hex)
	kind2 := fixtureHex(t, view.SellerOpening.Hex)
	kind3 := fixtureHex(t, view.SellerPresign.Hex)
	kind4 := fixtureHex(t, view.FundingDelivery.Hex)
	kind5 := fixtureHex(t, view.BuyerRequest.Kind5Hex)
	kind6 := fixtureHex(t, view.SellerDelivery.Hex)
	seed := fixtureHex(t, view.Quote.SeedHex)
	seedHash := fixtureHex(t, view.Quote.SeedHashHex)
	sellerSigner := fixedSigner(t, "22")
	buyerSigner := fixedSigner(t, "44")
	arbiterSigner := fixedSigner(t, "33")

	// 卖方预签：买方签名被篡改 → 拒绝且卖方 Signer 调用 0 次。
	_, _, err := seller.PreparePresign(ctx, tamperKind2(t, kind2), sellerSigner)
	if !protocol.IsCode(err, protocol.CodeInvalidEvidence) && !protocol.IsCode(err, protocol.CodeInvalidSignature) {
		t.Fatalf("tampered kind2 error = %v", err)
	}
	if sellerSigner.calls != 0 {
		t.Fatalf("seller signer calls after tampered kind2 = %d, want 0", sellerSigner.calls)
	}

	// 建立买卖双方普通证据包。
	fundingRaw, sellerPool, err := seller.VerifyFunding(kind4, seller.SellerOpeningEvidence{RawKind2: kind2, RawKind3: kind3})
	if err != nil {
		t.Fatal(err)
	}
	if len(fundingRaw) == 0 || sellerPool.Opening == nil {
		t.Fatal("verify funding lost the pool evidence")
	}
	buyerPool := buyer.BuyerPoolEvidence{Opening: sellerPool.Opening}
	authorization := buyer.BuyerAuthorizationEvidence{RawKind1: kind1, RawKind5: kind5}

	// 买方交付验收：payload 被篡改 → 拒绝且买方 Signer 调用 0 次。
	_, _, err = buyer.VerifyDelivery(ctx, facts, buyer.VerifyDeliveryInput{
		Authorization: authorization,
		Pool:          buyerPool,
		DeliveryRaw:   tamperKind6Payload(t, kind6),
		Seed:          seed,
	}, buyerSigner)
	if !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("tampered kind6 payload error = %v", err)
	}
	if buyerSigner.calls != 0 {
		t.Fatalf("buyer signer calls after tampered kind6 = %d, want 0", buyerSigner.calls)
	}

	// 卖方交付：退款锁定已到期（facts.now == locktime）→ expired 且 Signer 0 次。
	expiredFacts := protocol.Facts{Now: time.Unix(int64(view.ExpiryLockTime), 0).UTC(), BlockHeight: protocol.BlockHeight(view.FactsBlockHeight)}
	_, _, err = seller.PrepareDelivery(ctx, expiredFacts, seller.DeliveryInput{
		QuoteRaw:        kind1,
		Pool:            sellerPool,
		RequestRaw:      kind5,
		ContentPayloads: [][]byte{seed},
		Seed:            seed,
	}, sellerSigner)
	if !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("expired delivery error = %v", err)
	}
	if sellerSigner.calls != 0 {
		t.Fatalf("seller signer calls after expired delivery = %d, want 0", sellerSigner.calls)
	}

	// 买方内容请求：交付截止晚于报价失效 → invalid_evidence 且 Signer 0 次。
	_, _, err = buyer.PrepareContentRequest(ctx, facts, buyer.RequestContentInput{
		QuoteRaw:         kind1,
		Pool:             buyerPool,
		ContentHashes:    [][]byte{seedHash},
		DeliveryDeadline: content.UnixSeconds(2000000001),
		Seed:             seed,
	}, buyerSigner)
	if !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("deadline beyond quote error = %v", err)
	}
	if buyerSigner.calls != 0 {
		t.Fatalf("buyer signer calls after bad deadline = %d, want 0", buyerSigner.calls)
	}

	// 报价在失效当秒验收 → expired。
	expiredQuoteFacts := protocol.Facts{Now: time.Unix(2000000000, 0).UTC(), BlockHeight: protocol.BlockHeight(view.FactsBlockHeight)}
	if _, err := buyer.AcceptQuote(expiredQuoteFacts, kind1); !protocol.IsCode(err, protocol.CodeExpired) {
		t.Fatalf("expired quote error = %v", err)
	}

	// 仲裁 Prepare：零费用 → invalid_evidence，且不触碰任何 Signer。
	kind8 := fixtureHex(t, view.Arbitration.Kind8Hex)
	if _, err := arbiter.PrepareArbitration(facts, kind8, 0); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("zero arbitration fee error = %v", err)
	}
	prepared, err := arbiter.PrepareArbitration(facts, kind8, protocol.Satoshis(500))
	if err != nil {
		t.Fatal(err)
	}
	// Sign 前篡改 candidate → state_conflict 且仲裁 Signer 调用 0 次。
	tampered := *prepared
	tampered.CandidateRaw = append([]byte(nil), prepared.CandidateRaw...)
	tampered.CandidateRaw[len(tampered.CandidateRaw)-1] ^= 0x01
	if _, err := arbiter.SignPreparedArbitration(ctx, facts, tampered, arbiterSigner); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("tampered candidate error = %v", err)
	}
	if arbiterSigner.calls != 0 {
		t.Fatalf("arbiter signer calls after tampered candidate = %d, want 0", arbiterSigner.calls)
	}

	// 成功路径：仲裁 Sign 在合法证据上恰好调用 Signer 一次并产出 exact Kind 9。
	signed, err := arbiter.SignPreparedArbitration(ctx, facts, *prepared, arbiterSigner)
	if err != nil {
		t.Fatal(err)
	}
	// 仲裁签署需要两次密钥操作：交易签名 + 回执消息签名。
	if arbiterSigner.calls != 2 {
		t.Fatalf("arbiter signer calls on success = %d, want 2", arbiterSigner.calls)
	}
	if signed.Outbound.Kind() != wire.ArbitrationResponse || hex.EncodeToString(signed.Outbound.Bytes()) != view.Arbitration.Kind9Hex {
		t.Fatal("signed arbitration response does not match the frozen fixture")
	}
	if hex.EncodeToString(prepared.ArbitrationClaimID[:]) != view.Arbitration.ClaimID {
		t.Fatal("claim ID does not match the frozen fixture")
	}
}

func TestPureFunctionsAreRepeatable(t *testing.T) {
	view, facts := loadRoleFixture(t)
	ctx := context.Background()
	kind1 := fixtureHex(t, view.Quote.Kind1Hex)
	kind2 := fixtureHex(t, view.SellerOpening.Hex)
	sellerSigner := fixedSigner(t, "22")

	first, firstEvidence, err := seller.PreparePresign(ctx, kind2, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	second, secondEvidence, err := seller.PreparePresign(ctx, kind2, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(first.Bytes()) != hex.EncodeToString(second.Bytes()) ||
		hex.EncodeToString(firstEvidence.RawKind3) != hex.EncodeToString(secondEvidence.RawKind3) {
		t.Fatal("repeated presign calls are not stable")
	}

	terms := &content.FileQuoteTerms{
		SeedHash:                  fixtureHex(t, view.Quote.SeedHashHex),
		BuyerPublicKey:            mustPub(t, "44"),
		SeedPriceSatoshis:         100,
		FullBlockPriceSatoshis:    1000,
		FileSizeBytes:             4096,
		QuoteExpiresAtUnixSeconds: 2000000000,
		RecommendedFilename:       "file.bin",
	}
	arbiters, err := content.EncodeSupportedArbiterPublicKeys([][]byte{mustPub(t, "33")})
	if err != nil {
		t.Fatal(err)
	}
	terms.SupportedArbiterPublicKeysCBOR = arbiters
	firstClass, err := content.ClassifyContentHashes(ctx, terms, [][]byte{terms.SeedHash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondClass, err := content.ClassifyContentHashes(ctx, terms, [][]byte{terms.SeedHash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstClass) != 1 || !firstClass[0].IsSeed || secondClass[0] != firstClass[0] {
		t.Fatal("repeated classification calls are not stable")
	}

	// 纯函数面不接受也不返回任何跨步骤对象：报价验收结果只含 terms/ID/公钥。
	verified, err := buyer.AcceptQuote(facts, kind1)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Terms() == nil || verified.ID().IsZero() || len(verified.SellerPublicKey()) == 0 {
		t.Fatal("verified quote lost its plain fields")
	}
}

func mustPub(t *testing.T, repeat string) []byte {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(repeat, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key.PubKey().Compressed()
}

var _ = pool.CloneOpeningProof
