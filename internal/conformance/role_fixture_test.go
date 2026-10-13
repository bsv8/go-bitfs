package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
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

// 本文件冻结跨语言角色纯函数真值：固定 Signer 下的报价、预签、资金交付、
// 授权、交付、付款、关池、退款与仲裁报文/交易字节，以及计价向量与语义拒绝
// 向量。Go 与 TypeScript 测试消费同一份 fixtures/role-v1.json；任何漂移都由
// make conformance 阻断。
var roleFixtureUpdate = flag.Bool("update-role-fixtures", false, "regenerate fixtures/role-v1.json")

type roleWireFixture struct {
	Hex string `json:"hex"`
}

type roleQuoteFixture struct {
	Kind1Hex      string `json:"kind1_hex"`
	TermsCBORHex  string `json:"terms_cbor_hex"`
	TermsID       string `json:"terms_id"`
	Recommended   string `json:"recommended_filename"`
	SeedHashHex   string `json:"seed_hash_hex"`
	SeedHex       string `json:"seed_hex"`
	FileSizeBytes uint64 `json:"file_size_bytes"`
}

type roleBuyerRequestFixture struct {
	Kind5Hex        string `json:"kind5_hex"`
	AuthorizationID string `json:"authorization_id"`
}

type roleArbitrationFixture struct {
	Kind8Hex              string `json:"kind8_hex"`
	Kind9Hex              string `json:"kind9_hex"`
	ClaimID               string `json:"claim_id"`
	RetrievalKind10Hex    string `json:"retrieval_kind10_hex"`
	RetrievalRequestID    string `json:"retrieval_request_id"`
	AvailableKind11Hex    string `json:"available_kind11_hex"`
	UnavailableKind11Hex  string `json:"unavailable_kind11_hex"`
	UnavailableReasonCode uint64 `json:"unavailable_reason_code"`
}

type rolePriceVector struct {
	Name                   string                `json:"name"`
	SeedPriceSatoshis      uint64                `json:"seed_price_satoshis"`
	FullBlockPriceSatoshis uint64                `json:"full_block_price_satoshis"`
	FileSizeBytes          uint64                `json:"file_size_bytes"`
	SeedHex                string                `json:"seed_hex"`
	HashesHex              []string              `json:"hashes_hex"`
	ExpectClassification   []roleClassifiedEntry `json:"expect_classification,omitempty"`
	ExpectPriceSatoshis    string                `json:"expect_price_satoshis,omitempty"`
	ExpectErrorCode        string                `json:"expect_error_code,omitempty"`
}

type roleClassifiedEntry struct {
	IsSeed    bool   `json:"is_seed"`
	BlockSize uint64 `json:"block_size"`
}

type roleRejectVector struct {
	Name        string `json:"name"`
	Artifact    string `json:"artifact"`
	Mutation    string `json:"mutation"`
	ErrorCode   string `json:"error_code"`
	Description string `json:"description_zh"`
}

type roleMaliciousFixture struct {
	Kind5Decrease      string `json:"kind5_decrease_hex"`
	Kind6Decrease      string `json:"kind6_decrease_hex"`
	Kind7Decrease      string `json:"kind7_decrease_hex"`
	Kind5Capacity      string `json:"kind5_capacity_hex"`
	Kind6Capacity      string `json:"kind6_capacity_hex"`
	Kind7Capacity      string `json:"kind7_capacity_hex"`
	Kind5PriceMismatch string `json:"kind5_price_mismatch_hex"`
	Kind6PriceMismatch string `json:"kind6_price_mismatch_hex"`
}

type roleFixture struct {
	Protocol           string                  `json:"protocol"`
	WireVersion        uint64                  `json:"wire_version"`
	FixedKeys          string                  `json:"fixed_keys"`
	FactsNowUnix       int64                   `json:"facts_now_unix_seconds"`
	FactsBlockHeight   uint32                  `json:"facts_block_height"`
	DeliveryDeadline   int64                   `json:"delivery_deadline_unix_seconds"`
	ExpiryLockTime     uint32                  `json:"expiry_lock_time"`
	PoolOutputSatoshis uint64                  `json:"pool_output_satoshis"`
	Quote              roleQuoteFixture        `json:"quote"`
	SellerOpening      roleWireFixture         `json:"seller_opening_kind2"`
	SellerPresign      roleWireFixture         `json:"seller_presign_kind3"`
	FundingDelivery    roleWireFixture         `json:"funding_delivery_kind4"`
	BuyerRequest       roleBuyerRequestFixture `json:"buyer_request_kind5"`
	SellerDelivery     roleWireFixture         `json:"seller_delivery_kind6"`
	BuyerPayment       roleWireFixture         `json:"buyer_payment_kind7"`
	PaymentMerged      roleWireFixture         `json:"payment_merged_raw"`
	CloseUnsigned      roleWireFixture         `json:"close_unsigned_raw"`
	CloseSigned        roleWireFixture         `json:"close_signed_raw"`
	// CloseRequest 是买方生成的 Kind 12 关池请求原文。
	CloseRequest roleWireFixture `json:"close_request_kind12"`
	// CloseResponse 是卖方返回的 Kind 13 完整关闭响应原文。
	CloseResponse  roleWireFixture        `json:"close_response_kind13"`
	RefundMatured  roleWireFixture        `json:"refund_matured_raw"`
	Arbitration    roleArbitrationFixture `json:"arbitration"`
	Malicious      roleMaliciousFixture   `json:"malicious"`
	PriceVectors   []rolePriceVector      `json:"price_vectors"`
	EvidenceReject []roleRejectVector     `json:"evidence_reject_vectors"`
}

func mustRoleKey(t *testing.T, repeat string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(repeat, 64))
	if err != nil {
		t.Fatalf("role fixture key %q: %v", repeat, err)
	}
	return key
}

func mustRoleSigner(t *testing.T, key *ec.PrivateKey) protocol.Signer {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// buildRoleFixture 运行一次完整角色流并返回全部冻结真值。
func buildRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	ctx := context.Background()
	buyerKey := mustRoleKey(t, "44")
	sellerKey := mustRoleKey(t, "22")
	arbiterKey := mustRoleKey(t, "33")
	retrievalKey := mustRoleKey(t, "55")
	buyerSigner := mustRoleSigner(t, buyerKey)
	sellerSigner := mustRoleSigner(t, sellerKey)
	arbiterSigner := mustRoleSigner(t, arbiterKey)
	_ = retrievalKey

	fileBytes := make([]byte, 4096)
	for index := range fileBytes {
		fileBytes[index] = byte(index*31 + 7)
	}
	var seedBuffer bytes.Buffer
	if _, err := masterseed.CreateSeed(ctx, bytes.NewReader(fileBytes), &seedBuffer); err != nil {
		t.Fatal(err)
	}
	seed := seedBuffer.Bytes()
	seedHash := masterseed.Sum256(seed).Bytes()

	fundingLock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPublicKey: buyerKey.PubKey().Compressed(), SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	sourceHash, err := chainhash.NewHash(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding.AddInput(&tx.TransactionInput{SourceTXID: sourceHash, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(fundingLock)})
	fundingRaw := funding.Bytes()

	quoteArtifact, terms, err := seller.CreateQuote(ctx, roleFacts(1999999000), sellerSigner, seller.QuoteDraft{
		SeedHash:                   seedHash,
		BuyerPublicKey:             mustRolePublicKey(t, buyerKey.PubKey().Compressed()),
		SeedPriceSatoshis:          protocol.Satoshis(100),
		FullBlockPriceSatoshis:     protocol.Satoshis(1000),
		FileSizeBytes:              uint64(len(fileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(2000000000),
		SupportedArbiterPublicKeys: []protocol.PublicKey{mustRolePublicKey(t, arbiterKey.PubKey().Compressed())},
		RecommendedFilename:        "file.bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	termsCBOR, err := content.EncodeFileQuoteTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	termsID, err := content.FileQuoteTermsID(termsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	kind2, openingEvidence, err := buyer.PrepareOpening(ctx, buyer.PrepareOpeningInput{
		QuoteRaw:                        quoteArtifact.Bytes(),
		FundingTransactionRaw:           fundingRaw,
		ExpiryLockTime:                  protocol.RefundLockTime(2000000000),
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 mustRolePublicKey(t, sellerKey.PubKey().Compressed()),
		ArbiterPublicKey:                mustRolePublicKey(t, arbiterKey.PubKey().Compressed()),
	}, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	kind3, _, err := seller.PreparePresign(ctx, kind2.Bytes(), sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, buyerPool, err := buyer.CompleteOpening(openingEvidence, kind3.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kind4, err := buyer.PrepareFundingDelivery(buyerPool)
	if err != nil {
		t.Fatal(err)
	}
	_, sellerPool, err := seller.VerifyFunding(kind4.Bytes(), seller.SellerOpeningEvidence{RawKind2: kind2.Bytes(), RawKind3: kind3.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	kind5, authEvidence, err := buyer.PrepareContentRequest(ctx, roleFacts(1999999000), buyer.RequestContentInput{
		QuoteRaw:         quoteArtifact.Bytes(),
		Pool:             buyerPool,
		ContentHashes:    [][]byte{seedHash},
		DeliveryDeadline: content.UnixSeconds(1999999500),
		Seed:             seed,
	}, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	authID, err := content.PaymentAuthorizationID(mustDecodeAuthorizationCBOR(t, kind5.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	kind6, _, err := seller.PrepareDelivery(ctx, roleFacts(1999999000), seller.DeliveryInput{
		QuoteRaw:        quoteArtifact.Bytes(),
		Pool:            sellerPool,
		RequestRaw:      kind5.Bytes(),
		ContentPayloads: [][]byte{seed},
		Seed:            seed,
	}, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, kind7, err := buyer.VerifyDelivery(ctx, roleFacts(1999999000), buyer.VerifyDeliveryInput{
		Authorization: authEvidence,
		Pool:          buyerPool,
		DeliveryRaw:   kind6.Bytes(),
		Seed:          seed,
	}, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	deliveryEvidence := seller.SellerDeliveryEvidence{RawKind1: quoteArtifact.Bytes(), RawKind5: kind5.Bytes(), RawKind6: kind6.Bytes()}
	paymentMerged, sellerNext, err := seller.CompletePayment(ctx, roleFacts(1999999000), seller.CompletePaymentInput{
		Pool:       sellerPool,
		Delivery:   deliveryEvidence,
		RequestRaw: kind5.Bytes(),
		UpdateRaw:  kind7.Bytes(),
	}, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	// 买方从链上付款原文推进池状态。
	buyerPaid := buyer.BuyerPoolEvidence{Opening: buyerPool.Opening, LatestPaymentRawTx: paymentMerged}
	closeUnsigned, buyerCloseSignature, err := buyer.PrepareClose(ctx, roleFacts(1999999000), buyer.PrepareCloseInput{
		Pool:                       buyerPaid,
		TargetSellerAmountSatoshis: protocol.Satoshis(150),
	}, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	closeSigned, err := seller.CompleteClose(ctx, roleFacts(1999999000), seller.CompleteCloseInput{
		Pool:           sellerNext,
		UnsignedRaw:    closeUnsigned,
		BuyerSignature: buyerCloseSignature,
	}, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	closeRequest, err := buyer.PrepareCloseArtifact(ctx, roleFacts(1999999000), buyer.PrepareCloseInput{
		Pool:                       buyerPaid,
		TargetSellerAmountSatoshis: protocol.Satoshis(150),
	}, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	closeResponse, err := seller.CompleteCloseArtifact(ctx, roleFacts(1999999000), seller.CompleteCloseArtifactInput{
		Pool:       sellerNext,
		RequestRaw: closeRequest.Bytes(),
	}, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	verifiedClose, err := buyer.VerifyCompletedCloseArtifact(buyer.VerifyCompletedCloseArtifactInput{
		Pool:        buyerPaid,
		ResponseRaw: closeResponse.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifiedClose.RawTx(), closeSigned) {
		t.Fatal("Kind 12/13 role path changed the completed close transaction")
	}
	refundMatured, err := buyer.BuildMaturedRefund(roleFacts(2000000000), buyerPaid)
	if err != nil {
		t.Fatal(err)
	}
	kind8, claimID, err := seller.PrepareArbitration(ctx, roleFacts(1999999000), seller.PrepareArbitrationInput{
		Pool:        sellerNext,
		RequestRaw:  kind5.Bytes(),
		DeliveryRaw: kind6.Bytes(),
	}, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := arbiter.PrepareArbitration(roleFacts(1999999000), kind8.Bytes(), protocol.Satoshis(500))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := arbiter.SignPreparedArbitration(ctx, roleFacts(1999999000), *prepared, arbiterSigner)
	if err != nil {
		t.Fatal(err)
	}
	// 008 取回证据：Kind 10（显式 nonce）、unavailable 与 available 分支。
	nonce := bytes.Repeat([]byte{0xa7}, 32)
	kind10, err := buyer.RequestArbitratedContent(ctx, buyer.RetrievalRequestInput{
		Pool:          buyerPaid,
		Authorization: authEvidence,
		Nonce:         nonce,
	}, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	kind10Parsed, err := wire.ParseAs(wire.ContentRetrievalRequest, kind10.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	kind10Decoded, err := wire.DecodeContentRetrievalRequest(kind10Parsed)
	if err != nil {
		t.Fatal(err)
	}
	claimIDFromDoc, _, err := arbitration.DecodeContentRetrievalRequestDocument(kind10Decoded.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if claimIDFromDoc != claimID {
		t.Fatal("retrieval request claim ID mismatch")
	}
	requestIDHash := sha256.Sum256(kind10Decoded.ContentRetrievalRequestCBOR)
	requestID, err := protocol.NewContentRetrievalRequestID(requestIDHash[:])
	if err != nil {
		t.Fatal(err)
	}
	unavailable, err := arbiter.BuildUnavailableRetrieval(ctx, requestID, arbitration.RetrievalSellerArbitrationNotReady, arbiterSigner)
	if err != nil {
		t.Fatal(err)
	}
	storedKind8, err := arbitration.UnmarshalRequest(kind8.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	storedKind9, err := arbitration.UnmarshalResponse(signed.Outbound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	custody, err := arbitration.VerifyCustodiedContent(storedKind8, storedKind9)
	if err != nil {
		t.Fatal(err)
	}
	if err := arbiter.AuthenticateRetrieval(kind10.Bytes(), kind8.Bytes()); err != nil {
		t.Fatal(err)
	}
	available, err := arbiter.BuildAvailableRetrieval(ctx, requestID, custody, arbiterSigner)
	if err != nil {
		t.Fatal(err)
	}

	fixture := &roleFixture{
		Protocol:           protocol.ProtocolFamily,
		WireVersion:        protocol.WireVersion,
		FixedKeys:          "buyer=0x44*32 seller=0x22*32 arbiter=0x33*32 retrieval-buyer=0x55*32; funding input 0x01*32 placeholder",
		FactsNowUnix:       1999999000,
		FactsBlockHeight:   900000,
		DeliveryDeadline:   1999999500,
		ExpiryLockTime:     2000000000,
		PoolOutputSatoshis: 20000,
		Quote: roleQuoteFixture{
			Kind1Hex:      hexEncode(quoteArtifact.Bytes()),
			TermsCBORHex:  hexEncode(termsCBOR),
			TermsID:       hexEncode(termsID[:]),
			Recommended:   terms.RecommendedFilename,
			SeedHashHex:   hexEncode(seedHash),
			SeedHex:       hexEncode(seed),
			FileSizeBytes: uint64(len(fileBytes)),
		},
		SellerOpening:   roleWireFixture{Hex: hexEncode(kind2.Bytes())},
		SellerPresign:   roleWireFixture{Hex: hexEncode(kind3.Bytes())},
		FundingDelivery: roleWireFixture{Hex: hexEncode(kind4.Bytes())},
		BuyerRequest:    roleBuyerRequestFixture{Kind5Hex: hexEncode(kind5.Bytes()), AuthorizationID: hexEncode(authID[:])},
		SellerDelivery:  roleWireFixture{Hex: hexEncode(kind6.Bytes())},
		BuyerPayment:    roleWireFixture{Hex: hexEncode(kind7.Bytes())},
		PaymentMerged:   roleWireFixture{Hex: hexEncode(paymentMerged)},
		CloseUnsigned:   roleWireFixture{Hex: hexEncode(closeUnsigned)},
		CloseSigned:     roleWireFixture{Hex: hexEncode(closeSigned)},
		CloseRequest:    roleWireFixture{Hex: hexEncode(closeRequest.Bytes())},
		CloseResponse:   roleWireFixture{Hex: hexEncode(closeResponse.Bytes())},
		RefundMatured:   roleWireFixture{Hex: hexEncode(refundMatured.RawTx())},
		Arbitration: roleArbitrationFixture{
			Kind8Hex:              hexEncode(kind8.Bytes()),
			Kind9Hex:              hexEncode(signed.Outbound.Bytes()),
			ClaimID:               hexEncode(claimID[:]),
			RetrievalKind10Hex:    hexEncode(kind10.Bytes()),
			RetrievalRequestID:    hexEncode(requestID[:]),
			AvailableKind11Hex:    hexEncode(available.Bytes()),
			UnavailableKind11Hex:  hexEncode(unavailable.Bytes()),
			UnavailableReasonCode: uint64(arbitration.RetrievalSellerArbitrationNotReady),
		},
		Malicious:      buildMaliciousEvidence(t, ctx, termsID, sellerPool, paymentMerged, kind7.Bytes(), buyerSigner, sellerSigner, seed, seedHash),
		PriceVectors:   buildPriceVectors(t, ctx),
		EvidenceReject: buildRejectVectors(),
	}
	return fixture
}

// buildMaliciousEvidence 生成六类共享语义拒绝向量所需的“买方已签但业务非法”
// 授权/付款/交付证据：金额倒退、容量不足、价格不符。它们不是 SDK 能产出的
// 正常输入，而是调用方（这里由测试扮演）直接签署的非法条款。
func buildMaliciousEvidence(t *testing.T, ctx context.Context, termsID protocol.FileQuoteTermsID, sellerPool seller.SellerPoolEvidence, previousPaymentRaw, baselineKind7Raw []byte, buyerSigner, sellerSigner protocol.Signer, seed, seedHash []byte) roleMaliciousFixture {
	t.Helper()
	details, err := pool.DeriveOpeningDetails(sellerPool.Opening)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: sellerPool.Opening.BuyerPublicKey, SellerPublicKey: sellerPool.Opening.SellerPublicKey, ArbiterPublicKey: sellerPool.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(previousPaymentRaw, sellerPool.Opening)
	if err != nil {
		t.Fatal(err)
	}
	hashesCBOR, err := content.EncodeContentHashes([][]byte{seedHash})
	if err != nil {
		t.Fatal(err)
	}
	baselineKind7, err := wire.ParseAs(wire.PaymentUpdate, baselineKind7Raw)
	if err != nil {
		t.Fatal(err)
	}
	baselineUpdate, err := wire.DecodePaymentUpdate(baselineKind7)
	if err != nil {
		t.Fatal(err)
	}
	signAuthorization := func(sequence uint32, amount uint64) ([]byte, protocol.PaymentAuthorizationID) {
		t.Helper()
		authorization := &content.PaymentAuthorization{
			FileQuoteTermsID:            termsID,
			RefundTemplateTxID:          append([]byte(nil), details.RefundTemplateTxID[:]...),
			PaymentSequence:             sequence,
			SellerAmountAfterSatoshis:   amount,
			ContentHashesCBOR:           hashesCBOR,
			DeliveryDeadlineUnixSeconds: 1999999500,
		}
		signed, err := content.NewSignedContentRequest(ctx, authorization, buyerSigner)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := wire.EncodeContentRequest(signed)
		if err != nil {
			t.Fatal(err)
		}
		authID, err := content.PaymentAuthorizationID(signed.PaymentAuthorizationCBOR)
		if err != nil {
			t.Fatal(err)
		}
		return artifact.Bytes(), authID
	}
	signDelivery := func(authID protocol.PaymentAuthorizationID) []byte {
		t.Helper()
		document, err := content.EncodeContentDeliveryDocument(authID)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := protocol.SignWireDocument(ctx, sellerSigner, protocol.WireVersion, 6, document)
		if err != nil {
			t.Fatal(err)
		}
		payloadsCBOR, err := content.EncodeContentPayloads([][]byte{seed})
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := wire.EncodeContentDelivery(&content.SignedContentDelivery{ContentDeliveryCBOR: document, SellerContentDeliverySignature: signature, ContentPayloadsCBOR: payloadsCBOR})
		if err != nil {
			t.Fatal(err)
		}
		return artifact.Bytes()
	}
	updateWithAuthID := func(authID protocol.PaymentAuthorizationID) []byte {
		t.Helper()
		artifact, err := wire.EncodePaymentUpdate(&pool.PaymentUpdate{PaymentAuthorizationID: authID, BuyerPaymentTransactionSignature: append([]byte(nil), baselineUpdate.BuyerPaymentTransactionSignature...)})
		if err != nil {
			t.Fatal(err)
		}
		return artifact.Bytes()
	}

	// 金额倒退：买方签署低于上一状态的累计金额；SDK 在重建 candidate 之前拒绝。
	kind5Decrease, decreaseAuthID := signAuthorization(previous.PaymentSequence+1, previous.SellerAmountSatoshis-50)
	// 容量不足：买方签署超过费用池输出的累计金额。
	kind5Capacity, capacityAuthID := signAuthorization(previous.PaymentSequence+1, details.PoolOutputSatoshis+1)
	// 价格不符：买方签署的增量与内容哈希价格不一致。
	kind5Price, priceAuthID := signAuthorization(previous.PaymentSequence+1, previous.SellerAmountSatoshis+250)
	return roleMaliciousFixture{
		Kind5Decrease:      hexEncode(kind5Decrease),
		Kind6Decrease:      hexEncode(signDelivery(decreaseAuthID)),
		Kind7Decrease:      hexEncode(updateWithAuthID(decreaseAuthID)),
		Kind5Capacity:      hexEncode(kind5Capacity),
		Kind6Capacity:      hexEncode(signDelivery(capacityAuthID)),
		Kind7Capacity:      hexEncode(updateWithAuthID(capacityAuthID)),
		Kind5PriceMismatch: hexEncode(kind5Price),
		Kind6PriceMismatch: hexEncode(signDelivery(priceAuthID)),
	}
}

// roleFacts 组装 role fixture 的固定显式事实。
func roleFacts(nowUnix int64) protocol.Facts {
	return protocol.Facts{Now: time.Unix(nowUnix, 0).UTC(), BlockHeight: 900000}
}

func mustRolePublicKey(t *testing.T, raw []byte) protocol.PublicKey {
	t.Helper()
	key, err := protocol.PublicKeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustDecodeAuthorizationCBOR(t *testing.T, rawKind5 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeContentRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return request.PaymentAuthorizationCBOR
}

// buildPriceVectors 生成两语言共用的计价向量：seed/整块/末块/组合/边界与
// 溢出、越界、缺 seed、块不在 seed 等拒绝向量。
func buildPriceVectors(t *testing.T, ctx context.Context) []rolePriceVector {
	t.Helper()
	fullBlock := bytes.Repeat([]byte{0xAB}, int(masterseed.BlockSize))
	tailBlock := bytes.Repeat([]byte{0xCD}, 4096)
	fullHash := masterseed.Sum256(fullBlock).Bytes()
	tailHash := masterseed.Sum256(tailBlock).Bytes()
	fullSeed := masterseed.Sum256(fullBlock).Bytes()
	tailSeed := masterseed.Sum256(tailBlock).Bytes()
	comboSeed := append(append([]byte(nil), fullSeed...), tailSeed...)
	comboSeedHash := masterseed.Sum256(comboSeed).Bytes()
	unknownHash := bytes.Repeat([]byte{0xEF}, 32)

	vectors := []rolePriceVector{
		{Name: "seed_only", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: 0, HashesHex: []string{hexEncode(masterseed.Sum256(nil).Bytes())}},
		{Name: "full_block", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: uint64(masterseed.BlockSize), SeedHex: hexEncode(fullSeed), HashesHex: []string{hexEncode(fullHash)}},
		{Name: "tail_block", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: 4096, SeedHex: hexEncode(tailSeed), HashesHex: []string{hexEncode(tailHash)}},
		{Name: "combination", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: uint64(masterseed.BlockSize) + 4096, SeedHex: hexEncode(comboSeed), HashesHex: []string{hexEncode(comboSeedHash), hexEncode(fullHash), hexEncode(tailHash)}},
		{Name: "zero_full_block_price_tail", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 0, FileSizeBytes: 4096, SeedHex: hexEncode(tailSeed), HashesHex: []string{hexEncode(tailHash)}},
		{Name: "block_not_in_seed", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: 4096, SeedHex: hexEncode(tailSeed), HashesHex: []string{hexEncode(unknownHash)}, ExpectErrorCode: string(protocol.CodeInvalidEvidence)},
		{Name: "missing_seed", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: 4096, HashesHex: []string{hexEncode(tailHash)}, ExpectErrorCode: string(protocol.CodeInvalidEvidence)},
		{Name: "duplicate_hash", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: 4096, SeedHex: hexEncode(tailSeed), HashesHex: []string{hexEncode(tailHash), hexEncode(tailHash)}, ExpectErrorCode: string(protocol.CodeInvalidEvidence)},
		{Name: "wrong_hash_width", SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: 4096, SeedHex: hexEncode(tailSeed), HashesHex: []string{hexEncode(tailHash[:31])}, ExpectErrorCode: string(protocol.CodeInvalidEvidence)},
		{Name: "overflow", SeedPriceSatoshis: ^uint64(0), FullBlockPriceSatoshis: ^uint64(0), FileSizeBytes: uint64(masterseed.BlockSize), SeedHex: hexEncode(fullSeed), HashesHex: []string{hexEncode(masterseed.Sum256(fullSeed).Bytes()), hexEncode(fullHash)}, ExpectErrorCode: string(protocol.CodeInsufficientBalance)},
	}
	// seed_only 的 seedHash 是空 seed 的 SHA-256；classification 需要真实条款。
	for index := range vectors {
		vector := &vectors[index]
		terms := &content.FileQuoteTerms{
			SeedHash:                  mustSeedHashForVector(t, vector),
			BuyerPublicKey:            mustRoleKey(t, "44").PubKey().Compressed(),
			SeedPriceSatoshis:         vector.SeedPriceSatoshis,
			FullBlockPriceSatoshis:    vector.FullBlockPriceSatoshis,
			FileSizeBytes:             vector.FileSizeBytes,
			QuoteExpiresAtUnixSeconds: 2000000000,
			RecommendedFilename:       "file.bin",
		}
		arbiters, err := content.EncodeSupportedArbiterPublicKeys([][]byte{mustRoleKey(t, "33").PubKey().Compressed()})
		if err != nil {
			t.Fatal(err)
		}
		terms.SupportedArbiterPublicKeysCBOR = arbiters
		hashes := decodeHexList(t, vector.HashesHex)
		seed := decodeHexOrNil(t, vector.SeedHex)
		classification, classErr := content.ClassifyContentHashes(ctx, terms, hashes, seed)
		if classErr == nil {
			for _, item := range classification {
				vector.ExpectClassification = append(vector.ExpectClassification, roleClassifiedEntry{IsSeed: item.IsSeed, BlockSize: item.BlockSize})
			}
			price, priceErr := content.ContentHashesPriceSatoshis(ctx, terms, hashes, seed)
			if priceErr == nil {
				vector.ExpectPriceSatoshis = decimalUint64(price)
			} else {
				vector.ExpectErrorCode = string(errorCodeOf(priceErr))
				vector.ExpectClassification = nil
			}
		} else {
			vector.ExpectErrorCode = string(errorCodeOf(classErr))
		}
	}
	return vectors
}

func mustSeedHashForVector(t *testing.T, vector *rolePriceVector) []byte {
	t.Helper()
	if vector.Name == "seed_only" {
		return masterseed.Sum256(nil).Bytes()
	}
	// 其余向量的 seed 哈希来自各自 seed 原文；combination 的条款 seed 是组合 seed。
	seed := decodeHexOrNil(t, vector.SeedHex)
	return masterseed.Sum256(seed).Bytes()
}

// buildRejectVectors 冻结两语言必须同码拒绝的语义无效真值。artifact 指向
// role-v1.json 中的基线报文；mutation 是双方测试共同实现的确定性篡改。
func buildRejectVectors() []roleRejectVector {
	return []roleRejectVector{
		{Name: "kind1_expired", Artifact: "kind1", Mutation: "facts_at_expiry", ErrorCode: string(protocol.CodeExpired), Description: "报价在 facts.now 当秒已失效"},
		{Name: "kind5_signature_flip", Artifact: "kind5", Mutation: "signature_last_byte_flip", ErrorCode: string(protocol.CodeInvalidSignature), Description: "买方授权签名被翻转"},
		{Name: "kind5_deadline_beyond_quote", Artifact: "kind5", Mutation: "delivery_deadline_beyond_quote", ErrorCode: string(protocol.CodeInvalidEvidence), Description: "交付截止晚于报价失效"},
		{Name: "kind6_payload_flip", Artifact: "kind6", Mutation: "payload_last_byte_flip", ErrorCode: string(protocol.CodeInvalidEvidence), Description: "payload 与授权哈希不符"},
		{Name: "kind7_authorization_id_flip", Artifact: "kind7", Mutation: "authorization_id_first_byte_flip", ErrorCode: string(protocol.CodeStateConflict), Description: "付款更新引用了不同授权"},
		{Name: "kind9_receipt_signature_flip", Artifact: "kind9", Mutation: "receipt_signature_last_byte_flip", ErrorCode: string(protocol.CodeInvalidSignature), Description: "仲裁回执签名被翻转"},
		{Name: "kind10_zero_nonce", Artifact: "kind10", Mutation: "zero_nonce", ErrorCode: string(protocol.CodeInvalidEvidence), Description: "取回 nonce 全零"},
		{Name: "kind11_available_attachment_flip", Artifact: "kind11_available", Mutation: "attachment_last_byte_flip", ErrorCode: string(protocol.CodeInvalidEvidence), Description: "available attachment 哈希不符"},
		{Name: "foreign_seller_signer", Artifact: "kind2", Mutation: "foreign_seller_signer", ErrorCode: string(protocol.CodeUnauthorized), Description: "角色不符：卖方 Signer 与请求角色不一致"},
		{Name: "kind2_refund_template_flip", Artifact: "kind2", Mutation: "kind2_refund_template_flip", ErrorCode: string(protocol.CodeInvalidSignature), Description: "退款模板被篡改，买方签名不再覆盖重建结果"},
		{Name: "stale_sequence_second_round", Artifact: "kind7", Mutation: "stale_sequence_second_round", ErrorCode: string(protocol.CodeStateConflict), Description: "序号陈旧：第二轮复用第一轮授权"},
		{Name: "amount_decrease_second_round", Artifact: "kind7", Mutation: "amount_decrease_second_round", ErrorCode: string(protocol.CodeInvalidEvidence), Description: "金额倒退：买方签署更低累计金额"},
		{Name: "capacity_insufficient_second_round", Artifact: "kind7", Mutation: "capacity_insufficient_second_round", ErrorCode: string(protocol.CodeInsufficientBalance), Description: "容量不足：授权金额超过费用池输出"},
		{Name: "price_mismatch_second_round", Artifact: "kind6", Mutation: "price_mismatch_second_round", ErrorCode: string(protocol.CodeInvalidEvidence), Description: "价格不符：授权金额与内容哈希价格不一致"},
	}
}

func decodeHexList(t *testing.T, values []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(values))
	for index, value := range values {
		out[index] = decodeHex(t, value)
	}
	return out
}

func decodeHexOrNil(t *testing.T, value string) []byte {
	t.Helper()
	if value == "" {
		return nil
	}
	return decodeHex(t, value)
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decimalUint64(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func errorCodeOf(err error) protocol.ErrorCode {
	code, _ := protocol.CodeOf(err)
	return code
}

func hexEncode(raw []byte) string { return hex.EncodeToString(raw) }

// TestRoleFixtureMatchesFrozenFile 用当前实现重算全部角色真值并逐字节比对
// fixtures/role-v1.json；-update-role-fixtures 仅在人工审查后重建。
func TestRoleFixtureMatchesFrozenFile(t *testing.T) {
	rebuilt := buildRoleFixture(t)
	path, err := FixturePath(".", "role_manifest")
	if err != nil {
		t.Fatalf("resolve role_manifest from fixtures/manifest.json: %v", err)
	}
	if *roleFixtureUpdate {
		raw, err := json.MarshalIndent(rebuilt, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s; 必须附协议级证据并经人工审查后才能合入", path)
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen role fixture: %v", err)
	}
	var frozen roleFixture
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustJSON(t, frozen), mustJSON(t, *rebuilt)) {
		t.Fatal("role fixture drifted from the current implementation; 逐字段对比后更新")
	}
}

// TestRoleFixtureInspectDeliveryRequest verifies the Go preflight API against
// the same frozen Kind 1/2/3/4/5 evidence consumed by the TypeScript test.
func TestRoleFixtureInspectDeliveryRequest(t *testing.T) {
	frozen := loadFrozenRoleFixture(t)
	kind1 := decodeHex(t, frozen.Quote.Kind1Hex)
	kind2 := decodeHex(t, frozen.SellerOpening.Hex)
	kind3 := decodeHex(t, frozen.SellerPresign.Hex)
	kind4 := decodeHex(t, frozen.FundingDelivery.Hex)
	kind5 := decodeHex(t, frozen.BuyerRequest.Kind5Hex)

	_, sellerPool, err := seller.VerifyFunding(kind4, seller.SellerOpeningEvidence{RawKind2: kind2, RawKind3: kind3})
	if err != nil {
		t.Fatalf("rebuild seller pool from shared opening fixture: %v", err)
	}
	input := seller.InspectDeliveryRequestInput{QuoteRaw: kind1, Pool: sellerPool, RequestRaw: kind5}
	summary, err := seller.InspectDeliveryRequest(roleFacts(frozen.FactsNowUnix), input)
	if err != nil {
		t.Fatalf("inspect shared Kind 5 fixture: %v", err)
	}
	if got := hexEncode(summary.PaymentAuthorizationID[:]); got != frozen.BuyerRequest.AuthorizationID {
		t.Fatalf("authorization ID = %s, want %s", got, frozen.BuyerRequest.AuthorizationID)
	}
	artifact, err := wire.ParseAs(wire.ContentRequest, kind5)
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeContentRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := content.DecodePaymentAuthorization(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	expectedHashes, err := content.DecodeContentHashes(authorization.ContentHashesCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PaymentSequence != protocol.PaymentSequence(authorization.PaymentSequence) ||
		summary.SellerAmountAfterSatoshis != protocol.Satoshis(authorization.SellerAmountAfterSatoshis) ||
		summary.DeliveryDeadlineUnixSeconds != content.UnixSeconds(authorization.DeliveryDeadlineUnixSeconds) ||
		!bytes.Equal(summary.FileQuoteTermsID[:], authorization.FileQuoteTermsID[:]) ||
		!bytes.Equal(summary.RefundTemplateTxID[:], authorization.RefundTemplateTxID) ||
		!equalHashBatches(summary.ContentHashes, expectedHashes) {
		t.Fatal("inspection summary does not match the strictly decoded Kind 5 authorization")
	}

	// The returned hashes are caller-owned copies.
	originalHash := bytes.Clone(summary.ContentHashes[0])
	summary.ContentHashes[0][0] ^= 0xff
	second, err := seller.InspectDeliveryRequest(roleFacts(frozen.FactsNowUnix), input)
	if err != nil {
		t.Fatalf("re-inspect shared Kind 5 fixture: %v", err)
	}
	if !bytes.Equal(second.ContentHashes[0], originalHash) {
		t.Fatal("mutating the summary changed a later inspection result")
	}

	tampered := tamperKind5Signature(t, kind5)
	if _, err := seller.InspectDeliveryRequest(roleFacts(frozen.FactsNowUnix), seller.InspectDeliveryRequestInput{QuoteRaw: kind1, Pool: sellerPool, RequestRaw: tampered}); !protocol.IsCode(err, protocol.CodeInvalidSignature) {
		t.Fatalf("tampered buyer signature inspection error = %v", err)
	}

	stalePool := sellerPool
	stalePool.LatestPaymentRawTx = decodeHex(t, frozen.PaymentMerged.Hex)
	if _, err := seller.InspectDeliveryRequest(roleFacts(frozen.FactsNowUnix), seller.InspectDeliveryRequestInput{QuoteRaw: kind1, Pool: stalePool, RequestRaw: kind5}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("stale request inspection error = %v", err)
	}
}

// TestRoleFixtureCloseArtifactLifecycle verifies the buyer → seller → buyer
// Kind 12/13 path against the same frozen role fixture used by TypeScript.
func TestRoleFixtureCloseArtifactLifecycle(t *testing.T) {
	frozen := loadFrozenRoleFixture(t)
	kind2 := decodeHex(t, frozen.SellerOpening.Hex)
	kind3 := decodeHex(t, frozen.SellerPresign.Hex)
	kind4 := decodeHex(t, frozen.FundingDelivery.Hex)
	kind4Artifact, err := wire.ParseAs(wire.FundingTransactionDelivery, kind4)
	if err != nil {
		t.Fatal(err)
	}
	funding, err := wire.DecodeFundingTransactionDelivery(kind4Artifact)
	if err != nil {
		t.Fatal(err)
	}
	openingEvidence := buyer.BuyerOpeningEvidence{
		RawKind2:              kind2,
		FundingTransactionRaw: funding.FundingTransactionRaw,
	}
	_, buyerPool, err := buyer.CompleteOpening(openingEvidence, kind3)
	if err != nil {
		t.Fatalf("rebuild buyer pool evidence from shared opening fixture: %v", err)
	}
	buyerPool.LatestPaymentRawTx = decodeHex(t, frozen.PaymentMerged.Hex)
	_, sellerPool, err := seller.VerifyFunding(kind4, seller.SellerOpeningEvidence{RawKind2: kind2, RawKind3: kind3})
	if err != nil {
		t.Fatalf("rebuild seller pool evidence from shared opening fixture: %v", err)
	}
	sellerPool.LatestPaymentRawTx = decodeHex(t, frozen.PaymentMerged.Hex)

	ctx := context.Background()
	buyerSigner := mustRoleSigner(t, mustRoleKey(t, "44"))
	sellerSigner := mustRoleSigner(t, mustRoleKey(t, "22"))
	request, err := buyer.PrepareCloseArtifact(ctx, roleFacts(frozen.FactsNowUnix), buyer.PrepareCloseInput{
		Pool:                       buyerPool,
		TargetSellerAmountSatoshis: protocol.Satoshis(150),
	}, buyerSigner)
	if err != nil {
		t.Fatalf("prepare shared Kind 12 role request: %v", err)
	}
	requestRaw := decodeHex(t, frozen.CloseRequest.Hex)
	if !bytes.Equal(request.Bytes(), requestRaw) {
		t.Fatal("buyer did not reproduce frozen Kind 12 request")
	}
	response, err := seller.CompleteCloseArtifact(ctx, roleFacts(frozen.FactsNowUnix), seller.CompleteCloseArtifactInput{
		Pool:       sellerPool,
		RequestRaw: requestRaw,
	}, sellerSigner)
	if err != nil {
		t.Fatalf("complete shared Kind 12 role request: %v", err)
	}
	responseRaw := decodeHex(t, frozen.CloseResponse.Hex)
	if !bytes.Equal(response.Bytes(), responseRaw) {
		t.Fatal("seller did not reproduce frozen Kind 13 response")
	}
	verified, err := buyer.VerifyCompletedCloseArtifact(buyer.VerifyCompletedCloseArtifactInput{
		Pool: buyerPool, ResponseRaw: responseRaw,
	})
	if err != nil {
		t.Fatalf("accept shared Kind 13 role response: %v", err)
	}
	if !bytes.Equal(verified.RawTx(), decodeHex(t, frozen.CloseSigned.Hex)) {
		t.Fatal("buyer accepted a different completed close transaction")
	}

	requestArtifact, err := wire.ParseAs(wire.PoolCloseRequest, requestRaw)
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest, err := wire.DecodePoolCloseRequest(requestArtifact)
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest.RefundTemplateTxID[0] ^= 0x01
	wrongRequestArtifact, err := wire.EncodePoolCloseRequest(wrongRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seller.CompleteCloseArtifact(ctx, roleFacts(frozen.FactsNowUnix), seller.CompleteCloseArtifactInput{
		Pool: sellerPool, RequestRaw: wrongRequestArtifact.Bytes(),
	}, sellerSigner); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("wrong request pool ID error = %v, want state_conflict", err)
	}
	responseArtifact, err := wire.ParseAs(wire.PoolCloseResponse, responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	wrongResponse, err := wire.DecodePoolCloseResponse(responseArtifact)
	if err != nil {
		t.Fatal(err)
	}
	wrongResponse.RefundTemplateTxID[0] ^= 0x01
	wrongResponseArtifact, err := wire.EncodePoolCloseResponse(wrongResponse)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buyer.VerifyCompletedCloseArtifact(buyer.VerifyCompletedCloseArtifactInput{
		Pool: buyerPool, ResponseRaw: wrongResponseArtifact.Bytes(),
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("wrong response pool ID error = %v, want state_conflict", err)
	}
}

func equalHashBatches(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// loadFrozenRoleFixture 读取根清单指向的角色真值文件。
func loadFrozenRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	path, err := FixturePath(".", "role_manifest")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var frozen roleFixture
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	return &frozen
}

func flipLastByte(t *testing.T, value []byte) []byte {
	t.Helper()
	flipped := append([]byte(nil), value...)
	flipped[len(flipped)-1] ^= 0x01
	return flipped
}

func tamperKind5Signature(t *testing.T, rawKind5 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeContentRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	request.BuyerPaymentAuthorizationSignature = flipLastByte(t, request.BuyerPaymentAuthorizationSignature)
	tampered, err := wire.EncodeContentRequest(request)
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
	payloads[len(payloads)-1] = flipLastByte(t, payloads[len(payloads)-1])
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

func tamperKind7AuthorizationID(t *testing.T, rawKind7 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.PaymentUpdate, rawKind7)
	if err != nil {
		t.Fatal(err)
	}
	update, err := wire.DecodePaymentUpdate(artifact)
	if err != nil {
		t.Fatal(err)
	}
	update.PaymentAuthorizationID[0] ^= 0x01
	tampered, err := wire.EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	return tampered.Bytes()
}

func tamperKind9ReceiptSignature(t *testing.T, rawKind9 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ArbitrationResponse, rawKind9)
	if err != nil {
		t.Fatal(err)
	}
	response, err := wire.DecodeArbitrationResponse(artifact)
	if err != nil {
		t.Fatal(err)
	}
	response.ArbiterArbitrationReceiptSignature = flipLastByte(t, response.ArbiterArbitrationReceiptSignature)
	tampered, err := wire.EncodeArbitrationResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return tampered.Bytes()
}

func tamperKind11Attachment(t *testing.T, rawKind11 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.ContentRetrievalResponse, rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	response, err := wire.DecodeContentRetrievalResponse(artifact)
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := content.DecodeContentPayloads(response.ContentPayloadsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	payloads[len(payloads)-1] = flipLastByte(t, payloads[len(payloads)-1])
	response.ContentPayloadsCBOR, err = content.EncodeContentPayloads(payloads)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := wire.EncodeContentRetrievalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return tampered.Bytes()
}

func tamperKind2RefundTemplate(t *testing.T, rawKind2 []byte) []byte {
	t.Helper()
	artifact, err := wire.ParseAs(wire.RefundPresignRequest, rawKind2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	request.RefundTemplateRaw = flipLastByte(t, request.RefundTemplateRaw)
	tampered, err := wire.EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return tampered.Bytes()
}

// TestRoleRejectVectorsMatchFrozen 执行共享语义拒绝向量：每一条都由 Go 新公开
// 面在基线证据上重放，错误分类必须与冻结文件逐条一致。它与 TypeScript 测试
// 使用同一份 mutation 名称与基线，是 make conformance 的双语言门禁。
func TestRoleRejectVectorsMatchFrozen(t *testing.T) {
	frozen := loadFrozenRoleFixture(t)
	ctx := context.Background()
	facts := roleFacts(frozen.FactsNowUnix)
	sellerSigner := mustRoleSigner(t, mustRoleKey(t, "22"))
	buyerSigner := mustRoleSigner(t, mustRoleKey(t, "44"))
	foreignSellerSigner := mustRoleSigner(t, mustRoleKey(t, "99"))

	kind1 := decodeHex(t, frozen.Quote.Kind1Hex)
	kind2 := decodeHex(t, frozen.SellerOpening.Hex)
	kind3 := decodeHex(t, frozen.SellerPresign.Hex)
	kind4 := decodeHex(t, frozen.FundingDelivery.Hex)
	kind5 := decodeHex(t, frozen.BuyerRequest.Kind5Hex)
	kind6 := decodeHex(t, frozen.SellerDelivery.Hex)
	kind7 := decodeHex(t, frozen.BuyerPayment.Hex)
	kind8 := decodeHex(t, frozen.Arbitration.Kind8Hex)
	kind9 := decodeHex(t, frozen.Arbitration.Kind9Hex)
	kind10 := decodeHex(t, frozen.Arbitration.RetrievalKind10Hex)
	kind11Available := decodeHex(t, frozen.Arbitration.AvailableKind11Hex)
	paymentMerged := decodeHex(t, frozen.PaymentMerged.Hex)
	seed := decodeHex(t, frozen.Quote.SeedHex)
	seedHash := decodeHex(t, frozen.Quote.SeedHashHex)

	_, sellerPool, err := seller.VerifyFunding(kind4, seller.SellerOpeningEvidence{RawKind2: kind2, RawKind3: kind3})
	if err != nil {
		t.Fatal(err)
	}
	poolWithLatest := sellerPool
	poolWithLatest.LatestPaymentRawTx = paymentMerged
	buyerInitial := buyer.BuyerPoolEvidence{Opening: sellerPool.Opening}
	buyerPaid := buyer.BuyerPoolEvidence{Opening: sellerPool.Opening, LatestPaymentRawTx: paymentMerged}
	authorization := buyer.BuyerAuthorizationEvidence{RawKind1: kind1, RawKind5: kind5}
	delivery := seller.SellerDeliveryEvidence{RawKind1: kind1, RawKind5: kind5, RawKind6: kind6}
	malicious := frozen.Malicious
	maliciousDelivery := func(kind5Hex, kind6Hex string) seller.SellerDeliveryEvidence {
		return seller.SellerDeliveryEvidence{RawKind1: kind1, RawKind5: decodeHex(t, kind5Hex), RawKind6: decodeHex(t, kind6Hex)}
	}

	for _, vector := range frozen.EvidenceReject {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			var runErr error
			switch vector.Mutation {
			case "facts_at_expiry":
				_, runErr = buyer.AcceptQuote(roleFacts(2000000000), kind1)
			case "signature_last_byte_flip":
				_, _, runErr = seller.PrepareDelivery(ctx, facts, seller.DeliveryInput{QuoteRaw: kind1, Pool: sellerPool, RequestRaw: tamperKind5Signature(t, kind5), ContentPayloads: [][]byte{seed}, Seed: seed}, sellerSigner)
			case "delivery_deadline_beyond_quote":
				_, _, runErr = buyer.PrepareContentRequest(ctx, facts, buyer.RequestContentInput{QuoteRaw: kind1, Pool: buyerInitial, ContentHashes: [][]byte{seedHash}, DeliveryDeadline: 2000000001, Seed: seed}, buyerSigner)
			case "payload_last_byte_flip":
				_, _, runErr = buyer.VerifyDelivery(ctx, facts, buyer.VerifyDeliveryInput{Authorization: authorization, Pool: buyerInitial, DeliveryRaw: tamperKind6Payload(t, kind6), Seed: seed}, buyerSigner)
			case "authorization_id_first_byte_flip":
				_, _, runErr = seller.CompletePayment(ctx, facts, seller.CompletePaymentInput{Pool: poolWithLatest, Delivery: delivery, RequestRaw: kind5, UpdateRaw: tamperKind7AuthorizationID(t, kind7)}, sellerSigner)
			case "receipt_signature_last_byte_flip":
				_, runErr = seller.CompleteArbitratedPayment(ctx, facts, seller.CompleteArbitratedPaymentInput{RequestRaw: kind8, ResponseRaw: tamperKind9ReceiptSignature(t, kind9)}, sellerSigner)
			case "zero_nonce":
				_, runErr = buyer.RequestArbitratedContent(ctx, buyer.RetrievalRequestInput{Pool: buyerPaid, Authorization: authorization, Nonce: make([]byte, 32)}, buyerSigner)
			case "attachment_last_byte_flip":
				_, runErr = buyer.VerifyArbitratedContent(ctx, buyer.ArbitratedContentInput{Authorization: authorization, Pool: buyerInitial, RetrievalRequestRaw: kind10, RetrievalResponseRaw: tamperKind11Attachment(t, kind11Available), Seed: seed})
			case "foreign_seller_signer":
				_, _, runErr = seller.PreparePresign(ctx, kind2, foreignSellerSigner)
			case "kind2_refund_template_flip":
				_, _, runErr = seller.PreparePresign(ctx, tamperKind2RefundTemplate(t, kind2), sellerSigner)
			case "stale_sequence_second_round":
				_, _, runErr = seller.CompletePayment(ctx, facts, seller.CompletePaymentInput{Pool: poolWithLatest, Delivery: delivery, RequestRaw: kind5, UpdateRaw: kind7}, sellerSigner)
			case "amount_decrease_second_round":
				kind5Decrease := decodeHex(t, malicious.Kind5Decrease)
				_, _, runErr = seller.CompletePayment(ctx, facts, seller.CompletePaymentInput{Pool: poolWithLatest, Delivery: maliciousDelivery(malicious.Kind5Decrease, malicious.Kind6Decrease), RequestRaw: kind5Decrease, UpdateRaw: decodeHex(t, malicious.Kind7Decrease)}, sellerSigner)
			case "capacity_insufficient_second_round":
				kind5Capacity := decodeHex(t, malicious.Kind5Capacity)
				_, _, runErr = seller.CompletePayment(ctx, facts, seller.CompletePaymentInput{Pool: poolWithLatest, Delivery: maliciousDelivery(malicious.Kind5Capacity, malicious.Kind6Capacity), RequestRaw: kind5Capacity, UpdateRaw: decodeHex(t, malicious.Kind7Capacity)}, sellerSigner)
			case "price_mismatch_second_round":
				_, _, runErr = buyer.VerifyDelivery(ctx, facts, buyer.VerifyDeliveryInput{Authorization: buyer.BuyerAuthorizationEvidence{RawKind1: kind1, RawKind5: decodeHex(t, malicious.Kind5PriceMismatch)}, Pool: buyerPaid, DeliveryRaw: decodeHex(t, malicious.Kind6PriceMismatch), Seed: seed}, buyerSigner)
			default:
				t.Fatalf("未实现的拒绝向量 mutation: %s", vector.Mutation)
			}
			if runErr == nil {
				t.Fatalf("拒绝向量 %s 被接受", vector.Name)
			}
			if code, _ := protocol.CodeOf(runErr); string(code) != vector.ErrorCode {
				t.Fatalf("拒绝向量 %s 错误码 = %s (%v), want %s", vector.Name, code, runErr, vector.ErrorCode)
			}
		})
	}
}
