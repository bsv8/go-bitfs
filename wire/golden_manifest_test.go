package wire_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/conformance"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	wire "github.com/bsv8/go-bitfs/wire"
)

// 本文件把 Kind 1–11 冻结为机器可读 manifest（wire/testdata/v1/
// golden_messages.json）：exact hex、SHA-256 与关键子文档 typed ID。固定
// signer 下逐字节相等是兼容边界的验收证据之一；-update 仅允许在单独给出
// 协议级证据并经人工审查后重建，绝不能为让测试通过而顺手更新。
var goldenUpdate = flag.Bool("update-golden-manifest", false, "regenerate wire/testdata/v1/golden_messages.json")

type goldenManifestEntry struct {
	Kind        int    `json:"kind"`
	Name        string `json:"name"`
	ExactHex    string `json:"exact_hex"`
	SHA256      string `json:"sha256"`
	ChildDocHex string `json:"child_doc_hex,omitempty"`
	ChildID     string `json:"child_id,omitempty"`
}

type goldenManifest struct {
	Protocol    string                `json:"protocol"`
	WireVersion uint64                `json:"wire_version"`
	FixedKeys   string                `json:"fixed_keys"`
	Entries     []goldenManifestEntry `json:"entries"`
}

func buildGoldenManifest(t *testing.T) *goldenManifest {
	t.Helper()
	quote := goldenQuote(t)
	manifest := &goldenManifest{Protocol: wire.ProtocolFamily, WireVersion: protocol.WireVersion, FixedKeys: "repeat-byte keys: seller=0x22 buyer=0x44 arbiter=0x33 retrieval-buyer=0x55"}

	add := func(kind wire.Kind, name string, artifact wire.Artifact, childDoc []byte) {
		t.Helper()
		entry := goldenManifestEntry{Kind: int(kind), Name: name, ExactHex: hex.EncodeToString(artifact.Bytes()), SHA256: hex.EncodeToString(hashBytes(artifact.Bytes()))}
		if childDoc != nil {
			entry.ChildDocHex = hex.EncodeToString(childDoc)
			entry.ChildID = hex.EncodeToString(hashBytes(childDoc))
		}
		manifest.Entries = append(manifest.Entries, entry)
	}

	// Kind 2/3/4：结构固定的池开池报文（与 wire_pool_test 同一 fixture 形态）。
	presignRequest, err := wire.EncodeRefundPresignRequest(&pool.RefundPresignRequest{
		RefundTemplateRaw:               []byte{1, 2, 3},
		BuyerPublicKey:                  mustGoldenKey(t, "44").PubKey().Compressed(),
		SellerPublicKey:                 mustGoldenKey(t, "22").PubKey().Compressed(),
		ArbiterPublicKey:                mustGoldenKey(t, "33").PubKey().Compressed(),
		MinerFeeRateSatoshisPerKilobyte: 1,
		BuyerRefundTransactionSignature: []byte{9},
	})
	if err != nil {
		t.Fatal(err)
	}
	add(wire.RefundPresignRequest, "refund_presign_request", presignRequest, nil)
	presignResponse, err := wire.EncodeRefundPresignResponse(&pool.RefundPresignResponse{
		RefundTemplateTxID:               pool.RefundTemplateTxID(bytes.Repeat([]byte{3}, 32)),
		SellerRefundTransactionSignature: []byte{7, 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	add(wire.RefundPresignResponse, "refund_presign_response", presignResponse, nil)
	fundingDelivery, err := wire.EncodeFundingTransactionDelivery(&pool.FundingTransactionDelivery{
		RefundTemplateTxID:    pool.RefundTemplateTxID(bytes.Repeat([]byte{4}, 32)),
		FundingTransactionRaw: []byte{5, 6, 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	add(wire.FundingTransactionDelivery, "funding_transaction_delivery", fundingDelivery, nil)

	quoteArtifact, err := wire.EncodeFileQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.FileQuote, "file_quote", quoteArtifact, quote.FileQuoteTermsCBOR)

	quoteID, err := content.FileQuoteTermsID(quote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := bytes.Repeat([]byte{5}, 32)
	authorization := &content.PaymentAuthorization{
		FileQuoteTermsID:            quoteID,
		RefundTemplateTxID:          bytes.Repeat([]byte{9}, 32),
		PaymentSequence:             3,
		SellerAmountAfterSatoshis:   1100,
		ContentHashesCBOR:           goldenContentHashes(t, contentHash),
		DeliveryDeadlineUnixSeconds: 1999999000,
	}
	request, err := content.NewSignedContentRequest(testContext(), authorization, mustGoldenSigner(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, err := wire.EncodeContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ContentRequest, "content_request", requestArtifact, request.PaymentAuthorizationCBOR)

	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := content.NewSignedContentDelivery(testContext(), authID, [][]byte{[]byte("seed-payload")}, mustGoldenSigner(t, "22"))
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := wire.EncodeContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ContentDelivery, "content_delivery", deliveryArtifact, delivery.ContentDeliveryCBOR)

	update := &pool.PaymentUpdate{PaymentAuthorizationID: protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, 32)), BuyerPaymentTransactionSignature: []byte{5, 6}}
	updateArtifact, err := wire.EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.PaymentUpdate, "payment_update", updateArtifact, nil)

	request8, arbiter := wireArbitrationEvidence(t)
	const arbitrationFee = protocol.Satoshis(500)
	prepared, err := arbiter.PrepareArbitration(mustGoldenFacts(), func() []byte {
		raw, err := arbitration.MarshalRequest(request8)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}(), arbitrationFee)
	if err != nil {
		t.Fatal(err)
	}
	response9, err := arbiter.SignPreparedArbitration(testContext(), mustGoldenFacts(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	request8Artifact, err := wire.EncodeArbitrationRequest(request8)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ArbitrationRequest, "arbitration_request", request8Artifact, request8.ArbitrationClaimCBOR)
	response8Artifact, err := wire.DecodeArbitrationResponse(response9)
	if err != nil {
		t.Fatal(err)
	}
	responseArtifact, err := wire.EncodeArbitrationResponse(response8Artifact)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ArbitrationResponse, "arbitration_response", responseArtifact, response8Artifact.ArbitrationReceiptCBOR)

	claimID, err := arbitration.ArbitrationClaimID(request8.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	retrievalRequest, err := arbitration.NewContentRetrievalRequest(testContext(), claimID, protocol.RetrievalNonce(bytes.Repeat([]byte{0xa7}, 32)), mustGoldenSigner(t, "55"))
	if err != nil {
		t.Fatal(err)
	}
	retrievalArtifact, err := wire.EncodeContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ContentRetrievalRequest, "content_retrieval_request", retrievalArtifact, retrievalRequest.ContentRetrievalRequestCBOR)

	requestIDHash := sha256.Sum256(retrievalRequest.ContentRetrievalRequestCBOR)
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(testContext(), protocol.ContentRetrievalRequestID(requestIDHash), arbitration.RetrievalSellerArbitrationNotReady, mustGoldenSigner(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	unavailableArtifact, err := wire.EncodeContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ContentRetrievalResponse, "content_retrieval_unavailable", unavailableArtifact, unavailable.ContentRetrievalResultCBOR)

	available, err := arbitration.BuildContentRetrievalAvailableRaw(testContext(), protocol.ContentRetrievalRequestID(requestIDHash), request8.ContentPayloadsCBOR, mustGoldenSigner(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	availableArtifact, err := wire.EncodeContentRetrievalResponse(available)
	if err != nil {
		t.Fatal(err)
	}
	add(wire.ContentRetrievalResponse, "content_retrieval_available", availableArtifact, available.ContentRetrievalResultCBOR)

	return manifest
}

func hashBytes(raw []byte) []byte { digest := sha256.Sum256(raw); return digest[:] }

// testContext 返回测试用根 context。
func testContext() context.Context { return context.Background() }

func TestGoldenMessagesManifestMatchesFrozenFile(t *testing.T) {
	manifest := buildGoldenManifest(t)
	path, err := conformance.FixturePath(".", "wire_manifest")
	if err != nil {
		t.Fatalf("resolve wire_manifest from fixtures/manifest.json: %v", err)
	}
	if *goldenUpdate {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
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
		t.Fatalf("read frozen golden manifest: %v(-update-golden-manifest 可重建,但需要协议级证据)", err)
	}
	var frozen goldenManifest
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	if len(frozen.Entries) != len(manifest.Entries) {
		t.Fatalf("entry count drifted: frozen %d rebuilt %d", len(frozen.Entries), len(manifest.Entries))
	}
	for index, want := range frozen.Entries {
		got := manifest.Entries[index]
		if got.Kind != want.Kind || got.Name != want.Name {
			t.Fatalf("entry %d identity drifted: %+v vs %+v", index, got, want)
		}
		if got.ExactHex != want.ExactHex {
			t.Fatalf("golden %s exact bytes drifted:\n got %s\nwant %s", want.Name, got.ExactHex, want.ExactHex)
		}
		if got.SHA256 != want.SHA256 {
			t.Fatalf("golden %s sha256 drifted", want.Name)
		}
		if got.ChildDocHex != want.ChildDocHex || got.ChildID != want.ChildID {
			t.Fatalf("golden %s child document/id drifted", want.Name)
		}
	}
}
