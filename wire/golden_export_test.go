package wire_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	wire "github.com/bsv8/go-bitfs/wire"
)

// 新实现独立导出器：与 golden_messages_test 相同的确定性 fixture，输出与
// 旧实现导出器同名的向量集，用于新旧逐字节对照证据。
func TestExportGoldenVectors(t *testing.T) {
	if os.Getenv("GOLDEN_EXPORT") == "" {
		t.Skip("set GOLDEN_EXPORT=<path> to dump current-implementation vectors for legacy diff evidence")
	}
	out := exportCurrentGoldenVectors(t)
	raw, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile(os.Getenv("GOLDEN_EXPORT"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// exportCurrentGoldenVectors 构造与旧实现导出器同名的向量集。
func exportCurrentGoldenVectors(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	add := func(name string, raw []byte) { out[name] = hex.EncodeToString(raw) }
	ctx := context.Background()

	quote := goldenQuote(t)
	quoteID, err := content.FileQuoteTermsID(quote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	auth := &content.PaymentAuthorization{
		FileQuoteTermsID:            quoteID,
		RefundTemplateTxID:          bytes.Repeat([]byte{9}, 32),
		PaymentSequence:             3,
		SellerAmountAfterSatoshis:   1100,
		ContentHashesCBOR:           goldenContentHashes(t, bytes.Repeat([]byte{5}, 32)),
		DeliveryDeadlineUnixSeconds: 1999999000,
	}
	request, err := content.NewSignedContentRequest(ctx, auth, mustGoldenSigner(t, "44"))
	if err != nil {
		t.Fatal(err)
	}
	authID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := content.NewSignedContentDelivery(ctx, authID, [][]byte{[]byte("seed-payload")}, mustGoldenSigner(t, "22"))
	if err != nil {
		t.Fatal(err)
	}
	deliveryArtifact, err := wire.EncodeContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	add("content_delivery", deliveryArtifact.Bytes())
	add("payment_authorization_cbor", request.PaymentAuthorizationCBOR)

	update := &pool.PaymentUpdate{PaymentAuthorizationID: protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, 32)), BuyerPaymentTransactionSignature: []byte{5, 6}}
	updateArtifact, err := wire.EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	add("payment_update", updateArtifact.Bytes())

	req8, arbiterWf := wireArbitrationEvidence(t)
	rawRequest8, err := arbitration.MarshalRequest(req8)
	if err != nil {
		t.Fatal(err)
	}
	add("arbitration_request", rawRequest8)
	add("claim_cbor", req8.ArbitrationClaimCBOR)
	claimID, err := arbitration.ArbitrationClaimID(req8.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	add("claim_id", claimID[:])
	facts := mustGoldenFacts()
	prepared, err := arbiterWf.PrepareArbitration(facts, rawRequest8, protocol.Satoshis(500))
	if err != nil {
		t.Fatal(err)
	}
	resp9Artifact, err := arbiterWf.SignPreparedArbitration(context.Background(), facts, prepared)
	if err != nil {
		t.Fatal(err)
	}
	resp9, err := wire.DecodeArbitrationResponse(resp9Artifact)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse9, err := arbitration.MarshalResponse(resp9)
	if err != nil {
		t.Fatal(err)
	}
	add("arbitration_response", rawResponse9)
	add("receipt_cbor", resp9.ArbitrationReceiptCBOR)
	// 独立重建 candidate：与 Prepare 内部同一 builder，保证新旧对照同源。
	_, _, _, unsigned, _, _, _, err := arbitration.ValidateRequestEvidence(req8, 500)
	if err != nil {
		t.Fatal(err)
	}
	add("unsigned_candidate", unsigned.RawTx)

	nonce := protocol.RetrievalNonce(bytes.Repeat([]byte{0xa7}, 32))
	retrieval, err := arbitration.NewContentRetrievalRequest(ctx, claimID, nonce, mustGoldenSigner(t, "55"))
	if err != nil {
		t.Fatal(err)
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrieval)
	if err != nil {
		t.Fatal(err)
	}
	add("content_retrieval_request", rawKind10)
	add("retrieval_request_doc", retrieval.ContentRetrievalRequestCBOR)
	requestIDHash := sha256.Sum256(retrieval.ContentRetrievalRequestCBOR)
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(ctx, protocol.ContentRetrievalRequestID(requestIDHash), arbitration.RetrievalSellerArbitrationNotReady, mustGoldenSigner(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	rawK11u, err := arbitration.MarshalContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	add("retrieval_unavailable", rawK11u)
	available, err := arbitration.BuildContentRetrievalAvailableRaw(ctx, protocol.ContentRetrievalRequestID(requestIDHash), req8.ContentPayloadsCBOR, mustGoldenSigner(t, "33"))
	if err != nil {
		t.Fatal(err)
	}
	rawK11a, err := arbitration.MarshalContentRetrievalResponse(available)
	if err != nil {
		t.Fatal(err)
	}
	add("retrieval_available", rawK11a)

	return out
}
