package wire_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/flowtest/arbiter"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

func wireTestSellerPubkey() []byte {
	key, err := ec.PrivateKeyFromHex("4444444444444444444444444444444444444444444444444444444444444444")
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}

func wireTestBuyerPubkey() []byte {
	key, err := ec.PrivateKeyFromHex("5555555555555555555555555555555555555555555555555555555555555555")
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}

// wireGoldenFacts 是 golden/round-trip 测试共用的显式事实（时间早于全部
// fixture 的退款锁定与交付截止）。
func wireGoldenFacts() protocol.Facts {
	return protocol.Facts{Now: time.Unix(1999999000, 0).UTC(), BlockHeight: 900000}
}

func TestPoolRefundPresignRequestTypedRoundTrip(t *testing.T) {
	request := &pool.RefundPresignRequest{
		RefundTemplateRaw:               []byte{1, 2, 3},
		BuyerPublicKey:                  wireTestBuyerPubkey(),
		SellerPublicKey:                 wireTestSellerPubkey(),
		ArbiterPublicKey:                wireTestArbiterPubkey(),
		MinerFeeRateSatoshisPerKilobyte: 1,
		BuyerRefundTransactionSignature: []byte{9},
	}
	artifact, err := wire.EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	raw := artifact.Bytes()
	decoded, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.RefundTemplateRaw, request.RefundTemplateRaw) || decoded.MinerFeeRateSatoshisPerKilobyte != request.MinerFeeRateSatoshisPerKilobyte {
		t.Fatal("presign request changed during wire round trip")
	}
	if _, err := wire.ParseAs(wire.RefundPresignRequest, append(raw, 0)); err == nil {
		t.Fatal("decoder accepted trailing bytes")
	}
}

func TestPoolRefundPresignResponseTypedRoundTrip(t *testing.T) {
	response := &pool.RefundPresignResponse{
		RefundTemplateTxID:               pool.RefundTemplateTxID(bytes.Repeat([]byte{3}, 32)),
		SellerRefundTransactionSignature: []byte{7, 8},
	}
	artifact, err := wire.EncodeRefundPresignResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	raw := artifact.Bytes()
	decoded, err := wire.DecodeRefundPresignResponse(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RefundTemplateTxID != response.RefundTemplateTxID || !bytes.Equal(decoded.SellerRefundTransactionSignature, response.SellerRefundTransactionSignature) {
		t.Fatal("presign response changed during wire round trip")
	}
	if len(raw) == 0 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x03 {
		t.Fatalf("002 presign response must be a four-element [1,3,...] array: %x", raw)
	}
}

func TestFundingTransactionDeliveryTypedRoundTrip(t *testing.T) {
	delivery := &pool.FundingTransactionDelivery{
		RefundTemplateTxID:    pool.RefundTemplateTxID(bytes.Repeat([]byte{4}, 32)),
		FundingTransactionRaw: []byte{5, 6, 7},
	}
	artifact, err := wire.EncodeFundingTransactionDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	raw := artifact.Bytes()
	decoded, err := wire.DecodeFundingTransactionDelivery(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RefundTemplateTxID != delivery.RefundTemplateTxID || !bytes.Equal(decoded.FundingTransactionRaw, delivery.FundingTransactionRaw) {
		t.Fatal("funding delivery changed during wire round trip")
	}
	if len(raw) == 0 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x04 {
		t.Fatalf("002 funding delivery must be a four-element [1,4,...] array: %x", raw)
	}
}

func TestPoolCloseEncodersRejectArtifactsAboveGlobalWireLimit(t *testing.T) {
	oversizedTransaction := bytes.Repeat([]byte{1}, wire.MaxWireParseBytes)
	request, err := wire.EncodePoolCloseRequest(&pool.PoolCloseRequest{
		RefundTemplateTxID:             pool.RefundTemplateTxID(bytes.Repeat([]byte{2}, 32)),
		UnsignedCloseTransactionRaw:    oversizedTransaction,
		BuyerCloseTransactionSignature: []byte{1},
	})
	if !protocol.IsCode(err, protocol.CodeMalformedWire) || !request.IsZero() {
		t.Fatalf("oversized Kind 12 = artifact %v, err %v; want zero artifact and malformed_wire", request.IsZero(), err)
	}
	response, err := wire.EncodePoolCloseResponse(&pool.PoolCloseResponse{
		RefundTemplateTxID:          pool.RefundTemplateTxID(bytes.Repeat([]byte{2}, 32)),
		CompleteCloseTransactionRaw: oversizedTransaction,
	})
	if !protocol.IsCode(err, protocol.CodeMalformedWire) || !response.IsZero() {
		t.Fatalf("oversized Kind 13 = artifact %v, err %v; want zero artifact and malformed_wire", response.IsZero(), err)
	}
}

func TestArbitrationMessagesTypedRoundTrip(t *testing.T) {
	request, arbiterWorkflow := wireArbitrationEvidence(t)
	rawRequest, err := arbitration.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, err := wire.ParseAs(wire.ArbitrationRequest, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := wire.DecodeArbitrationRequest(requestArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedRequest.ArbitrationClaimCBOR, request.ArbitrationClaimCBOR) || !bytes.Equal(decodedRequest.ContentPayloadsCBOR, request.ContentPayloadsCBOR) {
		t.Fatal("007 request evidence changed during wire round trip")
	}
	if len(rawRequest) == 0 || rawRequest[0] != 0x85 || rawRequest[1] != 0x01 || rawRequest[2] != 0x08 {
		t.Fatalf("007 request must be [1,8,...] five-element array: %x", rawRequest)
	}
	prepared, err := arbiterWorkflow.PrepareArbitration(wireGoldenFacts(), rawRequest, 500)
	if err != nil {
		t.Fatal(err)
	}
	responseArtifact, err := arbiterWorkflow.SignPreparedArbitration(context.Background(), wireGoldenFacts(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse := responseArtifact.Bytes()
	if len(rawResponse) == 0 || rawResponse[0] != 0x84 || rawResponse[1] != 0x01 || rawResponse[2] != 0x09 {
		t.Fatalf("007 response must be a four-element [1,9,...] array starting with 0x84: %x", rawResponse)
	}
	responseArtifactParsed, err := wire.ParseAs(wire.ArbitrationResponse, rawResponse)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := wire.DecodeArbitrationResponse(responseArtifactParsed)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(decodedResponse.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbiterAmountSatoshis != 500 || len(receipt.ArbitrationClaimID) != sha256.Size || len(receipt.ArbiterPaymentTransactionSignature) == 0 {
		t.Fatalf("decoded receipt is incomplete or mispriced: %+v", receipt)
	}
	// Kind never carries instance identity: decoding a payload under a
	// different kind must fail rather than silently reinterpreting it.
	if _, err := wire.ParseAs(wire.PaymentUpdate, rawRequest); err == nil {
		t.Fatal("payload was decoded under an unrelated kind")
	}
	if _, err := wire.ParseAs(wire.ArbitrationResponse, rawRequest); err == nil {
		t.Fatal("Kind 8 body decoded as Kind 9")
	}
	if _, err := wire.ParseAs(wire.ArbitrationRequest, rawResponse); err == nil {
		t.Fatal("Kind 9 body decoded as Kind 8")
	}
}

func wireArbitrationEvidence(t *testing.T) (*arbitration.ArbitrationRequest, *arbiter.Workflow) {
	t.Helper()
	buyerKey := wireTestBuyerKey(t)
	sellerKey, err := ec.PrivateKeyFromHex("2222222222222222222222222222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	arbiterKey, err := ec.PrivateKeyFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPublicKey: buyerKey.PubKey().Compressed(), SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := chainhash.NewHash(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock)})
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: buyerKey.PubKey().Compressed(), SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := pool.NewBuyerPoolAdapter(engine, wireTestSigner(t, buyerKey)).BuildRefundPresignRequest(context.Background(), pool.OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: 2000000000, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := pool.NewSellerPoolAdapter(engine, wireTestSigner(t, sellerKey)).SignSellerRefund(context.Background(), presign)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(presign, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	refundID, err := pool.DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	hashes, err := content.EncodeContentHashes([][]byte{digest[:]})
	if err != nil {
		t.Fatal(err)
	}
	signedAuthorization, err := content.NewSignedContentRequest(context.Background(), &content.PaymentAuthorization{FileQuoteTermsID: protocol.FileQuoteTermsID(bytes.Repeat([]byte{1}, 32)), RefundTemplateTxID: refundID[:], PaymentSequence: 3, SellerAmountAfterSatoshis: 100, ContentHashesCBOR: hashes, DeliveryDeadlineUnixSeconds: 2000000100}, wireTestSigner(t, buyerKey))
	if err != nil {
		t.Fatal(err)
	}
	details, err := pool.DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := arbitration.MarshalClaim(&arbitration.ArbitrationClaim{PoolOutputSatoshis: details.PoolOutputSatoshis, PoolOutputLockingScript: details.PoolLockingScript, RefundTemplateRaw: proof.RefundTemplateRaw, PaymentAuthorizationCBOR: signedAuthorization.PaymentAuthorizationCBOR, BuyerPaymentAuthorizationSignature: signedAuthorization.BuyerPaymentAuthorizationSignature})
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := protocol.SignWireDocument(context.Background(), wireTestSigner(t, sellerKey), protocol.WireVersion, 8, claim)
	if err != nil {
		t.Fatal(err)
	}
	payloadCBOR, err := content.EncodeContentPayloads([][]byte{payload})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := arbiter.NewWorkflow(wireTestSigner(t, arbiterKey))
	if err != nil {
		t.Fatal(err)
	}
	return &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: claim, SellerArbitrationClaimSignature: sellerSig, ContentPayloadsCBOR: payloadCBOR}, workflow
}

func TestContentDeliveryTypedRoundTrip(t *testing.T) {
	sellerKey, err := ec.PrivateKeyFromHex("4444444444444444444444444444444444444444444444444444444444444444")
	if err != nil {
		t.Fatal(err)
	}
	hashesCBOR, err := content.EncodeContentHashes([][]byte{bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	requestTerms := &content.PaymentAuthorization{
		FileQuoteTermsID:            protocol.FileQuoteTermsID(bytes.Repeat([]byte{1}, 32)),
		RefundTemplateTxID:          bytes.Repeat([]byte{2}, 32),
		PaymentSequence:             2,
		SellerAmountAfterSatoshis:   10,
		ContentHashesCBOR:           hashesCBOR,
		DeliveryDeadlineUnixSeconds: 2_000_000_000,
	}
	signedRequest, err := content.NewSignedContentRequest(context.Background(), requestTerms, wireTestSigner(t, wireTestBuyerKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	authID, err := content.PaymentAuthorizationID(signedRequest.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := content.NewSignedContentDelivery(context.Background(), authID, [][]byte{[]byte("payload")}, wireTestSigner(t, sellerKey))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := wire.EncodeContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	raw := artifact.Bytes()
	decoded, err := wire.DecodeContentDelivery(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ContentDeliveryCBOR, delivery.ContentDeliveryCBOR) || !bytes.Equal(decoded.SellerContentDeliverySignature, delivery.SellerContentDeliverySignature) || !bytes.Equal(decoded.ContentPayloadsCBOR, delivery.ContentPayloadsCBOR) {
		t.Fatal("content delivery changed during wire round trip")
	}
	// The Kind 6 shell must be a five-element array led by [1, 6] and the
	// payload attachment stays outside the signed document.
	if len(raw) == 0 || raw[0] != 0x85 || raw[1] != 0x01 || raw[2] != 0x06 {
		t.Fatalf("004 must be a five-element [1,6,...] array: %x", raw)
	}
	if _, err := wire.ParseAs(wire.ContentDelivery, append(raw, 0)); err == nil {
		t.Fatal("decoder accepted trailing bytes")
	}
}

func wireTestBuyerKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex("5555555555555555555555555555555555555555555555555555555555555555")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestContentRetrievalMessagesTypedRoundTrip(t *testing.T) {
	request, _ := wireArbitrationEvidence(t)
	claimID, err := arbitration.ArbitrationClaimID(request.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	var nonce protocol.RetrievalNonce
	copy(nonce[:], bytes.Repeat([]byte{0x71}, 32))
	retrievalRequest, err := arbitration.NewContentRetrievalRequest(context.Background(), claimID, nonce, wireTestSigner(t, wireTestBuyerKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	request10Artifact, err := wire.EncodeContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	raw10 := request10Artifact.Bytes()
	if len(raw10) == 0 || raw10[0] != 0x84 || raw10[1] != 0x01 || raw10[2] != 0x0a {
		t.Fatalf("Kind 10 must be a four-element [1,10,...] array: %x", raw10)
	}

	requestIDHash := sha256.Sum256(retrievalRequest.ContentRetrievalRequestCBOR)
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(context.Background(), protocol.ContentRetrievalRequestID(requestIDHash), arbitration.RetrievalSellerArbitrationNotReceived, wireTestSigner(t, mustArbiterKey()))
	if err != nil {
		t.Fatal(err)
	}
	unavailable11Artifact, err := wire.EncodeContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	raw11Unavailable := unavailable11Artifact.Bytes()
	if len(raw11Unavailable) == 0 || raw11Unavailable[0] != 0x84 || raw11Unavailable[1] != 0x01 || raw11Unavailable[2] != 0x0b {
		t.Fatalf("unavailable Kind 11 must be a four-element [1,11,...] array: %x", raw11Unavailable)
	}
	available, err := arbitration.BuildContentRetrievalAvailable(context.Background(), protocol.ContentRetrievalRequestID(requestIDHash), [][]byte{[]byte("payload")}, wireTestSigner(t, mustArbiterKey()))
	if err != nil {
		t.Fatal(err)
	}
	available11Artifact, err := wire.EncodeContentRetrievalResponse(available)
	if err != nil {
		t.Fatal(err)
	}
	raw11Available := available11Artifact.Bytes()
	if len(raw11Available) == 0 || raw11Available[0] != 0x85 || raw11Available[1] != 0x01 || raw11Available[2] != 0x0b {
		t.Fatalf("available Kind 11 must be a five-element [1,11,...] array: %x", raw11Available)
	}

	decoded10, err := wire.DecodeContentRetrievalRequest(request10Artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded10.ContentRetrievalRequestCBOR, retrievalRequest.ContentRetrievalRequestCBOR) || !bytes.Equal(decoded10.BuyerContentRetrievalRequestSignature, retrievalRequest.BuyerContentRetrievalRequestSignature) {
		t.Fatal("Kind 10 typed round trip changed fields")
	}
	decoded11, err := wire.DecodeContentRetrievalResponse(available11Artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded11.ContentRetrievalResultCBOR, available.ContentRetrievalResultCBOR) || !bytes.Equal(decoded11.ContentPayloadsCBOR, available.ContentPayloadsCBOR) {
		t.Fatal("Kind 11 typed round trip changed fields")
	}

	// transport Kind 必须与 CBOR 本体第二项一致：贴错一律失败。
	if _, err := wire.ParseAs(wire.ContentRetrievalResponse, raw10); err == nil {
		t.Fatal("Kind 10 body decoded as Kind 11")
	}
	if _, err := wire.ParseAs(wire.ContentRetrievalRequest, raw11Available); err == nil {
		t.Fatal("Kind 11 body decoded as Kind 10")
	}
	// 8/9/10/11 交叉解码全部拒绝。
	if _, err := wire.ParseAs(wire.ArbitrationRequest, raw10); err == nil {
		t.Fatal("Kind 10 body decoded as Kind 8")
	}
	if _, err := wire.ParseAs(wire.ArbitrationResponse, raw10); err == nil {
		t.Fatal("Kind 10 body decoded as Kind 9")
	}
	if _, err := wire.ParseAs(wire.ArbitrationRequest, raw11Available); err == nil {
		t.Fatal("Kind 11 body decoded as Kind 8")
	}
	if _, err := wire.ParseAs(wire.ArbitrationResponse, raw11Available); err == nil {
		t.Fatal("Kind 11 body decoded as Kind 9")
	}
}

func mustArbiterKey() *ec.PrivateKey {
	key, err := ec.PrivateKeyFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	if err != nil {
		panic(err)
	}
	return key
}
