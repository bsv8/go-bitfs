package wire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
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

func TestPoolRefundPresignRequestTypedRoundTrip(t *testing.T) {
	request := &pool.RefundPresignRequest{
		RefundTemplateRaw:               []byte{1, 2, 3},
		BuyerPublicKey:                  wireTestBuyerPubkey(),
		SellerPublicKey:                 wireTestSellerPubkey(),
		ArbiterPublicKey:                wireTestArbiterPubkey(),
		MinerFeeRateSatoshisPerKilobyte: 1,
		BuyerRefundTransactionSignature: []byte{9},
	}
	raw, err := MarshalRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalRefundPresignRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.RefundTemplateRaw, request.RefundTemplateRaw) || decoded.MinerFeeRateSatoshisPerKilobyte != request.MinerFeeRateSatoshisPerKilobyte {
		t.Fatal("presign request changed during wire round trip")
	}
	if _, err := Unmarshal(RefundPresignRequest, append(raw, 0)); err == nil {
		t.Fatal("decoder accepted trailing bytes")
	}
}

func TestPoolRefundPresignResponseTypedRoundTrip(t *testing.T) {
	response := &pool.RefundPresignResponse{
		RefundTemplateTxID:               pool.RefundTemplateTxID(bytes.Repeat([]byte{3}, 32)),
		SellerRefundTransactionSignature: []byte{7, 8},
	}
	raw, err := MarshalRefundPresignResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalRefundPresignResponse(raw)
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
	raw, err := MarshalFundingTransactionDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalFundingTransactionDelivery(raw)
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

func TestArbitrationMessagesTypedRoundTrip(t *testing.T) {
	request, arbiter := wireArbitrationEvidence(t)
	rawRequest, err := MarshalArbitrationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := UnmarshalArbitrationRequest(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedRequest.ArbitrationClaimCBOR, request.ArbitrationClaimCBOR) || !bytes.Equal(decodedRequest.ContentPayloadsCBOR, request.ContentPayloadsCBOR) {
		t.Fatal("007 request evidence changed during wire round trip")
	}
	if len(rawRequest) == 0 || rawRequest[0] != 0x85 || rawRequest[1] != 0x01 || rawRequest[2] != 0x08 {
		t.Fatalf("007 request must be [1,8,...] five-element array: %x", rawRequest)
	}
	prepared, err := arbiter.PreparePayment(context.Background(), request, 900000, 500)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbiter.SignPreparedPayment(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse, err := MarshalArbitrationResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawResponse) == 0 || rawResponse[0] != 0x84 || rawResponse[1] != 0x01 || rawResponse[2] != 0x09 {
		t.Fatalf("007 response must be a four-element [1,9,...] array starting with 0x84: %x", rawResponse)
	}
	decodedResponse, err := UnmarshalArbitrationResponse(rawResponse)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedResponse.ArbitrationReceiptCBOR, response.ArbitrationReceiptCBOR) || !bytes.Equal(decodedResponse.ArbiterArbitrationReceiptSignature, response.ArbiterArbitrationReceiptSignature) {
		t.Fatal("007 response receipt changed during wire round trip")
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
	if _, err := Unmarshal(PaymentUpdate, rawRequest); err == nil {
		t.Fatal("payload was decoded under an unrelated kind")
	}
	if _, err := Unmarshal(ArbitrationResponse, rawRequest); err == nil {
		t.Fatal("Kind 8 body decoded as Kind 9")
	}
	if _, err := Unmarshal(ArbitrationRequest, rawResponse); err == nil {
		t.Fatal("Kind 9 body decoded as Kind 8")
	}
}

func wireArbitrationEvidence(t *testing.T) (*arbitration.ArbitrationRequest, *arbitration.Workflow) {
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
	presign, err := pool.NewBuyerPoolAdapter(engine, buyerKey).BuildRefundPresignRequest(context.Background(), pool.OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: 2000000000, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := pool.NewSellerPoolAdapter(engine, sellerKey).SignSellerRefund(context.Background(), presign)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(context.Background(), presign, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	refundID, err := pool.DeriveRefundTemplateTxID(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	hashes, err := bitfs.EncodeContentHashes([][]byte{digest[:]})
	if err != nil {
		t.Fatal(err)
	}
	signedAuthorization, err := bitfs.NewSignedContentRequest(&bitfs.PaymentAuthorization{FileQuoteTermsID: protocol.FileQuoteTermsID(bytes.Repeat([]byte{1}, 32)), RefundTemplateTxID: refundID[:], PaymentSequence: 3, SellerAmountAfterSatoshis: 100, ContentHashesCBOR: hashes, DeliveryDeadlineUnixSeconds: 2000000100}, buyerKey)
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
	sellerSig, err := protocol.SignWireDocument(sellerKey, protocol.WireVersion, 8, claim)
	if err != nil {
		t.Fatal(err)
	}
	payloadCBOR, err := bitfs.EncodeContentPayloads([][]byte{payload})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: arbiterKey})
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
	hashesCBOR, err := bitfs.EncodeContentHashes([][]byte{bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	requestTerms := &bitfs.PaymentAuthorization{
		FileQuoteTermsID:            protocol.FileQuoteTermsID(bytes.Repeat([]byte{1}, 32)),
		RefundTemplateTxID:          bytes.Repeat([]byte{2}, 32),
		PaymentSequence:             2,
		SellerAmountAfterSatoshis:   10,
		ContentHashesCBOR:           hashesCBOR,
		DeliveryDeadlineUnixSeconds: 2_000_000_000,
	}
	signedRequest, err := bitfs.NewSignedContentRequest(requestTerms, wireTestBuyerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	authID, err := bitfs.PaymentAuthorizationID(signedRequest.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := bitfs.NewSignedContentDelivery(authID, [][]byte{[]byte("payload")}, sellerKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalContentDelivery(raw)
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
	if _, err := Unmarshal(ContentDelivery, append(raw, 0)); err == nil {
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
	retrievalRequest, err := arbitration.NewContentRetrievalRequest(claimID, bytes.Repeat([]byte{0x71}, 32), wireTestBuyerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	rawPacket10, err := Marshal(ContentRetrievalRequest, retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	raw10 := rawPacket10.CBOR
	if len(raw10) == 0 || raw10[0] != 0x84 || raw10[1] != 0x01 || raw10[2] != 0x0a {
		t.Fatalf("Kind 10 must be a four-element [1,10,...] array: %x", raw10)
	}

	requestIDHash := sha256.Sum256(retrievalRequest.ContentRetrievalRequestCBOR)
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(protocol.ContentRetrievalRequestID(requestIDHash), arbitration.RetrievalSellerArbitrationNotReceived, mustArbiterKey())
	if err != nil {
		t.Fatal(err)
	}
	raw11Unavailable, err := Marshal(ContentRetrievalResponse, unavailable)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw11Unavailable.CBOR) == 0 || raw11Unavailable.CBOR[0] != 0x84 || raw11Unavailable.CBOR[1] != 0x01 || raw11Unavailable.CBOR[2] != 0x0b {
		t.Fatalf("unavailable Kind 11 must be a four-element [1,11,...] array: %x", raw11Unavailable.CBOR)
	}
	available, err := arbitration.BuildContentRetrievalAvailable(protocol.ContentRetrievalRequestID(requestIDHash), [][]byte{[]byte("payload")}, mustArbiterKey())
	if err != nil {
		t.Fatal(err)
	}
	raw11Available, err := Marshal(ContentRetrievalResponse, available)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw11Available.CBOR) == 0 || raw11Available.CBOR[0] != 0x85 || raw11Available.CBOR[1] != 0x01 || raw11Available.CBOR[2] != 0x0b {
		t.Fatalf("available Kind 11 must be a five-element [1,11,...] array: %x", raw11Available.CBOR)
	}

	decoded10, err := Unmarshal(ContentRetrievalRequest, raw10)
	if err != nil {
		t.Fatal(err)
	}
	typed10, ok := decoded10.(*arbitration.ContentRetrievalRequest)
	if !ok || !bytes.Equal(typed10.ContentRetrievalRequestCBOR, retrievalRequest.ContentRetrievalRequestCBOR) || !bytes.Equal(typed10.BuyerContentRetrievalRequestSignature, retrievalRequest.BuyerContentRetrievalRequestSignature) {
		t.Fatal("Kind 10 typed round trip changed fields")
	}
	decoded11, err := Unmarshal(ContentRetrievalResponse, raw11Available.CBOR)
	if err != nil {
		t.Fatal(err)
	}
	typed11, ok := decoded11.(*arbitration.ContentRetrievalResponse)
	if !ok || !bytes.Equal(typed11.ContentRetrievalResultCBOR, available.ContentRetrievalResultCBOR) || !bytes.Equal(typed11.ContentPayloadsCBOR, available.ContentPayloadsCBOR) {
		t.Fatal("Kind 11 typed round trip changed fields")
	}

	// 错误 Go 类型必须被拒绝。
	if _, err := Marshal(ContentRetrievalRequest, unavailable); err == nil {
		t.Fatal("wire kind 10 accepted a foreign Go type")
	}
	if _, err := Marshal(ContentRetrievalResponse, retrievalRequest); err == nil {
		t.Fatal("wire kind 11 accepted a foreign Go type")
	}

	// transport Kind 必须与 CBOR 本体第二项一致：贴错一律失败。
	if _, err := Unmarshal(ContentRetrievalResponse, raw10); err == nil {
		t.Fatal("Kind 10 body decoded as Kind 11")
	}
	if _, err := Unmarshal(ContentRetrievalRequest, raw11Available.CBOR); err == nil {
		t.Fatal("Kind 11 body decoded as Kind 10")
	}
	// 8/9/10/11 交叉解码全部拒绝。
	if _, err := Unmarshal(ArbitrationRequest, raw10); err == nil {
		t.Fatal("Kind 10 body decoded as Kind 8")
	}
	if _, err := Unmarshal(ArbitrationResponse, raw10); err == nil {
		t.Fatal("Kind 10 body decoded as Kind 9")
	}
	if _, err := Unmarshal(ArbitrationRequest, raw11Available.CBOR); err == nil {
		t.Fatal("Kind 11 body decoded as Kind 8")
	}
	if _, err := Unmarshal(ArbitrationResponse, raw11Available.CBOR); err == nil {
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
