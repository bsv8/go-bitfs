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
	"github.com/bsv8/go-bitfs/bitfs"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/pool"
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
		Version:              pool.MajorVersion,
		RefundTx:             []byte{1, 2, 3},
		BuyerPubKey:          wireTestBuyerPubkey(),
		SellerPubKey:         wireTestSellerPubkey(),
		ArbiterPubKey:        wireTestArbiterPubkey(),
		MinerFeeRateSatPerKB: 1,
		BuyerRefundSignature: []byte{9},
	}
	raw, err := MarshalPoolRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPoolRefundPresignRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.RefundTx, request.RefundTx) || decoded.MinerFeeRateSatPerKB != request.MinerFeeRateSatPerKB {
		t.Fatal("presign request changed during wire round trip")
	}
	if _, err := Unmarshal(PoolRefundPresignRequest, append(raw, 0)); err == nil {
		t.Fatal("decoder accepted trailing bytes")
	}
}

func TestPoolRefundPresignResponseTypedRoundTrip(t *testing.T) {
	response := &pool.RefundPresignResponse{
		Version:               pool.MajorVersion,
		RefundTemplateTxID:    pool.RefundTemplateTxID(bytes.Repeat([]byte{3}, 32)),
		SellerRefundSignature: []byte{7, 8},
	}
	raw, err := MarshalPoolRefundPresignResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPoolRefundPresignResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RefundTemplateTxID != response.RefundTemplateTxID || !bytes.Equal(decoded.SellerRefundSignature, response.SellerRefundSignature) {
		t.Fatal("presign response changed during wire round trip")
	}
	if len(raw) == 0 || raw[0] != 0x84 {
		t.Fatalf("002 presign response must be a four-element array: %x", raw)
	}
}

func TestFundingTxDeliveryTypedRoundTrip(t *testing.T) {
	delivery := &pool.FundingTxDelivery{
		Version:            pool.MajorVersion,
		RefundTemplateTxID: pool.RefundTemplateTxID(bytes.Repeat([]byte{4}, 32)),
		FundingTx:          []byte{5, 6, 7},
	}
	raw, err := MarshalPoolFundingTxDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalPoolFundingTxDelivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RefundTemplateTxID != delivery.RefundTemplateTxID || !bytes.Equal(decoded.FundingTx, delivery.FundingTx) {
		t.Fatal("funding delivery changed during wire round trip")
	}
	if len(raw) == 0 || raw[0] != 0x84 {
		t.Fatalf("002 funding delivery must be a four-element array: %x", raw)
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
	if !bytes.Equal(decodedRequest.ClaimCBOR, request.ClaimCBOR) || !bytes.Equal(decodedRequest.ContentPayloadsCBOR, request.ContentPayloadsCBOR) {
		t.Fatal("007 request evidence changed during wire round trip")
	}
	if len(rawRequest) == 0 || rawRequest[0] != 0x85 || rawRequest[1] != 0x04 {
		t.Fatalf("007 request must be [4,8,...] five-element array: %x", rawRequest)
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
	if len(rawResponse) == 0 || rawResponse[0] != 0x84 || rawResponse[1] != 0x04 || rawResponse[2] != 0x09 {
		t.Fatalf("007 response must be a four-element [4,9,...] array starting with 0x84: %x", rawResponse)
	}
	decodedResponse, err := UnmarshalArbitrationResponse(rawResponse)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedResponse.ReceiptCBOR, response.ReceiptCBOR) || !bytes.Equal(decodedResponse.ArbiterReceiptSignature, response.ArbiterReceiptSignature) {
		t.Fatal("007 response receipt changed during wire round trip")
	}
	receipt, err := arbitration.UnmarshalReceipt(decodedResponse.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbiterAmountSat != 500 || len(receipt.ClaimID) != sha256.Size || len(receipt.ArbiterTransactionSignature) == 0 {
		t.Fatalf("decoded receipt is incomplete or mispriced: %+v", receipt)
	}
	// 旧五元 Kind 9 必须被 strict decoder 拒绝，不存在兼容解码。
	legacyReceiptCBOR, err := arbitration.MarshalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	legacyFiveElement, err := canonicalGoldenMarshal([]any{
		uint64(4), uint64(9), goldenBstr(legacyReceiptCBOR),
		goldenBstr(bytes.Repeat([]byte{7}, 70)), goldenBstr(bytes.Repeat([]byte{8}, 70)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalArbitrationResponse(legacyFiveElement); err == nil {
		t.Fatal("legacy five-element Kind 9 was accepted")
	}
	// Kind never carries instance identity: decoding a payload under a
	// different kind must fail rather than silently reinterpreting it.
	if _, err := Unmarshal(CumulativePayment, rawRequest); err == nil {
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
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
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
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	presign, err := pool.NewBuyerPoolAdapter(engine, buyerKey).BuildRefundPresignRequest(context.Background(), pool.OpeningInput{FundingTx: funding.Bytes(), ExpiryLockTime: 2000000000, MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
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
	authorization, err := bitfs.NewSignedContentRequest(&bitfs.ContentRequestTerms{QuoteTermsHash: bytes.Repeat([]byte{1}, 32), RefundTemplateTxID: refundID[:], PaymentSequence: 3, SellerAmountAfterSat: 100, ContentHashesCBOR: hashes, DeliveryDeadlineUnix: 2000000100}, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	details, err := pool.DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := arbitration.MarshalClaim(&arbitration.ArbitrationClaim{PoolOutputSatoshis: details.PoolOutputSatoshis, PoolOutputLockingScript: details.PoolLockingScript, RefundTemplateRaw: proof.RefundTx, TermsCBOR: authorization.TermsCBOR, BuyerSignature: authorization.BuyerSignature})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := arbitration.SellerClaimSigningCBOR(claim)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := bitfs.SignMessage(sellerKey, domain)
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
	return &arbitration.ArbitrationRequest{Version: arbitration.MajorVersion, ClaimCBOR: claim, SellerClaimSignature: sellerSig, ContentPayloadsCBOR: payloadCBOR}, workflow
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
	requestTerms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:       bytes.Repeat([]byte{1}, 32),
		RefundTemplateTxID:   bytes.Repeat([]byte{2}, 32),
		PaymentSequence:      2,
		SellerAmountAfterSat: 10,
		ContentHashesCBOR:    hashesCBOR,
		DeliveryDeadlineUnix: 2_000_000_000,
	}
	signedRequest, err := bitfs.NewSignedContentRequest(requestTerms, wireTestBuyerKey(t))
	if err != nil {
		t.Fatal(err)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(signedRequest.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := bitfs.NewSignedContentDelivery(authHash[:], [][]byte{[]byte("payload")}, sellerKey)
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
	if !bytes.Equal(decoded.PaymentAuthorizationHash, delivery.PaymentAuthorizationHash) || !bytes.Equal(decoded.SellerPaymentAuthorizationHashSignature, delivery.SellerPaymentAuthorizationHashSignature) || !bytes.Equal(decoded.ContentPayloadsCBOR, delivery.ContentPayloadsCBOR) {
		t.Fatal("content delivery changed during wire round trip")
	}
	// The 004 shell must be a four-element array led by version 4 and must
	// not repeat the pool correlation ID.
	if len(raw) == 0 || raw[0] != 0x84 {
		t.Fatalf("004 must be a four-element array: %x", raw)
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
