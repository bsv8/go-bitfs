package wire

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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
	request := &arbitration.ArbitrationRequest{
		Version:                    arbitration.MajorVersion,
		RefundTemplateTxID:         pool.RefundTemplateTxID(bytes.Repeat([]byte{6}, 32)),
		PoolOpeningProofCBOR:       []byte{1},
		PaymentAuthorizationCBOR:   []byte{2},
		UnsignedStateTxRaw:         []byte{3},
		SellerTransactionSignature: []byte{4},
	}
	rawRequest, err := MarshalArbitrationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := UnmarshalArbitrationRequest(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	if decodedRequest.RefundTemplateTxID != request.RefundTemplateTxID {
		t.Fatal("007 request correlation ID changed during wire round trip")
	}
	if len(rawRequest) == 0 || rawRequest[0] != 0x86 {
		t.Fatalf("007 request must be a six-element array: %x", rawRequest)
	}
	response := &arbitration.ArbitrationResponse{
		Version:                     arbitration.MajorVersion,
		RefundTemplateTxID:          request.RefundTemplateTxID,
		PaymentAuthorizationHash:    bytes.Repeat([]byte{1}, 32),
		UnsignedStateTxHash:         bytes.Repeat([]byte{2}, 32),
		ArbiterTransactionSignature: []byte{5},
	}
	rawResponse, err := MarshalArbitrationResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := UnmarshalArbitrationResponse(rawResponse)
	if err != nil {
		t.Fatal(err)
	}
	if decodedResponse.RefundTemplateTxID != response.RefundTemplateTxID {
		t.Fatal("007 response correlation ID changed during wire round trip")
	}
	if len(rawResponse) == 0 || rawResponse[0] != 0x85 {
		t.Fatalf("007 response must be a five-element array: %x", rawResponse)
	}
	// Kind never carries instance identity: decoding a payload under a
	// different kind must fail rather than silently reinterpreting it.
	if _, err := Unmarshal(CumulativePayment, rawRequest); err == nil {
		t.Fatal("payload was decoded under an unrelated kind")
	}
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
