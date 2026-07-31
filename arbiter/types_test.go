package arbiter

import (
	"bytes"
	"testing"
)

func TestV2ArbitrationRequestRoundTrip(t *testing.T) {
	request := &ArbitrationRequest{
		Version: MajorVersion,
		PoolOpeningProofCBOR: []byte{1, 2},
		PaymentAuthorizationCBOR: []byte{3, 4},
		UnsignedStateTxRaw: []byte{5, 6},
		SellerTransactionSignature: []byte{7, 8},
	}
	raw, err := MarshalRequest(request)
	if err != nil { t.Fatal(err) }
	decoded, err := UnmarshalRequest(raw)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(decoded.PaymentAuthorizationCBOR, request.PaymentAuthorizationCBOR) || !bytes.Equal(decoded.UnsignedStateTxRaw, request.UnsignedStateTxRaw) { t.Fatalf("decoded request = %#v", decoded) }
	if _, err := UnmarshalRequest(append(raw, 0)); err == nil { t.Fatal("request decoder accepted trailing bytes") }
}

func TestV2ArbitrationResponseBindsTwoHashes(t *testing.T) {
	response := &ArbitrationResponse{Version: MajorVersion, PaymentAuthorizationHash: bytes.Repeat([]byte{1}, 32), UnsignedStateTxHash: bytes.Repeat([]byte{2}, 32), ArbiterTransactionSignature: []byte{3}}
	raw, err := MarshalResponse(response)
	if err != nil { t.Fatal(err) }
	decoded, err := UnmarshalResponse(raw)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(decoded.UnsignedStateTxHash, response.UnsignedStateTxHash) { t.Fatal("response hash changed") }
}
