package bitfs

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestHashDeliveryCBORVector fixes the cross-language V1 wire vector.
func TestHashDeliveryCBORVector(t *testing.T) {
	hash := make([]byte, 32)
	for index := range hash {
		hash[index] = byte(index)
	}
	message := &HashDelivery{SessionID: "s", Sequence: 7, ContentHash: hash, Payload: []byte{1, 2, 3}}
	want, err := hex.DecodeString("8601036173075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f43010203")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeMessage(message)
	if err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded = %x, want %x", encoded, want)
	}
	id, err := PacketID(message)
	if err != nil {
		t.Fatalf("PacketID() error = %v", err)
	}
	if got := hex.EncodeToString(id[:]); got != "7613600cd1068d3762bb09c332daa856dff9c91fdb5b88a29d0e9ca09fae030f" {
		t.Fatalf("packet id = %s", got)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage() error = %v", err)
	}
	got, ok := decoded.(*HashDelivery)
	if !ok || got.SessionID != message.SessionID || got.Sequence != message.Sequence || !bytes.Equal(got.ContentHash, message.ContentHash) || !bytes.Equal(got.Payload, message.Payload) {
		t.Fatalf("decoded = %#v, want %#v", decoded, message)
	}
}

func TestDecodeMessageRejectsNonDeterministicEncoding(t *testing.T) {
	// 0x98 0x06 is a legal but non-preferred encoding of an array of six items.
	data, err := hex.DecodeString("980601036173075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f43010203")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMessage(data); err == nil {
		t.Fatal("DecodeMessage() accepted non-deterministic CBOR")
	}
}

func TestEveryV1MessageHasCanonicalCBORRoundTrip(t *testing.T) {
	hash := bytes.Repeat([]byte{0x11}, 32)
	ticket := &HashGetTicket{SessionID: "s", Sequence: 1, RootSeedHash: hash, ContentHash: hash, ContentIndex: SeedContentIndex, ExpectedSize: 32, PriceSat: 1, BuyerPubkey: []byte{2}, SellerPubkey: []byte{3}, ExpiresAtUnix: 100, BuyerSignature: []byte{4}}
	claim := &ArbitrationClaim{Ticket: ticket, Payload: []byte("seed"), ClaimantRole: ArbitrationClaimantRoleSeller}
	decision := &ArbitrationDecision{SessionID: "s", Sequence: 1, TicketID: hash, Approved: true, ReasonCode: "payload_verified", FinalPayoutSat: 1, SellerPubkey: []byte{3}}
	messages := []any{
		&FileQuote{SeedHash: hash, RecommendedFilename: "f", QuoteExpiresAtUnix: 100, SellerPubkey: []byte{3}},
		ticket,
		&HashDelivery{SessionID: "s", Sequence: 1, ContentHash: hash, Payload: []byte("seed")},
		claim,
		decision,
		&ArbitrationRecord{SessionID: "s", Sequence: 1, State: ArbitrationStateClosed, Claim: claim, Decision: decision, CreatedAtUnix: 1, UpdatedAtUnix: 1},
	}
	for _, message := range messages {
		encoded, err := EncodeMessage(message)
		if err != nil {
			t.Fatalf("EncodeMessage(%T) error = %v", message, err)
		}
		if _, err := DecodeMessage(encoded); err != nil {
			t.Fatalf("DecodeMessage(%T) error = %v", message, err)
		}
	}
}
