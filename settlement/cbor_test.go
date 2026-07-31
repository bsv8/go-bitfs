//go:build legacy

package settlement

import (
	"bytes"
	"testing"
)

func TestPaymentPrepareCBORRoundTrip(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 32)
	message := NewPaymentPrepare(TicketRef{SpendTxID: id, Sequence: 7, ContentHash: id, PriceSat: 5, TicketID: id})
	encoded, err := EncodeMessage(message)
	if err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage() error = %v", err)
	}
	got, ok := decoded.(*PaymentPrepare)
	if !ok || got.Ticket.Sequence != 7 || !bytes.Equal(got.Ticket.TicketID, id) {
		t.Fatalf("decoded = %#v", decoded)
	}
}
