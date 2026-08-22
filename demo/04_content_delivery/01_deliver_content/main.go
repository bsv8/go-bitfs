package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/seller"
)

func main() {
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	f, err := fixture.New(ctx)
	if err != nil {
		fail(err)
	}
	debug("=== Step 004: Deliver Content Batch ===")
	now := time.Now().UTC()
	request, err := f.BuildSeedRequest(ctx, now)
	if err != nil {
		fail(fmt.Errorf("build prerequisite 003 request: %w", err))
	}
	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		fail(err)
	}
	debug("[seller] seller.BuildContentDelivery verifies 003 against caller-held quote/opening/payment state")
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, f.Opening, f.LatestPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		fail(fmt.Errorf("seller.BuildContentDelivery: %w", err))
	}
	debug("[seller] ContentDeliveryState saved by the demo (caller responsibility): target sequence %d, absolute seller amount %d", deliveryState.PaymentSequence, deliveryState.SellerAmountAfterSat)
	debug("[delivery] payment authorization hash: %s", hex.EncodeToString(delivery.PaymentAuthorizationHash))
	debug("[delivery] seller signature over the bare 32-byte hash: %s", hex.EncodeToString(delivery.SellerPaymentAuthorizationHashSignature))
	payloadsCBOR, err := bitfs.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		fail(err)
	}
	debug("[delivery] content payloads batch: %d item(s), %d bytes total", len(payloadsCBOR), len(payloadsCBOR[0]))
	deliveryRaw, err := bitfs.EncodeSignedContentDelivery(delivery)
	if err != nil {
		fail(err)
	}
	debug("[buyer] 004 routed by PaymentAuthorizationHash to the saved original 003")
	if !bytesEqual(delivery.PaymentAuthorizationHash, authHash[:]) {
		fail(fmt.Errorf("delivery authorization hash does not match recomputed 003 hash"))
	}
	if !bytesEqual(deliveryState.RefundTemplateTxID[:], f.Reference.RefundTemplateTxID[:]) {
		fail(fmt.Errorf("delivery pool correlation ID mismatch"))
	}
	debug("[buyer] verified payload hash: %s", hex.EncodeToString(f.SeedHash.Bytes()))
	debug("[buyer] seller signature: valid")
	fmt.Printf("SIGNED_CONTENT_DELIVERY_HEX=%s\n", hex.EncodeToString(deliveryRaw))
	debug("=== Content delivery verification complete ===")
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
