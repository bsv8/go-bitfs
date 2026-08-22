package main

import (
	"bytes"
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
	debug("=== Step 004: Deliver Content ===")
	now := time.Now().UTC()
	request, err := f.BuildSeedRequest(ctx, now)
	if err != nil {
		fail(fmt.Errorf("build prerequisite 003 request: %w", err))
	}
	debug("[seller] seller.BuildContentDelivery verifies 003 against caller-held quote/opening/payment state")
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, f.Opening, f.LatestPayment, request, seller.ContentDeliveryInput{Content: append([]byte(nil), f.Seed...)})
	if err != nil {
		fail(fmt.Errorf("seller.BuildContentDelivery: %w", err))
	}
	debug("[seller] ContentDeliveryState saved by the demo (caller responsibility): base sequence %d, expected increment %d", deliveryState.BasePaymentSequence, deliveryState.ExpectedSellerAmountSat)
	debug("[delivery] seller signature: %s", hex.EncodeToString(delivery.SellerSignature))
	debug("[delivery] terms CBOR: %s", hex.EncodeToString(delivery.TermsCBOR))
	debug("[buyer] bitfs.VerifySignedContentDeliveryAt verifies 004 without creating 005")
	payload, err := bitfs.VerifySignedContentDelivery(request, delivery, f.Quote)
	if err != nil {
		fail(fmt.Errorf("verify 004 delivery: %w", err))
	}
	deliveryRaw, err := bitfs.EncodeSignedContentDelivery(delivery)
	if err != nil {
		fail(err)
	}
	debug("[buyer] verified payload bytes: %d", len(payload))
	terms, err := bitfs.DecodeContentDeliveryTerms(delivery.TermsCBOR)
	if err != nil {
		fail(err)
	}
	debug("[buyer] delivery refund tx hash: %s", hex.EncodeToString(terms.RefundTemplateTxID))
	debug("[buyer] fixture pool correlation ID matches: %t", bytes.Equal(terms.RefundTemplateTxID, f.Reference.RefundTemplateTxID[:]))
	debug("[buyer] verified payload hash: %s", hex.EncodeToString(f.SeedHash.Bytes()))
	debug("[buyer] seller signature: valid")
	fmt.Printf("SIGNED_CONTENT_DELIVERY_HEX=%s\n", hex.EncodeToString(deliveryRaw))
	debug("=== Content delivery verification complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
