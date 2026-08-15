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
	request, err := f.BuildSeedRequest(ctx)
	if err != nil {
		fail(fmt.Errorf("build prerequisite 003 request: %w", err))
	}
	debug("[seller] seller.DeliverRequestedContent verifies 003 before loading content")
	delivery, err := f.Seller.DeliverRequestedContent(ctx, request)
	if err != nil {
		fail(fmt.Errorf("seller.DeliverRequestedContent: %w", err))
	}
	debug("[delivery] seller signature: %s", hex.EncodeToString(delivery.SellerSignature))
	debug("[delivery] terms CBOR: %s", hex.EncodeToString(delivery.TermsCBOR))
	debug("[buyer] bitfs.VerifySignedContentDeliveryAt verifies 004 without creating 005")
	payload, err := bitfs.VerifySignedContentDeliveryAt(request, delivery, f.Quote, time.Now().UTC(), bitfs.VerifySignature, bitfs.VerifySignature, bitfs.VerifySignature)
	if err != nil {
		fail(fmt.Errorf("verify 004 delivery: %w", err))
	}
	deliveryRaw, err := bitfs.EncodeSignedContentDelivery(delivery)
	if err != nil {
		fail(err)
	}
	debug("[buyer] verified payload bytes: %d", len(payload))
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
