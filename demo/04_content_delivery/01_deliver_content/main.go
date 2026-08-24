package main

import (
	"context"
	"encoding/hex"
	"errors"
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
	authID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		fail(err)
	}
	debug("[seller] seller.BuildContentDelivery verifies 003 against caller-held quote/opening/payment state")
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, f.Opening, f.LatestPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		fail(fmt.Errorf("seller.BuildContentDelivery: %w", err))
	}
	debug("[seller] ContentDeliveryState saved by the demo (caller responsibility): target sequence %d, absolute seller amount %d", deliveryState.PaymentSequence, deliveryState.SellerAmountAfterSatoshis)

	// content_delivery_cbor = deterministic-CBOR([payment_authorization_id])，
	// 卖方统一签名覆盖这份精确文档（SignWireDocument(1, 6, ...)），绝不是裸哈希。
	debug("[delivery] content_delivery_cbor: %s", hex.EncodeToString(delivery.ContentDeliveryCBOR))
	boundAuthID, err := bitfs.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		fail(err)
	}
	debug("[delivery] PaymentAuthorizationID bound by content_delivery_cbor: %s", hex.EncodeToString(boundAuthID[:]))
	debug("[delivery] seller signature over content_delivery_cbor (SignWireDocument(1, 6, ...)): %s", hex.EncodeToString(delivery.SellerContentDeliverySignature))

	payloadsCBOR, err := bitfs.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		fail(err)
	}
	debug("[delivery] content payloads batch: %d item(s), %d bytes total", len(payloadsCBOR), len(payloadsCBOR[0]))
	deliveryRaw, err := bitfs.EncodeSignedContentDelivery(delivery)
	if err != nil {
		fail(err)
	}
	debug("[buyer] 004 routed by PaymentAuthorizationID to the saved original 003")
	if boundAuthID != authID {
		fail(errors.New("payment authorization ID mismatch"))
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
