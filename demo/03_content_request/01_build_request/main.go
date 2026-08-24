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
	debug("=== Step 003: Build Content Request ===")
	debug("[state] FileQuoteTermsID: %s", hex.EncodeToString(f.FileQuoteTermsID[:]))
	debug("[state] RefundTemplateTxID: %s", hex.EncodeToString(f.Reference.RefundTemplateTxID[:]))
	debug("[state] current accepted payment sequence: %d", f.Reference.PaymentSequence)

	now := time.Now().UTC()
	request, err := f.BuildSeedRequest(ctx, now)
	if err != nil {
		fail(fmt.Errorf("buyer.BuildContentRequest: %w", err))
	}
	terms, err := bitfs.DecodePaymentAuthorization(request.PaymentAuthorizationCBOR)
	if err != nil {
		fail(err)
	}
	raw, err := bitfs.EncodeSignedContentRequest(request)
	if err != nil {
		fail(err)
	}
	paymentAuthorizationID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		fail(err)
	}
	contentHashes, err := bitfs.DecodeContentHashes(terms.ContentHashesCBOR)
	if err != nil {
		fail(err)
	}
	debug("[request] content hashes batch: %d item(s)", len(contentHashes))
	for index, hash := range contentHashes {
		debug("[request] content hash #%d: %s", index+1, hex.EncodeToString(hash))
	}
	debug("[request] target payment sequence: %d (current + 1)", terms.PaymentSequence)
	debug("[request] seller amount after: %d satoshis (absolute cumulative)", terms.SellerAmountAfterSatoshis)
	debug("[request] delivery deadline: %d", terms.DeliveryDeadlineUnixSeconds)
	debug("[request] buyer signature: %s", hex.EncodeToString(request.BuyerPaymentAuthorizationSignature))
	debug("[request] PaymentAuthorizationID: %s", hex.EncodeToString(paymentAuthorizationID[:]))
	fmt.Printf("SIGNED_CONTENT_REQUEST_HEX=%s\n", hex.EncodeToString(raw))
	debug("=== Content request build complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
