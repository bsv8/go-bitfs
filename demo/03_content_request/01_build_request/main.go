package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

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
	debug("[state] quote terms hash: %s", hex.EncodeToString(f.QuoteHash[:]))
	debug("[state] SpendTxID: %s", hex.EncodeToString(f.Reference.SpendTxID[:]))
	debug("[state] base payment sequence: %d", f.Reference.BasePaymentSequence)

	request, err := f.BuildSeedRequest(ctx)
	if err != nil {
		fail(fmt.Errorf("buyer.RequestContent: %w", err))
	}
	terms, err := bitfs.DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		fail(err)
	}
	raw, err := bitfs.EncodeSignedContentRequest(request)
	if err != nil {
		fail(err)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		fail(err)
	}
	debug("[request] ContentType: %d (0 = seed, 1 = block)", terms.ContentType)
	debug("[request] ContentHash: %s", hex.EncodeToString(terms.ContentHash))
	debug("[request] base sequence: %d", terms.BasePaymentSequence)
	debug("[request] next sequence: %d", terms.PaymentSequenceAfter)
	debug("[request] seller amount after: %d satoshis", terms.SellerAmountAfterSat)
	debug("[request] delivery deadline: %d", terms.DeliveryDeadlineUnix)
	debug("[request] buyer signature: %s", hex.EncodeToString(request.BuyerSignature))
	debug("[request] PaymentAuthorizationHash: %s", hex.EncodeToString(authHash[:]))
	fmt.Printf("SIGNED_CONTENT_REQUEST_HEX=%s\n", hex.EncodeToString(raw))
	debug("=== Content request build complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
