// Command buyer builds a signed BitFS 003 content request.
//
// 报价、开池证据和最新付款状态都由 fixture（调用方应用）显式持有；买方角色
// API 校验报价/池/批次上下文/聚合价格/余额后签署授权，返回待发送的 exact
// Kind 5 Artifact 与必须先持久化的 AuthorizationCheckpoint。
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

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
	now := time.Now().UTC()
	debug("=== Step 003: Build Content Request ===")
	poolID := f.BuyerPool.RefundTemplateTxID()
	debug("[state] FileQuoteTermsID: %s", f.VerifiedQuote.ID().String())
	debug("[state] RefundTemplateTxID: %s", hex.EncodeToString(poolID[:]))
	debug("[state] current accepted payment sequence: %d", f.BuyerPool.Payment().PaymentSequence)

	round, err := f.RequestSeed(ctx, now)
	if err != nil {
		fail(fmt.Errorf("build seed request: %w", err))
	}
	debug("[request] PaymentAuthorizationID: %s (pa_ typed id)", round.PaymentID.String())
	fmt.Printf("PAYMENT_AUTHORIZATION_ID=%s\n", round.PaymentID.String())
	fmt.Printf("SIGNED_CONTENT_REQUEST_HEX=%s\n", fmt.Sprintf("%x", round.Kind5Raw))
	debug("=== Content request build complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
