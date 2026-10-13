// Command seller delivers a content batch (BitFS 004).
//
// fixture 先构造一张 003（买方侧），再由卖方纯函数 API 验证其全链证据并构造、
// 签署 exact Kind 6 Artifact。卖方在生成 004 的同时把交付证据包与 payload
// 保存到应用状态（persist-before-send）。
package main

import (
	"context"
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
	debug("=== Step 004: Deliver Content Batch ===")
	round, err := f.RequestSeed(ctx, now)
	if err != nil {
		fail(fmt.Errorf("build prerequisite 003 request: %w", err))
	}
	debug("[seller] seller.PrepareDelivery verifies 003 against caller-held quote/pool state and signs the delivery")
	if err := f.DeliverRound(ctx, now, round, [][]byte{append([]byte(nil), f.Seed...)}); err != nil {
		fail(err)
	}
	debug("[seller] delivery evidence saved by the demo (caller responsibility): target sequence %d, absolute seller amount %d",
		round.AuthorizationTerms.PaymentSequence, round.AuthorizationTerms.SellerAmountAfterSatoshis)
	debug("[delivery] PaymentAuthorizationID bound by content_delivery_cbor: %s", round.PaymentID.String())
	fmt.Printf("PAYMENT_AUTHORIZATION_ID=%s\n", round.PaymentID.String())
	fmt.Printf("SIGNED_CONTENT_DELIVERY_HEX=%x\n", round.Kind6Raw)
	debug("=== Content delivery complete ===")
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
