package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/poolopening"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/wire"
)

func main() {
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	session, err := poolopening.NewSeller(ctx)
	if err != nil {
		fail(err)
	}
	deliveryRaw, err := poolopening.ReadHex(os.Stdin, "FUNDING_TX_DELIVERY_HEX")
	if err != nil {
		fail(err)
	}
	delivery, err := wire.UnmarshalPoolFundingTxDelivery(deliveryRaw)
	if err != nil {
		fail(fmt.Errorf("decode FundingTxDelivery: %w", err))
	}

	debug("=== 0205 卖方：接受、检验 FundingTxDelivery 并提交资金 ===")
	debug("[transport] seller <- buyer: PoolFundingTxDelivery (%d bytes)", len(deliveryRaw))
	debug("[seller] 根据 0202 保存的 opening proof 检验 FundingTx 与退款证据一致")
	opening, err := session.Seller.AcceptPoolFunding(ctx, delivery)
	if err != nil {
		fail(fmt.Errorf("seller.AcceptPoolFunding: %w", err))
	}
	openingRaw, err := pool.EncodeOpeningProof(opening)
	if err != nil {
		fail(fmt.Errorf("encode seller completed opening proof: %w", err))
	}
	debug("[seller] FundingTx 已通过验证并提交给 demo backend")
	debug("[seller] funding submissions accepted: %d", session.Backend.Fundings)
	debug("[state] pool opened: true")
	fmt.Printf("POOL_OPENED=true\n")
	fmt.Printf("FUNDING_TX_ID_HEX=%s\n", hex.EncodeToString(opening.FundingTxID))
	fmt.Printf("SPEND_TX_ID_HEX=%s\n", hex.EncodeToString(opening.SpendTxID))
	var spendTxID pool.Hash32
	copy(spendTxID[:], opening.SpendTxID)
	initial, err := session.Store.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		fail(fmt.Errorf("load seller initial payment state: %w", err))
	}
	if initial == nil {
		fail(fmt.Errorf("seller initial payment state was not persisted"))
	}
	fmt.Printf("INITIAL_PAYMENT_SEQUENCE=%d\n", initial.PaymentSequence)
	if err := poolopening.WriteHex(os.Stdout, "SELLER_OPENING_PROOF_HEX", openingRaw); err != nil {
		fail(err)
	}
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
