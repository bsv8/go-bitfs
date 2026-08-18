package main

import (
	"context"
	"encoding/hex"
	"flag"
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
	requestFile := flag.String("request-file", os.Getenv("DEMO_02_REQUEST_FILE"), "0201 output file containing REFUND_PRESIGN_REQUEST_HEX")
	flag.Parse()
	if *requestFile == "" {
		fail(fmt.Errorf("--request-file or DEMO_02_REQUEST_FILE is required"))
	}
	ctx := context.Background()
	session, err := poolopening.NewBuyer(ctx)
	if err != nil {
		fail(err)
	}
	addresses, err := session.FundingAddresses()
	if err != nil {
		fail(fmt.Errorf("derive buyer funding addresses: %w", err))
	}
	debug("=== 0203 买方：接受并检验 RefundPresignResponse ===")
	debug("[buyer] selected network: %s", addresses.Network)
	debug("[buyer] funding address: %s", addresses.SelectedAddress)
	requestRaw, err := poolopening.ReadHexFile(*requestFile, "REFUND_PRESIGN_REQUEST_HEX")
	if err != nil {
		fail(err)
	}
	request, err := wire.UnmarshalPoolRefundPresignRequest(requestRaw)
	if err != nil {
		fail(fmt.Errorf("decode original RefundPresignRequest: %w", err))
	}
	responseRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_PRESIGN_RESPONSE_HEX")
	if err != nil {
		fail(err)
	}
	response, err := wire.UnmarshalPoolRefundPresignResponse(responseRaw)
	if err != nil {
		fail(fmt.Errorf("decode RefundPresignResponse: %w", err))
	}
	fundingTx, err := poolopening.LoadFundingTx()
	if err != nil {
		fail(fmt.Errorf("load buyer-local funding transaction from 0201: %w", err))
	}

	debug("[transport] buyer <- seller: PoolRefundPresignResponse (%d bytes)", len(responseRaw))
	debug("[buyer] 检验卖方退款签名，并把完整 opening proof 持久化")
	debug("[buyer] 使用 0201 本地保存的真实 FundingTx；它没有通过 seller-facing 报文泄露")
	reference, err := session.Buyer.AcceptRefundPresign(ctx, request, response, fundingTx)
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptRefundPresign: %w", err))
	}
	proof, err := session.Store.LoadOpeningProof(ctx, reference.SpendTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer opening proof: %w", err))
	}
	if proof == nil {
		fail(fmt.Errorf("buyer opening proof was not persisted"))
	}
	proofRaw, err := pool.EncodeOpeningProof(proof)
	if err != nil {
		fail(fmt.Errorf("encode buyer local opening proof: %w", err))
	}
	initial, err := session.Store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer initial payment state: %w", err))
	}
	debug("[buyer] seller refund signature: valid")
	debug("[buyer] opening proof: persisted")
	debug("[buyer] initial payment sequence: %d", initial.PaymentSequence)
	debug("[local state] FundingTx 现在才允许交付给卖方")
	if err := poolopening.WriteHex(os.Stdout, "BUYER_OPENING_PROOF_HEX", proofRaw); err != nil {
		fail(err)
	}
	fmt.Printf("SPEND_TX_ID_HEX=%s\n", hex.EncodeToString(reference.SpendTxID[:]))
	fmt.Printf("BASE_PAYMENT_SEQUENCE=%d\n", reference.BasePaymentSequence)
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
