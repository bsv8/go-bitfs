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
	session, err := poolopening.NewBuyer(ctx)
	if err != nil {
		fail(err)
	}

	addresses, err := session.FundingAddresses()
	if err != nil {
		fail(fmt.Errorf("derive buyer funding addresses: %w", err))
	}
	debug("=== 0201 买方：接受开池条件并发送 RefundPresignRequest ===")
	debug("[buyer] selected network: %s", addresses.Network)
	debug("[buyer] funding address: %s", addresses.SelectedAddress)
	funding, err := session.PrepareFunding(ctx)
	if err != nil {
		fail(fmt.Errorf("prepare real funding transaction: %w", err))
	}
	historyEndpoint, err := funding.Client.AddressHistoryEndpoint(funding.Network, funding.SelectedAddress)
	if err != nil {
		fail(err)
	}
	transactionEndpoint, err := funding.Client.TransactionEndpoint(funding.Network, funding.SelectedUTXO.TxHash)
	if err != nil {
		fail(err)
	}
	debug("[junglebus] address history endpoint: %s", historyEndpoint)
	debug("[junglebus] selected transaction endpoint: %s", transactionEndpoint)
	debug("[junglebus] reconstructed confirmed UTXOs: %d", len(funding.UTXOs))
	for index, utxo := range funding.UTXOs {
		if index == 20 {
			debug("[junglebus] ... remaining UTXOs omitted from trace")
			break
		}
		debug("[junglebus] utxo[%d] txid=%s vout=%d satoshis=%d status=%s height=%d spent_in_mempool=%t", index, utxo.TxHash, utxo.Vout, utxo.Satoshis, utxo.Status, utxo.Height, utxo.IsSpentInMempoolTx)
	}
	selected := funding.SelectedUTXO
	debug("[junglebus] selected UTXO: txid=%s vout=%d satoshis=%d status=%s", selected.TxHash, selected.Vout, selected.Satoshis, selected.Status)
	if funding.MinerFeeRateSource != "environment override" {
		debug("[config] JungleBus does not provide fee recommendations; using demo default")
	} else {
		debug("[config] miner fee rate override: DEMO_02_MINER_FEE_RATE_SAT_PER_KB")
	}
	debug("[funding] miner fee rate: %d sat/KB (%s)", funding.MinerFeeRateSatPerKB, funding.MinerFeeRateSource)
	debug("[funding] actual miner fee: %d satoshis; raw size: %d bytes", funding.FundingFeeSatoshis, len(funding.RawTx))
	if err := poolopening.SaveFundingTx(funding.RawTx); err != nil {
		fail(err)
	}
	fundingTransaction, err := pool.ParseCanonicalTransaction(funding.RawTx)
	if err != nil {
		fail(fmt.Errorf("parse prepared funding transaction: %w", err))
	}
	debug("[funding] real funding txid: %s", fundingTransaction.TxID().String())
	debug("[funding] raw tx hex: %s", hex.EncodeToString(funding.RawTx))
	debug("[funding] buyer-local file: %s", poolopening.FundingTxPath())
	debug("[buyer] 构造并签名退款交易预签名请求")
	request, err := session.Buyer.PreparePoolOpening(ctx, session.OpeningInput(funding.RawTx, funding.MinerFeeRateSatPerKB))
	if err != nil {
		fail(fmt.Errorf("buyer.PreparePoolOpening: %w", err))
	}
	raw, err := wire.MarshalPoolRefundPresignRequest(request)
	if err != nil {
		fail(fmt.Errorf("encode RefundPresignRequest: %w", err))
	}
	debug("[buyer] RefundTx bytes: %d", len(request.RefundTx))
	debug("[buyer] FundingTxID: %s", hex.EncodeToString(request.FundingTxID))
	debug("[buyer] FundingTx 原文尚未进入报文：yes")
	debug("[transport] buyer -> seller: PoolRefundPresignRequest (%d bytes)", len(raw))
	if err := poolopening.WriteHex(os.Stdout, "REFUND_PRESIGN_REQUEST_HEX", raw); err != nil {
		fail(err)
	}
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
