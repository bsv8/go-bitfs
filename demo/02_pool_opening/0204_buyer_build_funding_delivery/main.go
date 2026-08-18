package main

import (
	"bytes"
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
	debug("=== 0204 买方：构造并发送 FundingTxDelivery ===")
	debug("[buyer] selected network: %s", addresses.Network)
	debug("[buyer] funding address: %s", addresses.SelectedAddress)
	proofRaw, err := poolopening.ReadHex(os.Stdin, "BUYER_OPENING_PROOF_HEX")
	if err != nil {
		fail(err)
	}
	proof, err := pool.DecodeOpeningProof(proofRaw)
	if err != nil {
		fail(fmt.Errorf("decode buyer local opening proof: %w", err))
	}
	spendTxID, err := pool.SpendTxID(ctx, proof)
	if err != nil {
		fail(fmt.Errorf("calculate SpendTxID: %w", err))
	}
	stored, err := session.Store.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		fail(fmt.Errorf("load persisted buyer opening proof: %w", err))
	}
	if stored == nil {
		fail(fmt.Errorf("buyer opening proof is not persisted; run 0203 first"))
	}
	storedRaw, err := pool.EncodeOpeningProof(stored)
	if err != nil {
		fail(fmt.Errorf("encode persisted buyer opening proof: %w", err))
	}
	if !bytes.Equal(storedRaw, proofRaw) {
		fail(fmt.Errorf("local proof does not match buyer's persisted proof"))
	}

	debug("[buyer] 已确认 0203 的 opening proof 在本地持久化")
	delivery, err := session.Buyer.BuildFundingTxDelivery(proof.FundingTx)
	if err != nil {
		fail(fmt.Errorf("buyer.BuildFundingTxDelivery: %w", err))
	}
	deliveryRaw, err := wire.MarshalPoolFundingTxDelivery(delivery)
	if err != nil {
		fail(fmt.Errorf("encode FundingTxDelivery: %w", err))
	}
	debug("[buyer] FundingTx bytes: %d", len(delivery.FundingTx))
	debug("[buyer] FundingTxID: %s", hex.EncodeToString(proof.FundingTxID))
	debug("[transport] buyer -> seller: PoolFundingTxDelivery (%d bytes)", len(deliveryRaw))
	if err := poolopening.WriteHex(os.Stdout, "FUNDING_TX_DELIVERY_HEX", deliveryRaw); err != nil {
		fail(err)
	}
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
