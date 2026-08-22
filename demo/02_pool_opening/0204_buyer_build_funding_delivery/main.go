// 0204 是开池流程中公开完整 FundingTx 的买方动作。
//
// 本命令从 stdin 读取 0203 输出的 REFUND_TEMPLATE_TXID_HEX，按该关联 ID 从买方
// 自己的 checkpoint 加载已验证的 OpeningProof，显式传给 SDK 构造
// FundingTxDelivery。调用方不能伪造 delivery 字段；SDK 会复核 proof 与 hash。
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
	// 读取环境配置并组装买方会话。0204 与 0203 是两个独立进程，因此只信任
	// checkpoint 中已经保存的证据，而不是进程间传递的报文。
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
	// 标准输入承接 0203 的 REFUND_TEMPLATE_TXID_HEX。hash 只是定位键；真正的
	// FundingTx 与 opening proof 全部来自调用方自己的 checkpoint。
	refundTemplateTxIDRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_TEMPLATE_TXID_HEX")
	if err != nil {
		fail(err)
	}
	if len(refundTemplateTxIDRaw) != len(pool.Hash32{}) {
		fail(fmt.Errorf("refund tx hash must be %d bytes, got %d", len(pool.Hash32{}), len(refundTemplateTxIDRaw)))
	}
	var refundTemplateTxID pool.RefundTemplateTxID
	copy(refundTemplateTxID[:], refundTemplateTxIDRaw)
	checkpointPath := poolopening.BuyerOpeningProofCheckpointPath()
	opening, err := poolopening.LoadBuyerOpeningProof(checkpointPath, refundTemplateTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer opening proof checkpoint (caller state): %w", err))
	}
	debug("[buyer] 已按 RefundTemplateTxID 找到本地保存的 opening proof")
	// BuildFundingTxDelivery 复核 proof 的所有权、完整性和 hash 一致性，
	// 然后从 proof 携带的 FundingTx 构造交付报文；它不会重新签名 FundingTx。
	delivery, err := session.Buyer.BuildFundingTxDelivery(ctx, opening)
	if err != nil {
		fail(fmt.Errorf("buyer.BuildFundingTxDelivery: %w", err))
	}
	deliveryRaw, err := wire.MarshalPoolFundingTxDelivery(delivery)
	if err != nil {
		fail(fmt.Errorf("encode FundingTxDelivery: %w", err))
	}
	debug("[buyer] FundingTx bytes: %d", len(delivery.FundingTx))
	debug("[buyer] RefundTemplateTxID (pool correlation ID): %s", hex.EncodeToString(delivery.RefundTemplateTxID[:]))
	debug("[transport] buyer -> seller: PoolFundingTxDelivery (%d bytes)", len(deliveryRaw))
	// 这是本流程中 FundingTx 原文第一次进入 seller-facing 网络报文。
	// 仍将报文写成 stdout 上的 hex，保持与前几个步骤相同的管道接口。
	if err := poolopening.WriteHex(os.Stdout, "FUNDING_TX_DELIVERY_HEX", deliveryRaw); err != nil {
		fail(err)
	}
}

// debug 只写 stderr，stdout 保留给下游命令需要的报文。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 输出错误并终止，防止未通过本地 proof 检查的 FundingTx 被交付。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
