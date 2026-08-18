// 0205 是开池流程的卖方收尾动作。
//
// 它接收 0204 首次公开的完整 FundingTx，使用 0202 已保存的 opening proof
// 验证资金交易确实匹配退款证据和池输出，然后把交易交给 demo backend。
// backend 仍是内存实现，不会广播真实交易；本命令展示的是卖方 workflow
// 到节点/费用池后端之间的校验与提交边界。
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
	// 加载环境并打开卖方 FileStore。0202 已把待接收资金所需的 proof 保存在
	// 同一个状态目录中，0205 必须从持久化状态恢复，而不能相信买方传来的 proof。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	session, err := poolopening.NewSeller(ctx)
	if err != nil {
		fail(err)
	}
	// 读取并严格解码 0204 的 FundingTxDelivery。报文中的 FundingTx 原文
	// 可能很大，但它仍然必须经过 wire 层的固定类型和编码校验。
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
	// AcceptPoolFunding 会按 FundingTxID 找到 0202 保存的 proof，验证完整
	// FundingTx 的规范编码、资金 outpoint、池输出和开池证据，然后调用 demo
	// backend 提交。任一校验失败都不会产生“已开池”状态。
	opening, err := session.Seller.AcceptPoolFunding(ctx, delivery)
	if err != nil {
		fail(fmt.Errorf("seller.AcceptPoolFunding: %w", err))
	}
	// 返回的 opening 是 seller 侧已经完成的证据快照。编码并输出它方便演示
	// 查看两方最终证据，但它不是另一个需要买方响应的网络报文。
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
	// 重新从 seller store 读取初始支付状态，验证提交资金后 opening proof
	// 和 PaymentState 都已经持久化，而不是只在 AcceptPoolFunding 返回值中存在。
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
	// 最后输出 seller 侧 proof 快照。stdout 中的标量和 hex 字段都可以被脚本
	// 读取，调试过程则始终由 stderr 承载。
	if err := poolopening.WriteHex(os.Stdout, "SELLER_OPENING_PROOF_HEX", openingRaw); err != nil {
		fail(err)
	}
}

// debug 不污染 stdout 上的状态结果和 proof 快照。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 在任意解码、校验或持久化错误时终止开池收尾动作。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
