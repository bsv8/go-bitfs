// 0205 是开池流程的卖方收尾动作。
//
// 它接收 0204 首次公开的完整 FundingTx，按 delivery.RefundTemplateTxID 从卖方
// 自己的 checkpoint 加载 0202 保存的预签证据，显式传给 SDK 验证资金交易
// 确实匹配退款证据和池输出，并得到完整的 opening proof、初始付款状态和
// 待广播的资金交易原文。SDK 不提交任何交易；真实应用在此处调用自己的
// 节点适配器完成广播与对账。
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
	// 加载环境并组装卖方会话。0202 已把预签证据保存在同一状态目录的
	// checkpoint 中，0205 必须从调用方状态恢复，而不能相信买方传来的 proof。
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

	debug("=== 0205 卖方：接受并检验 FundingTxDelivery ===")
	debug("[transport] seller <- buyer: PoolFundingTxDelivery (%d bytes)", len(deliveryRaw))
	debug("[seller] 按 delivery.RefundTemplateTxID 加载 0202 保存的预签证据并交叉验证")
	checkpointPath := poolopening.SellerPresignProofCheckpointPath()
	presignProof, err := poolopening.LoadSellerPresignProof(checkpointPath, delivery.RefundTemplateTxID)
	if err != nil {
		fail(fmt.Errorf("load seller presign checkpoint (caller state): %w", err))
	}
	// AcceptPoolFunding 用显式传入的预签证据复核派生 hash 一致性，验证完整
	// FundingTx 的规范编码、资金 outpoint、池输出和开池证据，然后返回完整
	// proof、初始付款状态和待调用方广播的资金交易。任一校验失败都不会产生
	// “已开池”结果；SDK 不执行任何广播或持久化。
	acceptance, err := session.Seller.AcceptPoolFunding(ctx, presignProof, delivery)
	if err != nil {
		fail(fmt.Errorf("seller.AcceptPoolFunding: %w", err))
	}
	details, err := pool.DeriveOpeningDetails(acceptance.Opening)
	if err != nil {
		fail(fmt.Errorf("derive seller opening details: %w", err))
	}
	if details.RefundTemplateTxID != delivery.RefundTemplateTxID {
		fail(fmt.Errorf("opening proof does not match delivery correlation ID"))
	}
	debug("[seller] FundingTx 已通过验证；广播资金交易是调用方的节点适配器职责")
	debug("[seller] funding tx to broadcast: %d bytes", len(acceptance.FundingTx))
	debug("[state] pool opened (locally verified): true")
	fmt.Printf("POOL_OPENED=true\n")
	fmt.Printf("FUNDING_TX_ID_HEX=%s\n", hex.EncodeToString(details.FundingTxID[:]))
	fmt.Printf("REFUND_TEMPLATE_TXID_HEX=%s\n", hex.EncodeToString(details.RefundTemplateTxID[:]))
	fmt.Printf("INITIAL_PAYMENT_SEQUENCE=%d\n", acceptance.InitialPayment.PaymentSequence)
	// 输出初始付款状态的规范交易，供脚本观察“待保存/待广播”的结果形态；
	// 它不是新的网络报文。
	if err := poolopening.WriteHex(os.Stdout, "INITIAL_REFUND_TX_HEX", acceptance.InitialPayment.RawTx); err != nil {
		fail(err)
	}
}

// debug 不污染 stdout 上的状态结果和报文字段。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 在任意解码、校验错误时终止开池收尾动作。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
