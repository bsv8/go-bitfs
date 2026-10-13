// 0205 是开池流程的卖方收尾动作。
//
// 它接收 0204 首次公开的完整 FundingTransactionRaw（exact Kind 4 bytes），按
// 报文中的 RefundTemplateTxID 从卖方自己的 checkpoint 加载 0202 保存的预签证
// 据（用保存的 exact Kind 2 request 字节重跑 seller.PreparePresign 得到等价
// 证据包），显式传给纯函数 API 验证资金交易确实匹配退款证据和池输出，并得到
// 完整的开池证明、初始池证据包和待广播的资金交易原文。
// SDK 不提交任何交易；真实应用在此处调用自己的节点适配器完成广播与对账。
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/poolopening"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

// wireParseAsFunding / wireDecodeFunding 是展示层的严格解码 helper：
// 只用于从报文中取出关联 ID 做本地路由，业务验证仍由角色 API 完成。
func wireParseAsFunding(raw []byte) (wire.Artifact, error) {
	return wire.ParseAs(wire.FundingTransactionDelivery, raw)
}

func wireDecodeFunding(artifact wire.Artifact) (*pool.FundingTransactionDelivery, error) {
	return wire.DecodeFundingTransactionDelivery(artifact)
}

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
	// 读取并严格解码 0204 的 exact Kind 4 bytes。报文中的 FundingTransactionRaw
	// 原文可能很大，但它仍然必须经过 wire 层的固定类型和编码校验
	// （seller.VerifyFunding 内部使用 wire.ParseAs）。
	deliveryRaw, err := poolopening.ReadHex(os.Stdin, "FUNDING_TX_DELIVERY_HEX")
	if err != nil {
		fail(err)
	}

	debug("=== 0205 卖方：接受并检验资金交付（Kind 4）===")
	debug("[transport] seller <- buyer: FundingTransactionDelivery (%d bytes)", len(deliveryRaw))
	// 展示层解码报文以取出关联 ID 定位自己的 checkpoint 记录。
	deliveryArtifact, err := wireParseAsFunding(deliveryRaw)
	if err != nil {
		fail(fmt.Errorf("parse FundingTransactionDelivery artifact: %w", err))
	}
	delivery, err := wireDecodeFunding(deliveryArtifact)
	if err != nil {
		fail(fmt.Errorf("decode FundingTransactionDelivery: %w", err))
	}
	refundTemplateTxID := delivery.RefundTemplateTxID
	debug("[seller] 按 delivery.RefundTemplateTxID 加载 0202 保存的预签证据并交叉验证")
	checkpointPath := poolopening.SellerPresignCheckpointPath()
	presignEvidence, err := poolopening.LoadSellerPresignCheckpoint(ctx, session, checkpointPath, refundTemplateTxID)
	if err != nil {
		fail(fmt.Errorf("load seller presign checkpoint (caller state): %w", err))
	}
	// VerifyFunding 用显式传入的预签证据包复核派生 hash 一致性，验证完整
	// FundingTransactionRaw 的规范编码、资金 outpoint、池输出和开池证据，然后
	// 返回待调用方广播的资金交易与池证据包。任一校验失败都不会产生“已开池”
	// 结果；SDK 不执行任何广播或持久化——池证据包必须在广播决策前由应用保存。
	fundingRaw, sellerPool, err := seller.VerifyFunding(deliveryRaw, presignEvidence)
	if err != nil {
		fail(fmt.Errorf("seller.VerifyFunding: %w", err))
	}
	details, err := pool.DeriveOpeningDetails(sellerPool.Opening)
	if err != nil {
		fail(fmt.Errorf("derive seller opening details: %w", err))
	}
	if details.RefundTemplateTxID != refundTemplateTxID {
		fail(fmt.Errorf("opening proof does not match delivery correlation ID"))
	}
	initial, err := poolopening.DerivePaymentState(sellerPool.Opening, sellerPool.LatestPaymentRawTx)
	if err != nil {
		fail(fmt.Errorf("derive initial pool state: %w", err))
	}
	debug("[seller] FundingTransactionRaw 已通过验证；广播资金交易是调用方的节点适配器职责")
	debug("[seller] funding tx to broadcast: %d bytes", len(fundingRaw))
	debug("[state] pool opened (locally verified): true")
	fmt.Printf("POOL_OPENED=true\n")
	fmt.Printf("FUNDING_TX_ID_HEX=%s\n", hex.EncodeToString(details.FundingTxID[:]))
	fmt.Printf("REFUND_TEMPLATE_TXID_HEX=%s\n", hex.EncodeToString(details.RefundTemplateTxID[:]))
	fmt.Printf("INITIAL_PAYMENT_SEQUENCE=%d\n", initial.PaymentSequence)
	// 输出初始付款状态的规范交易，供脚本观察“待保存/待广播”的结果形态；
	// 它不是新的网络报文。
	if err := poolopening.WriteHex(os.Stdout, "INITIAL_REFUND_TX_HEX", initial.RawTx); err != nil {
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
