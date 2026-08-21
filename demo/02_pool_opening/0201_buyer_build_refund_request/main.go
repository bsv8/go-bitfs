// 0201 是开池流程的第一个买方动作。
//
// 这个子项目负责两件事：先在买方本地准备一笔真实的 FundingTx，再根据
// FundingTx 构造退款交易并生成 RefundPresignRequest。需要特别注意的是，
// FundingTx 的原文不会放进本次发给卖方的报文，报文中只公开其交易 ID；
// 这样卖方可以先验证退款条件，但要等买方完成本地证据保存后，才会收到
// 完整的资金交易（见 0204）。
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
	// demo/.env 中保存了本演示需要的私钥和其他配置。Load 只负责把配置
	// 放入环境变量，不会创建协议对象，也不会向网络发送请求。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	// 使用一个贯穿本次命令的 context，供 JungleBus 查询和 buyer workflow
	// 传递取消信号。这个演示是一次性命令，因此使用 Background 即可。
	ctx := context.Background()
	// NewBuyer 会加载买方、卖方和仲裁方密钥，创建买方本地 FileStore，
	// 并组装 buyer.Workflow。FileStore 让后续 0203/0204 进程仍能读取本地状态。
	session, err := poolopening.NewBuyer(ctx)
	if err != nil {
		fail(err)
	}

	// 先派生地址，再访问 JungleBus。这样即使地址没有历史交易，日志中也
	// 能明确显示当前 BITFS_NETWORK 对应的充值地址，便于准备测试资金。
	addresses, err := session.FundingAddresses()
	if err != nil {
		fail(fmt.Errorf("derive buyer funding addresses: %w", err))
	}
	debug("=== 0201 买方：接受开池条件并发送 RefundPresignRequest ===")
	debug("[buyer] selected network: %s", addresses.Network)
	debug("[buyer] funding address: %s", addresses.SelectedAddress)
	// PrepareFunding 在 demo 层查询 JungleBus，重建地址的已确认 UTXO，
	// 选择一个可用输出，并使用买方私钥签名真实 FundingTx。它不是协议报文，
	// 只在买方本地短暂持有，稍后会保存到 DEMO_02_FUNDING_TX_FILE。
	funding, err := session.PrepareFunding(ctx)
	if err != nil {
		fail(fmt.Errorf("prepare real funding transaction: %w", err))
	}
	// 以下两个 endpoint 只用于调试输出：它们帮助读者知道本次 UTXO 查询
	// 和交易原文获取分别对应 JungleBus 的哪个地址/交易接口，不参与签名。
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
	// 先把真实 FundingTx 保存到买方本地，再进入协议报文阶段。0203 会从
	// 这个文件取回原文，将卖方响应与原始请求重新绑定并形成完整 opening proof。
	if err := poolopening.SaveFundingTx(funding.RawTx); err != nil {
		fail(err)
	}
	// 这里用库的规范交易解析器计算 FundingTxID，而不是对原始 hex 做普通
	// 哈希。规范解析同时保证后续流程使用的交易序列化与协议身份一致。
	fundingTransaction, err := pool.ParseCanonicalTransaction(funding.RawTx)
	if err != nil {
		fail(fmt.Errorf("parse prepared funding transaction: %w", err))
	}
	debug("[funding] real funding txid: %s", fundingTransaction.TxID().String())
	debug("[funding] raw tx hex: %s", hex.EncodeToString(funding.RawTx))
	debug("[funding] buyer-local file: %s", poolopening.FundingTxPath())
	debug("[buyer] 构造并签名退款交易预签名请求")
	// OpeningInput 把资金交易、费用率和参与方公钥交给
	// buyer workflow。workflow 会构造退款交易，并由买方对退款交易签名；
	// 卖方稍后只需在同一退款交易上补充自己的签名。
	request, err := session.Buyer.PreparePoolOpening(ctx, session.OpeningInput(funding.RawTx, funding.MinerFeeRateSatPerKB))
	if err != nil {
		fail(fmt.Errorf("buyer.PreparePoolOpening: %w", err))
	}
	// wire 层使用协议规定的严格 CBOR 编码。编码失败时不能继续输出，
	// 否则下一个子项目会把不完整数据误当成 RefundPresignRequest。
	raw, err := wire.MarshalPoolRefundPresignRequest(request)
	if err != nil {
		fail(fmt.Errorf("encode RefundPresignRequest: %w", err))
	}
	debug("[buyer] RefundTx bytes: %d", len(request.RefundTx))
	debug("[buyer] FundingTxID (derived from RefundTx): %s", fundingTransaction.TxID().String())
	debug("[buyer] FundingTx 原文尚未进入报文：yes")
	debug("[transport] buyer -> seller: PoolRefundPresignRequest (%d bytes)", len(raw))
	// stdout 只输出可传给下一个命令的 hex 报文，stderr 承载调试日志。
	// 这种分离使得 tee 保存的文件不会混入人类可读日志。
	if err := poolopening.WriteHex(os.Stdout, "REFUND_PRESIGN_REQUEST_HEX", raw); err != nil {
		fail(err)
	}
}

// debug 将过程日志写到 stderr，避免污染 stdout 上的机器可读协议报文。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 统一记录错误并以非零状态退出，使流水线中的后续步骤不会继续消费
// 一个已经失败或不完整的协议报文。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
