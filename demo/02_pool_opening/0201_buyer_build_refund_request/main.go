// 0201 是开池流程的第一个买方动作。
//
// 这个子项目负责两件事：先在买方本地准备一笔真实的 FundingTransactionRaw，再
// 用角色 API 构造退款预签请求（Kind 2）。需要特别注意的是，FundingTransactionRaw
// 的原文不会放进本次发给卖方的报文，报文中只公开其交易 ID；这样卖方可以先验
// 证退款条件，但要等买方把 OpeningCheckpoint 的证据写入自己的 checkpoint 之后，
// 才会收到完整的资金交易（见 0204）。
//
// 流程：load（密钥/UTXO）→ buyer.PreparePoolOpening → persist（exact Kind 2
// bytes + 私有资金交易原文）→ send。
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/poolopening"
	"github.com/bsv8/go-bitfs/pool"
)

// nowUTC 返回当前 UTC 时间；demo 应用允许读取系统时钟并把它作为显式事实
// 传入 SDK（SDK 自身绝不读钟）。
func nowUTC() time.Time { return time.Now().UTC() }

func main() {
	// demo/.env 中保存了本演示需要的私钥和其他配置。Load 只负责把配置
	// 放入环境变量，不会创建协议对象，也不会向网络发送请求。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	// 使用一个贯穿本次命令的 context，供 JungleBus 查询和 buyer workflow
	// 传递取消信号。这个演示是一次性命令，因此使用 Background 即可。
	ctx := context.Background()
	// NewBuyer 会加载三方密钥并经 protocol.NewPrivateKeySigner 组装只含
	// Signer 的 buyer.Workflow。跨进程状态由本 demo 的 checkpoint 函数保存，
	// 不经过 SDK。
	session, err := poolopening.NewBuyer(ctx)
	if err != nil {
		fail(err)
	}

	// DEMO_02_OFFLINE=1 时走确定性内存资金交易：不访问任何网络，供 CI
	// 离线冒烟验收（空状态即可完整跑通 0201→0205）。真实资金路径仍由
	// PrepareFunding 提供，两条路径在 OpeningCommand 之后完全一致。
	var funding *poolopening.FundingPreparation
	if os.Getenv("DEMO_02_OFFLINE") == "1" {
		funding, err = session.PrepareFundingOffline()
		if err != nil {
			fail(fmt.Errorf("prepare offline funding transaction: %w", err))
		}
		if err := session.EnsureOfflineQuote(ctx, nowUTC()); err != nil {
			fail(fmt.Errorf("prepare offline quote: %w", err))
		}
		debug("[offline] deterministic funding + in-process 001 round complete")
	} else {
		// 先派生地址，再访问 JungleBus。这样即使地址没有历史交易，日志中
		// 也能明确显示当前 BITFS_NETWORK 对应的充值地址，便于准备测试资金。
		addresses, addrErr := session.FundingAddresses()
		if addrErr != nil {
			fail(fmt.Errorf("derive buyer funding addresses: %w", addrErr))
		}
		debug("=== 0201 买方：构造开池条件并发送退款预签请求（Kind 2）===")
		debug("[buyer] selected network: %s", addresses.Network)
		debug("[buyer] funding address: %s", addresses.SelectedAddress)
		// PrepareFunding 在 demo 层查询 JungleBus，重建地址的已确认 UTXO，
		// 选择一个可用输出，并使用买方私钥签名真实 FundingTransactionRaw。它不是协议报文，
		// 只在买方本地短暂持有，稍后随 OpeningCheckpoint 进入买方 checkpoint。
		funding, fundErr := session.PrepareFunding(ctx)
		if fundErr != nil {
			fail(fmt.Errorf("prepare real funding transaction: %w", fundErr))
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
	}
	debug("[funding] miner fee rate: %d sat/KB (%s)", funding.MinerFeeRateSatoshisPerKilobyte, funding.MinerFeeRateSource)
	debug("[funding] actual miner fee: %d satoshis; raw size: %d bytes", funding.FundingFeeSatoshis, len(funding.RawTx))
	// 这里用库的规范交易解析器计算 FundingTxID，而不是对原始 hex 做普通
	// 哈希。规范解析同时保证后续流程使用的交易序列化与协议身份一致。
	fundingTransaction, err := pool.ParseCanonicalTransaction(funding.RawTx)
	if err != nil {
		fail(fmt.Errorf("parse prepared funding transaction: %w", err))
	}
	debug("[funding] real funding txid: %s", fundingTransaction.TxID().String())
	debug("[buyer] 构造并签名退款交易预签名请求")
	openingCommand, err := session.OpeningCommand(funding.RawTx, uint64(funding.MinerFeeRateSatoshisPerKilobyte))
	if err != nil {
		fail(fmt.Errorf("build opening command: %w", err))
	}
	// buyer.PreparePoolOpening 返回待发送的 exact Kind 2 Artifact 与必须先
	// 持久化的 OpeningCheckpoint。SDK 不做任何保存；应用必须先持久化
	// checkpoint 的证据，再发送 Outbound。这里由 demo checkpoint 承担
	// “应用数据库”的角色。
	prepared, err := session.Buyer.PreparePoolOpening(ctx, openingCommand)
	if err != nil {
		fail(fmt.Errorf("buyer.PreparePoolOpening: %w", err))
	}
	checkpointPath := poolopening.BuyerOpeningCheckpointPath()
	if err := poolopening.SaveBuyerOpeningCheckpoint(checkpointPath, prepared); err != nil {
		fail(fmt.Errorf("save buyer opening checkpoint (caller responsibility): %w", err))
	}
	raw := prepared.Outbound.Bytes() // exact Kind 2 bytes：先持久化 checkpoint 再发送
	debug("[buyer] OpeningCheckpoint 已保存到应用 checkpoint %s", checkpointPath)
	refundTemplateTxID := prepared.Checkpoint.RefundTemplateTxID()
	debug("[buyer] RefundTemplateRaw bytes: %d", len(prepared.Checkpoint.Request().RefundTemplateRaw))
	debug("[buyer] RefundTemplateTxID (pool correlation ID): %s", hex.EncodeToString(refundTemplateTxID[:]))
	debug("[buyer] FundingTxID (derived from RefundTemplateRaw): %s", fundingTransaction.TxID().String())
	debug("[buyer] FundingTransactionRaw 原文尚未进入报文：yes（仅保存在买方私有 checkpoint）")
	debug("[transport] buyer -> seller: RefundPresignRequest (%d bytes)", len(raw))
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
