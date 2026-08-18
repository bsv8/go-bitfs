// 0204 是开池流程中公开完整 FundingTx 的买方动作。
//
// 本命令不重新构造退款证据，而是先检查 0203 输出的 OpeningProof 与买方
// FileStore 中保存的 proof 完全一致；确认本地证据已落盘后，才把 proof 中
// 的 FundingTx 放入 FundingTxDelivery，发送给卖方进入 0205。
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
	// 读取环境配置并打开买方 FileStore。0204 与 0203 是两个独立进程，
	// 因此不能依赖 0203 的内存对象来判断证据是否已保存。
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
	// 标准输入承接 0203 的本地 proof 快照。DecodeOpeningProof 会检查
	// pool 状态编码，而不是把任意 hex 当成可交付证据。
	proofRaw, err := poolopening.ReadHex(os.Stdin, "BUYER_OPENING_PROOF_HEX")
	if err != nil {
		fail(err)
	}
	proof, err := pool.DecodeOpeningProof(proofRaw)
	if err != nil {
		fail(fmt.Errorf("decode buyer local opening proof: %w", err))
	}
	// SpendTxID 是退款交易的规范交易 ID，也是 OpeningProof 在 store 中的
	// 主键。重新计算它可以避免仅凭 proof 内携带的 ID 去查询本地状态。
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
	// 规范重新编码后逐字节比较，确保 stdin 中的 proof 正是本地已保存的
	// 那一份，而不是被替换过的证据。这个检查是“先保存、后交付”的门槛。
	storedRaw, err := pool.EncodeOpeningProof(stored)
	if err != nil {
		fail(fmt.Errorf("encode persisted buyer opening proof: %w", err))
	}
	if !bytes.Equal(storedRaw, proofRaw) {
		fail(fmt.Errorf("local proof does not match buyer's persisted proof"))
	}

	debug("[buyer] 已确认 0203 的 opening proof 在本地持久化")
	// BuildFundingTxDelivery 只负责把已验证过的 FundingTx 包装成传输对象；
	// 它不会重新签名 FundingTx，也不会改变 opening proof 中的交易内容。
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
