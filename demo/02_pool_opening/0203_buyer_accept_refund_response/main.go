// 0203 是开池流程的第二个买方动作，也是买方建立完整池证据的边界。
//
// 0202 的 Kind 3 响应显式携带费用池统一关联 ID RefundTemplateTxID。本命令从
// stdin 读取响应，展示层解码出该关联 ID，按它从买方自己的 checkpoint 加载
// 0201 保存的 OpeningCheckpoint（exact Kind 2 bytes + 私有资金交易原文，经
// buyer.RestoreOpeningCheckpoint 全量重验恢复），显式传给角色 API；
// buyer.CompletePoolOpening 重新派生 hash、拒绝一切错配并验证卖方签名。
// 跨进程、无 session、无需原请求文件，全部由调用方状态承载。
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/poolopening"
	"github.com/bsv8/go-bitfs/wire"
)

func main() {
	// 加载与 0201 相同的买方配置。workflow 只持有受约束 Signer；本地状态来自
	// demo checkpoint，而不是 SDK 内部存储。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	session, err := poolopening.NewBuyer(ctx)
	if err != nil {
		fail(err)
	}
	// 离线冒烟跳过地址派生展示；真实路径仍显示网络与充值地址。
	if os.Getenv("DEMO_02_OFFLINE") != "1" {
		addresses, err := session.FundingAddresses()
		if err != nil {
			fail(fmt.Errorf("derive buyer funding addresses: %w", err))
		}
		debug("[buyer] selected network: %s", addresses.Network)
		debug("[buyer] funding address: %s", addresses.SelectedAddress)
	}
	debug("=== 0203 买方：接受并检验退款预签响应（Kind 3）===")
	// 标准输入承接 0202 的响应；展示层解码出 RefundTemplateTxID 用于定位
	// 自己的 checkpoint 记录，再把本地状态与 exact bytes 一起传给 SDK。
	responseRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_PRESIGN_RESPONSE_HEX")
	if err != nil {
		fail(err)
	}
	responseArtifact, err := wire.ParseAs(wire.RefundPresignResponse, responseRaw)
	if err != nil {
		fail(fmt.Errorf("parse RefundPresignResponse artifact: %w", err))
	}
	response, err := wire.DecodeRefundPresignResponse(responseArtifact)
	if err != nil {
		fail(fmt.Errorf("decode RefundPresignResponse: %w", err))
	}
	refundTemplateTxID := response.RefundTemplateTxID
	debug("[transport] buyer <- seller: RefundPresignResponse (%d bytes)", len(responseRaw))
	debug("[buyer] refund tx hash: %s", hex.EncodeToString(refundTemplateTxID[:]))
	debug("[buyer] 从应用 checkpoint 找回 0201 的 request/资金交易原文并检验卖方退款签名")
	checkpointPath := poolopening.BuyerOpeningCheckpointPath()
	openingCheckpoint, err := poolopening.LoadBuyerOpeningCheckpoint(checkpointPath, refundTemplateTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer opening checkpoint (caller state): %w", err))
	}
	// CompletePoolOpening 用显式传入的本地状态重新派生 hash 并拒绝一切错配，
	// 针对原请求验证卖方签名，然后返回完整 verified opening 和初始池
	// checkpoint。SDK 不保存任何结果；保存仍是调用方的责任。
	completed, err := session.Buyer.CompletePoolOpening(openingCheckpoint, responseRaw)
	if err != nil {
		fail(fmt.Errorf("buyer.CompletePoolOpening: %w", err))
	}
	poolPath := poolopening.BuyerPoolCheckpointPath()
	if err := poolopening.SaveBuyerPoolCheckpoint(poolPath, completed.InitialPool); err != nil {
		fail(fmt.Errorf("save buyer pool checkpoint (caller responsibility): %w", err))
	}
	initial := completed.InitialPool.Payment()
	debug("[buyer] seller refund signature: valid")
	debug("[buyer] 初始池证据已保存到应用 checkpoint %s", poolPath)
	debug("[buyer] initial payment sequence: %d", initial.PaymentSequence)
	debug("[local state] FundingTransactionRaw 现在才允许交付给卖方；完整 opening proof 只保存在可信的调用方存储中")
	// stdout 只输出标量字段：0204 仅凭 REFUND_TEMPLATE_TXID_HEX 就能从买方
	// checkpoint 加载池证据并构造交付报文；opening proof 不作为进程间交接物。
	fmt.Printf("REFUND_TEMPLATE_TXID_HEX=%s\n", hex.EncodeToString(refundTemplateTxID[:]))
	fmt.Printf("INITIAL_PAYMENT_SEQUENCE=%d\n", initial.PaymentSequence)
}

// debug 将运行轨迹写入 stderr，保证 stdout 可以安全地作为下一步输入。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 统一处理错误并停止流水线。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
