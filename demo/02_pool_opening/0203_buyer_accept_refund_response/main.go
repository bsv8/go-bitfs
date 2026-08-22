// 0203 是开池流程的第二个买方动作，也是买方建立完整 opening proof 的边界。
//
// 0202 的 RefundPresignResponse 显式携带费用池统一关联 ID RefundTemplateTxID。
// 本命令从 stdin 读取响应，按该关联 ID 从买方自己的 checkpoint 加载 0201
// 保存的 BuyerOpeningState（原 request 与私有 FundingTx），显式传给 SDK；
// SDK 重新派生 hash、严格比较错配并验证卖方签名。跨进程、无 session、
// 无需原请求文件，全部由调用方状态承载。
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
	// 加载与 0201 相同的买方配置。workflow 只持有 Signer；本地状态来自
	// demo checkpoint，而不是 SDK 内部存储。
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
	debug("=== 0203 买方：接受并检验 RefundPresignResponse ===")
	debug("[buyer] selected network: %s", addresses.Network)
	debug("[buyer] funding address: %s", addresses.SelectedAddress)
	// 标准输入承接 0202 的响应；应用按响应中的 RefundTemplateTxID 定位自己的
	// checkpoint 记录，再把本地状态与报文一起显式传给 SDK。
	responseRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_PRESIGN_RESPONSE_HEX")
	if err != nil {
		fail(err)
	}
	response, err := wire.UnmarshalPoolRefundPresignResponse(responseRaw)
	if err != nil {
		fail(fmt.Errorf("decode RefundPresignResponse: %w", err))
	}
	debug("[transport] buyer <- seller: PoolRefundPresignResponse (%d bytes)", len(responseRaw))
	debug("[buyer] refund tx hash: %s", hex.EncodeToString(response.RefundTemplateTxID[:]))
	debug("[buyer] 从应用 checkpoint 找回 0201 的 request/FundingTx 并检验卖方退款签名")
	checkpointPath := poolopening.BuyerOpeningCheckpointPath()
	state, err := poolopening.LoadBuyerOpeningState(checkpointPath, response.RefundTemplateTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer opening checkpoint (caller state): %w", err))
	}
	// AcceptRefundPresign 用显式传入的本地状态重新派生 hash 并拒绝一切
	// 错配，针对原请求验证签名，然后返回完整 OpeningProof 和初始付款状态。
	// SDK 不保存任何结果；保存仍是调用方的责任。
	acceptance, err := session.Buyer.AcceptRefundPresign(ctx, state, response)
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptRefundPresign: %w", err))
	}
	proofPath := poolopening.BuyerOpeningProofCheckpointPath()
	if err := poolopening.SaveBuyerOpeningProof(proofPath, acceptance.Opening); err != nil {
		fail(fmt.Errorf("save buyer opening proof checkpoint (caller responsibility): %w", err))
	}
	debug("[buyer] seller refund signature: valid")
	debug("[buyer] opening proof 已保存到应用 checkpoint %s", proofPath)
	debug("[buyer] initial payment sequence: %d", acceptance.InitialPayment.PaymentSequence)
	debug("[local state] FundingTx 现在才允许交付给卖方；完整 OpeningProof 只保存在可信的调用方存储中")
	// stdout 只输出标量字段：0204 仅凭 REFUND_TEMPLATE_TXID_HEX 就能从买方
	// checkpoint 加载 proof 并构造交付报文；OpeningProof 不作为进程间交接物。
	fmt.Printf("REFUND_TEMPLATE_TXID_HEX=%s\n", hex.EncodeToString(acceptance.Reference.RefundTemplateTxID[:]))
	fmt.Printf("BASE_PAYMENT_SEQUENCE=%d\n", acceptance.Reference.BasePaymentSequence)
}

// debug 将运行轨迹写入 stderr，保证 stdout 可以安全地作为下一步输入。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 统一处理错误并停止流水线。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
