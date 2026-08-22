// 0202 是开池流程的卖方接收动作。
//
// 它从标准输入读取 0201 产生的 RefundPresignRequest，交给 seller
// workflow 做结构、参与方、公钥、退款交易以及买方签名的完整校验；校验
// 成功后，卖方从收到的 request 重新派生 RefundTemplateTxID 并签署同一笔退款交易，
// 返回携带该关联 ID 的 RefundPresignResponse。响应不携带 FundingTx 原文。
// 卖方的预签证据由本 demo 的 checkpoint 显式保存——SDK 不做任何持久化。
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
	// 读取 demo/.env，获得卖方私钥等配置。workflow 只持有 Signer。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	session, err := poolopening.NewSeller(ctx)
	if err != nil {
		fail(err)
	}

	// 0201 输出的是带字段名的 hex 文本，而不是直接的二进制流。ReadHex
	// 会提取指定字段并解码，避免把日志或错误输出误当成协议内容。
	requestRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_PRESIGN_REQUEST_HEX")
	if err != nil {
		fail(err)
	}
	// wire 解码使用固定的 PoolRefundPresignRequest 类型，并检查编码是否
	// 符合协议约束；未能严格解码的数据不能进入业务校验层。
	request, err := wire.UnmarshalPoolRefundPresignRequest(requestRaw)
	if err != nil {
		fail(fmt.Errorf("decode RefundPresignRequest: %w", err))
	}

	debug("=== 0202 卖方：接受、检验并回应 RefundPresignRequest ===")
	debug("[transport] seller <- buyer: PoolRefundPresignRequest (%d bytes)", len(requestRaw))
	debug("[seller] 检验请求结构、参与方、公钥、退款交易和买方签名")
	// PresignPoolOpening 会确认请求中的卖方公钥确实属于当前卖方，验证
	// 买方对退款交易的签名，并返回卖方签名与预签 opening proof。SDK 不保存
	// 任何证据；应用必须先保存 Opening，再发送 Response。
	result, err := session.Seller.PresignPoolOpening(ctx, request)
	if err != nil {
		fail(fmt.Errorf("seller.PresignPoolOpening: %w", err))
	}
	checkpointPath := poolopening.SellerPresignProofCheckpointPath()
	if err := poolopening.SaveSellerPresignProof(checkpointPath, result); err != nil {
		fail(fmt.Errorf("save seller presign checkpoint (caller responsibility): %w", err))
	}
	debug("[seller] 预签 opening proof 已保存到应用 checkpoint %s", checkpointPath)
	// 响应是独立的 wire 报文。其核心内容是卖方重新派生的 RefundTemplateTxID 和
	// 退款签名；0203 只凭该 hash 关联买方自己的本地状态。
	responseRaw, err := wire.MarshalPoolRefundPresignResponse(result.Response)
	if err != nil {
		fail(fmt.Errorf("encode RefundPresignResponse: %w", err))
	}
	debug("[seller] refund tx hash (pool correlation ID): %s", hex.EncodeToString(result.Response.RefundTemplateTxID[:]))
	debug("[seller] seller refund signature: %s", hex.EncodeToString(result.Response.SellerRefundSignature))
	debug("[transport] seller -> buyer: PoolRefundPresignResponse (%d bytes)", len(responseRaw))
	// 与 0201 一样，stdout 保持为可继续传输的单一 hex 字段，调试日志全部
	// 走 stderr，方便调用方用管道或 tee 连接下一步。
	if err := poolopening.WriteHex(os.Stdout, "REFUND_PRESIGN_RESPONSE_HEX", responseRaw); err != nil {
		fail(err)
	}
}

// debug 输出不会混入 stdout 的协议报文。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 记录失败原因并终止当前角色动作，避免继续传播无效响应。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
