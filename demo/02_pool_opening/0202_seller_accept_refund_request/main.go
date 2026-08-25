// 0202 是开池流程的卖方接收动作。
//
// 它从标准输入读取 0201 产生的 exact Kind 2 bytes，交给 seller workflow 做结
// 构、参与方、公钥、退款交易以及买方签名的完整校验；校验成功后，卖方从收到
// 的 request 重新派生 RefundTemplateTxID 并签署同一笔退款交易，返回携带该关
// 联 ID 的 Kind 3 预签响应。响应不携带 FundingTransactionRaw 原文。
// 卖方的预签证据（exact Kind 2 request 字节）由本 demo 的 checkpoint 显式保
// 存——SDK 不做任何持久化。
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

func main() {
	// 读取 demo/.env，获得卖方私钥等配置。workflow 只持有受约束 Signer。
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

	debug("=== 0202 卖方：接受、检验并回应退款预签请求（Kind 2）===")
	debug("[transport] seller <- buyer: RefundPresignRequest (%d bytes)", len(requestRaw))
	debug("[seller] 检验请求结构、参与方、公钥、退款交易和买方签名")
	// seller.PreparePoolOpening 会确认请求中的卖方公钥确实属于当前卖方，
	// 计算卖方退款签名并返回待发送 Kind 3 Artifact 与必须先持久化的
	// OpeningCheckpoint。SDK 不保存任何证据；应用必须先保存 checkpoint，
	// 再发送 Outbound。
	prepared, err := session.Seller.PreparePoolOpening(ctx, poolopening.Facts(time.Now().UTC()), requestRaw)
	if err != nil {
		fail(fmt.Errorf("seller.PreparePoolOpening: %w", err))
	}
	checkpointPath := poolopening.SellerPresignCheckpointPath()
	// 卖方预签 checkpoint 的关联 ID 从本地 opening proof 重新派生（不信任传输层）。
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxID(prepared.Checkpoint.Opening())
	if err != nil {
		fail(fmt.Errorf("derive presign correlation id: %w", err))
	}
	if err := poolopening.SaveSellerPresignCheckpoint(checkpointPath, refundTemplateTxID, requestRaw); err != nil {
		fail(fmt.Errorf("save seller presign checkpoint (caller responsibility): %w", err))
	}
	responseRaw := prepared.Outbound.Bytes() // exact Kind 3 bytes：先持久化证据再发送
	debug("[seller] 预签 evidence 已保存到应用 checkpoint %s", checkpointPath)
	// 响应是独立的 wire 报文。其核心内容是卖方重新派生的 RefundTemplateTxID 和
	// 退款签名；0203 只凭该 hash 关联买方自己的本地状态。
	debug("[seller] refund tx hash (pool correlation ID): %s", hex.EncodeToString(refundTemplateTxID[:]))
	debug("[transport] seller -> buyer: RefundPresignResponse (%d bytes)", len(responseRaw))
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
