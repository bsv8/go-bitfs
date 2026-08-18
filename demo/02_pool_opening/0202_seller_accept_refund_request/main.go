// 0202 是开池流程的卖方接收动作。
//
// 它从标准输入读取 0201 产生的 RefundPresignRequest，交给 seller
// workflow 做结构、参与方、公钥、退款交易以及买方签名的完整校验；校验
// 成功后，卖方签署同一笔退款交易并返回 RefundPresignResponse。响应只携带
// 卖方退款签名，不携带 FundingTx 原文。
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
	// 读取 demo/.env，获得卖方私钥和 FileStore 所需的状态目录配置。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	// seller workflow 会在本地保存“待接收资金”的 opening proof。该状态
	// 必须跨越 0202 与 0205 两个独立进程，因此使用持久化 FileStore。
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
	// 买方对退款交易的签名，并把补齐卖方签名所需的证据保存到 seller store。
	// 在这个调用成功前，绝不能生成或发送响应。
	response, err := session.Seller.PresignPoolOpening(ctx, request)
	if err != nil {
		fail(fmt.Errorf("seller.PresignPoolOpening: %w", err))
	}
	// 响应是独立的 wire 报文。其核心内容只有卖方退款签名，0203 会把它
	// 与原始请求及买方本地 FundingTx 合并成完整 OpeningProof。
	responseRaw, err := wire.MarshalPoolRefundPresignResponse(response)
	if err != nil {
		fail(fmt.Errorf("encode RefundPresignResponse: %w", err))
	}
	debug("[seller] 已保存预签 opening proof；FundingTx 原文仍未接收")
	debug("[seller] seller refund signature: %s", hex.EncodeToString(response.SellerRefundSignature))
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
