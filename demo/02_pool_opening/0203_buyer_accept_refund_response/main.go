// 0203 是开池流程的第二个买方动作，也是买方建立完整 opening proof 的
// 边界。
//
// 因为 0202 的 RefundPresignResponse 只带卖方签名，所以本命令必须同时
// 读取 0201 的原始请求和 0202 的响应，再从 0201 留在买方本地的 FundingTx
// 文件取回资金交易。只有三部分证据重新绑定并验证成功后，才会持久化
// OpeningProof 和初始 PaymentState。
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/demo/internal/poolopening"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/wire"
)

func main() {
	// 加载与 0201 相同的买方配置，并打开同一个本地 FileStore，以便读取
	// 0201 保存的 FundingTx 并写入本步骤生成的 opening proof。
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	// request-file 是必要输入：响应本身不重复携带买方请求中的退款交易、
	// FundingTxID 和参与方信息，无法仅凭响应独立完成验签。
	requestFile := flag.String("request-file", os.Getenv("DEMO_02_REQUEST_FILE"), "0201 output file containing REFUND_PRESIGN_REQUEST_HEX")
	flag.Parse()
	if *requestFile == "" {
		fail(fmt.Errorf("--request-file or DEMO_02_REQUEST_FILE is required"))
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
	// 先读回 0201 的请求并严格解码。这个请求是验证卖方响应归属的上下文，
	// 不能用 0203 的其他输入临时拼接替代。
	requestRaw, err := poolopening.ReadHexFile(*requestFile, "REFUND_PRESIGN_REQUEST_HEX")
	if err != nil {
		fail(err)
	}
	request, err := wire.UnmarshalPoolRefundPresignRequest(requestRaw)
	if err != nil {
		fail(fmt.Errorf("decode original RefundPresignRequest: %w", err))
	}
	// 标准输入承接 0202 的响应；响应中的签名稍后会绑定到上面解码出的
	// 原始请求，而不是绑定到某个单独的 FundingTx 或用户提供的任意交易。
	responseRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_PRESIGN_RESPONSE_HEX")
	if err != nil {
		fail(err)
	}
	response, err := wire.UnmarshalPoolRefundPresignResponse(responseRaw)
	if err != nil {
		fail(fmt.Errorf("decode RefundPresignResponse: %w", err))
	}
	// FundingTx 从买方本地文件加载，刻意不从 seller-facing 报文读取。
	// 这体现了协议的两阶段交付：先让双方锁定退款证据，再公开用于开池的
	// 完整资金交易。
	fundingTx, err := poolopening.LoadFundingTx()
	if err != nil {
		fail(fmt.Errorf("load buyer-local funding transaction from 0201: %w", err))
	}

	debug("[transport] buyer <- seller: PoolRefundPresignResponse (%d bytes)", len(responseRaw))
	debug("[buyer] 检验卖方退款签名，并把完整 opening proof 持久化")
	debug("[buyer] 使用 0201 本地保存的真实 FundingTx；它没有通过 seller-facing 报文泄露")
	// AcceptRefundPresign 会重新核对请求与响应的协议版本、角色公钥、退款
	// 交易和两方签名，并将 request + response + fundingTx 组合成 OpeningProof。
	// 成功返回意味着买方已经可以把该 proof 作为后续交付前置条件。
	reference, err := session.Buyer.AcceptRefundPresign(ctx, request, response, fundingTx)
	if err != nil {
		fail(fmt.Errorf("buyer.AcceptRefundPresign: %w", err))
	}
	// 这里再次从 store 读取，而不是直接使用内存返回值，是为了明确验证
	// workflow 确实完成了持久化；后续 0204 也会执行同样的本地状态检查。
	proof, err := session.Store.LoadOpeningProof(ctx, reference.SpendTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer opening proof: %w", err))
	}
	if proof == nil {
		fail(fmt.Errorf("buyer opening proof was not persisted"))
	}
	// 以 pool 的规范编码输出本地 proof。该输出是状态快照，不是新的网络
	// 协议报文；0204 会读取它并与 store 中的规范编码逐字节比较。
	proofRaw, err := pool.EncodeOpeningProof(proof)
	if err != nil {
		fail(fmt.Errorf("encode buyer local opening proof: %w", err))
	}
	// 初始支付状态与 opening proof 一起保存。读取并打印 sequence 是一个
	// 可观察性检查，证明开池后的第一笔累计支付状态已经建立。
	initial, err := session.Store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		fail(fmt.Errorf("load buyer initial payment state: %w", err))
	}
	debug("[buyer] seller refund signature: valid")
	debug("[buyer] opening proof: persisted")
	debug("[buyer] initial payment sequence: %d", initial.PaymentSequence)
	debug("[local state] FundingTx 现在才允许交付给卖方")
	// stdout 同时输出 proof 和两个标量字段，供 0204 读取 proof，供人工或
	// 脚本查看稳定的 SpendTxID 与初始支付序号；日志仍然在 stderr。
	if err := poolopening.WriteHex(os.Stdout, "BUYER_OPENING_PROOF_HEX", proofRaw); err != nil {
		fail(err)
	}
	fmt.Printf("SPEND_TX_ID_HEX=%s\n", hex.EncodeToString(reference.SpendTxID[:]))
	fmt.Printf("BASE_PAYMENT_SEQUENCE=%d\n", reference.BasePaymentSequence)
}

// debug 将运行轨迹写入 stderr，保证 stdout 可以安全地作为下一步输入。
func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

// fail 统一处理错误并停止流水线。
func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
