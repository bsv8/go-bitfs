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
	if err := demoenv.Load(); err != nil {
		fail(err)
	}
	ctx := context.Background()
	session, err := poolopening.NewSeller(ctx)
	if err != nil {
		fail(err)
	}
	requestRaw, err := poolopening.ReadHex(os.Stdin, "REFUND_PRESIGN_REQUEST_HEX")
	if err != nil {
		fail(err)
	}
	request, err := wire.UnmarshalPoolRefundPresignRequest(requestRaw)
	if err != nil {
		fail(fmt.Errorf("decode RefundPresignRequest: %w", err))
	}

	debug("=== 0202 卖方：接受、检验并回应 RefundPresignRequest ===")
	debug("[transport] seller <- buyer: PoolRefundPresignRequest (%d bytes)", len(requestRaw))
	debug("[seller] 检验请求结构、参与方、公钥、退款交易和买方签名")
	response, err := session.Seller.PresignPoolOpening(ctx, request)
	if err != nil {
		fail(fmt.Errorf("seller.PresignPoolOpening: %w", err))
	}
	responseRaw, err := wire.MarshalPoolRefundPresignResponse(response)
	if err != nil {
		fail(fmt.Errorf("encode RefundPresignResponse: %w", err))
	}
	debug("[seller] 已保存预签 opening proof；FundingTx 原文仍未接收")
	debug("[seller] seller refund signature: %s", hex.EncodeToString(response.SellerRefundSignature))
	debug("[transport] seller -> buyer: PoolRefundPresignResponse (%d bytes)", len(responseRaw))
	if err := poolopening.WriteHex(os.Stdout, "REFUND_PRESIGN_RESPONSE_HEX", responseRaw); err != nil {
		fail(err)
	}
}

func debug(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) }

func fail(err error) {
	debug("[FAIL] %v", err)
	os.Exit(1)
}
