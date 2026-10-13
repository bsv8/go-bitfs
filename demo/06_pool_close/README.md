# 006：关闭费用池

这一步演示双方在完成内容交付和累计付款后协商关闭费用池。买家发送 Kind 12，卖家签名后返回 Kind 13，买家验证完整交易。SDK 不广播交易。

本离线示例将内存中构造并验证的付款交易放入双方证据的 `LatestPaymentRawTx`，只演示协议步骤，不表示节点已确认。实际接入时，调用方应填入最近一次已确认付款的交易原文，并保存每次发出的 exact Artifact，供网络重试和审计使用。

运行完整示例：

```sh
go run ./demo/06_pool_close/01_close_pool
```

以下函数可以直接放入 Go 文件编译，展示 Kind 12/13 的角色 API 和到期退款 API：

```go
package main

import (
	"context"

	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
)

func negotiateClose(
	ctx context.Context,
	facts protocol.Facts,
	buyerPool buyer.BuyerPoolEvidence,
	sellerPool seller.SellerPoolEvidence,
	targetAmount protocol.Satoshis,
	buyerSigner protocol.Signer,
	sellerSigner protocol.Signer,
) ([]byte, error) {
	// 买方构造 Kind 12，其中包含未签名关闭交易和买方交易签名。
	kind12, err := buyer.PrepareCloseArtifact(ctx, facts, buyer.PrepareCloseInput{
		Pool:                       buyerPool,
		TargetSellerAmountSatoshis: targetAmount,
	}, buyerSigner)
	if err != nil {
		return nil, err
	}

	// 卖方验证池 ID、候选交易和买方签名，补签后返回 Kind 13；不广播。
	kind13, err := seller.CompleteCloseArtifact(ctx, facts, seller.CompleteCloseArtifactInput{
		Pool:       sellerPool,
		RequestRaw: kind12.Bytes(),
	}, sellerSigner)
	if err != nil {
		return nil, err
	}

	// 买方复核池 ID 和完整交易。是否广播由应用决定。
	verified, err := buyer.VerifyCompletedCloseArtifact(buyer.VerifyCompletedCloseArtifactInput{
		Pool:        buyerPool,
		ResponseRaw: kind13.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	return verified.RawTx(), nil
}

func buildMaturedRefund(facts protocol.Facts, evidence buyer.BuyerPoolEvidence) ([]byte, error) {
	// 未到退款锁定时间时返回 CodeNotMatured；本函数不广播。
	refund, err := buyer.BuildMaturedRefund(facts, evidence)
	if err != nil {
		return nil, err
	}
	return refund.RawTx(), nil
}
```

关闭交易以当前累计付款状态作为最终分配依据。超时退款则由 `buildMaturedRefund` 在显式事实表明退款锁定已到期后构造。交易是否提交由调用方负责。

完整示例中的证据更新、Artifact 持久化位置和调试输出见 [`01_close_pool/main.go`](01_close_pool/main.go)。
