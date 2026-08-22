// Package fixture 提供结构稳定的内存 demo fixture。
//
// 它作为“调用方应用”显式持有并传递全部本地状态：报价、开池证据、最新付款
// 状态和内容字节都保存在 Fixture 自身字段里，每一步都显式传给 SDK。它不创建
// 任何 Store 或节点 backend，也不代表 BSV 节点；广播与持久化在真实应用中由
// 调用方实现。
package fixture

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

// Fixture 显式保存从报价到开池完成所需的全部对象和中间结果。
// 它扮演调用方应用的本地状态存储：后续 003、004、005、006、007 演示把这些
// 字段逐个显式传回 workflow，而不是依赖任何 SDK 内部加载行为。
type Fixture struct {
	Buyer         *buyer.Workflow
	Seller        *seller.Workflow
	Arbiter       *arbitration.Workflow
	BuyerKey      *ec.PrivateKey
	SellerKey     *ec.PrivateKey
	ArbiterKey    *ec.PrivateKey
	Quote         *bitfs.SignedFileQuote
	QuoteHash     bitfs.Hash32
	Seed          []byte
	SeedHash      masterseed.Digest
	FileBytes     []byte
	FundingTx     []byte
	Opening       *pool.OpeningProof
	Reference     pool.Reference
	LatestPayment *pool.PaymentState
}

// New 创建一套已经完成 002 开池的显式状态。
//
// 初始化顺序与真实业务流程一致：读取文件并生成 seed，加载三方密钥，卖方创建
// 报价，买方接受报价，然后依次执行退款预签、买方验收、资金交付和卖方验收。
// 每一步的返回值都保存在本 fixture（即调用方）中，并显式传给下一步。
func New(ctx context.Context) (*Fixture, error) {
	// 文件内容同时决定报价中的 SeedHash、传输的 seed，以及卖方可交付的
	// 完整 Block；读取失败意味着整个 fixture 无法建立。
	filePath := envOr("FILE_PATH", "demo/file.bin")
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read demo file %q: %w", filePath, err)
	}
	var seedOutput bytes.Buffer
	if _, err := masterseed.CreateSeed(ctx, bytes.NewReader(fileBytes), &seedOutput); err != nil {
		return nil, fmt.Errorf("create demo seed: %w", err)
	}
	seed := seedOutput.Bytes()
	seedHash := masterseed.Sum256(seed)

	// 三个角色使用独立私钥。fixture 只在创建 Signer 时持有私钥，后续协议
	// 字段使用各自的压缩公钥。
	buyerKey, err := loadKey("BUYER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	sellerKey, err := loadKey("SELLER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	arbiterKey, err := loadKey("ARBITER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	// Workflow 直接持有官方 BSV 私钥；demo 不再包装任何 signer。
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: buyerKey})
	if err != nil {
		return nil, err
	}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: sellerKey})
	if err != nil {
		return nil, err
	}
	arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: arbiterKey})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	// 001：报价先由卖方创建，再由买方验证接受；买方把返回值保留为本地状态。
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		return nil, err
	}
	quote, err := sellerWorkflow.CreateQuote(ctx, bitfs.FileQuoteTerms{SeedHash: seedHash.Bytes(), BuyerPubkey: buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: uint64(len(fileBytes)), QuoteExpiresAtUnix: now.Add(time.Hour).Unix(), SupportedArbiterPubkeysCBOR: arbiters}, filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("create fixture quote: %w", err)
	}
	if _, err := buyerWorkflow.AcceptQuote(ctx, quote); err != nil {
		return nil, fmt.Errorf("accept fixture quote: %w", err)
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	// 下面按 002 的两阶段顺序建立 opening：买方构造请求并得到自己的本地
	// opening state，卖方预签并返回本地 presign proof，买方凭 0201 私有
	// 状态验收响应，最后才交付资金交易。所有中间值都由 fixture 显式持有。
	funding, err := buildFundingTx(buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed())
	if err != nil {
		return nil, err
	}
	preparation, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding, ExpiryLockTime: uint32(now.Add(time.Hour).Unix()), MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		return nil, fmt.Errorf("prepare fixture opening: %w", err)
	}
	presignResult, err := sellerWorkflow.PresignPoolOpening(ctx, preparation.Request)
	if err != nil {
		return nil, fmt.Errorf("presign fixture opening: %w", err)
	}
	acceptance, err := buyerWorkflow.AcceptRefundPresign(ctx, preparation.State, presignResult.Response)
	if err != nil {
		return nil, fmt.Errorf("accept fixture refund presign: %w", err)
	}
	delivery, err := buyerWorkflow.BuildFundingTxDelivery(ctx, acceptance.Opening)
	if err != nil {
		return nil, err
	}
	fundingAcceptance, err := sellerWorkflow.AcceptPoolFunding(ctx, presignResult.Opening, delivery)
	if err != nil {
		return nil, fmt.Errorf("accept fixture funding: %w", err)
	}
	return &Fixture{
		Buyer:         buyerWorkflow,
		Seller:        sellerWorkflow,
		Arbiter:       arbiterWorkflow,
		BuyerKey:      buyerKey,
		SellerKey:     sellerKey,
		ArbiterKey:    arbiterKey,
		Quote:         quote,
		QuoteHash:     bitfs.Hash32(quoteHash),
		Seed:          seed,
		SeedHash:      seedHash,
		FileBytes:     fileBytes,
		FundingTx:     funding,
		Opening:       fundingAcceptance.Opening,
		Reference:     acceptance.Reference,
		LatestPayment: fundingAcceptance.InitialPayment,
	}, nil
}

// BuildSeedRequest 构造一条请求 seed 内容的 003 报文。报价、开池证据和最新
// 付款状态都从 fixture 字段显式传入，并设置一个相对当前时间的交付截止时间。
func (f *Fixture) BuildSeedRequest(ctx context.Context, at time.Time) (*bitfs.SignedContentRequest, error) {
	input := buyer.ContentRequestInput{
		Content:          bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: f.SeedHash.Bytes()},
		ContentSize:      1,
		DeliveryDeadline: bitfs.UnixSeconds(at.Add(30 * time.Minute).Unix()),
	}
	return f.Buyer.BuildContentRequest(ctx, f.Quote, f.Opening, f.LatestPayment, input)
}

// DeliverAndBuildPayment 串起一次完整的内容交付和支付更新：买方请求、卖方
// 构造交付（fixture 保存返回的 ContentDeliveryState）、买方验收并构造
// PaymentUpdate。返回值保留协议对象供测试断言。
func (f *Fixture) DeliverAndBuildPayment(ctx context.Context, at time.Time) (*bitfs.SignedContentRequest, *bitfs.SignedContentDelivery, *seller.ContentDeliveryState, *buyer.VerifiedDelivery, error) {
	request, err := f.BuildSeedRequest(ctx, at)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, f.Opening, f.LatestPayment, request, seller.ContentDeliveryInput{Content: append([]byte(nil), f.Seed...)})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	verified, err := f.Buyer.AcceptDelivery(ctx, f.Quote, f.Opening, f.LatestPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return request, delivery, deliveryState, verified, nil
}

// buildFundingTx 创建供内存 fixture 使用的最小资金交易。它使用零哈希作为
// 输入占位符，不代表真实可花费 UTXO；真实 JungleBus 资金交易由
// demo/internal/poolopening 负责构造。
func buildFundingTx(buyer, seller, arbiter []byte) ([]byte, error) {
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
	})
	if err != nil {
		return nil, err
	}
	transaction := tx.NewTransaction()
	zero, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		return nil, err
	}
	transaction.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	transaction.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	return transaction.Bytes(), nil
}

// loadKey 从环境变量读取十六进制私钥，并把解析错误附上变量名，方便 demo
// 在多个角色配置同时缺失时定位问题。
func loadKey(name string) (*ec.PrivateKey, error) {
	key, err := ec.PrivateKeyFromHex(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", name, err)
	}
	return key, nil
}

// envOr 返回非空环境变量，否则返回 demo 的默认值。
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
