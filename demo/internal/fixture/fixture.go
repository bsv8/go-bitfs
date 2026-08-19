// Package fixture 提供结构稳定的内存 demo fixture。
//
// 它用于学习和观察各角色工作流之间的调用关系。DemoBackend 只会解析并
// 记录交易，不是 BSV 节点，也不会把交易广播到真实网络。
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

// Signer 把 SDK 私钥包装成 go-bitfs workflow 所需的 Signer 接口。
// 私钥只在 fixture 内部使用；workflow 对外只拿到压缩公钥和 DER 签名。
type Signer struct{ Key *ec.PrivateKey }

// PublicKey 返回固定的压缩公钥，作为角色身份参与协议绑定。
func (s Signer) PublicKey(context.Context) ([]byte, error) { return s.Key.PubKey().Compressed(), nil }

// Sign 对 workflow 传入的摘要签名，并只返回序列化后的 DER 签名。
func (s Signer) Sign(_ context.Context, digest []byte) ([]byte, error) {
	signature, err := s.Key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

// QuoteStore 是报价的内存存储。key 使用报价条款的规范哈希，保存时复制
// 报价对象，避免调用方随后修改切片而改变 store 中的内容。
type QuoteStore struct {
	Quotes map[bitfs.Hash32]*bitfs.SignedFileQuote
}

// SaveQuote 根据 TermsCBOR 计算报价身份，并保存报价的独立副本。
func (s *QuoteStore) SaveQuote(_ context.Context, quote *bitfs.SignedFileQuote) error {
	hash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return err
	}
	if s.Quotes == nil {
		s.Quotes = make(map[bitfs.Hash32]*bitfs.SignedFileQuote)
	}
	s.Quotes[bitfs.Hash32(hash)] = bitfs.CloneSignedFileQuote(quote)
	return nil
}

// LoadQuote 按条款哈希读取报价，并返回独立副本，防止外部修改内存存储。
func (s *QuoteStore) LoadQuote(_ context.Context, hash bitfs.Hash32) (*bitfs.SignedFileQuote, error) {
	quote := s.Quotes[hash]
	if quote == nil {
		return nil, fmt.Errorf("quote %x not found", hash)
	}
	return bitfs.CloneSignedFileQuote(quote), nil
}

// Content 同时实现买方需要的 SeedSource/ContentSink 和卖方需要的
// ContentSource。Seed 与 Block 都来自同一个本地 demo 文件的派生结果。
type Content struct {
	Seed  []byte
	Block []byte
}

// LoadSeed 返回 seed 的副本，避免 workflow 直接持有 fixture 的底层切片。
func (c Content) LoadSeed(context.Context, masterseed.Digest) ([]byte, error) {
	return append([]byte(nil), c.Seed...), nil
}

// LoadBlock 返回完整文件内容；空 Block 表示 fixture 没有配置完整内容。
func (c Content) LoadBlock(context.Context, masterseed.Digest) ([]byte, error) {
	if len(c.Block) == 0 {
		return nil, fmt.Errorf("demo block is not configured")
	}
	return append([]byte(nil), c.Block...), nil
}

// SaveVerifiedContent 在真实应用中应把验证后的内容写入持久化存储；这里
// 只为满足 ContentSink 接口，demo 不需要再保存一份数据。
func (c Content) SaveVerifiedContent(_ context.Context, _ bitfs.Hash32, payload []byte) error {
	return nil
}

// DemoBackend 接收已经由 verified node adapter 校验过的规范交易。
// 它只记录各类提交被调用的次数，并根据交易内容生成返回值，不会广播到 BSV。
type DemoBackend struct {
	Store    *pool.MemoryStore
	Updates  int
	Fundings int
	Finals   int
}

// SubmitTransaction 模拟资金交易提交。先重新解析规范交易，再返回其交易
// ID；这样测试可以观察 workflow 是否把完整交易送到了 backend。
func (b *DemoBackend) SubmitTransaction(_ context.Context, raw []byte) (pool.Hash32, error) {
	b.Fundings++
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return pool.Hash32{}, err
	}
	return poolHash(transaction.TxID().CloneBytes()), nil
}

// SubmitUpdate 模拟非终态支付提交。除了检查交易可解析，还根据资金交易
// outpoint 找到 opening proof，并用相同的多签引擎解析支付状态，最后返回
// 与交易一致的交易 ID、SpendTxID 和支付序号。
func (b *DemoBackend) SubmitUpdate(ctx context.Context, raw []byte) (*pool.UpdateAcceptance, error) {
	b.Updates++
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return nil, err
	}
	if len(transaction.Inputs) != 1 || transaction.Inputs[0].SourceTXID == nil {
		return nil, fmt.Errorf("demo update has no funding outpoint")
	}
	fundingID := poolHash(transaction.Inputs[0].SourceTXID.CloneBytes())
	proof, err := b.Store.LoadOpeningProofByFundingTxID(ctx, fundingID)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	state, err := engine.ParseNonFinalPaymentState(ctx, raw, proof)
	if err != nil {
		return nil, err
	}
	return &pool.UpdateAcceptance{TxID: poolHash(transaction.TxID().CloneBytes()), SpendTxID: state.SpendTxID, PaymentSequence: state.PaymentSequence}, nil
}

// SubmitFinal 模拟最终结算提交。DemoBackend 不判断链上确认，只验证输入是
// 规范交易并返回其交易 ID；更严格的业务校验由上游 adapter 完成。
func (b *DemoBackend) SubmitFinal(_ context.Context, raw []byte) (pool.Hash32, error) {
	b.Finals++
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return pool.Hash32{}, err
	}
	return poolHash(transaction.TxID().CloneBytes()), nil
}

// Fixture 集中保存从报价到开池完成所需的全部内存对象和中间结果。
// 后续 demo 可以直接使用 Buyer/Seller/Arbiter 继续演示内容交付、支付和仲裁，
// 不必每次重复创建密钥、报价、store 与 opening proof。
type Fixture struct {
	Buyer         *buyer.Workflow
	Seller        *seller.Workflow
	Arbiter       *arbitration.Workflow
	BuyerSigner   Signer
	SellerSigner  Signer
	ArbiterSigner Signer
	Quotes        *QuoteStore
	Pools         *pool.MemoryStore
	Content       Content
	Backend       *DemoBackend
	Quote         *bitfs.SignedFileQuote
	QuoteHash     bitfs.Hash32
	Seed          []byte
	SeedHash      masterseed.Digest
	FundingTx     []byte
	Opening       *pool.OpeningProof
	Reference     *pool.Reference
}

// New 创建一套已经完成 002 开池的内存状态。
//
// 初始化顺序与真实业务流程一致：读取文件并生成 seed，加载三方密钥，创建
// store/backend/workflow，卖方创建报价、买方接受报价，然后依次执行退款预签、
// 买方验收、资金交付和卖方验收。后续 003、004、005、006、007 demo 可以直接
// 从这个稳定的起点继续。
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
	quotes := &QuoteStore{Quotes: make(map[bitfs.Hash32]*bitfs.SignedFileQuote)}
	pools, err := pool.NewMemoryStore()
	if err != nil {
		return nil, err
	}
	backend := &DemoBackend{Store: pools}
	content := Content{Seed: seed, Block: fileBytes}
	buyerSigner := Signer{Key: buyerKey}
	sellerSigner := Signer{Key: sellerKey}
	arbiterSigner := Signer{Key: arbiterKey}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: sellerSigner, Quotes: quotes, Pools: pools, Pending: pools, Content: content, Backend: backend})
	if err != nil {
		return nil, err
	}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: buyerSigner, Quotes: quotes, Pools: pools, Backend: backend, SeedSource: content, ContentSink: content})
	if err != nil {
		return nil, err
	}
	arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{Signer: arbiterSigner})
	if err != nil {
		return nil, err
	}
	// 报价先由卖方创建，再由买方接受；这个顺序让后续内容请求能够引用
	// 已保存且已接受的报价哈希。
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
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
	// 下面按 002 的两阶段顺序建立 opening：买方先生成退款预签请求，卖方
	// 补签，买方把本地 FundingTx 与响应合并保存，最后才交付资金交易。
	funding, err := buildFundingTx(buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed())
	if err != nil {
		return nil, err
	}
	openingRequest, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding, PoolOutputIndex: 0, ExpiryLockTime: uint32(now.Add(time.Hour).Unix()), MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		return nil, fmt.Errorf("prepare fixture opening: %w", err)
	}
	openingResponse, err := sellerWorkflow.PresignPoolOpening(ctx, openingRequest)
	if err != nil {
		return nil, fmt.Errorf("presign fixture opening: %w", err)
	}
	ref, err := buyerWorkflow.AcceptRefundPresign(ctx, openingRequest, openingResponse, funding)
	if err != nil {
		return nil, fmt.Errorf("accept fixture refund presign: %w", err)
	}
	delivery, err := buyerWorkflow.BuildFundingTxDelivery(funding)
	if err != nil {
		return nil, err
	}
	opening, err := sellerWorkflow.AcceptPoolFunding(ctx, delivery)
	if err != nil {
		return nil, fmt.Errorf("accept fixture funding: %w", err)
	}
	return &Fixture{Buyer: buyerWorkflow, Seller: sellerWorkflow, Arbiter: arbiterWorkflow, BuyerSigner: buyerSigner, SellerSigner: sellerSigner, ArbiterSigner: arbiterSigner, Quotes: quotes, Pools: pools, Content: content, Backend: backend, Quote: quote, QuoteHash: bitfs.Hash32(quoteHash), Seed: seed, SeedHash: seedHash, FundingTx: funding, Opening: opening, Reference: ref}, nil
}

// BuildSeedRequest 构造一条请求 seed 内容的 003 报文。请求引用 New 中已经
// 接受的报价和开池 SpendTxID，并设置一个相对当前时间的交付截止时间。
func (f *Fixture) BuildSeedRequest(ctx context.Context) (*bitfs.SignedContentRequest, error) {
	return f.Buyer.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: f.QuoteHash, SpendTxID: f.Reference.SpendTxID, Content: bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: f.SeedHash.Bytes()}, ContentSize: 1, DeliveryDeadline: bitfs.UnixSeconds(time.Now().Add(30 * time.Minute).Unix())})
}

// DeliverAndBuildPayment 串起一次完整的内容交付和支付更新：买方请求、卖方
// 交付、买方验收并构造 PaymentUpdate。返回值保留三个协议对象供测试断言。
func (f *Fixture) DeliverAndBuildPayment(ctx context.Context) (*bitfs.SignedContentRequest, *bitfs.SignedContentDelivery, *pool.PaymentUpdate, error) {
	request, err := f.BuildSeedRequest(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	delivery, err := f.Seller.DeliverRequestedContent(ctx, request)
	if err != nil {
		return nil, nil, nil, err
	}
	update, err := f.Buyer.AcceptDelivery(ctx, request, delivery)
	if err != nil {
		return nil, nil, nil, err
	}
	return request, delivery, update, nil
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

// poolHash 把交易 ID 的字节复制到 pool.Hash32，作为 fixture backend 的返回值。
func poolHash(raw []byte) pool.Hash32 {
	var value pool.Hash32
	copy(value[:], raw)
	return value
}

var _ pool.PoolBackend = (*DemoBackend)(nil)
var _ buyer.QuoteStore = (*QuoteStore)(nil)
var _ seller.QuoteStore = (*QuoteStore)(nil)
var _ seller.ContentSource = Content{}
var _ buyer.SeedSource = Content{}
var _ buyer.ContentSink = Content{}
