// Package fixture 提供结构稳定的内存 demo fixture。
//
// 它作为“调用方应用”显式持有并传递全部本地状态：exact wire 字节（先保存后
// 发送）、买卖双侧 checkpoint、最新付款状态和内容字节都保存在 Fixture 自身
// 字段里，每一步都显式传给角色 API。它不创建任何 Store 或节点 backend，也不
// 代表 BSV 节点；广播与持久化在真实应用中由调用方实现。
//
// 时间与高度全部来自显式 Facts{Now, BlockHeight}；SDK 不读取系统时钟。
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
	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

// blockHeight 是调用方认可并提供的当前区块高度；SDK 不查询节点，demo 用它
// 组装每一步的 Facts。
const blockHeight protocol.BlockHeight = 900000

// Fixture 显式保存从报价到开池完成所需的全部对象和中间结果。
// 它扮演调用方应用的本地状态存储：后续 003–008 演示把这些字段逐个显式传回
// 角色 workflow，而不是依赖任何 SDK 内部加载行为。
type Fixture struct {
	Buyer      *buyer.Workflow   // 买方角色 API（001–006、008）
	Seller     *seller.Workflow  // 卖方角色 API（001–007）
	Arbiter    *arbiter.Workflow // 仲裁方角色 API（007 托管签署、008 取回应答）
	BuyerKey   *ec.PrivateKey    // 买方私钥（仅用于派生公钥与本地资金交易签名）
	SellerKey  *ec.PrivateKey    // 卖方私钥
	ArbiterKey *ec.PrivateKey    // 仲裁方私钥

	// ---- 001 报价 ----
	QuoteRaw      []byte                   // exact Kind 1 bytes（应用先持久化再发送）
	VerifiedQuote *content.VerifiedQuote   // 买方验收快照（不可变 verified value）
	SignedQuote   *content.SignedFileQuote // 卖方持有的 exact 已签报价（DeliverContent 输入）
	Seed          []byte                   // MasterSeed 原文（可交付内容之一）
	SeedHash      []byte                   // SHA-256(MasterSeed)，纯 seed 批次的内容哈希
	FileBytes     []byte                   // 源文件字节（块划分与哈希来源）

	// ---- 002 开池（双侧各自保存）----
	FundingTransactionRaw []byte                    // 买方私密资金交易原文（0204 前不进入报文）
	ExpiryLockTime        protocol.RefundLockTime   // 退款交易到期锁定时间（低于阈值按区块高解释）
	BuyerOpeningProofCBOR []byte                    // canonical opening proof 编码（买方恢复池 checkpoint 用）
	BuyerOpening          *buyer.OpeningCheckpoint  // 买方开池 checkpoint（Kind2 + 私有资金交易）
	BuyerPool             *buyer.PoolCheckpoint     // 买方当前池 checkpoint（opening + 最新付款状态）
	SellerOpening         *seller.OpeningCheckpoint // 卖方预签 checkpoint
	SellerPool            *seller.PoolCheckpoint    // 卖方当前池 checkpoint

	// LatestPayment 是双方共享的“节点已确认”最新付款状态；demo 中由卖方
	// CompletePayment 的合并结果直接同步给双方使用。
	LatestPayment *pool.PaymentState

	// authorizations 是应用侧付款授权索引：
	// PaymentAuthorizationID = SHA-256(exact payment_authorization_cbor) ->
	// exact 已签 Kind 5 授权 checkpoint。真实应用应使用数据库唯一索引并
	// 持久化该映射；哈希是内容寻址键，不可解码出池 ID 或金额。
	authorizations map[protocol.PaymentAuthorizationID]*buyer.AuthorizationCheckpoint
}

// Facts 以给定时刻为唯一时间事实组装一份显式事实集（高度为 demo 固定值）。
func (f *Fixture) Facts(at time.Time) protocol.Facts {
	return protocol.Facts{Now: at.UTC(), BlockHeight: blockHeight}
}

// New 创建一套已经完成 002 开池的显式状态。
//
// 初始化顺序与真实业务流程一致：读取文件并生成 seed，加载三方密钥并经
// protocol.NewPrivateKeySigner 构造角色 workflow，卖方创建报价并持久化 exact
// 字节，买方从字节验收，然后依次执行退款预签、买方验收、资金交付和卖方验收。
// 每一步都是“load → 角色 API → persist（变量赋值）→ send”。
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
	seedHash := masterseed.Sum256(seed).Bytes()

	// 三个角色使用独立私钥；Signer 经 protocol.NewPrivateKeySigner 进入，
	// 协议字段只使用各自的压缩公钥。
	buyerKey, sellerKey, arbiterKey, err := loadThreeKeys()
	if err != nil {
		return nil, err
	}
	signers, err := newSigners(buyerKey, sellerKey, arbiterKey)
	if err != nil {
		return nil, err
	}
	buyerWorkflow, err := buyer.NewWorkflow(signers.buyer)
	if err != nil {
		return nil, fmt.Errorf("create buyer workflow: %w", err)
	}
	sellerWorkflow, err := seller.NewWorkflow(signers.seller)
	if err != nil {
		return nil, fmt.Errorf("create seller workflow: %w", err)
	}
	arbiterWorkflowInst, err := arbiter.NewWorkflow(signers.arbiter)
	if err != nil {
		return nil, fmt.Errorf("create arbiter workflow: %w", err)
	}

	now := time.Now().UTC()
	facts := protocol.Facts{Now: now, BlockHeight: blockHeight}

	buyerPubKey, err := protocol.PublicKeyFromBytes(buyerKey.PubKey().Compressed())
	if err != nil {
		return nil, fmt.Errorf("parse buyer public key: %w", err)
	}
	sellerPubKey, err := protocol.PublicKeyFromBytes(sellerKey.PubKey().Compressed())
	if err != nil {
		return nil, fmt.Errorf("parse seller public key: %w", err)
	}

	f := &Fixture{
		Buyer:          buyerWorkflow,
		Seller:         sellerWorkflow,
		Arbiter:        arbiterWorkflowInst,
		BuyerKey:       buyerKey,
		SellerKey:      sellerKey,
		ArbiterKey:     arbiterKey,
		Seed:           seed,
		SeedHash:       seedHash,
		FileBytes:      fileBytes,
		authorizations: make(map[protocol.PaymentAuthorizationID]*buyer.AuthorizationCheckpoint),
	}

	// ---- 001：卖方创建报价 → 应用持久化 exact bytes → 买方验收。----
	quoteResult, err := sellerWorkflow.CreateQuote(ctx, facts, seller.QuoteDraft{
		SeedHash:                   seedHash,
		BuyerPublicKey:             buyerPubKey,
		SeedPriceSatoshis:          100,
		FullBlockPriceSatoshis:     1000,
		FileSizeBytes:              uint64(len(fileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(now.Add(time.Hour).Unix()),
		SupportedArbiterPublicKeys: []protocol.PublicKey{mustTypedKey(arbiterKey.PubKey().Compressed())},
		RecommendedFilename:        filepath.Base(filePath),
	})
	if err != nil {
		return nil, fmt.Errorf("create fixture quote: %w", err)
	}
	f.QuoteRaw = quoteResult.Outbound.Bytes() // persist-before-send：先保存 exact Artifact 字节
	sellerQuoteArtifact, err := wire.ParseAs(wire.FileQuote, f.QuoteRaw)
	if err != nil {
		return nil, fmt.Errorf("parse persisted quote artifact: %w", err)
	}
	f.SignedQuote, err = wire.DecodeFileQuote(sellerQuoteArtifact)
	if err != nil {
		return nil, fmt.Errorf("decode fixture quote for seller side: %w", err)
	}
	f.VerifiedQuote, err = buyerWorkflow.AcceptQuote(facts, f.QuoteRaw)
	if err != nil {
		return nil, fmt.Errorf("accept fixture quote: %w", err)
	}

	// ---- 002：两阶段开池，全部中间值由 fixture 显式持有。----
	funding, err := buildFundingTx(buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed())
	if err != nil {
		return nil, err
	}
	f.FundingTransactionRaw = funding
	f.ExpiryLockTime = protocol.RefundLockTime(now.Add(time.Hour).Unix())

	prepared, err := buyerWorkflow.PreparePoolOpening(ctx, facts, buyer.PrepareOpeningCommand{
		Quote:                           f.VerifiedQuote,
		FundingTransactionRaw:           funding,
		ExpiryLockTime:                  f.ExpiryLockTime,
		MinerFeeRateSatoshisPerKilobyte: protocol.SatoshisPerKilobyte(1),
		SellerPublicKey:                 sellerPubKey,
		ArbiterPublicKey:                mustPublicKey(arbiterKey.PubKey().Compressed()),
	})
	if err != nil {
		return nil, fmt.Errorf("prepare fixture opening: %w", err)
	}
	f.BuyerOpening = prepared.Checkpoint // 应用先持久化 checkpoint 再发送 Kind 2

	presignResult, err := sellerWorkflow.PreparePoolOpening(ctx, facts, prepared.Outbound.Bytes())
	if err != nil {
		return nil, fmt.Errorf("presign fixture opening: %w", err)
	}
	f.SellerOpening = presignResult.Checkpoint // 应用先持久化预签证据再发送 Kind 3

	completed, err := buyerWorkflow.CompletePoolOpening(ctx, f.BuyerOpening, presignResult.Outbound.Bytes())
	if err != nil {
		return nil, fmt.Errorf("accept fixture refund presign: %w", err)
	}
	f.BuyerPool = completed.InitialPool
	openingProofCBOR, err := pool.EncodeOpeningProof(f.BuyerPool.Opening())
	if err != nil {
		return nil, fmt.Errorf("encode canonical opening proof: %w", err)
	}
	f.BuyerOpeningProofCBOR = openingProofCBOR

	deliveryArtifact, err := buyerWorkflow.PrepareFundingDelivery(f.BuyerPool)
	if err != nil {
		return nil, fmt.Errorf("build funding delivery: %w", err)
	}
	fundingVerification, err := sellerWorkflow.VerifyFundingDelivery(f.SellerOpening, deliveryArtifact.Bytes())
	if err != nil {
		return nil, fmt.Errorf("accept fixture funding: %w", err)
	}
	f.SellerPool = fundingVerification.InitialPool
	f.LatestPayment = fundingVerification.InitialPool.Payment()
	return f, nil
}

// signerSet 聚合三个角色的受约束 Signer。
type signerSet struct {
	buyer   protocol.Signer
	seller  protocol.Signer
	arbiter protocol.Signer
}

// newSigners 把三方私钥包装成 SDK 唯一入口要求的 PrivateKeySigner。
func newSigners(buyerKey, sellerKey, arbiterKey *ec.PrivateKey) (*signerSet, error) {
	buyerSigner, err := protocol.NewPrivateKeySigner(buyerKey)
	if err != nil {
		return nil, fmt.Errorf("create buyer signer: %w", err)
	}
	sellerSigner, err := protocol.NewPrivateKeySigner(sellerKey)
	if err != nil {
		return nil, fmt.Errorf("create seller signer: %w", err)
	}
	arbiterSigner, err := protocol.NewPrivateKeySigner(arbiterKey)
	if err != nil {
		return nil, fmt.Errorf("create arbiter signer: %w", err)
	}
	return &signerSet{buyer: buyerSigner, seller: sellerSigner, arbiter: arbiterSigner}, nil
}

// mustPublicKey 把压缩公钥字节解析成协议 PublicKey 类型；demo 的密钥来自本
// 地配置，解析失败直接 panic 以暴露配置错误。
func mustPublicKey(compressed []byte) protocol.PublicKey {
	publicKey, err := protocol.PublicKeyFromBytes(compressed)
	if err != nil {
		panic(fmt.Sprintf("fixture: parse compressed public key: %v", err))
	}
	return publicKey
}

// BlockCount 返回报价文件按协议块长划分的块数（含尾块）。
func (f *Fixture) BlockCount() uint64 {
	return masterseed.BlockCountForSourceSize(uint64(len(f.FileBytes)))
}

// BlockPayload 返回文件第 index 个块（0 起）的原始字节；尾块为剩余字节。
func (f *Fixture) BlockPayload(index uint64) ([]byte, error) {
	count := f.BlockCount()
	if index >= count {
		return nil, fmt.Errorf("block index %d outside fixture file (%d blocks)", index, count)
	}
	start := index * masterseed.BlockSize
	end := start + masterseed.BlockSize
	if end > uint64(len(f.FileBytes)) {
		end = uint64(len(f.FileBytes))
	}
	return append([]byte(nil), f.FileBytes[start:end]...), nil
}

// BlockHashes 返回前 count 个块的有序哈希列表，与 seed 中对应位置一致。
func (f *Fixture) BlockHashes(count int) ([][]byte, error) {
	if uint64(count) > f.BlockCount() {
		return nil, fmt.Errorf("requested %d blocks exceed fixture file (%d blocks)", count, f.BlockCount())
	}
	hashes := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		payload, err := f.BlockPayload(uint64(index))
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, masterseed.Sum256(payload).Bytes())
	}
	return hashes, nil
}

// PurchaseRound 是一轮完整 003→004→005 的双侧产物：三个 exact wire Artifact
// 字节都遵循 persist-before-send（先赋值保存再交给对端角色 API）。
type PurchaseRound struct {
	Request    *buyer.RequestContentResult     // 003 结果（含 AuthorizationCheckpoint）
	Kind5Raw   []byte                          // exact Kind 5 bytes（先保存后发送）
	Delivery   *seller.DeliveryCheckpoint      // 卖方交付 checkpoint（验收 005 时回传）
	Kind6Raw   []byte                          // exact Kind 6 bytes
	Payment    *buyer.PaymentPreparationResult // 005 买方最小凭证构造结果
	Kind7Raw   []byte                          // exact Kind 7 bytes
	PaymentID  protocol.PaymentAuthorizationID // 本批次授权 ID（路由键）
	AcceptedTx *pool.VerifiedSignedTransaction // 卖方合并后的完整付款交易
}

// RequestSeed 只执行 003：买方从当前池状态请求 seed 内容。返回值由调用方
// 决定何时发送；fixture 同时把授权 checkpoint 存入付款授权索引。
func (f *Fixture) RequestSeed(ctx context.Context, at time.Time) (*PurchaseRound, error) {
	request, err := f.Buyer.RequestContent(ctx, f.Facts(at), buyer.RequestContentCommand{
		Quote:            f.VerifiedQuote,
		Pool:             f.BuyerPool,
		ContentHashes:    [][]byte{append([]byte(nil), f.SeedHash...)},
		DeliveryDeadline: content.UnixSeconds(at.Add(30 * time.Minute).Unix()),
	})
	if err != nil {
		return nil, fmt.Errorf("buyer.RequestContent: %w", err)
	}
	round := &PurchaseRound{Request: request, PaymentID: request.AuthorizationID}
	round.Kind5Raw = request.Outbound.Bytes() // 应用先持久化 exact Kind 5 与 checkpoint 再发送
	f.authorizations[request.AuthorizationID] = request.Checkpoint
	return round, nil
}

// DeliverRound 对已构造的 003 执行卖方交付（004）。调用方必须已保存
// round.Kind5Raw 与 round.Request.Checkpoint。
func (f *Fixture) DeliverRound(ctx context.Context, at time.Time, round *PurchaseRound, payloads [][]byte) error {
	delivery, err := f.Seller.DeliverContent(ctx, f.Facts(at), seller.DeliveryCommand{
		Quote:           f.SignedQuote,
		Pool:            f.SellerPool,
		RequestRaw:      round.Kind5Raw,
		ContentPayloads: payloads,
	})
	if err != nil {
		return fmt.Errorf("seller.DeliverContent: %w", err)
	}
	round.Delivery = delivery.Checkpoint // 应用先保存 payload 与 checkpoint 再发送 Kind 6
	round.Kind6Raw = delivery.Outbound.Bytes()
	return nil
}

// PayRound 对已交付批次执行买方验收与最小 005 构造。纯 seed 批次无需 seed。
func (f *Fixture) PayRound(ctx context.Context, at time.Time, round *PurchaseRound) error {
	payment, err := f.Buyer.VerifyDeliveryAndPreparePayment(ctx, f.Facts(at), buyer.VerifyDeliveryCommand{
		Quote:       f.VerifiedQuote,
		Pool:        f.BuyerPool,
		Request:     round.Request.Checkpoint,
		DeliveryRaw: round.Kind6Raw,
	})
	if err != nil {
		return fmt.Errorf("buyer.VerifyDeliveryAndPreparePayment: %w", err)
	}
	round.Payment = payment
	round.Kind7Raw = payment.Outbound.Bytes() // 先持久化 payloads 与 Result 再发送 Kind 7
	return nil
}

// CompleteRound 让卖方按 PaymentAuthorizationID 取回原始签名 003 并完成付款；
// 成功后双方本地状态推进到同一确认 checkpoint。
func (f *Fixture) CompleteRound(ctx context.Context, at time.Time, round *PurchaseRound) error {
	authorization, ok := f.authorizations[round.PaymentID]
	if !ok || authorization == nil {
		return fmt.Errorf("no signed content request indexed under authorization id %s", round.PaymentID.String())
	}
	completedPay, err := f.Seller.CompletePayment(ctx, f.Facts(at), seller.PaymentCommand{
		Pool:       f.SellerPool,
		Request:    authorization.Request(),
		UpdateRaw:  round.Kind7Raw,
		Checkpoint: round.Delivery,
	})
	if err != nil {
		return fmt.Errorf("seller.CompletePayment: %w", err)
	}
	round.AcceptedTx = completedPay.Transaction
	f.advanceSellerPool(completedPay.NextPool)
	return f.advanceBuyerPoolFromTx(completedPay.Transaction.RawTx())
}

// RunSeedPurchase 是 03–07 各演示使用的便捷组合：一轮完整 seed 购买
// （003→004→005），并把双方 checkpoint 推进到新的确认状态。
func (f *Fixture) RunSeedPurchase(ctx context.Context, at time.Time) (*PurchaseRound, error) {
	round, err := f.RequestSeed(ctx, at)
	if err != nil {
		return nil, err
	}
	if err := f.DeliverRound(ctx, at, round, [][]byte{append([]byte(nil), f.Seed...)}); err != nil {
		return nil, err
	}
	if err := f.PayRound(ctx, at, round); err != nil {
		return nil, err
	}
	if err := f.CompleteRound(ctx, at, round); err != nil {
		return nil, err
	}
	return round, nil
}

// LookupPaymentAuthorization 演示应用的付款授权查找：用最小 005 携带的
// PaymentAuthorizationID 取回精确的原始签名 003。哈希不可解码，找不到就
// 必须拒绝或请求对端重发，不能扫描池或按连接猜池。
func (f *Fixture) LookupPaymentAuthorization(paymentAuthorizationID protocol.PaymentAuthorizationID) (*content.SignedContentRequest, error) {
	checkpoint, ok := f.authorizations[paymentAuthorizationID]
	if !ok || checkpoint == nil || checkpoint.Request() == nil {
		return nil, fmt.Errorf("no signed content request indexed under authorization id %s", paymentAuthorizationID.String())
	}
	return checkpoint.Request(), nil
}

// advanceSellerPool 把卖方侧 checkpoint 推进到合并后的新状态。
func (f *Fixture) advanceSellerPool(next *seller.PoolCheckpoint) {
	f.SellerPool = next
	f.LatestPayment = next.Payment()
}

// advanceBuyerPoolFromTx 用 canonical opening proof + 完整付款 raw tx 恢复
// 买方侧池 checkpoint（Restore 全量重验，不信任任何派生字段）。
func (f *Fixture) advanceBuyerPoolFromTx(paymentRawTx []byte) error {
	next, err := buyer.RestorePoolCheckpoint(f.BuyerOpeningProofCBOR, paymentRawTx)
	if err != nil {
		return fmt.Errorf("buyer.RestorePoolCheckpoint: %w", err)
	}
	f.BuyerPool = next
	return nil
}

// buildFundingTx 创建供内存 fixture 使用的最小资金交易。它使用零哈希作为
// 输入占位符，不代表真实可花费 UTXO；真实 JungleBus 资金交易由
// demo/internal/poolopening 负责构造。
func buildFundingTx(buyerPub, sellerPub, arbiterPub []byte) ([]byte, error) {
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPublicKey: buyerPub, SellerPublicKey: sellerPub, ArbiterPublicKey: arbiterPub,
	})
	if err != nil {
		return nil, err
	}
	transaction := tx.NewTransaction()
	zero, err := chainhash.NewHash(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		return nil, err
	}
	transaction.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	transaction.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	return transaction.Bytes(), nil
}

// loadThreeKeys 从环境变量读取三方十六进制私钥，并把解析错误附上变量名，
// 方便 demo 在多个角色配置同时缺失时定位问题。
func loadThreeKeys() (*ec.PrivateKey, *ec.PrivateKey, *ec.PrivateKey, error) {
	buyerKey, err := loadKey("BUYER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, nil, nil, err
	}
	sellerKey, err := loadKey("SELLER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, nil, nil, err
	}
	arbiterKey, err := loadKey("ARBITER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, nil, nil, err
	}
	return buyerKey, sellerKey, arbiterKey, nil
}

// loadKey 从环境变量读取十六进制私钥；不打印原始值，避免私钥进入日志。
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

// mustTypedKey 把压缩公钥字节转换为强类型公钥；fixture 内的密钥均来自固定
// 解析的私钥，转换失败属于编程错误。
func mustTypedKey(raw []byte) protocol.PublicKey {
	typed, err := protocol.PublicKeyFromBytes(raw)
	if err != nil {
		panic(fmt.Sprintf("fixture public key: %v", err))
	}
	return typed
}
