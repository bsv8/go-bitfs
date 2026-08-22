// Package poolopening 提供细粒度 002 开池 demo 共用的应用组装、交易辅助逻辑
// 和演示私有本地 checkpoint。
//
// go-bitfs SDK 是无状态协议库：它不加载、不保存、不广播任何状态。本包扮演
// “调用方应用”，自己持有买方/卖方会话（只含 Signer），并用自己的 JSON
// checkpoint 按 RefundTemplateTxID 保存跨进程需要的本地角色状态。
//
// 注意：这里的 checkpoint 只是让多个独立示例命令能够衔接运行的示例实现。
// 它不是 SDK 能力，不承诺生产安全，不提供文件锁、事务、跨进程并发或崩溃
// 恢复保证；真实应用应使用自己的数据库与一致性策略。
package poolopening

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/internal/junglebus"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

const defaultStateDir = "demo/.state"

// BuyerSession 是单个 002 命令需要的买方应用组装结果。
// buyerKey 只留在本包内部用于派生地址和签名；公开的三个 PubKey 字段供
// 开池交易构造使用。跨进程状态由本包的 checkpoint 函数保存，不经过 SDK。
type BuyerSession struct {
	Buyer         *buyer.Workflow
	buyerKey      *ec.PrivateKey
	BuyerPubKey   []byte
	SellerPubKey  []byte
	ArbiterPubKey []byte
}

// SellerSession 是单个 002 命令需要的卖方应用组装结果。卖方的预签证据等
// 本地状态同样通过 checkpoint 显式保存和恢复。
type SellerSession struct {
	Seller *seller.Workflow
}

// NewBuyer 创建只含签名能力的买方 workflow，并派生开池交易所需的公钥。
func NewBuyer(ctx context.Context) (*BuyerSession, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	// 先加载所有角色密钥，尽早失败，避免创建了部分状态文件后才发现配置
	// 不完整。
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
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: buyerKey})
	if err != nil {
		return nil, fmt.Errorf("create buyer workflow: %w", err)
	}
	buyerPubKey := buyerKey.PubKey().Compressed()
	return &BuyerSession{
		Buyer:         buyerWorkflow,
		buyerKey:      buyerKey,
		BuyerPubKey:   append([]byte(nil), buyerPubKey...),
		SellerPubKey:  append([]byte(nil), sellerKey.PubKey().Compressed()...),
		ArbiterPubKey: append([]byte(nil), arbiterKey.PubKey().Compressed()...),
	}, nil
}

// NewSeller 创建只含签名能力的卖方 workflow。卖方只需要自己的私钥；买方和
// 仲裁方公钥已经随 0201 请求进入协议输入。
func NewSeller(ctx context.Context) (*SellerSession, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	sellerKey, err := loadKey("SELLER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: sellerKey})
	if err != nil {
		return nil, fmt.Errorf("create seller workflow: %w", err)
	}
	return &SellerSession{Seller: sellerWorkflow}, nil
}

// OpeningInput 根据买方已经选定的真实 UTXO 资金交易构造 002 开池输入。
// 退款有效期设置为当前 UTC 时间后一小时；FundingTx 原文只会进入买方自己的
// 本地 checkpoint，在 0204 之前不会进入发给卖方的报文。
func (session *BuyerSession) OpeningInput(fundingTx []byte, minerFeeRateSatPerKB uint64) pool.OpeningInput {
	return pool.OpeningInput{
		FundingTx:            append([]byte(nil), fundingTx...),
		ExpiryLockTime:       uint32(time.Now().UTC().Add(time.Hour).Unix()),
		MinerFeeRateSatPerKB: minerFeeRateSatPerKB,
		SellerPubKey:         append([]byte(nil), session.SellerPubKey...),
		ArbiterPubKey:        append([]byte(nil), session.ArbiterPubKey...),
	}
}

// FundingAddresses 保存买方 P2PKH 地址的主网和测试网变体。
// 地址会在访问 JungleBus 之前本地派生，即使后续查询失败，demo 仍能显示
// 当前网络对应的充值地址。
type FundingAddresses struct {
	Network         junglebus.Network
	MainnetAddress  string
	TestnetAddress  string
	SelectedAddress string
}

// FundingAddresses 派生买方主网/测试网地址，并根据 BITFS_NETWORK 选择本次
// 查询使用的地址。该方法纯本地运行，不会访问 JungleBus。
func (session *BuyerSession) FundingAddresses() (FundingAddresses, error) {
	if session == nil || session.buyerKey == nil {
		return FundingAddresses{}, errors.New("buyer session is required")
	}
	network, err := junglebus.ParseNetwork(os.Getenv("BITFS_NETWORK"))
	if err != nil {
		return FundingAddresses{}, err
	}
	mainnetAddress, err := script.NewAddressFromPublicKey(session.buyerKey.PubKey(), true)
	if err != nil {
		return FundingAddresses{}, fmt.Errorf("derive buyer mainnet address: %w", err)
	}
	testnetAddress, err := script.NewAddressFromPublicKey(session.buyerKey.PubKey(), false)
	if err != nil {
		return FundingAddresses{}, fmt.Errorf("derive buyer testnet address: %w", err)
	}
	selectedAddress := mainnetAddress.AddressString
	if network == junglebus.Testnet {
		selectedAddress = testnetAddress.AddressString
	}
	return FundingAddresses{
		Network:         network,
		MainnetAddress:  mainnetAddress.AddressString,
		TestnetAddress:  testnetAddress.AddressString,
		SelectedAddress: selectedAddress,
	}, nil
}

// FundingPreparation 是买方本地的 JungleBus 查询和资金交易构造结果。
// 它包含调试信息和原始交易，不会直接编码成任何 002 网络报文。
type FundingPreparation struct {
	Client               *junglebus.Client
	Network              junglebus.Network
	MainnetAddress       string
	TestnetAddress       string
	SelectedAddress      string
	UTXOs                []junglebus.UTXO
	SelectedUTXO         junglebus.UTXO
	PoolOutputSatoshis   uint64
	MinerFeeRateSatPerKB uint64
	FundingFeeSatoshis   uint64
	MinerFeeRateSource   string
	RawTx                []byte
}

// PrepareFunding 访问 JungleBus，选择真实可用 UTXO，并构造一笔规范、已签名
// 的资金交易。数据提供方调用被限制在 demo 层，go-bitfs workflow 本身不依赖
// JungleBus 客户端。
func (session *BuyerSession) PrepareFunding(ctx context.Context) (*FundingPreparation, error) {
	if session == nil || session.buyerKey == nil {
		return nil, errors.New("buyer session is required")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	// 地址派生和网络选择先于 HTTP 查询执行，保证后续请求使用同一网络和地址。
	addresses, err := session.FundingAddresses()
	if err != nil {
		return nil, err
	}
	client, err := junglebus.NewClient()
	if err != nil {
		return nil, err
	}
	utxos, err := client.ListUTXOs(ctx, addresses.SelectedAddress, addresses.Network)
	if err != nil {
		return nil, err
	}
	// pool 输出金额和费率均可由环境变量覆盖；JungleBus 不提供费率推荐，
	// 所以未配置时采用 demo 默认的 100 sat/KB。
	poolOutputSatoshis, err := envUint64("DEMO_02_POOL_OUTPUT_SAT", 20000)
	if err != nil {
		return nil, err
	}
	if poolOutputSatoshis == 0 {
		return nil, errors.New("DEMO_02_POOL_OUTPUT_SAT must be positive")
	}
	const defaultDemoMinerFeeRateSatPerKB uint64 = 100
	minerFeeRateSource := "demo default"
	if strings.TrimSpace(os.Getenv("DEMO_02_MINER_FEE_RATE_SAT_PER_KB")) != "" {
		minerFeeRateSource = "environment override"
	}
	minerFeeRateSatPerKB, err := envUint64("DEMO_02_MINER_FEE_RATE_SAT_PER_KB", defaultDemoMinerFeeRateSatPerKB)
	if err != nil {
		return nil, fmt.Errorf("load funding transaction miner fee rate: %w", err)
	}
	if minerFeeRateSatPerKB == 0 {
		return nil, errors.New("DEMO_02_MINER_FEE_RATE_SAT_PER_KB must be positive")
	}
	// 选择器会排除已被内存池花费或金额不足的候选，并在构造失败时尝试下一个
	// UTXO；成功返回的 rawTx 已经包含买方输入签名和找零输出。
	selected, rawTx, err := selectAndBuildFundingTx(session.buyerKey, session.SellerPubKey, session.ArbiterPubKey, utxos, poolOutputSatoshis, minerFeeRateSatPerKB, addresses.Network == junglebus.Mainnet)
	if err != nil {
		return nil, err
	}
	fundingFeeSatoshis, err := fundingTransactionFee(rawTx, selected.Satoshis)
	if err != nil {
		return nil, fmt.Errorf("calculate funding transaction fee: %w", err)
	}
	// 对最终字节重新计算矿工费，而不是使用估算值，便于日志准确反映实际
	// 输入金额、池输出和找零之间的差额。
	return &FundingPreparation{
		Client:               client,
		Network:              addresses.Network,
		MainnetAddress:       addresses.MainnetAddress,
		TestnetAddress:       addresses.TestnetAddress,
		SelectedAddress:      addresses.SelectedAddress,
		UTXOs:                append([]junglebus.UTXO(nil), utxos...),
		SelectedUTXO:         selected,
		PoolOutputSatoshis:   poolOutputSatoshis,
		MinerFeeRateSatPerKB: minerFeeRateSatPerKB,
		FundingFeeSatoshis:   fundingFeeSatoshis,
		MinerFeeRateSource:   minerFeeRateSource,
		RawTx:                append([]byte(nil), rawTx...),
	}, nil
}

var errFundingUTXOTooSmall = errors.New("funding UTXO is too small")

// selectAndBuildFundingTx 先验证并筛选 JungleBus 返回的候选 UTXO，再按稳定
// 规则排序：优先已确认、金额较小、txid 较小且 vout 较小的输出。
//
// 排序后逐个尝试构造交易。某个输出因手续费不足而失败时可以换下一个，只有
// 非金额类错误才立即返回，避免隐藏交易编码或签名问题。
func selectAndBuildFundingTx(key *ec.PrivateKey, seller, arbiter []byte, utxos []junglebus.UTXO, poolOutputSatoshis, feeRateSatPerKB uint64, mainnet bool) (junglebus.UTXO, []byte, error) {
	candidates := make([]junglebus.UTXO, 0, len(utxos))
	for _, candidate := range utxos {
		// 每个候选在进入交易构造器前都要独立验证，避免无效 txid 或零金额
		// 在 SDK 深处才暴露出难以定位的错误。
		if err := candidate.Validate(); err != nil {
			return junglebus.UTXO{}, nil, err
		}
		if candidate.IsSpentInMempoolTx || candidate.Satoshis <= poolOutputSatoshis {
			continue
		}
		candidates = append(candidates, candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return fundingUTXOIsBetter(candidates[i], candidates[j])
	})
	for _, candidate := range candidates {
		// 一个 UTXO 可能能覆盖池输出但不能覆盖指定费率的矿工费，因此需要
		// 继续尝试后续候选，而不是把第一次构造失败当成全局失败。
		raw, err := buildFundingTx(key, seller, arbiter, candidate, poolOutputSatoshis, feeRateSatPerKB, mainnet)
		if errors.Is(err, errFundingUTXOTooSmall) {
			continue
		}
		if err != nil {
			return junglebus.UTXO{}, nil, fmt.Errorf("build real funding transaction: %w", err)
		}
		return candidate, raw, nil
	}
	if len(candidates) == 0 {
		return junglebus.UTXO{}, nil, fmt.Errorf("no usable JungleBus UTXO has more than the %d satoshi pool output", poolOutputSatoshis)
	}
	return junglebus.UTXO{}, nil, fmt.Errorf("no usable JungleBus UTXO can cover the pool output and the %d sat/KB miner fee rate", feeRateSatPerKB)
}

// fundingUTXOIsBetter 定义确定性的资金选择顺序。确认状态优先于金额，随后
// 选择较小金额以减少不必要的找零，最后用 txid/vout 消除同金额候选的歧义。
func fundingUTXOIsBetter(candidate, current junglebus.UTXO) bool {
	if candidate.Confirmed() != current.Confirmed() {
		return candidate.Confirmed()
	}
	if candidate.Satoshis != current.Satoshis {
		return candidate.Satoshis < current.Satoshis
	}
	if candidate.TxHash != current.TxHash {
		return candidate.TxHash < current.TxHash
	}
	return candidate.Vout < current.Vout
}

// buildFundingTx 使用所选 UTXO 构造 2-of-3 池输出和可选找零输出，并反复估算
// 交易大小直到找零稳定。若带找零输出无法覆盖费率，则退化为单输出交易，
// 把剩余金额全部作为矿工费。
func buildFundingTx(key *ec.PrivateKey, seller, arbiter []byte, selected junglebus.UTXO, poolOutputSatoshis, feeRateSatPerKB uint64, mainnet bool) ([]byte, error) {
	if key == nil {
		return nil, errors.New("buyer private key is required")
	}
	if feeRateSatPerKB == 0 {
		return nil, errors.New("funding miner fee rate must be positive")
	}
	if err := selected.Validate(); err != nil {
		return nil, err
	}
	if selected.Satoshis <= poolOutputSatoshis {
		return nil, fmt.Errorf("%w: selected UTXO has %d satoshis; pool output is %d", errFundingUTXOTooSmall, selected.Satoshis, poolOutputSatoshis)
	}
	sourceAddress, err := script.NewAddressFromPublicKey(key.PubKey(), mainnet)
	if err != nil {
		return nil, fmt.Errorf("derive funding source address: %w", err)
	}
	sourceLock, err := p2pkh.Lock(sourceAddress)
	if err != nil {
		return nil, fmt.Errorf("build funding source lock: %w", err)
	}
	if strings.TrimSpace(selected.ScriptHex) != "" {
		// JungleBus 报告的锁定脚本必须与买方地址派生出的 P2PKH 脚本完全
		// 一致；否则即使 txid 和金额看起来合法，也不能使用该输出签名。
		reportedLock, err := script.NewFromHex(selected.ScriptHex)
		if err != nil {
			return nil, fmt.Errorf("decode JungleBus UTXO locking script: %w", err)
		}
		if !bytes.Equal(reportedLock.Bytes(), sourceLock.Bytes()) {
			return nil, errors.New("JungleBus UTXO locking script does not match buyer address")
		}
	}
	previousTxID, err := chainhash.NewHashFromHex(strings.TrimSpace(selected.TxHash))
	if err != nil {
		return nil, fmt.Errorf("parse selected UTXO txid: %w", err)
	}
	poolLock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPubKey:   key.PubKey().Compressed(),
		SellerPubKey:  seller,
		ArbiterPubKey: arbiter,
	})
	if err != nil {
		return nil, err
	}
	availableForFeeAndChange := selected.Satoshis - poolOutputSatoshis
	change := availableForFeeAndChange
	for attempt := 0; attempt < 8; attempt++ {
		// 找零金额会影响输出数量和交易大小，交易大小又会影响手续费；
		// 通过有限次迭代求一个稳定的“实际费率对应找零”。
		raw, err := signFundingTx(key, selected, previousTxID, sourceLock, poolLock, poolOutputSatoshis, change)
		if err != nil {
			return nil, err
		}
		feeSatoshis, err := minerFeeForSize(len(raw), feeRateSatPerKB)
		if err != nil {
			return nil, err
		}
		if availableForFeeAndChange < feeSatoshis {
			break
		}
		nextChange := availableForFeeAndChange - feeSatoshis
		if nextChange == 0 {
			break
		}
		if nextChange == change {
			return raw, nil
		}
		change = nextChange
	}

	// 如果该 UTXO 在指定费率下无法保留找零输出，则尝试只保留池输出；剩余
	// 金额会成为实际矿工费。若连最低手续费也无法覆盖，返回可重试的金额错误。
	raw, err := signFundingTx(key, selected, previousTxID, sourceLock, poolLock, poolOutputSatoshis, 0)
	if err != nil {
		return nil, err
	}
	minimumFee, err := minerFeeForSize(len(raw), feeRateSatPerKB)
	if err != nil {
		return nil, err
	}
	if availableForFeeAndChange < minimumFee {
		return nil, fmt.Errorf("%w: selected UTXO has %d satoshis available for fee; need at least %d", errFundingUTXOTooSmall, availableForFeeAndChange, minimumFee)
	}
	return raw, nil
}

// signFundingTx 把 UTXO 映射成 SDK 输入，添加池输出/找零输出，并使用买方
// P2PKH 私钥按 AllForkID 签名。最后重新解析规范交易，确保返回 bytes 与
// 后续交易 ID 计算使用的序列化完全一致。
func signFundingTx(key *ec.PrivateKey, selected junglebus.UTXO, previousTxID *chainhash.Hash, sourceLock *script.Script, poolLock []byte, poolOutputSatoshis, changeSatoshis uint64) ([]byte, error) {
	transaction := tx.NewTransaction()
	if err := transaction.AddInputsFromUTXOs(&tx.UTXO{
		TxID:          previousTxID,
		Vout:          selected.Vout,
		LockingScript: sourceLock,
		Satoshis:      selected.Satoshis,
	}); err != nil {
		return nil, fmt.Errorf("add selected UTXO: %w", err)
	}
	transaction.AddOutput(&tx.TransactionOutput{Satoshis: poolOutputSatoshis, LockingScript: script.NewFromBytes(poolLock)})
	if changeSatoshis > 0 {
		// 找零仍然回到买方原始 P2PKH 脚本；零找零时省略输出，避免产生
		// 不可花费或不经济的 dust 输出。
		transaction.AddOutput(&tx.TransactionOutput{Satoshis: changeSatoshis, LockingScript: script.NewFromBytes(sourceLock.Bytes())})
	}
	flag := sighash.AllForkID
	unlocker, err := p2pkh.Unlock(key, &flag)
	if err != nil {
		return nil, fmt.Errorf("create P2PKH unlocker: %w", err)
	}
	unlockingScript, err := unlocker.Sign(transaction, 0)
	if err != nil {
		return nil, fmt.Errorf("sign funding input: %w", err)
	}
	transaction.Inputs[0].UnlockingScript = unlockingScript
	raw := transaction.Bytes()
	if _, err := pool.ParseCanonicalTransaction(raw); err != nil {
		return nil, fmt.Errorf("validate canonical funding transaction: %w", err)
	}
	return raw, nil
}

// minerFeeForSize 按 sat/KB 计算给定原始字节数的手续费，并向上取整到整 satoshi。
// 这里使用整数运算，避免浮点误差，也显式检查 uint64 溢出。
func minerFeeForSize(sizeBytes int, feeRateSatPerKB uint64) (uint64, error) {
	if sizeBytes <= 0 {
		return 0, errors.New("transaction size must be positive")
	}
	if feeRateSatPerKB == 0 {
		return 0, errors.New("miner fee rate must be positive")
	}
	byteCount := uint64(sizeBytes)
	if byteCount > (^uint64(0)-999)/feeRateSatPerKB {
		return 0, errors.New("transaction size and miner fee rate overflow uint64")
	}
	return (byteCount*feeRateSatPerKB + 999) / 1000, nil
}

// fundingTransactionFee 用输入总金额减去所有输出金额，计算规范资金交易的
// 实际手续费。它同时检查输出求和溢出和“输出大于输入”这两类异常。
func fundingTransactionFee(raw []byte, inputSatoshis uint64) (uint64, error) {
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return 0, err
	}
	var outputSatoshis uint64
	for _, output := range transaction.Outputs {
		if output == nil || ^uint64(0)-outputSatoshis < output.Satoshis {
			return 0, errors.New("funding transaction output value overflow")
		}
		outputSatoshis += output.Satoshis
	}
	if outputSatoshis > inputSatoshis {
		return 0, errors.New("funding transaction outputs exceed selected UTXO")
	}
	return inputSatoshis - outputSatoshis, nil
}

func envUint64(name string, fallback uint64) (uint64, error) {
	// 空值表示使用调用方提供的 fallback；非空值必须是十进制无符号整数，
	// 这样错误会在构造交易前暴露。
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return parsed, nil
}

func stateDir() string {
	// 买方与卖方的 checkpoint 默认共用 demo/.state；显式状态目录便于
	// 让一整次 0201～0205 流程相互隔离。
	if value := strings.TrimSpace(os.Getenv("DEMO_02_STATE_DIR")); value != "" {
		return value
	}
	return defaultStateDir
}

// BuyerOpeningCheckpointPath 返回买方 0201 私有状态的 checkpoint 文件路径。
func BuyerOpeningCheckpointPath() string {
	return filepath.Join(stateDir(), "buyer-opening-checkpoint.json")
}

// BuyerOpeningProofCheckpointPath 返回买方完整 opening proof 的 checkpoint 路径。
func BuyerOpeningProofCheckpointPath() string {
	return filepath.Join(stateDir(), "buyer-opening-proof.json")
}

// SellerPresignProofCheckpointPath 返回卖方 0202 预签证据的 checkpoint 路径。
func SellerPresignProofCheckpointPath() string {
	return filepath.Join(stateDir(), "seller-presign-proof.json")
}

// buyerOpeningCheckpoint 是 0201 之后买方必须自行保存的私有状态快照。
// 它包含原 request 和买方私有 FundingTx；两者都不会被放进网络报文。
type buyerOpeningCheckpoint struct {
	RefundTemplateTxID string `json:"refund_template_txid"`
	Request            string `json:"request_hex"`
	FundingTx          string `json:"funding_tx_hex"`
}

// SaveBuyerOpeningState 把 0201 的买方本地状态写入演示 checkpoint。
// 应用先保存该状态，然后才允许把 Request 发送给卖方。
func SaveBuyerOpeningState(path string, state *buyer.BuyerOpeningState) error {
	if state == nil || state.Request == nil {
		return errors.New("buyer opening state with its request is required")
	}
	requestRaw, err := encodeRequestForCheckpoint(state.Request)
	if err != nil {
		return err
	}
	record := buyerOpeningCheckpoint{RefundTemplateTxID: hex.EncodeToString(state.RefundTemplateTxID[:]), Request: hex.EncodeToString(requestRaw), FundingTx: hex.EncodeToString(state.FundingTx)}
	return writeCheckpoint(path, record)
}

// LoadBuyerOpeningState 按 RefundTemplateTxID 读取买方 0201 私有状态。
// hash 不匹配时拒绝恢复，交给调用方决定重试或放弃；SDK 侧还会再次派生校验。
func LoadBuyerOpeningState(path string, refundTemplateTxID pool.RefundTemplateTxID) (*buyer.BuyerOpeningState, error) {
	var record buyerOpeningCheckpoint
	if err := readCheckpoint(path, &record); err != nil {
		return nil, err
	}
	stored, err := hex.DecodeString(record.RefundTemplateTxID)
	if err != nil || len(stored) != len(pool.RefundTemplateTxID{}) {
		return nil, errors.New("checkpoint correlation ID is malformed")
	}
	if !bytes.Equal(stored, refundTemplateTxID[:]) {
		return nil, fmt.Errorf("checkpoint correlation ID does not match requested RefundTemplateTxID")
	}
	requestRaw, err := hex.DecodeString(record.Request)
	if err != nil {
		return nil, fmt.Errorf("decode checkpoint request: %w", err)
	}
	request, err := decodeRequestFromCheckpoint(requestRaw)
	if err != nil {
		return nil, err
	}
	fundingTx, err := hex.DecodeString(record.FundingTx)
	if err != nil {
		return nil, fmt.Errorf("decode checkpoint funding tx: %w", err)
	}
	return &buyer.BuyerOpeningState{RefundTemplateTxID: refundTemplateTxID, Request: request, FundingTx: fundingTx}, nil
}

// buyerProofCheckpoint 保存买方在 0203 得到的完整 opening proof（含 FundingTx），
// 供独立进程运行的 0204 显式读取。
type buyerProofCheckpoint struct {
	RefundTemplateTxID string `json:"refund_template_txid"`
	OpeningProof       string `json:"opening_proof_hex"`
}

// SaveBuyerOpeningProof 保存买方完整 opening proof 到演示 checkpoint。
func SaveBuyerOpeningProof(path string, proof *pool.OpeningProof) error {
	if proof == nil {
		return errors.New("opening proof is required")
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxID(nil, proof)
	if err != nil {
		return err
	}
	encoded, err := pool.EncodeOpeningProof(proof)
	if err != nil {
		return err
	}
	record := buyerProofCheckpoint{RefundTemplateTxID: hex.EncodeToString(refundTemplateTxID[:]), OpeningProof: hex.EncodeToString(encoded)}
	return writeCheckpoint(path, record)
}

// LoadBuyerOpeningProof 按 RefundTemplateTxID 读取买方完整 opening proof。
func LoadBuyerOpeningProof(path string, refundTemplateTxID pool.RefundTemplateTxID) (*pool.OpeningProof, error) {
	var record buyerProofCheckpoint
	if err := readCheckpoint(path, &record); err != nil {
		return nil, err
	}
	stored, err := hex.DecodeString(record.RefundTemplateTxID)
	if err != nil || len(stored) != len(pool.RefundTemplateTxID{}) {
		return nil, errors.New("checkpoint correlation ID is malformed")
	}
	if !bytes.Equal(stored, refundTemplateTxID[:]) {
		return nil, fmt.Errorf("checkpoint correlation ID does not match requested RefundTemplateTxID")
	}
	encoded, err := hex.DecodeString(record.OpeningProof)
	if err != nil {
		return nil, fmt.Errorf("decode checkpoint opening proof: %w", err)
	}
	return pool.DecodeOpeningProof(encoded)
}

// sellerPresignCheckpoint 保存卖方在 0202 得到的预签证据，供独立进程运行的
// 0205 显式读取。
type sellerPresignCheckpoint struct {
	RefundTemplateTxID string `json:"refund_template_txid"`
	OpeningProof       string `json:"opening_proof_hex"`
}

// SaveSellerPresignProof 保存卖方预签证据到演示 checkpoint。应用先保存该
// 证据，然后才允许把 Response 发送给买方。
func SaveSellerPresignProof(path string, result *seller.SellerPresignResult) error {
	if result == nil || result.Opening == nil {
		return errors.New("seller presign result with its opening proof is required")
	}
	hash, err := pool.DeriveRefundTemplateTxID(nil, result.Opening)
	if err != nil {
		return err
	}
	encoded, err := pool.EncodeOpeningProof(result.Opening)
	if err != nil {
		return err
	}
	record := sellerPresignCheckpoint{RefundTemplateTxID: hex.EncodeToString(hash[:]), OpeningProof: hex.EncodeToString(encoded)}
	return writeCheckpoint(path, record)
}

// LoadSellerPresignProof 按 RefundTemplateTxID 读取卖方预签证据。
func LoadSellerPresignProof(path string, refundTemplateTxID pool.RefundTemplateTxID) (*pool.OpeningProof, error) {
	var record sellerPresignCheckpoint
	if err := readCheckpoint(path, &record); err != nil {
		return nil, err
	}
	stored, err := hex.DecodeString(record.RefundTemplateTxID)
	if err != nil || len(stored) != len(pool.RefundTemplateTxID{}) {
		return nil, errors.New("checkpoint correlation ID is malformed")
	}
	if !bytes.Equal(stored, refundTemplateTxID[:]) {
		return nil, fmt.Errorf("checkpoint correlation ID does not match requested RefundTemplateTxID")
	}
	encoded, err := hex.DecodeString(record.OpeningProof)
	if err != nil {
		return nil, fmt.Errorf("decode checkpoint opening proof: %w", err)
	}
	return pool.DecodeOpeningProof(encoded)
}

func writeCheckpoint(path string, record any) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("checkpoint path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create checkpoint directory: %w", err)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	// 直接写整份文件；这是示例实现，不做 rename/fsync/锁等原子性处理。
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write checkpoint %s: %w", path, err)
	}
	return nil
}

func readCheckpoint(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read checkpoint %s: %w", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode checkpoint %s: %w", path, err)
	}
	return nil
}

// ReadHex 读取 LABEL=deadbeef 形式的传输行或裸 hex 文本。
// 解析器放在 demo helper 中，使 stdout 始终可通过管道传输，角色日志可以
// 独立留在 stderr。
func ReadHex(reader io.Reader, label string) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("hex input is required")
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read hex input: %w", err)
	}
	return DecodeHexText(string(raw), label)
}

// ReadHexFile 读取前一个 demo 写出的带标签传输文件。
func ReadHexFile(path, label string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("hex input file is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return DecodeHexText(string(raw), label)
}

// DecodeHexText 支持裸 hex、指定 LABEL=hex 行，以及在 label 为空时兼容任意
// 单行 key=value 的输入，并拒绝空内容或非法十六进制。
func DecodeHexText(text, label string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("hex input is empty")
	}
	if label != "" {
		// 多行输入可能包含多个状态字段；指定 label 时只取完全匹配的键，
		// 避免把别的 ID 或日志内容误当成当前报文。
		found := ""
		for _, line := range strings.Split(text, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && strings.TrimSpace(key) == label {
				found = strings.TrimSpace(value)
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("label %s is missing from hex input", label)
		}
		text = found
	} else if key, value, ok := strings.Cut(text, "="); ok {
		// 不要求 key 的具体名称，但仍只按第一个等号取值，兼容临时手工
		// 传入的单字段 artifact。
		_ = key
		text = strings.TrimSpace(value)
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("decoded hex input is empty")
	}
	return decoded, nil
}

// WriteHex 把一个非空二进制值写成 LABEL=hex 单行。
// 调用方通常把它写入 stdout，下一步命令再通过 ReadHex 读取；调试日志不应
// 经过这个函数写入 stdout。
func WriteHex(writer io.Writer, label string, value []byte) error {
	if writer == nil {
		return errors.New("hex output is required")
	}
	if label == "" {
		return errors.New("hex output label is required")
	}
	if len(value) == 0 {
		return errors.New("cannot write empty hex output")
	}
	_, err := fmt.Fprintf(writer, "%s=%s\n", label, hex.EncodeToString(value))
	return err
}

func loadKey(name string) (*ec.PrivateKey, error) {
	// 这里不打印原始环境变量，只在错误中指出变量名称，避免私钥出现在日志。
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	key, err := ec.PrivateKeyFromHex(value)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", name, err)
	}
	return key, nil
}

// encodeRequestForCheckpoint 把 0201 request 编码为规范 wire 字节保存。
func encodeRequestForCheckpoint(request *pool.RefundPresignRequest) ([]byte, error) {
	return wire.MarshalPoolRefundPresignRequest(request)
}

// decodeRequestFromCheckpoint 从 checkpoint 字节恢复 0201 request。
func decodeRequestFromCheckpoint(raw []byte) (*pool.RefundPresignRequest, error) {
	return wire.UnmarshalPoolRefundPresignRequest(raw)
}
