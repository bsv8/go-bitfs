// Package junglebus 提供 demo 应用使用的轻量 JungleBus 客户端。
//
// 它被刻意放在 go-bitfs workflow 之外：workflow 只接收原始交易数据和已
// 选择的 UTXO，不直接持有区块链索引器连接，便于将来替换成其他数据源。
package junglebus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

const (
	mainnetBaseURL  = "https://junglebus.gorillapool.io"
	testnetBaseURL  = "https://testnet.junglebus.gorillapool.io"
	maxResponseBody = 128 << 20
)

// Network 表示地址派生和 JungleBus 查询共同使用的 BSV 网络。
type Network string

const (
	// Mainnet 是生产 BSV 主网。
	Mainnet Network = "mainnet"
	// Testnet 是 BSV 测试网，也是 demo 的安全默认网络。
	Testnet Network = "testnet"
)

// ParseNetwork 接受 mainnet/testnet 及其短名称。空字符串故意选择 testnet，
// 防止调用 demo 时因为忘记配置而意外访问主网。
func ParseNetwork(value string) (Network, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "testnet", "test":
		return Testnet, nil
	case "mainnet", "main":
		return Mainnet, nil
	default:
		return "", fmt.Errorf("unsupported BSV network %q; use mainnet or testnet", value)
	}
}

// String 返回网络的配置字符串，便于日志输出。
func (network Network) String() string { return string(network) }

// UTXO 是构造真实资金交易所需的未花费输出子集。
//
// JungleBus 地址接口提供的是交易历史而不是现成 UTXO；Client 会读取历史中
// 每笔交易的输入和输出，重建这些记录。ScriptHex 用于再次确认输出确实锁
// 定到买方地址，IsSpentInMempoolTx 用于排除已被内存池交易抢先花费的输出。
type UTXO struct {
	Height             int64  `json:"height"`
	Vout               uint32 `json:"tx_pos"`
	TxHash             string `json:"tx_hash"`
	Satoshis           uint64 `json:"value"`
	IsSpentInMempoolTx bool   `json:"isSpentInMempoolTx"`
	ScriptHex          string `json:"hex"`
	Status             string `json:"status"`
}

// Confirmed 根据高度或状态判断输出是否已经被索引到区块中。
func (utxo UTXO) Confirmed() bool {
	return utxo.Height > 0 || strings.EqualFold(strings.TrimSpace(utxo.Status), "confirmed")
}

// Validate 在 UTXO 进入 SDK 交易构造器前检查交易 ID 和金额字段。
func (utxo UTXO) Validate() error {
	txHash := strings.TrimSpace(utxo.TxHash)
	if len(txHash) != 64 {
		return fmt.Errorf("UTXO tx_hash must be 32-byte hex, got %q", utxo.TxHash)
	}
	if _, err := hex.DecodeString(txHash); err != nil {
		return fmt.Errorf("UTXO tx_hash is not hex: %w", err)
	}
	if utxo.Satoshis == 0 {
		return errors.New("UTXO value must be positive")
	}
	return nil
}

// Client 负责访问 JungleBus 地址历史和交易详情接口。
// JUNGLEBUS_BASE_URL 可用于本地 HTTP 测试；为空时，客户端根据每次请求的
// Network 自动选择主网或测试网公共地址。
type Client struct {
	// BaseURL 非空时覆盖按网络选择的公共 endpoint。
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient 根据 JUNGLEBUS_BASE_URL 创建客户端，并为默认 HTTP 请求设置超时。
// 网络对应的公共 endpoint 会在具体请求时由 baseURL 决定。
func NewClient() (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(getenv("JUNGLEBUS_BASE_URL", "")), "/")
	if baseURL != "" {
		parsed, err := url.Parse(baseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid JUNGLEBUS_BASE_URL %q", baseURL)
		}
	}
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// AddressHistoryEndpoint 构造地址历史 endpoint。该接口返回涉及地址的交易
// 索引，而不是余额或预先计算好的 UTXO 集合。
func (client *Client) AddressHistoryEndpoint(network Network, address string) (string, error) {
	base, err := client.baseURL(network)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(address) == "" {
		return "", errors.New("address is required")
	}
	return fmt.Sprintf("%s/v1/address/get/%s", base, url.PathEscape(address)), nil
}

// TransactionEndpoint 构造获取交易原始 bytes 和元数据的 endpoint，并在构造
// 路径前验证交易 ID 是 32 字节十六进制字符串。
func (client *Client) TransactionEndpoint(network Network, txID string) (string, error) {
	base, err := client.baseURL(network)
	if err != nil {
		return "", err
	}
	if err := validateTxID(txID); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/v1/transaction/get/%s", base, strings.ToLower(strings.TrimSpace(txID))), nil
}

// ListUTXOs 根据 JungleBus 地址历史和交易原文重建地址的 UTXO 投影。
//
// 处理顺序是：把地址转换成 locking script，读取并排序历史，逐笔取得规范
// 交易原文，先用输入删除被花费的 outpoint，再用匹配地址的输出加入新 UTXO。
// 该方法只覆盖已被接口索引的交易；它不是节点 mempool 或链重组状态的完整视图。
func (client *Client) ListUTXOs(ctx context.Context, address string, network Network) ([]UTXO, error) {
	if client == nil {
		return nil, errors.New("JungleBus client is required")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("address is required")
	}
	targetScript, err := lockingScriptForAddress(address)
	if err != nil {
		return nil, fmt.Errorf("derive locking script for address: %w", err)
	}
	history, err := client.addressHistory(ctx, address, network)
	if err != nil {
		return nil, err
	}
	// 必须按区块高度和交易在区块中的位置排序，才能保证“先产生输出、后
	// 花费输出”的状态转移顺序稳定；未确认记录的排序也保持确定性。
	sort.SliceStable(history, func(i, j int) bool {
		if history[i].BlockHeight != history[j].BlockHeight {
			return history[i].BlockHeight < history[j].BlockHeight
		}
		if history[i].BlockIndex != history[j].BlockIndex {
			return history[i].BlockIndex < history[j].BlockIndex
		}
		return history[i].TransactionID < history[j].TransactionID
	})

	utxos := make(map[string]UTXO)
	seenTransactions := make(map[string]struct{}, len(history))
	for _, item := range history {
		// 同一交易可能因多个输出或索引记录重复出现，只读取一次交易原文。
		txID := strings.ToLower(strings.TrimSpace(item.TransactionID))
		if _, seen := seenTransactions[txID]; seen {
			continue
		}
		if err := validateTxID(txID); err != nil {
			return nil, fmt.Errorf("invalid address history transaction ID: %w", err)
		}
		seenTransactions[txID] = struct{}{}

		record, parsed, err := client.transaction(ctx, network, txID)
		if err != nil {
			return nil, err
		}
		height := item.BlockHeight
		if record.BlockHeight > 0 {
			height = record.BlockHeight
		}
		status := "unconfirmed"
		if height > 0 {
			status = "confirmed"
		}

		// 当某个输入引用已有 outpoint 时，该输出已经被花费；先处理输入再处理
		// 输出，才能正确表示同一笔交易中“花掉旧输出、又给该地址找零”的情况。
		for _, input := range parsed.Inputs {
			if input == nil || input.SourceTXID == nil {
				continue
			}
			delete(utxos, outpointKey(input.SourceTXID.String(), input.SourceTxOutIndex))
		}
		for index, output := range parsed.Outputs {
			if output == nil || output.LockingScript == nil || !bytes.Equal(output.LockingScript.Bytes(), targetScript.Bytes()) {
				continue
			}
			if output.Satoshis == 0 {
				continue
			}
			utxo := UTXO{
				Height:    height,
				Vout:      uint32(index),
				TxHash:    txID,
				Satoshis:  output.Satoshis,
				ScriptHex: hex.EncodeToString(output.LockingScript.Bytes()),
				Status:    status,
			}
			utxos[outpointKey(txID, uint32(index))] = utxo
		}
	}

	result := make([]UTXO, 0, len(utxos))
	// map 的遍历顺序不稳定，返回前按确认状态、金额和 outpoint 排序，保证
	// 资金选择在相同链上数据下可复现。
	for _, utxo := range utxos {
		if err := utxo.Validate(); err != nil {
			return nil, fmt.Errorf("invalid reconstructed UTXO: %w", err)
		}
		result = append(result, utxo)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Confirmed() != result[j].Confirmed() {
			return result[i].Confirmed()
		}
		if result[i].Satoshis != result[j].Satoshis {
			return result[i].Satoshis > result[j].Satoshis
		}
		if result[i].TxHash != result[j].TxHash {
			return result[i].TxHash < result[j].TxHash
		}
		return result[i].Vout < result[j].Vout
	})
	return result, nil
}

// addressTransaction 是地址历史接口返回的最小字段集合。排序使用区块高度
// 和区块内位置，TransactionID 用于随后获取原始交易。
type addressTransaction struct {
	TransactionID string `json:"transaction_id"`
	BlockHeight   int64  `json:"block_height"`
	BlockHash     string `json:"block_hash"`
	BlockIndex    uint64 `json:"block_index"`
}

// transactionRecord 是交易详情接口的响应结构，其中 Transaction 是 Base64
// 编码的原始交易 bytes，ID/BlockHeight 用于交叉校验和确认状态。
type transactionRecord struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
	BlockHeight int64  `json:"block_height"`
}

// addressHistory 请求地址交易索引。JungleBus 对不存在或没有历史的地址返回
// 404 时按空历史处理，调用方最终会得到空 UTXO 列表而不是把它当成网络故障。
func (client *Client) addressHistory(ctx context.Context, address string, network Network) ([]addressTransaction, error) {
	endpoint, err := client.AddressHistoryEndpoint(network, address)
	if err != nil {
		return nil, err
	}
	body, statusCode, err := client.get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("JungleBus address history request: %w", err)
	}
	if statusCode == http.StatusNotFound {
		return nil, nil
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("JungleBus address history request returned HTTP %d: %s", statusCode, preview(body, 512))
	}
	var history []addressTransaction
	if err := json.Unmarshal(body, &history); err != nil {
		return nil, fmt.Errorf("decode JungleBus address history response: %w", err)
	}
	return history, nil
}

// transaction 获取并验证单笔交易：解码 Base64 原文、解析 SDK 交易、检查规范
// 序列化，并将计算出的交易 ID 与请求 ID 及响应 ID 逐一比对。
func (client *Client) transaction(ctx context.Context, network Network, expectedTxID string) (transactionRecord, *transaction.Transaction, error) {
	endpoint, err := client.TransactionEndpoint(network, expectedTxID)
	if err != nil {
		return transactionRecord{}, nil, err
	}
	body, statusCode, err := client.get(ctx, endpoint)
	if err != nil {
		return transactionRecord{}, nil, fmt.Errorf("JungleBus transaction request: %w", err)
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return transactionRecord{}, nil, fmt.Errorf("JungleBus transaction request returned HTTP %d: %s", statusCode, preview(body, 512))
	}
	var record transactionRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return transactionRecord{}, nil, fmt.Errorf("decode JungleBus transaction response: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(record.Transaction)
	if err != nil {
		return transactionRecord{}, nil, fmt.Errorf("decode JungleBus transaction bytes: %w", err)
	}
	parsed, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return transactionRecord{}, nil, fmt.Errorf("parse JungleBus transaction %s: %w", expectedTxID, err)
	}
	if !bytes.Equal(parsed.Bytes(), raw) {
		return transactionRecord{}, nil, fmt.Errorf("JungleBus transaction %s is not canonically encoded", expectedTxID)
	}
	computedTxID := strings.ToLower(parsed.TxID().String())
	if computedTxID != strings.ToLower(expectedTxID) {
		return transactionRecord{}, nil, fmt.Errorf("JungleBus transaction ID mismatch: requested %s, computed %s", expectedTxID, computedTxID)
	}
	if record.ID != "" && !strings.EqualFold(record.ID, expectedTxID) {
		return transactionRecord{}, nil, fmt.Errorf("JungleBus response ID mismatch: requested %s, response %s", expectedTxID, record.ID)
	}
	return record, parsed, nil
}

// get 执行带 context 的 GET 请求，限制响应最大尺寸，避免异常服务端返回
// 无限大 body；调用方负责根据 HTTP 状态码解释业务结果。
func (client *Client) get(ctx context.Context, endpoint string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create JungleBus request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody))
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return body, response.StatusCode, nil
}

// baseURL 校验网络并选择 endpoint。自定义 BaseURL 主要供测试服务器使用，
// 但仍会统一去掉末尾斜杠，避免路径拼接出现双斜杠。
func (client *Client) baseURL(network Network) (string, error) {
	if client == nil {
		return "", errors.New("JungleBus client is required")
	}
	if network != Mainnet && network != Testnet {
		return "", fmt.Errorf("unsupported network %q", network)
	}
	if client.BaseURL != "" {
		return strings.TrimRight(client.BaseURL, "/"), nil
	}
	if network == Mainnet {
		return mainnetBaseURL, nil
	}
	return testnetBaseURL, nil
}

// lockingScriptForAddress 将 Base58 地址解析成 P2PKH locking script，后续
// UTXO 重建只把脚本完全匹配的输出视为该地址的收款输出。
func lockingScriptForAddress(address string) (*script.Script, error) {
	parsed, err := script.NewAddressFromString(strings.TrimSpace(address))
	if err != nil {
		return nil, err
	}
	return p2pkh.Lock(parsed)
}

// outpointKey 为 txid:vout 生成 map key，用于插入和删除同一个 UTXO。
func outpointKey(txID string, vout uint32) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(txID)), vout)
}

// validateTxID 检查交易 ID 的固定长度和十六进制编码，不负责判断链上是否存在。
func validateTxID(txID string) error {
	txID = strings.TrimSpace(txID)
	if len(txID) != 64 {
		return fmt.Errorf("transaction ID must be 32-byte hex, got %q", txID)
	}
	if _, err := hex.DecodeString(txID); err != nil {
		return fmt.Errorf("transaction ID is not hex: %w", err)
	}
	return nil
}

// preview 生成有限长度的错误响应摘要，避免把远端返回的大段内容写入错误。
func preview(body []byte, limit int) string {
	value := strings.TrimSpace(string(body))
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

// getenv 在保留“变量存在但为空”语义的同时提供默认值。
func getenv(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
