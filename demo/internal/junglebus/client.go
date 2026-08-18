// Package junglebus is the demo application's small, concrete JungleBus
// client. It is intentionally outside go-bitfs: protocol workflows receive
// raw transaction data and do not own blockchain-indexer connections.
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

// Network is the BSV network used for both address display and JungleBus
// lookup.
type Network string

const (
	// Mainnet is the production BSV network.
	Mainnet Network = "mainnet"
	// Testnet is the BSV test network and the safe default for demos.
	Testnet Network = "testnet"
)

// ParseNetwork accepts mainnet/testnet and their shorter names. Empty input
// deliberately selects testnet.
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

func (network Network) String() string { return string(network) }

// UTXO is the subset of an unspent transaction output needed to construct a
// real funding transaction. JungleBus does not return UTXOs directly; Client
// derives these records from the address history and transaction inputs and
// outputs.
type UTXO struct {
	Height             int64  `json:"height"`
	Vout               uint32 `json:"tx_pos"`
	TxHash             string `json:"tx_hash"`
	Satoshis           uint64 `json:"value"`
	IsSpentInMempoolTx bool   `json:"isSpentInMempoolTx"`
	ScriptHex          string `json:"hex"`
	Status             string `json:"status"`
}

// Confirmed reports whether this output was created by an indexed block.
func (utxo UTXO) Confirmed() bool {
	return utxo.Height > 0 || strings.EqualFold(strings.TrimSpace(utxo.Status), "confirmed")
}

// Validate checks the identity and value fields before they reach the SDK's
// transaction builder.
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

// Client queries JungleBus address history and transaction endpoints. The
// optional JUNGLEBUS_BASE_URL environment variable is useful for local HTTP
// tests; when it is empty, the network-specific public endpoint is selected.
type Client struct {
	// BaseURL overrides the network-specific public endpoint when non-empty.
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient builds a client from JUNGLEBUS_BASE_URL. The default is the
// public JungleBus endpoint for the network passed to each request.
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

// AddressHistoryEndpoint returns the endpoint used to discover transactions
// involving an address. The endpoint returns history, not a precomputed
// balance or UTXO set.
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

// TransactionEndpoint returns the endpoint used to fetch a transaction's raw
// bytes and metadata.
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

// ListUTXOs reconstructs the confirmed UTXO projection for an address from
// JungleBus address history and raw transactions. JungleBus's public address
// endpoint is a transaction index, so inputs remove previously created
// outpoints and matching outputs add new ones.
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

		// An output is spent when a later transaction input references its
		// outpoint. Process inputs before outputs so the same address can be
		// spent and paid again in one transaction.
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

type addressTransaction struct {
	TransactionID string `json:"transaction_id"`
	BlockHeight   int64  `json:"block_height"`
	BlockHash     string `json:"block_hash"`
	BlockIndex    uint64 `json:"block_index"`
}

type transactionRecord struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
	BlockHeight int64  `json:"block_height"`
}

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

func lockingScriptForAddress(address string) (*script.Script, error) {
	parsed, err := script.NewAddressFromString(strings.TrimSpace(address))
	if err != nil {
		return nil, err
	}
	return p2pkh.Lock(parsed)
}

func outpointKey(txID string, vout uint32) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(txID)), vout)
}

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

func preview(body []byte, limit int) string {
	value := strings.TrimSpace(string(body))
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func getenv(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
