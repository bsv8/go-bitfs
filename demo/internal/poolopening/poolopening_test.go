// 本文件覆盖 002 demo 层的本地交易构造、网络地址选择和 JungleBus 交互。
// 测试只使用临时目录和 httptest 服务，不广播任何真实交易。
package poolopening

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv8/go-bitfs/demo/internal/junglebus"
	"github.com/bsv8/go-bitfs/pool"
)

func TestBuildFundingTxUsesSelectedUTXOAndSignsInput(t *testing.T) {
	// 验证资金交易确实花费传入的 txid:vout，输入已经签名，且输出金额与
	// 实际手续费满足“池输出 + 找零 + 矿工费 = UTXO 金额”。
	buyer := testPrivateKey(t, 0x11)
	seller := testPrivateKey(t, 0x22)
	arbiter := testPrivateKey(t, 0x33)
	previousTxID := strings.Repeat("ab", 32)

	raw, err := buildFundingTx(
		buyer,
		seller.PubKey().Compressed(),
		arbiter.PubKey().Compressed(),
		junglebus.UTXO{TxHash: previousTxID, Vout: 7, Satoshis: 25_000},
		20_000,
		100,
		false,
	)
	if err != nil {
		t.Fatalf("build funding transaction: %v", err)
	}
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		t.Fatalf("parse funding transaction: %v", err)
	}
	if len(transaction.Inputs) != 1 {
		t.Fatalf("input count = %d, want 1", len(transaction.Inputs))
	}
	selectedHash, err := chainhash.NewHashFromHex(previousTxID)
	if err != nil {
		t.Fatalf("parse selected txid: %v", err)
	}
	input := transaction.Inputs[0]
	if input.SourceTXID == nil || !bytes.Equal(input.SourceTXID.CloneBytes(), selectedHash.CloneBytes()) {
		t.Fatalf("input txid does not match selected JungleBus UTXO")
	}
	if input.SourceTxOutIndex != 7 {
		t.Fatalf("input vout = %d, want 7", input.SourceTxOutIndex)
	}
	if input.UnlockingScript == nil || len(input.UnlockingScript.Bytes()) == 0 {
		t.Fatal("funding input is not signed")
	}
	if len(transaction.Outputs) != 2 {
		t.Fatalf("output count = %d, want pool output plus change", len(transaction.Outputs))
	}
	if transaction.Outputs[0].Satoshis != 20_000 {
		t.Fatalf("pool output = %d, want 20000", transaction.Outputs[0].Satoshis)
	}
	actualFee := uint64(25_000) - transaction.Outputs[0].Satoshis - transaction.Outputs[1].Satoshis
	// 费率按交易原始字节数计算，因此断言不能只检查固定手续费金额。
	expectedFee, err := minerFeeForSize(len(raw), 100)
	if err != nil {
		t.Fatalf("calculate expected miner fee: %v", err)
	}
	if actualFee != expectedFee {
		t.Fatalf("actual miner fee = %d, want %d for 100 sat/KB", actualFee, expectedFee)
	}
}

func TestFundingAddressesDerivesBothNetworks(t *testing.T) {
	// 同一公钥应能派生出主网和测试网两种地址，BITFS_NETWORK 决定本次选中
	// 哪一个，但不会影响另一个地址的计算结果。
	session := &BuyerSession{buyerKey: testPrivateKey(t, 0x11)}
	t.Setenv("BITFS_NETWORK", "testnet")

	addresses, err := session.FundingAddresses()
	if err != nil {
		t.Fatalf("derive funding addresses: %v", err)
	}
	mainnet, err := script.NewAddressFromPublicKey(session.buyerKey.PubKey(), true)
	if err != nil {
		t.Fatalf("derive expected mainnet address: %v", err)
	}
	testnet, err := script.NewAddressFromPublicKey(session.buyerKey.PubKey(), false)
	if err != nil {
		t.Fatalf("derive expected testnet address: %v", err)
	}
	if addresses.MainnetAddress != mainnet.AddressString {
		t.Fatalf("mainnet address = %q, want %q", addresses.MainnetAddress, mainnet.AddressString)
	}
	if addresses.TestnetAddress != testnet.AddressString {
		t.Fatalf("testnet address = %q, want %q", addresses.TestnetAddress, testnet.AddressString)
	}
	if addresses.Network != junglebus.Testnet || addresses.SelectedAddress != testnet.AddressString {
		t.Fatalf("selected address = %q on %q, want testnet %q", addresses.SelectedAddress, addresses.Network, testnet.AddressString)
	}
}

func TestPrepareFundingUsesJungleBusAndConfiguredFeeRate(t *testing.T) {
	// 使用本地 HTTP 服务模拟地址历史和交易详情，验证 PrepareFunding 会
	// 使用真实接口数据构造资金交易，并把环境变量费率传递到最终 OpeningInput。
	buyer := testPrivateKey(t, 0x11)
	buyerAddress, err := script.NewAddressFromPublicKey(buyer.PubKey(), false)
	if err != nil {
		t.Fatalf("derive buyer address: %v", err)
	}
	address := buyerAddress.AddressString
	sourceLock, err := p2pkh.Lock(buyerAddress)
	if err != nil {
		t.Fatalf("build source locking script: %v", err)
	}
	source := tx.NewTransaction()
	coinbaseHash := &chainhash.Hash{}
	source.AddInput(&tx.TransactionInput{
		SourceTXID:       coinbaseHash,
		UnlockingScript:  script.NewFromBytes([]byte{0x01}),
		SourceTxOutIndex: ^uint32(0),
		SequenceNumber:   tx.DefaultSequenceNumber,
	})
	source.AddOutput(&tx.TransactionOutput{Satoshis: 30_000, LockingScript: sourceLock})
	rawSource := source.Bytes()
	sourceID := source.TxID().String()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		// 服务端返回一笔含买方 P2PKH 输出的规范交易，客户端随后会从它重建
		// UTXO 并为资金交易输入签名。
		switch request.URL.Path {
		case "/v1/address/get/" + address:
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode([]map[string]any{{
				"transaction_id": sourceID,
				"block_height":   100,
				"block_hash":     strings.Repeat("ab", 32),
				"block_index":    0,
			}})
		case "/v1/transaction/get/" + sourceID:
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{
				"id":           sourceID,
				"transaction":  base64.StdEncoding.EncodeToString(rawSource),
				"block_height": 100,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	t.Setenv("BUYER_PRIVATE_KEY_HEX", hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)))
	t.Setenv("SELLER_PRIVATE_KEY_HEX", hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)))
	t.Setenv("ARBITER_PRIVATE_KEY_HEX", hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)))
	t.Setenv("BITFS_NETWORK", "testnet")
	t.Setenv("JUNGLEBUS_BASE_URL", server.URL)
	t.Setenv("DEMO_02_STATE_DIR", t.TempDir())
	t.Setenv("DEMO_02_POOL_OUTPUT_SAT", "20000")
	t.Setenv("DEMO_02_MINER_FEE_RATE_SAT_PER_KB", "100")

	session, err := NewBuyer(t.Context())
	if err != nil {
		t.Fatalf("new buyer: %v", err)
	}
	funding, err := session.PrepareFunding(t.Context())
	if err != nil {
		t.Fatalf("prepare funding: %v", err)
	}
	if funding.MinerFeeRateSatPerKB != 100 || funding.MinerFeeRateSource != "environment override" {
		t.Fatalf("fee rate = %d from %q, want 100 from environment override", funding.MinerFeeRateSatPerKB, funding.MinerFeeRateSource)
	}
	actualFee, err := fundingTransactionFee(funding.RawTx, funding.SelectedUTXO.Satoshis)
	if err != nil {
		t.Fatalf("calculate actual funding fee: %v", err)
	}
	if actualFee != funding.FundingFeeSatoshis {
		t.Fatalf("stored funding fee = %d, actual fee = %d", funding.FundingFeeSatoshis, actualFee)
	}
	if session.OpeningInput(funding.RawTx, funding.MinerFeeRateSatPerKB).MinerFeeRateSatPerKB != 100 {
		t.Fatal("opening input did not use the dynamic miner fee rate")
	}
}

func testPrivateKey(t *testing.T, value byte) *ec.PrivateKey {
	// 使用重复字节生成确定性的测试私钥，便于构造三方角色而不依赖仓库中的
	// 真实 .env 私钥。
	t.Helper()
	key, err := ec.PrivateKeyFromHex(hex.EncodeToString(bytes.Repeat([]byte{value}, 32)))
	if err != nil {
		t.Fatalf("create test private key: %v", err)
	}
	return key
}
