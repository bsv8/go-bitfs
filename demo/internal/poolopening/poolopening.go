// Package poolopening contains the shared wiring used by the fine-grained 002
// message-flow demos. It deliberately keeps the buyer and seller workflows
// backed by a FileStore so each command can represent one process in the
// business flow.
package poolopening

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"github.com/bsv8/go-bitfs/demo/internal/fixture"
	"github.com/bsv8/go-bitfs/demo/internal/junglebus"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

const defaultStateDir = "demo/.state"

// BuyerSession is the buyer-only application wiring for one 002 command. The
// buyer's store is process-safe; DemoBackend is an in-memory stand-in used
// only to satisfy workflow construction for these local demos.
type BuyerSession struct {
	Buyer         *buyer.Workflow
	Store         *pool.FileStore
	buyerKey      *ec.PrivateKey
	BuyerPubKey   []byte
	SellerPubKey  []byte
	ArbiterPubKey []byte
}

// SellerSession is the seller-only application wiring for one 002 command.
// Its store survives between 0202 and 0205, while the backend records the
// funding submission made by 0205.
type SellerSession struct {
	Seller  *seller.Workflow
	Store   *pool.FileStore
	Backend *fixture.DemoBackend
}

// NewBuyer creates only the buyer workflow and its local store. Seller and
// arbiter public keys are derived from their private-key configuration for the
// buyer-side funding lock.
func NewBuyer(ctx context.Context) (*BuyerSession, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
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
	sellerPubKey := sellerKey.PubKey().Compressed()
	arbiterPubKey := arbiterKey.PubKey().Compressed()

	buyerStore, err := pool.NewFileStore(BuyerStorePath())
	if err != nil {
		return nil, fmt.Errorf("open buyer pool store: %w", err)
	}
	backend, err := newBackend()
	if err != nil {
		return nil, fmt.Errorf("create demo backend: %w", err)
	}
	quotes := &fixture.QuoteStore{}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{
		Signer:  fixture.Signer{Key: buyerKey},
		Quotes:  quotes,
		Pools:   buyerStore,
		Backend: backend,
	})
	if err != nil {
		return nil, fmt.Errorf("create buyer workflow: %w", err)
	}

	buyerPubKey := buyerKey.PubKey().Compressed()
	return &BuyerSession{
		Buyer:         buyerWorkflow,
		Store:         buyerStore,
		buyerKey:      buyerKey,
		BuyerPubKey:   append([]byte(nil), buyerPubKey...),
		SellerPubKey:  append([]byte(nil), sellerPubKey...),
		ArbiterPubKey: append([]byte(nil), arbiterPubKey...),
	}, nil
}

// NewSeller creates only the seller workflow and its local store.
func NewSeller(ctx context.Context) (*SellerSession, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	sellerKey, err := loadKey("SELLER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	sellerStore, err := pool.NewFileStore(SellerStorePath())
	if err != nil {
		return nil, fmt.Errorf("open seller pool store: %w", err)
	}
	backend, err := newBackend()
	if err != nil {
		return nil, fmt.Errorf("create demo backend: %w", err)
	}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{
		Signer:  fixture.Signer{Key: sellerKey},
		Quotes:  &fixture.QuoteStore{},
		Pools:   sellerStore,
		Pending: sellerStore,
		Content: fixture.Content{},
		Backend: backend,
	})
	if err != nil {
		return nil, fmt.Errorf("create seller workflow: %w", err)
	}
	return &SellerSession{Seller: sellerWorkflow, Store: sellerStore, Backend: backend}, nil
}

// OpeningInput returns the 002 opening input after the buyer has prepared a
// real funding transaction from a selected UTXO. The funding transaction is
// known only to the buyer until 0204.
func (session *BuyerSession) OpeningInput(fundingTx []byte, minerFeeRateSatPerKB uint64) pool.OpeningInput {
	return pool.OpeningInput{
		FundingTx:            append([]byte(nil), fundingTx...),
		PoolOutputIndex:      0,
		ExpiryLockTime:       uint32(time.Now().UTC().Add(time.Hour).Unix()),
		MinerFeeRateSatPerKB: minerFeeRateSatPerKB,
		SellerPubKey:         append([]byte(nil), session.SellerPubKey...),
		ArbiterPubKey:        append([]byte(nil), session.ArbiterPubKey...),
	}
}

// FundingAddresses contains both network variants of the buyer's P2PKH
// address. They are derived locally before any JungleBus request is made so a demo
// can display the funding destination even when the lookup later fails.
type FundingAddresses struct {
	Network         junglebus.Network
	MainnetAddress  string
	TestnetAddress  string
	SelectedAddress string
}

// FundingAddresses derives the buyer's mainnet and testnet addresses and
// selects the one used by BITFS_NETWORK. It does not contact JungleBus.
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

// FundingPreparation is the buyer-local result of the JungleBus lookup and funding
// transaction construction. It is never encoded into a protocol message.
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

// PrepareFunding queries JungleBus and constructs a canonical, signed funding
// transaction spending the selected real UTXO. The provider is called here in
// the demo layer, not by a go-bitfs workflow.
func (session *BuyerSession) PrepareFunding(ctx context.Context) (*FundingPreparation, error) {
	if session == nil || session.buyerKey == nil {
		return nil, errors.New("buyer session is required")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
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
	selected, rawTx, err := selectAndBuildFundingTx(session.buyerKey, session.SellerPubKey, session.ArbiterPubKey, utxos, poolOutputSatoshis, minerFeeRateSatPerKB, addresses.Network == junglebus.Mainnet)
	if err != nil {
		return nil, err
	}
	fundingFeeSatoshis, err := fundingTransactionFee(rawTx, selected.Satoshis)
	if err != nil {
		return nil, fmt.Errorf("calculate funding transaction fee: %w", err)
	}
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

func selectAndBuildFundingTx(key *ec.PrivateKey, seller, arbiter []byte, utxos []junglebus.UTXO, poolOutputSatoshis, feeRateSatPerKB uint64, mainnet bool) (junglebus.UTXO, []byte, error) {
	candidates := make([]junglebus.UTXO, 0, len(utxos))
	for _, candidate := range utxos {
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

	// If the selected UTXO cannot leave a change output at the requested rate,
	// try a one-output transaction. Any remaining value becomes the actual fee.
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

// FundingTxPath is the buyer-local handoff between 0201 and 0203. It is not
// sent to the seller; only its transaction ID enters RefundPresignRequest.
func FundingTxPath() string {
	if value := strings.TrimSpace(os.Getenv("DEMO_02_FUNDING_TX_FILE")); value != "" {
		return value
	}
	return filepath.Join(stateDir(), "buyer-funding-tx.hex")
}

// SaveFundingTx persists the buyer's real funding transaction for later local
// steps without putting it into the seller-facing request artifact.
func SaveFundingTx(raw []byte) error {
	if len(raw) == 0 {
		return errors.New("funding transaction is required")
	}
	path := FundingTxPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create funding transaction directory: %w", err)
	}
	if err := os.WriteFile(path, []byte("BUYER_FUNDING_TX_HEX="+hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		return fmt.Errorf("save buyer funding transaction: %w", err)
	}
	return nil
}

// LoadFundingTx loads the buyer-local funding transaction created by 0201.
func LoadFundingTx() ([]byte, error) {
	return ReadHexFile(FundingTxPath(), "BUYER_FUNDING_TX_HEX")
}

func envUint64(name string, fallback uint64) (uint64, error) {
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

// envUint64WithLegacy gives the clarified variable name precedence while
// keeping the previous demo-only name usable for existing local .env files.
// BuyerStorePath is the buyer's durable demo state path. Set
// DEMO_02_STATE_DIR to use a fresh temporary directory for a run, or override
// DEMO_02_BUYER_POOL_STORE_FILE directly.
func BuyerStorePath() string {
	if value := strings.TrimSpace(os.Getenv("DEMO_02_BUYER_POOL_STORE_FILE")); value != "" {
		return value
	}
	return filepath.Join(stateDir(), "buyer-pool.json")
}

// SellerStorePath is the seller's durable demo state path. Set
// DEMO_02_STATE_DIR to use a fresh temporary directory for a run, or override
// DEMO_02_SELLER_POOL_STORE_FILE directly.
func SellerStorePath() string {
	if value := strings.TrimSpace(os.Getenv("DEMO_02_SELLER_POOL_STORE_FILE")); value != "" {
		return value
	}
	return filepath.Join(stateDir(), "seller-pool.json")
}

func stateDir() string {
	if value := strings.TrimSpace(os.Getenv("DEMO_02_STATE_DIR")); value != "" {
		return value
	}
	return defaultStateDir
}

// ReadHex reads a transport line such as LABEL=deadbeef or a raw hex line.
// Keeping this parser in the demo helper lets stdout remain pipeable while
// stderr carries human-readable role logs.
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

// ReadHexFile reads a labelled transport artifact written by an earlier demo.
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

// DecodeHexText decodes either a raw hex value or a LABEL=hex transport line.
func DecodeHexText(text, label string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("hex input is empty")
	}
	if label != "" {
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

// WriteHex writes one labelled, transport-safe value to stdout.
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

func newBackend() (*fixture.DemoBackend, error) {
	store, err := pool.NewMemoryStore()
	if err != nil {
		return nil, err
	}
	return &fixture.DemoBackend{Store: store}, nil
}

func loadKey(name string) (*ec.PrivateKey, error) {
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
