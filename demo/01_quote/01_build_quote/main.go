// Command seller builds a signed BitFS 001 file quote.
//
// 全部二进制输入输出使用 hex。卖方私钥从 SELLER_PRIVATE_KEY_HEX 读取且绝不
// 打印。纯函数 API：protocol.NewPrivateKeySigner → seller.CreateQuote(ctx,
// facts, signer, QuoteDraft)，返回待发送的 exact Kind 1 Artifact 与最终条款；
// 应用先持久化其字节再发送（demo 中以 stdout hex 表示“发送”）。
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
)

// blockHeight 是调用方认可并提供的当前区块高度；SDK 不查询节点。
const blockHeight protocol.BlockHeight = 900000

func main() {
	if err := demoenv.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "seller:", err)
		os.Exit(1)
	}
	filePath := flag.String("file", envOr("FILE_PATH", "demo/file.bin"), "source file used to generate the MasterSeed")
	privateKeyHex := flag.String("private-key-hex", envOr("SELLER_PRIVATE_KEY_HEX", ""), "seller private key in hex; prefer SELLER_PRIVATE_KEY_HEX")
	privateKeyFile := flag.String("private-key-file", envOr("SELLER_PRIVATE_KEY_FILE", ""), "file containing the seller private key as hex")
	seedPrice := flag.Uint64("seed-price-sat", envUint64("SEED_PRICE_SAT", 0), "seed price in satoshis")
	blockPrice := flag.Uint64("block-price-sat", envUint64("FULL_BLOCK_PRICE_SAT", 0), "full block price in satoshis")
	validFor := flag.Duration("quote-valid-for", envDuration("QUOTE_VALID_FOR", time.Hour), "how long the quote remains valid, for example 1h or 30m")
	flag.Parse()

	if err := run(*privateKeyHex, *privateKeyFile, *filePath, *seedPrice, *blockPrice, *validFor); err != nil {
		fmt.Fprintln(os.Stderr, "seller:", err)
		os.Exit(1)
	}
}

func run(privateKeyHex, privateKeyFile, filePath string, seedPrice, blockPrice uint64, validFor time.Duration) error {
	filename := filepath.Base(filePath)
	debugf("=== BitFS Seller Quote Builder ===")
	debugf("[config] source file       : %s", filePath)
	debugf("[config] seed price        : %d satoshis", seedPrice)
	debugf("[config] full block price : %d satoshis", blockPrice)
	debugf("[config] valid for         : %s", validFor)
	debugf("[config] recommended name  : %q (from FILE_PATH)", filename)
	if validFor <= 0 {
		return fmt.Errorf("quote validity duration must be positive")
	}
	if strings.TrimSpace(privateKeyFile) != "" {
		debugf("[key] reading seller private key from: %s", privateKeyFile)
		value, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("read seller private-key file: %w", err)
		}
		privateKeyHex = string(value)
	}
	privateKey, err := ec.PrivateKeyFromHex(strings.TrimSpace(privateKeyHex))
	if err != nil {
		return fmt.Errorf("parse seller private key: %w", err)
	}
	debugf("[key] seller public key   : %s", hex.EncodeToString(privateKey.PubKey().Compressed()))
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read source file %q: %w", filePath, err)
	}
	debugf("[file] source file loaded : %d bytes", len(fileBytes))
	var seedOutput bytes.Buffer
	if _, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(fileBytes), &seedOutput); err != nil {
		return fmt.Errorf("create MasterSeed: %w", err)
	}
	seed := seedOutput.Bytes()
	seedHash := masterseed.Sum256(seed).Bytes()
	debugf("[seed] MasterSeed size    : %d bytes", len(seed))
	debugf("[seed] SeedHash            : %s", hex.EncodeToString(seedHash))

	buyerPrivateKey, err := ec.PrivateKeyFromHex(strings.TrimSpace(os.Getenv("BUYER_PRIVATE_KEY_HEX")))
	if err != nil {
		return fmt.Errorf("derive buyer public key from BUYER_PRIVATE_KEY_HEX: %w", err)
	}
	buyerPubkey := buyerPrivateKey.PubKey().Compressed()
	debugf("[key] buyer public key    : %s", hex.EncodeToString(buyerPubkey))
	arbiterPrivateKey, err := ec.PrivateKeyFromHex(strings.TrimSpace(os.Getenv("ARBITER_PRIVATE_KEY_HEX")))
	if err != nil {
		return fmt.Errorf("derive arbiter public key from ARBITER_PRIVATE_KEY_HEX: %w", err)
	}
	arbiterPubkeyBytes := [][]byte{arbiterPrivateKey.PubKey().Compressed()}
	debugf("[key] arbiter public key  : %s", hex.EncodeToString(arbiterPubkeyBytes[0]))
	arbiterPubkeys := make([]protocol.PublicKey, 0, len(arbiterPubkeyBytes))
	for _, rawKey := range arbiterPubkeyBytes {
		typed, err := protocol.PublicKeyFromBytes(rawKey)
		if err != nil {
			return fmt.Errorf("parse arbiter public key: %w", err)
		}
		arbiterPubkeys = append(arbiterPubkeys, typed)
	}

	// 显式事实：Now 是本操作唯一时间事实，BlockHeight 是唯一高度事实；
	// SDK 不读系统时钟、不查节点。
	now := time.Now().UTC()
	facts := protocol.Facts{Now: now, BlockHeight: blockHeight}
	expiresAt := now.Add(validFor).Unix()
	debugf("[quote] created at UTC    : %s", now.Format(time.RFC3339))
	debugf("[quote] expires at UTC    : %s", time.Unix(expiresAt, 0).UTC().Format(time.RFC3339))

	// Signer 是单次调用专用能力；QuoteDraft 是唯一的条款来源，SDK 先
	// sanitize 文件名再编码并签署。
	signer, err := protocol.NewPrivateKeySigner(privateKey)
	if err != nil {
		return fmt.Errorf("create seller signer: %w", err)
	}
	quoteArtifact, terms, err := seller.CreateQuote(context.Background(), facts, signer, seller.QuoteDraft{
		SeedHash:                   seedHash,
		BuyerPublicKey:             mustPublicKey(buyerPubkey),
		SeedPriceSatoshis:          protocol.Satoshis(seedPrice),
		FullBlockPriceSatoshis:     protocol.Satoshis(blockPrice),
		FileSizeBytes:              uint64(len(fileBytes)),
		QuoteExpiresAtUnixSeconds:  content.UnixSeconds(expiresAt),
		SupportedArbiterPublicKeys: arbiterPubkeys,
		RecommendedFilename:        filename,
	})
	if err != nil {
		return fmt.Errorf("seller.CreateQuote: %w", err)
	}

	rawQuote := quoteArtifact.Bytes() // 应用先持久化 exact Kind 1 bytes 再发送
	// terms 是最终规范化并已签署的条款快照（展示实际签署值）。
	debugf("[quote] recommended name (signed): %q", terms.RecommendedFilename)
	debugf("[quote] expires at (signed)      : %d", terms.QuoteExpiresAtUnixSeconds)
	debugf("[quote] seed price / block price : %d / %d satoshis", terms.SeedPriceSatoshis, terms.FullBlockPriceSatoshis)
	debugf("[quote] complete Kind 1 artifact : %d bytes", len(rawQuote))
	debugf("[output] exact Kind 1 artifact hex is written to stdout")
	debugf("[output] debug information is written to stderr")
	debugf("=== Seller quote build complete ===")
	fmt.Println(hex.EncodeToString(rawQuote))
	return nil
}

func mustPublicKey(compressed []byte) protocol.PublicKey {
	publicKey, err := protocol.PublicKeyFromBytes(compressed)
	if err != nil {
		panic(fmt.Sprintf("parse compressed public key: %v", err))
	}
	return publicKey
}

func debugf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envUint64(name string, fallback uint64) uint64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
