// Command buyer parses and verifies a BitFS 001 file quote.
//
// 输入是 exact Kind 1 Artifact 的 hex。纯函数 API：买方用
// buyer.AcceptQuote(facts, raw) 一次完成严格解析、卖方验签与过期判断，得到
// 不可变 VerifiedQuote；它不绑定买方身份，调用方自行比较 Terms。
// BuyerPublicKey。wire.Parse 仅用于展示层打印报文自描述 Kind。
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// blockHeight 是调用方认可并提供的当前区块高度；SDK 不查询节点。
const blockHeight protocol.BlockHeight = 900000

func main() {
	if err := demoenv.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "buyer:", err)
		os.Exit(1)
	}
	flag.Parse()

	if err := run(os.Stdin); err != nil {
		debugf("[FAIL] %v", err)
		fmt.Fprintln(os.Stderr, "buyer:", err)
		os.Exit(1)
	}
}

func run(input io.Reader) error {
	debugf("=== BitFS Buyer Quote Parser ===")
	quoteHex, err := readQuoteHex(input)
	if err != nil {
		return err
	}
	debugf("[input] received quote hex: %d characters", len(quoteHex))
	debugf("[input] first 32 chars   : %s", preview(quoteHex, 32))

	rawQuote, err := hex.DecodeString(strings.TrimSpace(quoteHex))
	if err != nil {
		return fmt.Errorf("[decode hex] invalid quote hex: %w", err)
	}
	debugf("[decode] quote artifact bytes: %d", len(rawQuote))

	privateKey, err := ec.PrivateKeyFromHex(strings.TrimSpace(os.Getenv("BUYER_PRIVATE_KEY_HEX")))
	if err != nil {
		return fmt.Errorf("create buyer signer from BUYER_PRIVATE_KEY_HEX: %w", err)
	}

	// 展示层打印：wire.Parse 自读版本与 Kind 并分派严格 decoder；
	// 业务验证完全交给角色 API。
	artifact, err := wire.Parse(rawQuote)
	if err != nil {
		return fmt.Errorf("[parse wire] invalid artifact: %w", err)
	}
	debugf("[parse] self-described kind: %d (FileQuote=%d)", artifact.Kind(), wire.FileQuote)

	// 显式事实：过期判断只依赖调用方传入的 Facts.Now。
	// AcceptQuote 不接收身份参数；买方绑定由调用方自行比较。
	now := time.Now().UTC()
	facts := protocol.Facts{Now: now, BlockHeight: blockHeight}
	verified, err := buyer.AcceptQuote(facts, rawQuote)
	if err != nil {
		return fmt.Errorf("[verify seller signature/expiry] rejected: %w", err)
	}
	terms := verified.Terms()
	debugf("[verify] seller signature : valid")
	debugf("[verify] quote not expired: yes")
	if !strings.EqualFold(hex.EncodeToString(privateKey.PubKey().Compressed()), hex.EncodeToString(terms.BuyerPublicKey)) {
		return errors.New("[verify buyer binding] quote is addressed to a different buyer")
	}
	debugf("[verify] buyer binding    : valid")

	supportedArbiters := verified.SupportedArbiterPublicKeys()
	debugf("[id] FileQuoteTermsID       : %s", verified.ID().String())
	debugf("[terms] SeedHash         : %s", hex.EncodeToString(terms.SeedHash))
	debugf("[terms] buyer public key  : %s", hex.EncodeToString(terms.BuyerPublicKey))
	debugf("[terms] seed price        : %d satoshis", terms.SeedPriceSatoshis)
	debugf("[terms] full block price : %d satoshis", terms.FullBlockPriceSatoshis)
	debugf("[terms] file size         : %d bytes", terms.FileSizeBytes)
	debugf("[terms] expires at UTC    : %s", time.Unix(terms.QuoteExpiresAtUnixSeconds, 0).UTC().Format(time.RFC3339))
	debugf("[terms] supported arbiters: %d", len(supportedArbiters))
	for index, pubkey := range supportedArbiters {
		debugf("[terms] arbiter[%d]        : %s", index, hex.EncodeToString(pubkey))
	}
	debugf("[result] quote accepted   : yes")
	debugf("=== Buyer quote parse complete ===")

	// 每个二进制值都以 hex 打印，输出可以继续管道传输而不依赖 Go 内部结构。
	fmt.Println("VALID=true")
	fmt.Printf("QUOTE_CBOR_HEX=%s\n", hex.EncodeToString(rawQuote))
	fmt.Printf("FILE_QUOTE_TERMS_ID=%s\n", verified.ID().String())
	fmt.Printf("SEED_HASH_BYTES=%d\n", len(verified.SeedHash()))
	fmt.Printf("SELLER_PUBKEY_HEX=%s\n", hex.EncodeToString(verified.SellerPublicKey()))
	fmt.Printf("RECOMMENDED_FILENAME=%s\n", terms.RecommendedFilename)
	fmt.Printf("SEED_HASH_HEX=%s\n", hex.EncodeToString(terms.SeedHash))
	fmt.Printf("BUYER_PUBKEY_HEX=%s\n", hex.EncodeToString(terms.BuyerPublicKey))
	fmt.Printf("SEED_PRICE_SAT=%d\n", terms.SeedPriceSatoshis)
	fmt.Printf("FULL_BLOCK_PRICE_SAT=%d\n", terms.FullBlockPriceSatoshis)
	fmt.Printf("FILE_SIZE=%d\n", terms.FileSizeBytes)
	fmt.Printf("QUOTE_EXPIRES_AT_UNIX=%d\n", terms.QuoteExpiresAtUnixSeconds)
	fmt.Printf("SUPPORTED_ARBITER_COUNT=%d\n", len(supportedArbiters))
	for index, pubkey := range supportedArbiters {
		fmt.Printf("ARBITER_%d_PUBKEY_HEX=%s\n", index, hex.EncodeToString(pubkey))
	}
	return nil
}

func readQuoteHex(input io.Reader) (string, error) {
	if file, ok := input.(*os.File); ok {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(os.Stderr, "请输入卖家输出的 Kind 1 Artifact hex，然后按回车：")
			line, err := bufio.NewReader(input).ReadString('\n')
			if err != nil && len(line) == 0 {
				return "", fmt.Errorf("read interactive quote hex: %w", err)
			}
			value := strings.TrimSpace(line)
			if value == "" {
				return "", errors.New("quote hex is required")
			}
			return value, nil
		}
	}
	rawInput, err := io.ReadAll(input)
	if err != nil {
		return "", fmt.Errorf("read quote hex from stdin: %w", err)
	}
	value := strings.TrimSpace(string(rawInput))
	if value == "" {
		return "", errors.New("quote hex is required")
	}
	return value, nil
}

func preview(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length] + "..."
}

func debugf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
}
