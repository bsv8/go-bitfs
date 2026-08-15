// Command seller builds a signed BitFS 001 file quote.
//
// All binary input and output values use hex. The seller private key is read
// from SELLER_PRIVATE_KEY_HEX and is never printed.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
)

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
	filename := flag.String("filename", envOr("RECOMMENDED_FILENAME", ""), "display-only recommended filename")
	flag.Parse()

	if err := run(*privateKeyHex, *privateKeyFile, *filePath, *seedPrice, *blockPrice, *validFor, *filename); err != nil {
		fmt.Fprintln(os.Stderr, "seller:", err)
		os.Exit(1)
	}
}

func run(privateKeyHex, privateKeyFile, filePath string, seedPrice, blockPrice uint64, validFor time.Duration, filename string) error {
	debugf("=== BitFS Seller Quote Builder ===")
	debugf("[config] source file       : %s", filePath)
	debugf("[config] seed price        : %d satoshis", seedPrice)
	debugf("[config] full block price : %d satoshis", blockPrice)
	debugf("[config] valid for         : %s", validFor)
	debugf("[config] filename          : %q", filename)
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
	seedHash := masterseed.Sum256(seed)
	debugf("[seed] MasterSeed size    : %d bytes", len(seed))
	debugf("[seed] SeedHash            : %s", hex.EncodeToString(seedHash.Bytes()))
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
	arbiterPubkeys := [][]byte{arbiterPrivateKey.PubKey().Compressed()}
	debugf("[key] arbiter public key  : %s", hex.EncodeToString(arbiterPubkeys[0]))
	arbiterCBOR, err := bitfs.EncodeSupportedArbiterPubkeys(arbiterPubkeys)
	if err != nil {
		return fmt.Errorf("encode supported arbiters: %w", err)
	}

	expiresAt := time.Now().UTC().Add(validFor).Unix()
	debugf("[quote] created at UTC    : %s", time.Now().UTC().Format(time.RFC3339))
	debugf("[quote] expires at UTC    : %s", time.Unix(expiresAt, 0).UTC().Format(time.RFC3339))
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                    seedHash.Bytes(),
		BuyerPubkey:                 buyerPubkey,
		SeedPriceSat:                seedPrice,
		FullBlockPriceSat:           blockPrice,
		FileSize:                    uint64(len(fileBytes)),
		QuoteExpiresAtUnix:          expiresAt,
		SupportedArbiterPubkeysCBOR: arbiterCBOR,
	}
	sellerPubkey := privateKey.PubKey().Compressed()
	quote, err := bitfs.NewSignedFileQuote(terms, sellerPubkey, filename, func(rawTermsCBOR []byte) ([]byte, error) {
		digest := sha256.Sum256(rawTermsCBOR)
		signature, err := privateKey.Sign(digest[:])
		if err != nil {
			return nil, err
		}
		return signature.Serialize(), nil
	})
	if err != nil {
		return fmt.Errorf("build signed file quote: %w", err)
	}
	debugf("[quote] deterministic terms CBOR (%d bytes): %s", len(quote.TermsCBOR), hex.EncodeToString(quote.TermsCBOR))
	debugf("[quote] terms signature  : %s", hex.EncodeToString(quote.TermsSignature))

	// This is the canonical SignedFileQuote CBOR, represented as transport-safe hex.
	rawQuote, err := bitfs.EncodeSignedFileQuote(quote)
	if err != nil {
		return fmt.Errorf("encode signed file quote: %w", err)
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return fmt.Errorf("calculate quote terms hash: %w", err)
	}
	debugf("[quote] terms hash       : %s", hex.EncodeToString(quoteHash[:]))
	debugf("[quote] complete CBOR size: %d bytes", len(rawQuote))
	debugf("[output] canonical quote hex is written to stdout")
	debugf("[output] debug information is written to stderr")
	debugf("=== Seller quote build complete ===")
	fmt.Println(hex.EncodeToString(rawQuote))
	return nil
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
