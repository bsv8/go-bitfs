// Command buyer parses and verifies a BitFS 001 file quote.
//
// The quote is accepted as canonical SignedFileQuote CBOR encoded as hex.
// Binary fields in the decoded result are printed as hex. The buyer private
// key is used only to derive the expected buyer public key.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/demo/internal/demoenv"
)

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
	debugf("[decode] quote CBOR bytes  : %d", len(rawQuote))
	quote, err := bitfs.DecodeSignedFileQuote(rawQuote)
	if err != nil {
		return fmt.Errorf("[decode CBOR] invalid SignedFileQuote: %w", err)
	}
	debugf("[decode] canonical quote  : yes")
	debugf("[decode] terms CBOR bytes  : %d", len(quote.TermsCBOR))
	debugf("[decode] seller public key : %s", hex.EncodeToString(quote.SellerPubkey))
	debugf("[decode] signature bytes   : %d", len(quote.TermsSignature))
	terms, err := bitfs.VerifySignedFileQuoteAt(quote, time.Now().UTC(), verifySignature)
	if err != nil {
		return fmt.Errorf("[verify seller signature/expiry] rejected: %w", err)
	}
	debugf("[verify] seller signature : valid")
	debugf("[verify] quote not expired: yes")

	privateKey, err := ec.PrivateKeyFromHex(strings.TrimSpace(os.Getenv("BUYER_PRIVATE_KEY_HEX")))
	if err != nil {
		return fmt.Errorf("derive expected buyer public key from BUYER_PRIVATE_KEY_HEX: %w", err)
	}
	if !bytes.Equal(privateKey.PubKey().Compressed(), terms.BuyerPubkey) {
		return errors.New("[verify buyer binding] quote is addressed to a different buyer")
	}
	debugf("[verify] buyer binding    : valid")

	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return fmt.Errorf("calculate quote terms hash: %w", err)
	}
	debugf("[hash] QuoteTermsHash    : %s", hex.EncodeToString(quoteHash[:]))
	supportedArbiters, err := bitfs.DecodeSupportedArbiterPubkeys(terms.SupportedArbiterPubkeysCBOR)
	if err != nil {
		return fmt.Errorf("decode supported arbiters: %w", err)
	}
	debugf("[terms] SeedHash         : %s", hex.EncodeToString(terms.SeedHash))
	debugf("[terms] buyer public key  : %s", hex.EncodeToString(terms.BuyerPubkey))
	debugf("[terms] seed price        : %d satoshis", terms.SeedPriceSat)
	debugf("[terms] full block price : %d satoshis", terms.FullBlockPriceSat)
	debugf("[terms] file size         : %d bytes", terms.FileSize)
	debugf("[terms] expires at UTC    : %s", time.Unix(terms.QuoteExpiresAtUnix, 0).UTC().Format(time.RFC3339))
	debugf("[terms] supported arbiters: %d", len(supportedArbiters))
	for index, pubkey := range supportedArbiters {
		debugf("[terms] arbiter[%d]        : %s", index, hex.EncodeToString(pubkey))
	}
	debugf("[result] quote accepted   : yes")
	debugf("=== Buyer quote parse complete ===")

	// Every binary value is printed as hex so this output can be piped to another
	// program without depending on Go's internal structs.
	fmt.Println("VALID=true")
	fmt.Printf("QUOTE_CBOR_HEX=%s\n", hex.EncodeToString(rawQuote))
	fmt.Printf("QUOTE_TERMS_HASH_HEX=%s\n", hex.EncodeToString(quoteHash[:]))
	fmt.Printf("TERMS_CBOR_HEX=%s\n", hex.EncodeToString(quote.TermsCBOR))
	fmt.Printf("SELLER_PUBKEY_HEX=%s\n", hex.EncodeToString(quote.SellerPubkey))
	fmt.Printf("TERMS_SIGNATURE_HEX=%s\n", hex.EncodeToString(quote.TermsSignature))
	fmt.Printf("RECOMMENDED_FILENAME=%s\n", quote.RecommendedFilename)
	fmt.Printf("SEED_HASH_HEX=%s\n", hex.EncodeToString(terms.SeedHash))
	fmt.Printf("BUYER_PUBKEY_HEX=%s\n", hex.EncodeToString(terms.BuyerPubkey))
	fmt.Printf("SEED_PRICE_SAT=%d\n", terms.SeedPriceSat)
	fmt.Printf("FULL_BLOCK_PRICE_SAT=%d\n", terms.FullBlockPriceSat)
	fmt.Printf("FILE_SIZE=%d\n", terms.FileSize)
	fmt.Printf("QUOTE_EXPIRES_AT_UNIX=%d\n", terms.QuoteExpiresAtUnix)
	fmt.Printf("SUPPORTED_ARBITER_COUNT=%d\n", len(supportedArbiters))
	for index, pubkey := range supportedArbiters {
		fmt.Printf("ARBITER_%d_PUBKEY_HEX=%s\n", index, hex.EncodeToString(pubkey))
	}
	return nil
}

func readQuoteHex(input io.Reader) (string, error) {
	if file, ok := input.(*os.File); ok {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(os.Stderr, "请输入卖家输出的 SignedFileQuote hex，然后按回车：")
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

func verifySignature(pubkey, payload, signature []byte) error {
	key, err := ec.ParsePubKey(pubkey)
	if err != nil {
		return err
	}
	sig, err := ec.ParseDERSignature(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !sig.Verify(digest[:], key) {
		return errors.New("signature mismatch")
	}
	return nil
}
