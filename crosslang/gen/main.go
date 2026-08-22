// Command gen 生成 Go/TS 共享的普通消息签名向量。
//
// 真值：ECDSA(SHA-256(canonical CBOR))，DER(low-S)。
// Go 的 (*ec.PrivateKey).Sign 只接收已算好的摘要；TS 侧验证脚本必须把
// digest 喂给不再次哈希的 verify 入口（见 ../verify-go-vector.mjs）。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
)

func main() {
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("11"), 32)))
	if err != nil {
		panic(err)
	}
	arbiter, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("33"), 32)))
	if err != nil {
		panic(err)
	}
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiter.PubKey().Compressed()})
	if err != nil {
		panic(err)
	}
	buyer, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{0x44}, 32))
	terms := &bitfs.FileQuoteTerms{
		SeedHash:                    bytes.Repeat([]byte{1}, 32),
		BuyerPubkey:                 buyer.PubKey().Compressed(),
		SeedPriceSat:                100,
		FullBlockPriceSat:           1000,
		FileSize:                    4096,
		QuoteExpiresAtUnix:          2000000000,
		SupportedArbiterPubkeysCBOR: arbiters,
	}
	termsCBOR, err := bitfs.EncodeFileQuoteTerms(terms)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(termsCBOR)
	signature, err := bitfs.SignMessage(key, termsCBOR)
	if err != nil {
		panic(err)
	}
	vector := map[string]string{
		"algorithm":  "ECDSA-over-secp256k1, message hashed once with SHA-256",
		"messageHex": hex.EncodeToString(termsCBOR),
		"digestHex":  hex.EncodeToString(digest[:]),
		"pubkeyHex":  hex.EncodeToString(key.PubKey().Compressed()),
		"derSigHex":  hex.EncodeToString(signature),
	}
	out, _ := json.MarshalIndent(vector, "", "  ")
	fmt.Println(string(out))
	_ = os.Stdout
}
