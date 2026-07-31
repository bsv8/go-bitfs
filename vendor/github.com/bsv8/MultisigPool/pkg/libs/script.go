//go:build chainutils
// +build chainutils

package libs

import (
	"encoding/hex"

	bsv_hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
)

// 把script 转换成 hash
func (c *ChainUtils) GetScriptHash(script *script.Script) (string, error) {
	hash := bsv_hash.Sha256(script.Bytes())
	reversedHash := make([]byte, len(hash))
	for i := range hash {
		reversedHash[i] = hash[len(hash)-1-i]
	}
	hashString := hex.EncodeToString(reversedHash)
	return hashString, nil
}
