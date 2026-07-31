package libs

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	// "go.uber.org/zap"
)

// type ChainUtils struct {
// 	Chain *chain.Chain
// 	// IsMainnet bool
// 	// typename  string // wsc = whatsonchain,

// 	// setting
// 	feeRate float64

// 	// // header
// 	// headerRefreshIntervalSeconds int32
// 	// nowHeight                    uint32
// 	// getHeightTime                time.Time

// 	// // unspent         *[]UTXO
// 	// amount          uint64
// 	// allocateTimeout *time.Timer
// 	// lock            *sync.Mutex // 分配金额的锁
// 	// Demo         *demo.Demo
// 	// Whatsonchain *whatsonchain.WSC
// }

// func NewChainUtils(IsMainnet bool, typename string, feeRate float64, headerRefreshIntervalSeconds int32) (*ChainUtils, error) {
// 	chain, err := chain.NewChain(IsMainnet, typename, headerRefreshIntervalSeconds)
// 	chain, err := chain.NewChain(IsMainnet, typename, headerRefreshIntervalSeconds, logger)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &ChainUtils{
// 		Chain:   chain,
// 		feeRate: feeRate,
// 		Logger:  logger,
// 	}, nil
// }

func GetAddressFromPublicKey(pubKey *ec.PublicKey, isMain bool) (*script.Address, error) {
	return script.NewAddressFromPublicKey(pubKey, isMain)
}

// GetAddressFromPubKey is kept for backward compatibility.
func GetAddressFromPubKey(pubKey *ec.PublicKey, isMain bool) (*script.Address, error) {
	return GetAddressFromPublicKey(pubKey, isMain)
}
