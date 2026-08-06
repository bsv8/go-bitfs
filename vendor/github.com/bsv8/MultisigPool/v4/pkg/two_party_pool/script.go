package two_party_pool

import (
	"bytes"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

// BuildTwoPartyPoolLock 构建固定为 [Buyer, Seller] 的 2-of-2 锁定脚本。
func BuildTwoPartyPoolLock(roles TwoPartyPoolRoles) (*script.Script, error) {
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	return libs.Lock([]*ec.PublicKey{roles.Buyer, roles.Seller}, 2)
}

func sourceMatches(txInput *script.Script, expected *script.Script) bool {
	return txInput != nil && expected != nil && bytes.Equal(txInput.Bytes(), expected.Bytes())
}

func validateSignatureShape(signature []byte) error {
	if len(signature) < 10 {
		return fmt.Errorf("signature is empty or too short")
	}
	return nil
}

func requireSource(state *tx.Transaction, amount uint64, lock *script.Script) error {
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return fmt.Errorf("state must have exactly one input")
	}
	source := state.Inputs[0].SourceTxOutput()
	if source == nil || source.Satoshis != amount || !sourceMatches(source.LockingScript, lock) {
		return fmt.Errorf("state source output does not match configured pool")
	}
	return nil
}
