package arbitrated_pool

import (
	"bytes"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

// BuildArbitratedPoolLock 构建固定为 [Buyer, Seller, Arbiter] 的 2-of-3 脚本。
func BuildArbitratedPoolLock(roles ArbitratedPoolRoles) (*script.Script, error) {
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	return libs.Lock([]*ec.PublicKey{roles.Buyer, roles.Seller, roles.Arbiter}, 2)
}

func validateSignature(signature []byte) error {
	if len(signature) < 10 {
		return fmt.Errorf("signature is empty or too short")
	}
	return nil
}
func sameScript(a, b *script.Script) bool {
	return a != nil && b != nil && bytes.Equal(a.Bytes(), b.Bytes())
}

func requireSource(state *tx.Transaction, amount uint64, lock *script.Script) error {
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return fmt.Errorf("state must have exactly one input")
	}
	source := state.Inputs[0].SourceTxOutput()
	if source == nil || source.Satoshis != amount || !sameScript(source.LockingScript, lock) {
		return fmt.Errorf("state source output does not match configured pool")
	}
	return nil
}

func isPaymentProofScript(value *script.Script) bool {
	if value == nil {
		return false
	}
	b := value.Bytes()
	if len(b) < 3 || b[0] != byte(script.OpFALSE) || b[1] != byte(script.OpRETURN) {
		return false
	}
	offset := 2
	length := 0
	switch b[offset] {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75:
		length = int(b[offset])
		offset++
	case 0x4c:
		if len(b) < offset+2 {
			return false
		}
		length = int(b[offset+1])
		offset += 2
	case 0x4d:
		if len(b) < offset+3 {
			return false
		}
		length = int(b[offset+1]) | int(b[offset+2])<<8
		offset += 3
	case 0x4e:
		if len(b) < offset+5 {
			return false
		}
		length = int(b[offset+1]) | int(b[offset+2])<<8 | int(b[offset+3])<<16 | int(b[offset+4])<<24
		offset += 5
	default:
		return false
	}
	return length > 0 && offset+length == len(b)
}

func validateStateOutputs(state *tx.Transaction, roles ArbitratedPoolRoles, buyer, seller, arbiter *script.Script) error {
	if len(state.Outputs) != 3 && len(state.Outputs) != 4 {
		return fmt.Errorf("arbitrated pool state must have exactly three or four outputs")
	}
	expected := []*script.Script{buyer, seller, arbiter}
	for index, value := range expected {
		if state.Outputs[index] == nil || state.Outputs[index].Satoshis < 0 || !sameScript(state.Outputs[index].LockingScript, value) {
			return fmt.Errorf("arbitrated pool output %d does not match its role", index)
		}
	}
	if len(state.Outputs) == 4 && (state.Outputs[3] == nil || state.Outputs[3].Satoshis != 0 || !isPaymentProofScript(state.Outputs[3].LockingScript)) {
		return fmt.Errorf("invalid payment proof output")
	}
	return nil
}
