package arbitrated_pool

import (
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ecdsa "github.com/bsv-blockchain/go-sdk/primitives/ecdsa"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

func verify(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PublicKey, signature []byte) (bool, error) {
	if err := validateRoles(roles); err != nil {
		return false, err
	}
	if key == nil {
		return false, fmt.Errorf("signature public key is required")
	}
	if err := validateSignature(signature); err != nil {
		return false, err
	}
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return false, fmt.Errorf("state must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return false, fmt.Errorf("state must have an empty unlocking script")
	}
	lock, err := BuildArbitratedPoolLock(roles)
	if err != nil {
		return false, err
	}
	if err := requireSource(state, poolAmount, lock); err != nil {
		return false, err
	}
	_, buyer, seller, arbiter, err := scripts(roles)
	if err != nil {
		return false, err
	}
	if err := validateStateOutputs(state, roles, buyer, seller, arbiter); err != nil {
		return false, err
	}
	copy, err := clone(state)
	if err != nil {
		return false, err
	}
	copy.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	if signature[len(signature)-1] != byte(flag) {
		return false, fmt.Errorf("unexpected sighash flag")
	}
	parsed, err := ec.ParseDERSignature(signature[:len(signature)-1])
	if err != nil {
		return false, fmt.Errorf("invalid DER signature: %w", err)
	}
	hash, err := copy.CalcInputSignatureHash(0, flag)
	if err != nil {
		return false, fmt.Errorf("calculate signature hash: %w", err)
	}
	if !ecdsa.Verify(hash, parsed, key.ToECDSA()) {
		return false, fmt.Errorf("signature verification failed")
	}
	return true, nil
}
func VerifyArbitratedPoolBuyerSignature(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, signature []byte) (bool, error) {
	return verify(state, poolAmount, roles, roles.Buyer, signature)
}
func VerifyArbitratedPoolSellerSignature(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, signature []byte) (bool, error) {
	return verify(state, poolAmount, roles, roles.Seller, signature)
}
func VerifyArbitratedPoolArbiterSignature(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, signature []byte) (bool, error) {
	return verify(state, poolAmount, roles, roles.Arbiter, signature)
}
