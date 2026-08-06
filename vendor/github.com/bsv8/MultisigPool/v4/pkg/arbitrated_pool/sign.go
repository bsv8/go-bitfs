package arbitrated_pool

import (
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

func sign(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey, expected *ec.PublicKey, role string) ([]byte, error) {
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	if err := validatePrivateKey(key, expected, role); err != nil {
		return nil, err
	}
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return nil, fmt.Errorf("state must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, fmt.Errorf("state must have an empty unlocking script")
	}
	lock, err := BuildArbitratedPoolLock(roles)
	if err != nil {
		return nil, err
	}
	if err := requireSource(state, poolAmount, lock); err != nil {
		return nil, err
	}
	_, buyer, seller, arbiter, err := scripts(roles)
	if err != nil {
		return nil, err
	}
	if err := validateStateOutputs(state, roles, buyer, seller, arbiter); err != nil {
		return nil, err
	}
	copy, err := clone(state)
	if err != nil {
		return nil, err
	}
	copy.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	template, err := libs.Unlock(nil, []*ec.PublicKey{roles.Buyer, roles.Seller, roles.Arbiter}, 2, &flag)
	if err != nil {
		return nil, err
	}
	sig, err := template.SignOne(copy, 0, key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), (*sig)...), nil
}

func SignArbitratedPoolAsBuyer(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return sign(state, poolAmount, roles, key, roles.Buyer, "buyer")
}
func SignArbitratedPoolAsSeller(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return sign(state, poolAmount, roles, key, roles.Seller, "seller")
}
func SignArbitratedPoolAsArbiter(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return sign(state, poolAmount, roles, key, roles.Arbiter, "arbiter")
}

func merge(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, first, second []byte, firstKey, secondKey *ec.PublicKey) (*tx.Transaction, error) {
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	if err := validateSignature(first); err != nil {
		return nil, err
	}
	if err := validateSignature(second); err != nil {
		return nil, err
	}
	if string(first) == string(second) {
		return nil, fmt.Errorf("duplicate signatures are not permitted")
	}
	if firstKey == nil || secondKey == nil {
		return nil, fmt.Errorf("signature roles are required")
	}
	if ok, err := verify(state, poolAmount, roles, firstKey, first); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("first role signature does not match")
	}
	if ok, err := verify(state, poolAmount, roles, secondKey, second); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("second role signature does not match")
	}
	copy, err := clone(state)
	if err != nil {
		return nil, err
	}
	unlock, err := libs.BuildSignScript(&[][]byte{first, second})
	if err != nil {
		return nil, err
	}
	copy.Inputs[0].UnlockingScript = unlock
	return copy, nil
}

func MergeArbitratedPoolBuyerSellerSignatures(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, buyerSignature, sellerSignature []byte) (*tx.Transaction, error) {
	return merge(state, poolAmount, roles, buyerSignature, sellerSignature, roles.Buyer, roles.Seller)
}
func MergeArbitratedPoolBuyerArbiterSignatures(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, buyerSignature, arbiterSignature []byte) (*tx.Transaction, error) {
	return merge(state, poolAmount, roles, buyerSignature, arbiterSignature, roles.Buyer, roles.Arbiter)
}
func MergeArbitratedPoolSellerArbiterSignatures(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, sellerSignature, arbiterSignature []byte) (*tx.Transaction, error) {
	return merge(state, poolAmount, roles, sellerSignature, arbiterSignature, roles.Seller, roles.Arbiter)
}
