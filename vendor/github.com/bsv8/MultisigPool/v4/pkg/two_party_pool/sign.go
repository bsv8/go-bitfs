package two_party_pool

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

func signAs(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	if err := validateBuyerKey(roles, key); err != nil {
		return nil, err
	}
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return nil, fmt.Errorf("state must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, fmt.Errorf("state must have an empty unlocking script")
	}
	lock, err := BuildTwoPartyPoolLock(roles)
	if err != nil {
		return nil, err
	}
	if err := requireSource(state, poolAmount, lock); err != nil {
		return nil, err
	}
	copy, err := cloneTransaction(state)
	if err != nil {
		return nil, err
	}
	copy.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	template, err := libs.Unlock(nil, []*ec.PublicKey{roles.Buyer, roles.Seller}, 2, &flag)
	if err != nil {
		return nil, err
	}
	return valueOf(template.SignOne(copy, 0, key))
}

func valueOf(signature *[]byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if signature == nil || len(*signature) == 0 {
		return nil, fmt.Errorf("signature is empty")
	}
	return append([]byte(nil), (*signature)...), nil
}

// SignTwoPartyPoolAsBuyer signs an unsigned state with the Buyer key.
func SignTwoPartyPoolAsBuyer(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return signAs(state, poolAmount, roles, key)
}

// SignTwoPartyPoolAsSeller signs an unsigned state with the Seller key.
func SignTwoPartyPoolAsSeller(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("seller private key is required")
	}
	if !key.PubKey().IsEqual(roles.Seller) {
		return nil, fmt.Errorf("seller private key does not match seller public key")
	}
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return nil, fmt.Errorf("state must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, fmt.Errorf("state must have an empty unlocking script")
	}
	lock, err := BuildTwoPartyPoolLock(roles)
	if err != nil {
		return nil, err
	}
	if err := requireSource(state, poolAmount, lock); err != nil {
		return nil, err
	}
	copy, err := cloneTransaction(state)
	if err != nil {
		return nil, err
	}
	copy.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	template, err := libs.Unlock(nil, []*ec.PublicKey{roles.Buyer, roles.Seller}, 2, &flag)
	if err != nil {
		return nil, err
	}
	return valueOf(template.SignOne(copy, 0, key))
}

func merge(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, first, second []byte, firstKey, secondKey *ec.PublicKey) (*tx.Transaction, error) {
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	if err := validateSignatureShape(first); err != nil {
		return nil, err
	}
	if err := validateSignatureShape(second); err != nil {
		return nil, err
	}
	if string(first) == string(second) {
		return nil, fmt.Errorf("duplicate signatures are not permitted")
	}
	if firstKey == nil || secondKey == nil || !firstKey.IsEqual(roles.Buyer) || !secondKey.IsEqual(roles.Seller) {
		return nil, fmt.Errorf("signature roles do not match the two-party pool")
	}
	if ok, err := VerifyTwoPartyPoolBuyerSignature(state, poolAmount, roles, first); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("buyer signature does not match buyer role")
	}
	if ok, err := VerifyTwoPartyPoolSellerSignature(state, poolAmount, roles, second); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("seller signature does not match seller role")
	}
	copy, err := cloneTransaction(state)
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

// MergeTwoPartyPoolBuyerSellerSignatures verifies then orders [Buyer, Seller].
func MergeTwoPartyPoolBuyerSellerSignatures(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, buyerSignature, sellerSignature []byte) (*tx.Transaction, error) {
	return merge(state, poolAmount, roles, buyerSignature, sellerSignature, roles.Buyer, roles.Seller)
}

// UpdateTwoPartyPoolState returns a new state with explicit amounts and sequence.
func UpdateTwoPartyPoolState(input StateInput) (*tx.Transaction, error) {
	return BuildTwoPartyPoolState(input)
}

// FinalLockTime is the sequence-final locktime used by callers that close a state.
const FinalLockTime uint32 = 0xffffffff

var _ = script.NewFromBytes
