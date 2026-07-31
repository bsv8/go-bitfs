package triple_endpoint

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ecdsa "github.com/bsv-blockchain/go-sdk/primitives/ecdsa"
	script "github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"

	multisig "github.com/bsv8/MultisigPool/pkg/libs"
)

// verifyTripleSig 提供三方签名验证的公共实现。
func verifyTripleSig(
	transactionObject *tx.Transaction,
	lockingScript *script.Script,
	sourceSatoshis uint64,
	pub *ec.PublicKey,
	signBytes *[]byte,
) (bool, error) {
	if transactionObject == nil || len(transactionObject.Inputs) == 0 {
		return false, fmt.Errorf("empty transaction or inputs")
	}
	if signBytes == nil || len(*signBytes) < 10 {
		return false, fmt.Errorf("invalid signature length")
	}
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	if (*signBytes)[len(*signBytes)-1] != byte(flag) {
		return false, fmt.Errorf("unexpected sighash flag")
	}

	in := transactionObject.Inputs[0]
	prev := in.SourceTxOutput()
	in.SetSourceTxOutput(&tx.TransactionOutput{Satoshis: sourceSatoshis, LockingScript: lockingScript})

	hash, err := transactionObject.CalcInputSignatureHash(0, flag)
	if err != nil {
		in.SetSourceTxOutput(prev)
		return false, fmt.Errorf("calc sighash failed: %w", err)
	}
	sigDER := (*signBytes)[:len(*signBytes)-1]
	sig, err := ec.ParseDERSignature(sigDER)
	if err != nil {
		in.SetSourceTxOutput(prev)
		return false, fmt.Errorf("parse der failed: %w", err)
	}
	ok := ecdsa.Verify(hash, sig, pub.ToECDSA())
	in.SetSourceTxOutput(prev)
	if !ok {
		return false, fmt.Errorf("signature verify failed")
	}
	return true, nil
}

// ServerVerifyClientASig 用于验证 A 方在三方花费交易中的签名。
func ServerVerifyClientASig(
	transactionObject *tx.Transaction,
	totalAmount uint64,
	serverPublicKey *ec.PublicKey,
	aPublicKey *ec.PublicKey,
	escrowPublicKey *ec.PublicKey,
	aSignBytes *[]byte,
) (bool, error) {
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, escrowPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifyTripleSig(transactionObject, redeem, totalAmount, aPublicKey, aSignBytes)
}

// ClientVerifyServerSig 用于验证服务器在三方花费交易中的签名。
func ClientVerifyServerSig(
	transactionObject *tx.Transaction,
	totalAmount uint64,
	serverPublicKey *ec.PublicKey,
	aPublicKey *ec.PublicKey,
	escrowPublicKey *ec.PublicKey,
	serverSignBytes *[]byte,
) (bool, error) {
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, escrowPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifyTripleSig(transactionObject, redeem, totalAmount, serverPublicKey, serverSignBytes)
}

// ServerVerifyClientBSig 用于验证托管方（B 方）在三方花费交易中的签名。
func ServerVerifyClientBSig(
	transactionObject *tx.Transaction,
	totalAmount uint64,
	serverPublicKey *ec.PublicKey,
	aPublicKey *ec.PublicKey,
	escrowPublicKey *ec.PublicKey,
	bSignBytes *[]byte,
) (bool, error) {
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, escrowPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifyTripleSig(transactionObject, redeem, totalAmount, escrowPublicKey, bSignBytes)
}
