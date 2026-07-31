package chain_utils

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ecdsa "github.com/bsv-blockchain/go-sdk/primitives/ecdsa"
	script "github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"

	multisig "github.com/bsv8/MultisigPool/pkg/libs"
)

// verifySignatureWithContext 用于在指定锁定脚本和金额的上下文中验证 DER+SigHash 签名。
// 调用完成后会恢复输入的 SourceTxOutput，确保交易对象不会被持久修改。
func verifySignatureWithContext(
	transactionObject *tx.Transaction,
	inputIndex uint32,
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

	// Expected flag
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	if (*signBytes)[len(*signBytes)-1] != byte(flag) {
		return false, fmt.Errorf("unexpected sighash flag")
	}

	// Backup existing context
	input := transactionObject.Inputs[inputIndex]
	prev := input.SourceTxOutput()

	// Set context needed for sighash
	input.SetSourceTxOutput(&tx.TransactionOutput{Satoshis: sourceSatoshis, LockingScript: lockingScript})

	// Compute sighash and verify DER
	hash, err := transactionObject.CalcInputSignatureHash(inputIndex, flag)
	if err != nil {
		// Restore
		input.SetSourceTxOutput(prev)
		return false, fmt.Errorf("calc sighash failed: %w", err)
	}

	sigDER := (*signBytes)[:len(*signBytes)-1]
	sig, err := ec.ParseDERSignature(sigDER)
	if err != nil {
		input.SetSourceTxOutput(prev)
		return false, fmt.Errorf("parse der failed: %w", err)
	}

	ok := ecdsa.Verify(hash, sig, pub.ToECDSA())

	// Restore original source output
	input.SetSourceTxOutput(prev)
	if !ok {
		return false, fmt.Errorf("signature verify failed")
	}
	return true, nil
}

// ServerVerifyClientSpendSig 用于在 B-Tx 上验证客户端签名。
func ServerVerifyClientSpendSig(
	transactionObject *tx.Transaction,
	totalAmount uint64,
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
	clientSignBytes *[]byte,
) (bool, error) {
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifySignatureWithContext(transactionObject, 0, redeem, totalAmount, clientPublicKey, clientSignBytes)
}

// ClientVerifyServerSpendSig 用于在 B-Tx 上验证服务器签名。
func ClientVerifyServerSpendSig(
	transactionObject *tx.Transaction,
	totalAmount uint64,
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
	serverSignBytes *[]byte,
) (bool, error) {
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifySignatureWithContext(transactionObject, 0, redeem, totalAmount, serverPublicKey, serverSignBytes)
}

// ServerVerifyClientUpdateSig 用于在更新后的 B-Tx 上验证客户端签名。
func ServerVerifyClientUpdateSig(
	transactionObject *tx.Transaction,
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
	clientSignBytes *[]byte,
) (bool, error) {
	// source satoshis are expected set in input context for updates
	src := transactionObject.Inputs[0].SourceTxOutput()
	if src == nil {
		return false, fmt.Errorf("missing source tx output")
	}
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifySignatureWithContext(transactionObject, 0, redeem, src.Satoshis, clientPublicKey, clientSignBytes)
}

// ClientVerifyServerUpdateSig 用于在更新后的 B-Tx 上验证服务器签名。
func ClientVerifyServerUpdateSig(
	transactionObject *tx.Transaction,
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
	serverSignBytes *[]byte,
) (bool, error) {
	src := transactionObject.Inputs[0].SourceTxOutput()
	if src == nil {
		return false, fmt.Errorf("missing source tx output")
	}
	redeem, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return false, fmt.Errorf("build redeem script: %w", err)
	}
	return verifySignatureWithContext(transactionObject, 0, redeem, src.Satoshis, serverPublicKey, serverSignBytes)
}
