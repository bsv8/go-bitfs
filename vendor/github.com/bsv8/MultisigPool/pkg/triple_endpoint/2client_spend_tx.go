package triple_endpoint

import (
	"encoding/hex"
	"fmt"
	"log"

	libs "github.com/bsv8/MultisigPool/pkg/libs"
	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// SubBuildTripleFeePoolSpendTX builds a two-output state transaction.
// The fixed role order is server (seller), A (buyer), B (arbiter).
func SubBuildTripleFeePoolSpendTX(
	prevTxId string,
	serverValue uint64, // server 提供金额
	// cmdValue uint64, // cmd 提供金额
	endHeight uint32, // 区块高度
	serverPublicKey *ec.PublicKey,
	aPrivateKey *ec.PrivateKey,
	bPublicKey *ec.PublicKey,
	isMain bool,
	feeRate uint64,
) (*tx.Transaction, uint64, error) {
	return SubBuildTripleFeePoolSpendTXWithProof(
		prevTxId,
		serverValue,
		endHeight,
		serverPublicKey,
		aPrivateKey,
		bPublicKey,
		isMain,
		feeRate,
		nil,
	)
}

// SubBuildTripleFeePoolSpendTXWithProof 构造三方费用池付款交易，并可追加付款证明 OP_RETURN。
// 当前三方实现仍然是 2-of-3 资金池，proof 只影响输出集合，不改变门限语义。
func SubBuildTripleFeePoolSpendTXWithProof(
	prevTxId string,
	serverValue uint64, // server 提供金额
	endHeight uint32, // 区块高度
	serverPublicKey *ec.PublicKey,
	aPrivateKey *ec.PrivateKey,
	bPublicKey *ec.PublicKey,
	isMain bool,
	feeRate uint64,
	paymentProof []byte,
) (*tx.Transaction, uint64, error) {
	aAddress, err := libs.GetAddressFromPublicKey(aPrivateKey.PubKey(), isMain)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get client address: %w", err)
	}
	serverAddress, err := libs.GetAddressFromPublicKey(serverPublicKey, isMain)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get seller address: %w", err)
	}

	// 生成公钥
	aPublicKey := aPrivateKey.PubKey()

	transactionTwo := tx.NewTransaction()
	transactionTwo.LockTime = endHeight

	// 创建初始交易的锁定脚本
	prevMultisigScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, bPublicKey}, 2)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create server locking script: %w", err)
	}
	prevMultisigTxLockingAsm := hex.EncodeToString(prevMultisigScript.Bytes())

	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{}, []*ec.PublicKey{serverPublicKey, aPublicKey, bPublicKey}, 2, &sigHash)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 添加所有UTXO作为输入
	err = transactionTwo.AddInputFrom(
		prevTxId,
		0,
		prevMultisigTxLockingAsm,
		serverValue,
		aMultisigUnlockingScriptTemplate,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to add input: %w", err)
	}
	transactionTwo.Inputs[0].SequenceNumber = 1

	// 服务器找零脚本
	// serverAddress, err := script.NewAddressFromPublicKey(serverPublicKey, isMain)
	// if err != nil {
	// 	return nil, fmt.Errorf("无法从公钥生成地址: %v", err)
	// }
	serverChangeScript, err := p2pkh.Lock(serverAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create change locking script: %w", err)
	}

	// output[0] is always server/seller; output[1] is always A/buyer.
	transactionTwo.AddOutput(&tx.TransactionOutput{
		Satoshis:      0,
		LockingScript: serverChangeScript,
	})

	// 客户端找零脚本
	// clientAddress, err := script.NewAddressFromPublicKey(clientPublicKey, isMain)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create change locking script: %w", err)
	// }
	clientChangeScript, err := p2pkh.Lock(aAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create change locking script: %w", err)
	}

	// 添加客户端输出
	transactionTwo.AddOutput(&tx.TransactionOutput{
		Satoshis:      serverValue,
		LockingScript: clientChangeScript,
	})

	if len(paymentProof) != 0 {
		return nil, 0, fmt.Errorf("payment proofs are not permitted in a V2 state transaction")
	}

	// 做一个假的签名script，方便计算 size
	// Fee estimation may use a temporary script, but the returned candidate must
	// never carry fake signatures across the API boundary.
	unlockingScript, err := multisig.FakeSign(2)
	if err != nil {
		return nil, 0, fmt.Errorf("estimate input size: %w", err)
	}
	transactionTwo.Inputs[0].UnlockingScript = unlockingScript
	txSize := transactionTwo.Size()
	transactionTwo.Inputs[0].UnlockingScript = script.NewFromBytes(nil)

	// 计算交易大小（字节）
	// Integer satoshis per 1000 bytes, rounded up.
	fee, err := TriplePoolFeeSat(txSize, FeeSatPerKB(feeRate))
	if err != nil {
		return nil, 0, err
	}
	if serverValue < fee {
		return nil, 0, fmt.Errorf("not enough balance, need %d, have %d", fee, serverValue)
	}

	// 更新找零输出的金额
	transactionTwo.Outputs[1].Satoshis = serverValue - fee

	// transactionTwo.Inputs[0].UnlockingScript = serverSignByte

	return transactionTwo, serverValue - fee, nil
}

func SpendTXTripleFeePoolASign(
	B_Tx *tx.Transaction,
	targetAmount uint64,
	serverPublicKey *ec.PublicKey,
	aPrivKey *ec.PrivateKey,
	bPublicKey *ec.PublicKey,
) (*[]byte, error) {
	// 创建优先级脚本
	priorityScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPrivKey.PubKey(), bPublicKey}, 2)
	if err != nil {
		return nil, fmt.Errorf("创建优先级脚本失败: %v", err)
	}

	// 设置输入的锁定脚本
	B_Tx.Inputs[0].SetSourceTxOutput(
		&tx.TransactionOutput{
			Satoshis:      targetAmount,
			LockingScript: priorityScript,
		},
	)

	// unlocking script
	sighash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{aPrivKey}, []*ec.PublicKey{serverPublicKey, aPrivKey.PubKey(), bPublicKey}, 2, &sighash)
	if err != nil {
		return nil, fmt.Errorf("创建解锁脚本失败: %v", err)
	}

	// 重新签名所有输入
	aSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(B_Tx, 0, aPrivKey)
	if err != nil {
		return nil, fmt.Errorf("a 重新签名输入 %d 失败: %v", 1, err)
	}
	return aSignByte, nil
}

// 构建双端费用池花费交易
// 发起者 utxos, 服务器提供金额， 发起者私钥， 服务器地址
// fee 是 server 提供，我只负责精确的金额
func BuildTripleFeePoolSpendTX(
	A_Tx *tx.Transaction,
	serverValue uint64, // 服务器提供金额
	endHeight uint32, // 区块高度
	serverPublicKey *ec.PublicKey,
	aPrivateKey *ec.PrivateKey,
	bPublicKey *ec.PublicKey,
	isMain bool,
	feeRate uint64,
) (*tx.Transaction, *[]byte, uint64, error) {
	return BuildTripleFeePoolSpendTXWithProof(
		A_Tx,
		serverValue,
		endHeight,
		serverPublicKey,
		aPrivateKey,
		bPublicKey,
		isMain,
		feeRate,
		nil,
	)
}

// BuildTripleFeePoolSpendTXWithProof 构建三方费用池付款交易，并支持可选二进制付款证明。
func BuildTripleFeePoolSpendTXWithProof(
	A_Tx *tx.Transaction,
	serverValue uint64, // 服务器提供金额
	endHeight uint32, // 区块高度
	serverPublicKey *ec.PublicKey,
	aPrivateKey *ec.PrivateKey,
	bPublicKey *ec.PublicKey,
	isMain bool,
	feeRate uint64,
	paymentProof []byte,
) (*tx.Transaction, *[]byte, uint64, error) {

	txTwo, amount, err := SubBuildTripleFeePoolSpendTXWithProof(A_Tx.TxID().String(), serverValue, endHeight, serverPublicKey, aPrivateKey, bPublicKey, isMain, feeRate, paymentProof)
	if err != nil {
		log.Printf("BuildOneB error: %v", err)
		return nil, nil, 0, err
	}

	// log.Printf("------------------------------- BuildOneB success: %v", txTwo.Hex())

	// 重新签名
	clientSignByte, err := SpendTXTripleFeePoolASign(txTwo, serverValue, serverPublicKey, aPrivateKey, bPublicKey)
	if err != nil {
		log.Printf("BuildOneC error: %v", err)
		return nil, nil, 0, err
	}

	return txTwo, clientSignByte, amount, nil
}
