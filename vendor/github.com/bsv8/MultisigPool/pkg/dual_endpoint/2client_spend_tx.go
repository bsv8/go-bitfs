package chain_utils

import (
	"encoding/hex"
	"fmt"
	"log"

	script "github.com/bsv-blockchain/go-sdk/script"

	libs "github.com/bsv8/MultisigPool/pkg/libs"
	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// 多签 to client，server 提供金额
func SubBuildDualFeePoolSpendTX(
	prevTxId string,
	totalAmount uint64, // 多签 UTXO 总金额
	serverAmount uint64, // server 最终分配金额
	endHeight uint32, // 区块高度
	clientPrivateKey *ec.PrivateKey,
	serverPublicKey *ec.PublicKey,
	isMain bool,
	feeRate float64,
) (*tx.Transaction, uint64, error) {
	return SubBuildDualFeePoolSpendTXWithProof(
		prevTxId,
		totalAmount,
		serverAmount,
		endHeight,
		clientPrivateKey,
		serverPublicKey,
		isMain,
		feeRate,
		nil,
	)
}

// SubBuildDualFeePoolSpendTXWithProof 构造双端费用池付款交易，并可追加付款证明 OP_RETURN。
// proof 为空时不生成数据输出，保持旧交易结构与旧签名语义。
func SubBuildDualFeePoolSpendTXWithProof(
	prevTxId string,
	totalAmount uint64, // 多签 UTXO 总金额
	serverAmount uint64, // server 最终分配金额
	endHeight uint32, // 区块高度
	clientPrivateKey *ec.PrivateKey,
	serverPublicKey *ec.PublicKey,
	isMain bool,
	feeRate float64,
	paymentProof []byte,
) (*tx.Transaction, uint64, error) {
	clientAddress, err := libs.GetAddressFromPublicKey(clientPrivateKey.PubKey(), isMain)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get client address: %w", err)
	}
	serverAddress, err := libs.GetAddressFromPublicKey(serverPublicKey, isMain)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get server address: %w", err)
	}

	// 生成公钥
	clientPublicKey := clientPrivateKey.PubKey()

	transactionTwo := tx.NewTransaction()
	transactionTwo.LockTime = endHeight

	// 创建初始交易的锁定脚本
	prevMultisigScript, err := libs.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create server locking script: %w", err)
	}
	prevMultisigTxLockingAsm := hex.EncodeToString(prevMultisigScript.Bytes())

	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := libs.Unlock([]*ec.PrivateKey{}, []*ec.PublicKey{serverPublicKey, clientPublicKey}, 2, &sigHash)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 添加所有UTXO作为输入
	err = transactionTwo.AddInputFrom(
		prevTxId,
		0,
		prevMultisigTxLockingAsm,
		totalAmount,
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

	// 添加服务器输出
	transactionTwo.AddOutput(&tx.TransactionOutput{
		Satoshis:      serverAmount,
		LockingScript: serverChangeScript,
	})

	// 客户端找零脚本
	// clientAddress, err := script.NewAddressFromPublicKey(clientPublicKey, isMain)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create change locking script: %w", err)
	// }
	clientChangeScript, err := p2pkh.Lock(clientAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create change locking script: %w", err)
	}

	// 添加客户端输出
	transactionTwo.AddOutput(&tx.TransactionOutput{
		Satoshis:      totalAmount - serverAmount,
		LockingScript: clientChangeScript,
	})

	// 付款证明只影响交易输出集合，不参与金额分账；空 proof 保持旧输出结构。
	opReturnScript, err := libs.BuildOptionalOpReturnScript(paymentProof)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create op_return locking script: %w", err)
	}
	if opReturnScript != nil {
		transactionTwo.AddOutput(&tx.TransactionOutput{
			Satoshis:      0,
			LockingScript: opReturnScript,
		})
	}

	// 做一个假的签名script，方便计算 size
	unlockingScript, err := libs.FakeSign(2)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to sign input %d: %w", 1, err)
	}
	transactionTwo.Inputs[0].UnlockingScript = unlockingScript

	// 计算交易大小（字节）
	txSize := transactionTwo.Size()

	// 基于大小计算费用（向上取整到最接近的KB）
	fee := uint64(float64(txSize) / 1000.0 * feeRate)
	if totalAmount < serverAmount+fee {
		return nil, 0, fmt.Errorf("not enough balance, need %d (serverAmount %d + fee %d), have %d", serverAmount+fee, serverAmount, fee, totalAmount)
	}
	if fee == 0 {
		fee = 1
	}

	// 更新找零输出的金额
	transactionTwo.Outputs[1].Satoshis = totalAmount - serverAmount - fee

	// 清空假解锁脚本，防止广播时出现非规范 DER 签名错误，后续由真实签名填充
	transactionTwo.Inputs[0].UnlockingScript = script.NewFromBytes([]byte{})

	// transactionTwo.Inputs[0].UnlockingScript = serverSignByte

	return transactionTwo, totalAmount - serverAmount - fee, nil
}

func SpendTXDualFeePoolClientSign(B_Tx *tx.Transaction, targetAmount uint64, clientPrivKey *ec.PrivateKey, serverPublicKey *ec.PublicKey) (*[]byte, error) {
	// transactionTwo, err := tx.NewTransactionFromHex(txHex)
	// if err != nil {
	// 	return nil, fmt.Errorf("无法从 hex 创建交易: %v", err)
	// }

	// 创建优先级脚本
	priorityScript, err := libs.Lock([]*ec.PublicKey{serverPublicKey, clientPrivKey.PubKey()}, 2)
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
	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{clientPrivKey}, []*ec.PublicKey{serverPublicKey, clientPrivKey.PubKey()}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("创建解锁脚本失败: %v", err)
	}

	// 重新签名所有输入
	serverSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(B_Tx, 0, clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("a 重新签名输入 %d 失败: %v", 1, err)
	}
	return serverSignByte, nil
}

// 构建双端费用池花费交易
// 发起者 utxos, 服务器提供金额， 发起者私钥， 服务器地址
// fee 是 server 提供，我只负责精确的金额
func BuildDualFeePoolSpendTX(
	A_Tx *tx.Transaction,
	totalAmount uint64, // UTXO 总金额
	serverAmount uint64, // 服务器分配金额
	endHeight uint32, // 区块高度
	clientPrivateKey *ec.PrivateKey,
	serverPublicKey *ec.PublicKey,
	isMain bool,
	feeRate float64,
) (*tx.Transaction, *[]byte, uint64, error) {
	return BuildDualFeePoolSpendTXWithProof(
		A_Tx,
		totalAmount,
		serverAmount,
		endHeight,
		clientPrivateKey,
		serverPublicKey,
		isMain,
		feeRate,
		nil,
	)
}

// BuildDualFeePoolSpendTXWithProof 构建双端费用池付款交易，并支持可选二进制付款证明。
func BuildDualFeePoolSpendTXWithProof(
	A_Tx *tx.Transaction,
	totalAmount uint64, // UTXO 总金额
	serverAmount uint64, // 服务器分配金额
	endHeight uint32, // 区块高度
	clientPrivateKey *ec.PrivateKey,
	serverPublicKey *ec.PublicKey,
	isMain bool,
	feeRate float64,
	paymentProof []byte,
) (*tx.Transaction, *[]byte, uint64, error) {

	txTwo, amount, err := SubBuildDualFeePoolSpendTXWithProof(A_Tx.TxID().String(), totalAmount, serverAmount, endHeight, clientPrivateKey, serverPublicKey, isMain, feeRate, paymentProof)
	if err != nil {
		log.Printf("BuildOneB error: %v", err)
		return nil, nil, 0, err
	}

	// 重新签名
	clientSignByte, err := SpendTXDualFeePoolClientSign(txTwo, totalAmount, clientPrivateKey, serverPublicKey)
	if err != nil {
		log.Printf("BuildOneC error: %v", err)
		return nil, nil, 0, err
	}

	return txTwo, clientSignByte, amount, nil
}
