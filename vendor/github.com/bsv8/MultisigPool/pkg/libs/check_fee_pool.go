package libs

import (
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type FeePoolInfo struct {
	// ServerAmount  uint64
	ExpiredHeight uint32
	PreviousID    *[]byte
}

func GetInfoFromTxOne(
	tx *transaction.Transaction,
	// signature []byte,
	// minFeePoolAmount uint64,
	// feePoolHeaderCount uint32,
) (info *FeePoolInfo, err error) {

	info = &FeePoolInfo{}
	// info.ServerAmount = tx.Outputs[0].Satoshis
	// if info.ServerAmount < minFeePoolAmount {
	// 	return false, nil, errors.New("server amount is too small")
	// }

	info.ExpiredHeight = tx.LockTime
	// if info.ExpiredHeight < feePoolHeaderCount {
	// 	return false, nil, errors.New("expired height is too small")
	// }

	privTxID := tx.Inputs[0].SourceTXID.CloneBytes()
	info.PreviousID = &privTxID
	// TODO: 检查签名

	return info, nil
}
