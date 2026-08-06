package libs

import (
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type FeePoolInfo struct {
	// BuyerAmount  uint64
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
	// info.BuyerAmount = tx.Outputs[0].Satoshis
	// if info.BuyerAmount < minFeePoolAmount {
	// 	return false, nil, errors.New("buyer amount is too small")
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
