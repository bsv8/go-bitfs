// Package pkg provides the v4 multisig-pool protocol for Bitcoin SV transactions.
package pkg

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv8/MultisigPool/v4/internal/versioninfo"
	arbitrated "github.com/bsv8/MultisigPool/v4/pkg/arbitrated_pool"
	"github.com/bsv8/MultisigPool/v4/pkg/libs"
	twoParty "github.com/bsv8/MultisigPool/v4/pkg/two_party_pool"
)

const (
	ProtocolVersion = versioninfo.ProtocolVersion
	ReleaseVersion  = versioninfo.GoReleaseVersion
	Version         = ProtocolVersion
	Protocol        = versioninfo.Protocol
)

type MultiSig = libs.MultiSig
type UTXO = libs.UTXO
type TwoPartyPoolRoles = twoParty.TwoPartyPoolRoles
type ArbitratedPoolRoles = arbitrated.ArbitratedPoolRoles
type TwoPartyPoolStateInput = twoParty.StateInput
type ArbitratedPoolStateInput = arbitrated.StateInput
type TwoPartyPoolFundingResult = twoParty.FundingTxResult
type ArbitratedPoolFundingResult = arbitrated.FundingTxResult
type FeeSatPerKB = arbitrated.FeeSatPerKB

func Lock(pubKeys []*ec.PublicKey, m int) (*script.Script, error) {
	return libs.Lock(pubKeys, m)
}

func Unlock(privKeys []*ec.PrivateKey, pubKeys []*ec.PublicKey, m int, sigHashFlag *sighash.Flag) (*MultiSig, error) {
	return libs.Unlock(privKeys, pubKeys, m, sigHashFlag)
}

func GetAddressFromPublicKey(pubKey *ec.PublicKey, isMain bool) (*script.Address, error) {
	return libs.GetAddressFromPublicKey(pubKey, isMain)
}

var ErrInvalidPublicKeys = libs.ErrInvalidPublicKeys

func BuildTwoPartyPoolLock(roles TwoPartyPoolRoles) (*script.Script, error) {
	return twoParty.BuildTwoPartyPoolLock(roles)
}

func BuildTwoPartyPoolFundingTx(utxos []UTXO, poolAmount uint64, buyerPrivateKey *ec.PrivateKey, roles TwoPartyPoolRoles, isMain bool, feeRate float64) (*TwoPartyPoolFundingResult, error) {
	return twoParty.BuildTwoPartyPoolFundingTx(utxos, poolAmount, buyerPrivateKey, roles, isMain, feeRate)
}

func BuildTwoPartyPoolState(input TwoPartyPoolStateInput) (*tx.Transaction, error) {
	return twoParty.BuildTwoPartyPoolState(input)
}

func BuildTwoPartyPoolOpeningState(fundingTxID []byte, poolOutputIndex uint32, poolAmount uint64, roles TwoPartyPoolRoles, lockTime uint32, feeRate FeeSatPerKB) (*tx.Transaction, error) {
	return twoParty.BuildTwoPartyPoolOpeningState(fundingTxID, poolOutputIndex, poolAmount, roles, lockTime, twoParty.FeeSatPerKB(feeRate))
}

func SignTwoPartyPoolAsBuyer(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return twoParty.SignTwoPartyPoolAsBuyer(state, poolAmount, roles, key)
}

func SignTwoPartyPoolAsSeller(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return twoParty.SignTwoPartyPoolAsSeller(state, poolAmount, roles, key)
}

func VerifyTwoPartyPoolBuyerSignature(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, signature []byte) (bool, error) {
	return twoParty.VerifyTwoPartyPoolBuyerSignature(state, poolAmount, roles, signature)
}

func VerifyTwoPartyPoolSellerSignature(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, signature []byte) (bool, error) {
	return twoParty.VerifyTwoPartyPoolSellerSignature(state, poolAmount, roles, signature)
}

func MergeTwoPartyPoolBuyerSellerSignatures(state *tx.Transaction, poolAmount uint64, roles TwoPartyPoolRoles, buyerSignature, sellerSignature []byte) (*tx.Transaction, error) {
	return twoParty.MergeTwoPartyPoolBuyerSellerSignatures(state, poolAmount, roles, buyerSignature, sellerSignature)
}

func BuildArbitratedPoolLock(roles ArbitratedPoolRoles) (*script.Script, error) {
	return arbitrated.BuildArbitratedPoolLock(roles)
}

func BuildArbitratedPoolFundingTx(utxos []UTXO, poolAmount uint64, buyerPrivateKey *ec.PrivateKey, roles ArbitratedPoolRoles, isMain bool, feeRate FeeSatPerKB) (*ArbitratedPoolFundingResult, error) {
	return arbitrated.BuildArbitratedPoolFundingTx(utxos, poolAmount, buyerPrivateKey, roles, isMain, feeRate)
}

func BuildArbitratedPoolOpeningState(fundingTxID []byte, poolOutputIndex uint32, poolAmount uint64, roles ArbitratedPoolRoles, lockTime uint32, rate FeeSatPerKB) (*tx.Transaction, error) {
	return arbitrated.BuildArbitratedPoolOpeningState(fundingTxID, poolOutputIndex, poolAmount, roles, lockTime, rate)
}

func BuildArbitratedPoolState(input ArbitratedPoolStateInput) (*tx.Transaction, error) {
	return arbitrated.BuildArbitratedPoolState(input)
}

func BuildArbitratedPoolFinalState(input ArbitratedPoolStateInput) (*tx.Transaction, error) {
	return arbitrated.BuildArbitratedPoolFinalState(input)
}

func SignArbitratedPoolAsBuyer(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return arbitrated.SignArbitratedPoolAsBuyer(state, poolAmount, roles, key)
}

func SignArbitratedPoolAsSeller(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return arbitrated.SignArbitratedPoolAsSeller(state, poolAmount, roles, key)
}

func SignArbitratedPoolAsArbiter(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, key *ec.PrivateKey) ([]byte, error) {
	return arbitrated.SignArbitratedPoolAsArbiter(state, poolAmount, roles, key)
}

func VerifyArbitratedPoolBuyerSignature(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, signature []byte) (bool, error) {
	return arbitrated.VerifyArbitratedPoolBuyerSignature(state, poolAmount, roles, signature)
}

func VerifyArbitratedPoolSellerSignature(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, signature []byte) (bool, error) {
	return arbitrated.VerifyArbitratedPoolSellerSignature(state, poolAmount, roles, signature)
}

func VerifyArbitratedPoolArbiterSignature(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, signature []byte) (bool, error) {
	return arbitrated.VerifyArbitratedPoolArbiterSignature(state, poolAmount, roles, signature)
}

func MergeArbitratedPoolBuyerSellerSignatures(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, buyerSignature, sellerSignature []byte) (*tx.Transaction, error) {
	return arbitrated.MergeArbitratedPoolBuyerSellerSignatures(state, poolAmount, roles, buyerSignature, sellerSignature)
}

func MergeArbitratedPoolBuyerArbiterSignatures(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, buyerSignature, arbiterSignature []byte) (*tx.Transaction, error) {
	return arbitrated.MergeArbitratedPoolBuyerArbiterSignatures(state, poolAmount, roles, buyerSignature, arbiterSignature)
}

func MergeArbitratedPoolSellerArbiterSignatures(state *tx.Transaction, poolAmount uint64, roles ArbitratedPoolRoles, sellerSignature, arbiterSignature []byte) (*tx.Transaction, error) {
	return arbitrated.MergeArbitratedPoolSellerArbiterSignatures(state, poolAmount, roles, sellerSignature, arbiterSignature)
}
