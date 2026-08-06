package pool

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
)

// arbitratedPoolV4Fixture is copied from the MultisigPool repository's
// testdata/arbitrated_pool_v4_fixture.json. Keeping the exact upstream vector
// in this repository makes the vendored dependency and its byte-level output
// part of go-bitfs's clean-checkout test surface.
type arbitratedPoolV4Fixture struct {
	Protocol                 string    `json:"protocol"`
	Version                  uint64    `json:"version"`
	FeeRate                  uint64    `json:"feeRate"`
	BuyerPrivHex             string    `json:"buyerPrivHex"`
	SellerPrivHex            string    `json:"sellerPrivHex"`
	ArbiterPrivHex           string    `json:"arbiterPrivHex"`
	BuyerUtxos               []mp.UTXO `json:"buyerUtxos"`
	PoolAmount               uint64    `json:"poolAmount"`
	LockTime                 uint32    `json:"lockTime"`
	NegotiationSequence      uint32    `json:"negotiationSequence"`
	NegotiationSellerAmount  uint64    `json:"negotiationSellerAmount"`
	NegotiationArbiterAmount uint64    `json:"negotiationArbiterAmount"`
	PaidArbiterSequence      uint32    `json:"paidArbiterSequence"`
	PaidArbiterSellerAmount  uint64    `json:"paidArbiterSellerAmount"`
	PaidArbiterAmount        uint64    `json:"paidArbiterAmount"`
	ProofSequence            uint32    `json:"proofSequence"`
	ProofSellerAmount        uint64    `json:"proofSellerAmount"`
	ProofArbiterAmount       uint64    `json:"proofArbiterAmount"`
	PaymentProofHex          string    `json:"paymentProofHex"`
	FundingFee               uint64    `json:"fundingFee"`
	LockHex                  string    `json:"lockHex"`
	FundingHex               string    `json:"fundingHex"`
	FundingTxID              string    `json:"fundingTxId"`
	OpeningStateHex          string    `json:"openingStateHex"`
	OpeningStateTxID         string    `json:"openingStateTxId"`
	NegotiationStateHex      string    `json:"negotiationStateHex"`
	NegotiationStateTxID     string    `json:"negotiationStateTxId"`
	PaidArbiterStateHex      string    `json:"paidArbiterStateHex"`
	PaidArbiterStateTxID     string    `json:"paidArbiterStateTxId"`
	ProofStateHex            string    `json:"proofStateHex"`
	ProofStateTxID           string    `json:"proofStateTxId"`
	OpeningOutputs           []uint64  `json:"openingOutputs"`
	NegotiationOutputs       []uint64  `json:"negotiationOutputs"`
	PaidArbiterOutputs       []uint64  `json:"paidArbiterOutputs"`
	ProofOutputs             []uint64  `json:"proofOutputs"`
	BuyerSignatureHex        string    `json:"buyerSignatureHex"`
	SellerSignatureHex       string    `json:"sellerSignatureHex"`
	ArbiterSignatureHex      string    `json:"arbiterSignatureHex"`
	FinalBuyerSellerHex      string    `json:"finalBuyerSellerHex"`
	FinalBuyerArbiterHex     string    `json:"finalBuyerArbiterHex"`
	FinalSellerArbiterHex    string    `json:"finalSellerArbiterHex"`
}

func TestMultisigPoolV4OfficialSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "arbitrated_pool_v4_fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture arbitratedPoolV4Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Protocol != mp.Protocol || fixture.Version != uint64(mp.Version) {
		t.Fatalf("fixture protocol = %s v%d, want %s v%d", fixture.Protocol, fixture.Version, mp.Protocol, mp.Version)
	}
	buyer := mustFixturePrivateKey(t, fixture.BuyerPrivHex)
	seller := mustFixturePrivateKey(t, fixture.SellerPrivHex)
	arbiter := mustFixturePrivateKey(t, fixture.ArbiterPrivHex)
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}

	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "lock", lock.Bytes(), fixture.LockHex)
	funding, err := mp.BuildArbitratedPoolFundingTx(fixture.BuyerUtxos, fixture.PoolAmount, buyer, roles, false, mp.FeeSatPerKB(fixture.FeeRate))
	if err != nil {
		t.Fatal(err)
	}
	assertTxFixture(t, "funding", funding.Tx, fixture.FundingHex, fixture.FundingTxID)
	if funding.Fee != fixture.FundingFee {
		t.Fatalf("funding fee = %d, want %d", funding.Fee, fixture.FundingFee)
	}

	opening, err := mp.BuildArbitratedPoolOpeningState(funding.Tx.TxID().CloneBytes(), funding.PoolOutputIndex, funding.PoolAmount, roles, fixture.LockTime, mp.FeeSatPerKB(fixture.FeeRate))
	if err != nil {
		t.Fatal(err)
	}
	assertTxFixture(t, "opening", opening, fixture.OpeningStateHex, fixture.OpeningStateTxID)
	assertOutputs(t, "opening", opening, fixture.OpeningOutputs)
	negotiation := buildFixtureState(t, fixture, opening, fixture.NegotiationSequence, fixture.NegotiationSellerAmount, fixture.NegotiationArbiterAmount, nil, roles)
	assertTxFixture(t, "negotiation", negotiation, fixture.NegotiationStateHex, fixture.NegotiationStateTxID)
	assertOutputs(t, "negotiation", negotiation, fixture.NegotiationOutputs)
	paidArbiter := buildFixtureState(t, fixture, negotiation, fixture.PaidArbiterSequence, fixture.PaidArbiterSellerAmount, fixture.PaidArbiterAmount, nil, roles)
	assertTxFixture(t, "paid arbiter", paidArbiter, fixture.PaidArbiterStateHex, fixture.PaidArbiterStateTxID)
	assertOutputs(t, "paid arbiter", paidArbiter, fixture.PaidArbiterOutputs)
	proof, err := hex.DecodeString(fixture.PaymentProofHex)
	if err != nil {
		t.Fatal(err)
	}
	proofState := buildFixtureState(t, fixture, paidArbiter, fixture.ProofSequence, fixture.ProofSellerAmount, fixture.ProofArbiterAmount, proof, roles)
	assertTxFixture(t, "proof", proofState, fixture.ProofStateHex, fixture.ProofStateTxID)
	assertOutputs(t, "proof", proofState, fixture.ProofOutputs)

	buyerSig, err := mp.SignArbitratedPoolAsBuyer(paidArbiter, funding.PoolAmount, roles, buyer)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := mp.SignArbitratedPoolAsSeller(paidArbiter, funding.PoolAmount, roles, seller)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSig, err := mp.SignArbitratedPoolAsArbiter(paidArbiter, funding.PoolAmount, roles, arbiter)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "buyer signature", buyerSig, fixture.BuyerSignatureHex)
	assertHex(t, "seller signature", sellerSig, fixture.SellerSignatureHex)
	assertHex(t, "arbiter signature", arbiterSig, fixture.ArbiterSignatureHex)
	merged, err := mp.MergeArbitratedPoolBuyerSellerSignatures(paidArbiter, funding.PoolAmount, roles, buyerSig, sellerSig)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "Buyer+Seller merge", merged.Bytes(), fixture.FinalBuyerSellerHex)
	merged, err = mp.MergeArbitratedPoolBuyerArbiterSignatures(paidArbiter, funding.PoolAmount, roles, buyerSig, arbiterSig)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "Buyer+Arbiter merge", merged.Bytes(), fixture.FinalBuyerArbiterHex)
	merged, err = mp.MergeArbitratedPoolSellerArbiterSignatures(paidArbiter, funding.PoolAmount, roles, sellerSig, arbiterSig)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "Seller+Arbiter merge", merged.Bytes(), fixture.FinalSellerArbiterHex)
}

func buildFixtureState(t *testing.T, fixture arbitratedPoolV4Fixture, previous *tx.Transaction, sequence uint32, sellerAmount, arbiterAmount uint64, paymentProof []byte, roles mp.ArbitratedPoolRoles) *tx.Transaction {
	t.Helper()
	lockTime := fixture.LockTime
	state, err := mp.BuildArbitratedPoolState(mp.ArbitratedPoolStateInput{
		Protocol: fixture.Protocol, Version: uint32(fixture.Version), PreviousRawTx: previous.Bytes(), PreviousSourceOutput: previous.Inputs[0].SourceTxOutput(), Sequence: sequence, LockTime: &lockTime,
		SellerAmount: sellerAmount, ArbiterAmount: arbiterAmount, PoolAmount: fixture.PoolAmount, Roles: roles, FeeRate: mp.FeeSatPerKB(fixture.FeeRate), PaymentProof: paymentProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func mustFixturePrivateKey(t *testing.T, raw string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func assertTxFixture(t *testing.T, name string, state *tx.Transaction, expectedHex, expectedID string) {
	t.Helper()
	assertHex(t, name, state.Bytes(), expectedHex)
	if state.TxID().String() != expectedID {
		t.Fatalf("%s txid = %s, want %s", name, state.TxID().String(), expectedID)
	}
}

func assertOutputs(t *testing.T, name string, state *tx.Transaction, expected []uint64) {
	t.Helper()
	if len(state.Outputs) != len(expected) {
		t.Fatalf("%s outputs = %d, want %d", name, len(state.Outputs), len(expected))
	}
	for i, output := range state.Outputs {
		if output.Satoshis != expected[i] {
			t.Fatalf("%s output[%d] = %d, want %d", name, i, output.Satoshis, expected[i])
		}
	}
}

func assertHex(t *testing.T, name string, actual []byte, expected string) {
	t.Helper()
	want, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatalf("%s fixture hex: %v", name, err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("%s bytes differ:\n got %x\nwant %x", name, actual, want)
	}
}
