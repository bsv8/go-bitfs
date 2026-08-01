package pool

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/pkg"
)

type sharedPoolFixture struct {
	PoolAmountSat      uint64 `json:"poolAmountSat"`
	StateFeeSat        uint64 `json:"stateFeeSat"`
	StateOutputCount   int    `json:"stateOutputCount"`
	StateSequence      uint32 `json:"stateSequence"`
	ServerPubKey       string `json:"serverPubKey"`
	BuyerPubKey        string `json:"buyerPubKey"`
	ArbiterPubKey      string `json:"arbiterPubKey"`
	SourceTxID         string `json:"sourceTxID"`
	StateTxHex         string `json:"stateTxHex"`
	BuyerSignatureHex  string `json:"buyerSignatureHex"`
	ServerSignatureHex string `json:"serverSignatureHex"`
}

func TestSharedTriplePoolV2Fixture(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "testdata", "triple_pool_v2_fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture sharedPoolFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	state, err := tx.NewTransactionFromBytes(mustHexFixture(t, fixture.StateTxHex))
	if err != nil {
		t.Fatal(err)
	}
	server, err := ec.PublicKeyFromString(fixture.ServerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := ec.PublicKeyFromString(fixture.BuyerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	arbiter, err := ec.PublicKeyFromString(fixture.ArbiterPubKey)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := mp.BuildTriplePoolLock(server, buyer, arbiter)
	if err != nil {
		t.Fatal(err)
	}
	setPoolSource(state, fixture.PoolAmountSat, lock.Bytes())
	if got := state.Hex(); got != fixture.StateTxHex {
		t.Fatalf("state bytes changed: got %s want %s", got, fixture.StateTxHex)
	}
	if len(state.Outputs) != fixture.StateOutputCount || state.Inputs[0].SequenceNumber != fixture.StateSequence {
		t.Fatal("shared state shape changed")
	}
	var total uint64
	for _, output := range state.Outputs {
		total += output.Satoshis
	}
	if fixture.PoolAmountSat-total != fixture.StateFeeSat {
		t.Fatal("shared integer fee changed")
	}

	buyerSig := mustHexFixture(t, fixture.BuyerSignatureHex)
	serverSig := mustHexFixture(t, fixture.ServerSignatureHex)
	ok, err := mp.VerifyTriplePoolASignature(state, buyer, server, arbiter, &buyerSig)
	if err != nil || !ok {
		t.Fatal("shared buyer signature does not verify")
	}
	ok, err = mp.VerifyTriplePoolServerSignature(state, server, buyer, arbiter, &serverSig)
	if err != nil || !ok {
		t.Fatal("shared server signature does not verify")
	}
}

func mustHexFixture(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
