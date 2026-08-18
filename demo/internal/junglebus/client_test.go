package junglebus

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

func TestParseNetworkDefaultsToTestnet(t *testing.T) {
	network, err := ParseNetwork("")
	if err != nil || network != Testnet {
		t.Fatalf("ParseNetwork(\"\") = %q, %v; want testnet", network, err)
	}
	for _, input := range []string{"test", "testnet"} {
		network, err := ParseNetwork(input)
		if err != nil || network != Testnet {
			t.Fatalf("ParseNetwork(%q) = %q, %v; want testnet", input, network, err)
		}
	}
	for _, input := range []string{"main", "mainnet"} {
		network, err := ParseNetwork(input)
		if err != nil || network != Mainnet {
			t.Fatalf("ParseNetwork(%q) = %q, %v; want mainnet", input, network, err)
		}
	}
}

func TestListUTXOsReconstructsAddressStateFromHistory(t *testing.T) {
	key, err := ec.PrivateKeyFromHex(strings.Repeat("11", 32))
	if err != nil {
		t.Fatalf("create private key: %v", err)
	}
	address, err := script.NewAddressFromPublicKey(key.PubKey(), false)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}
	lockingScript, err := p2pkh.Lock(address)
	if err != nil {
		t.Fatalf("build locking script: %v", err)
	}

	first := tx.NewTransaction()
	coinbaseHash := &chainhash.Hash{}
	first.AddInput(&tx.TransactionInput{
		SourceTXID:       coinbaseHash,
		UnlockingScript:  script.NewFromBytes([]byte{0x01}),
		SourceTxOutIndex: ^uint32(0),
		SequenceNumber:   tx.DefaultSequenceNumber,
	})
	first.AddOutput(&tx.TransactionOutput{Satoshis: 30_000, LockingScript: lockingScript})
	firstRaw := first.Bytes()
	firstID := first.TxID().String()

	second := tx.NewTransaction()
	if err := second.AddInputsFromUTXOs(&tx.UTXO{
		TxID:          first.TxID(),
		Vout:          0,
		Satoshis:      30_000,
		LockingScript: lockingScript,
	}); err != nil {
		t.Fatalf("add spending input: %v", err)
	}
	second.AddOutput(&tx.TransactionOutput{Satoshis: 29_000, LockingScript: lockingScript})
	secondRaw := second.Bytes()
	secondID := second.TxID().String()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/address/get/" + address.AddressString:
			// Deliberately return reverse order; the client must order by block
			// position before applying spend transitions.
			_ = json.NewEncoder(response).Encode([]addressTransaction{
				{TransactionID: secondID, BlockHeight: 101, BlockIndex: 1},
				{TransactionID: firstID, BlockHeight: 100, BlockIndex: 0},
			})
		case "/v1/transaction/get/" + firstID:
			_ = json.NewEncoder(response).Encode(transactionRecord{
				ID:          firstID,
				Transaction: base64.StdEncoding.EncodeToString(firstRaw),
				BlockHeight: 100,
			})
		case "/v1/transaction/get/" + secondID:
			_ = json.NewEncoder(response).Encode(transactionRecord{
				ID:          secondID,
				Transaction: base64.StdEncoding.EncodeToString(secondRaw),
				BlockHeight: 101,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	utxos, err := client.ListUTXOs(context.Background(), address.AddressString, Testnet)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Fatalf("got %d UTXOs, want 1: %#v", len(utxos), utxos)
	}
	if utxos[0].TxHash != secondID || utxos[0].Vout != 0 || utxos[0].Satoshis != 29_000 {
		t.Fatalf("reconstructed UTXO = %#v, want second transaction output", utxos[0])
	}
	if utxos[0].Status != "confirmed" || utxos[0].Height != 101 {
		t.Fatalf("UTXO confirmation metadata = %#v", utxos[0])
	}
	if utxos[0].ScriptHex != hex.EncodeToString(lockingScript.Bytes()) {
		t.Fatalf("locking script = %q, want %q", utxos[0].ScriptHex, hex.EncodeToString(lockingScript.Bytes()))
	}
}

func TestListUTXOsTreatsMissingAddressAsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.NotFound(response, nil)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	utxos, err := client.ListUTXOs(context.Background(), "mzoCHSsgoUaPSMFUbMbyMTTRTCdwvzTpuq", Testnet)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 0 {
		t.Fatalf("got %d UTXOs, want empty result", len(utxos))
	}
}
