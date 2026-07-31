package pool

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	mp "github.com/bsv8/MultisigPool/pkg"
)

func TestMultisigPoolAdapterUsesServerABRoleOrder(t *testing.T) {
	server, err := ec.PrivateKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ec.PrivateKeyFromHex("2222222222222222222222222222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ec.PrivateKeyFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	roles := PoolRoles{Server: server.PubKey(), A: a.PubKey(), B: b.PubKey()}
	got, err := BuildPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	wantScript, err := mp.TripleFeePoolSpentScript(roles.Server, roles.A, roles.B)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantScript.Bytes()) {
		t.Fatal("adapter changed canonical server/A/B locking script")
	}
	if _, err := MergePoolServerA("00", nil, nil); err == nil {
		t.Fatal("server+A merge accepted missing signatures")
	}
	if _, err := MergePoolServerB("00", nil, nil); err == nil {
		t.Fatal("server+B merge accepted missing signatures")
	}
}
