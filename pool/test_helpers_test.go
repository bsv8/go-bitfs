package pool

import (
	"bytes"
	"testing"
)

func bytes32(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }

// poolTestPubkeys returns three distinct deterministic compressed keys in
// Buyer/Seller/Arbiter role order for pure protocol tests.
func poolTestPubkeys(t *testing.T) (buyer, seller, arbiter []byte) {
	t.Helper()
	return mustPoolTestKey(t, "11").PubKey().Compressed(), mustPoolTestKey(t, "22").PubKey().Compressed(), mustPoolTestKey(t, "33").PubKey().Compressed()
}
