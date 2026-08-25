package pool

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/protocol"
)

func bytes32(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }

// poolTestPubkeys returns three distinct deterministic compressed keys in
// Buyer/Seller/Arbiter role order for pure protocol tests.
func poolTestPubkeys(t *testing.T) (buyer, seller, arbiter []byte) {
	t.Helper()
	return mustPoolTestKey(t, "11").PubKey().Compressed(), mustPoolTestKey(t, "22").PubKey().Compressed(), mustPoolTestKey(t, "33").PubKey().Compressed()
}

// mustSigner 把测试私钥封装为受约束的 protocol.Signer；pool adapter 与仲裁签名
// 入口在新 API 下只接受该端口。
func mustSigner(t *testing.T, k *ec.PrivateKey) protocol.Signer {
	t.Helper()
	s, err := protocol.NewPrivateKeySigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
