package protocol

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestCompressedPublicKeyValidationRejectsUncompressedEncoding(t *testing.T) {
	key, err := ec.PrivateKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompressedPubKey(key.PubKey().Compressed()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompressedPubKey(key.PubKey().Uncompressed()); err == nil {
		t.Fatal("uncompressed public key was accepted")
	}
}
