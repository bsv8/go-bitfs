package bitfs

import (
	"crypto/sha256"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/protocol"
)

// VerifySignature is the protocol's fixed ECDSA verifier. The supplied payload
// is hashed with SHA-256 exactly once before DER ECDSA verification. Workflows
// use this implementation directly; callers only provide a public key and the
// exact signed bytes, never a verifier strategy.
func VerifySignature(pubkey, payload, signature []byte) error {
	key, err := protocol.ParseCompressedPubKey(pubkey)
	if err != nil {
		return err
	}
	sig, err := ec.ParseDERSignature(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !sig.Verify(digest[:], key) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
