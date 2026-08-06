package arbitrated_pool

import (
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ArbitratedPoolRoles 固定承载 2-of-3 池的业务角色。
type ArbitratedPoolRoles struct {
	Buyer   *ec.PublicKey
	Seller  *ec.PublicKey
	Arbiter *ec.PublicKey
}

func validateRoles(roles ArbitratedPoolRoles) error {
	if roles.Buyer == nil || roles.Seller == nil || roles.Arbiter == nil {
		return fmt.Errorf("buyer, seller and arbiter public keys are required")
	}
	if roles.Buyer.IsEqual(roles.Seller) || roles.Buyer.IsEqual(roles.Arbiter) || roles.Seller.IsEqual(roles.Arbiter) {
		return fmt.Errorf("buyer, seller and arbiter public keys must be different")
	}
	return nil
}

func validatePrivateKey(key *ec.PrivateKey, expected *ec.PublicKey, role string) error {
	if key == nil {
		return fmt.Errorf("%s private key is required", role)
	}
	if expected == nil || !key.PubKey().IsEqual(expected) {
		return fmt.Errorf("%s private key does not match %s public key", role, role)
	}
	return nil
}
