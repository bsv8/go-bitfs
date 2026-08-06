package two_party_pool

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TwoPartyPoolRoles 固定承载 2-of-2 池的业务角色。
type TwoPartyPoolRoles struct {
	Buyer  *ec.PublicKey
	Seller *ec.PublicKey
}

func validateRoles(roles TwoPartyPoolRoles) error {
	if roles.Buyer == nil || roles.Seller == nil {
		return fmt.Errorf("buyer and seller public keys are required")
	}
	if roles.Buyer.IsEqual(roles.Seller) {
		return fmt.Errorf("buyer and seller public keys must be different")
	}
	return nil
}

func validateBuyerKey(roles TwoPartyPoolRoles, key *ec.PrivateKey) error {
	if err := validateRoles(roles); err != nil {
		return err
	}
	if key == nil {
		return fmt.Errorf("buyer private key is required")
	}
	if !key.PubKey().IsEqual(roles.Buyer) {
		return fmt.Errorf("buyer private key does not match buyer public key")
	}
	return nil
}
