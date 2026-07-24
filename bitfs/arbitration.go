package bitfs

import (
	"errors"
	"fmt"
	"time"

	bitfspb "github.com/bsv8/go-bitfs/proto/bitfspb"
)

// ArbitrationEvidence 是经过协议级验证后的申诉证据结果。
type ArbitrationEvidence struct {
	TicketID        []byte
	PayloadVerified bool
}

// ValidateArbitrationClaim 校验 BitFS 仲裁申诉中的票据、签名与可选 payload。
// 买方可不带 payload 请求恢复；卖方必须提交可直接验证的 payload。
func ValidateArbitrationClaim(claim *bitfspb.ArbitrationClaimV1, now time.Time, verifier TicketSignatureVerifier) (*ArbitrationEvidence, error) {
	if claim == nil {
		return nil, errors.New("arbitration claim is required")
	}
	if claim.GetClaimantRole() != bitfspb.ArbitrationClaimantRoleV1_ARBITRATION_CLAIMANT_ROLE_BUYER &&
		claim.GetClaimantRole() != bitfspb.ArbitrationClaimantRoleV1_ARBITRATION_CLAIMANT_ROLE_SELLER {
		return nil, errors.New("arbitration claimant_role is invalid")
	}
	if err := ValidateHashGetTicketAt(claim.GetTicket(), now); err != nil {
		return nil, fmt.Errorf("arbitration ticket invalid: %w", err)
	}
	if err := VerifyHashGetTicket(claim.GetTicket(), verifier); err != nil {
		return nil, err
	}
	ticketID, err := TicketID(claim.GetTicket())
	if err != nil {
		return nil, err
	}
	if len(claim.GetPayload()) == 0 {
		if claim.GetClaimantRole() == bitfspb.ArbitrationClaimantRoleV1_ARBITRATION_CLAIMANT_ROLE_SELLER {
			return nil, errors.New("seller arbitration claim payload is required")
		}
		return &ArbitrationEvidence{TicketID: append([]byte(nil), ticketID[:]...)}, nil
	}
	delivery := &bitfspb.HashDeliveryV1{
		SessionId:   claim.GetTicket().GetSessionId(),
		Sequence:    claim.GetTicket().GetSequence(),
		ContentHash: claim.GetTicket().GetContentHash(),
		Payload:     claim.GetPayload(),
	}
	if err := ValidateDelivery(claim.GetTicket(), delivery); err != nil {
		return nil, fmt.Errorf("arbitration payload invalid: %w", err)
	}
	return &ArbitrationEvidence{
		TicketID:        append([]byte(nil), ticketID[:]...),
		PayloadVerified: true,
	}, nil
}
