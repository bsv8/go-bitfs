package bitfs

import (
	"errors"
	"fmt"
	"time"
)

// ArbitrationEvidence 是经过协议级验证后的申诉证据结果。
type ArbitrationEvidence struct {
	TicketID        []byte
	PayloadVerified bool
}

// ValidateArbitrationClaim 校验 BitFS 仲裁申诉中的票据、签名与可选 payload。
// 买方可不带 payload 请求恢复；卖方必须提交可直接验证的 payload。
func ValidateArbitrationClaim(claim *ArbitrationClaim, now time.Time, verifier TicketSignatureVerifier) (*ArbitrationEvidence, error) {
	if claim == nil {
		return nil, errors.New("arbitration claim is required")
	}
	if claim.ClaimantRole != ArbitrationClaimantRoleBuyer && claim.ClaimantRole != ArbitrationClaimantRoleSeller {
		return nil, errors.New("arbitration claimant_role is invalid")
	}
	if err := ValidateHashGetTicketAt(claim.Ticket, now); err != nil {
		return nil, fmt.Errorf("arbitration ticket invalid: %w", err)
	}
	if err := VerifyHashGetTicket(claim.Ticket, verifier); err != nil {
		return nil, err
	}
	ticketID, err := TicketID(claim.Ticket)
	if err != nil {
		return nil, err
	}
	if len(claim.Payload) == 0 {
		if claim.ClaimantRole == ArbitrationClaimantRoleSeller {
			return nil, errors.New("seller arbitration claim payload is required")
		}
		return &ArbitrationEvidence{TicketID: append([]byte(nil), ticketID[:]...)}, nil
	}
	delivery := &HashDelivery{
		SessionID:   claim.Ticket.SessionID,
		Sequence:    claim.Ticket.Sequence,
		ContentHash: claim.Ticket.ContentHash,
		Payload:     claim.Payload,
	}
	if err := ValidateDelivery(claim.Ticket, delivery); err != nil {
		return nil, fmt.Errorf("arbitration payload invalid: %w", err)
	}
	return &ArbitrationEvidence{
		TicketID:        append([]byte(nil), ticketID[:]...),
		PayloadVerified: true,
	}, nil
}
