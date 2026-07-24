// Package arbiter provides an in-memory arbitration workflow example. It is
// intentionally transport-neutral; adapters submit and publish CBOR messages.
package arbiter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
	pool "github.com/bsv8/go-bitfs/settlement"
)

type PoolClient interface {
	StartArbitration(context.Context, *pool.ArbitrationRequest) (*pool.CloseSignatureRequest, error)
	CompleteArbitration(context.Context, *pool.CloseSignature) (*pool.PoolArbitrated, error)
}

type SessionPoolRef struct {
	SpendTxID              []byte
	CurrentSellerAmountSat uint64
}

type SessionResolver interface {
	ResolveSessionPool(context.Context, string, []byte) (SessionPoolRef, error)
}
type PayloadResolver interface {
	RecoverPayload(context.Context, *core.HashGetTicket) ([]byte, error)
}
type DecisionSigner func(context.Context, [32]byte) ([]byte, error)
type CloseTxSigner func(context.Context, [32]byte) ([]byte, error)

type Config struct {
	Now            func() time.Time
	TicketVerifier core.TicketSignatureVerifier
	DecisionSigner DecisionSigner
	CloseTxSigner  CloseTxSigner
}

type Dependencies struct {
	Pool            PoolClient
	SessionResolver SessionResolver
	PayloadResolver PayloadResolver
}

type Service struct {
	pool            PoolClient
	sessionResolver SessionResolver
	payloadResolver PayloadResolver
	now             func() time.Time
	ticketVerifier  core.TicketSignatureVerifier
	decisionSigner  DecisionSigner
	closeTxSigner   CloseTxSigner
	mu              sync.RWMutex
	records         map[string]*core.ArbitrationRecord
}

func New(config Config, dependencies Dependencies) (*Service, error) {
	if dependencies.Pool == nil {
		return nil, errors.New("pool client is required")
	}
	if dependencies.SessionResolver == nil {
		return nil, errors.New("session resolver is required")
	}
	if config.TicketVerifier == nil {
		return nil, errors.New("ticket verifier is required")
	}
	if config.DecisionSigner == nil {
		return nil, errors.New("pool decision signer is required")
	}
	if config.CloseTxSigner == nil {
		return nil, errors.New("close transaction signer is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{pool: dependencies.Pool, sessionResolver: dependencies.SessionResolver, payloadResolver: dependencies.PayloadResolver, now: config.Now, ticketVerifier: config.TicketVerifier, decisionSigner: config.DecisionSigner, closeTxSigner: config.CloseTxSigner, records: make(map[string]*core.ArbitrationRecord)}, nil
}

// SubmitClaim is the application handler for an ArbitrationClaim packet.
// A network adapter publishes the returned ArbitrationDecision as a new packet.
func (service *Service) SubmitClaim(ctx context.Context, claim *core.ArbitrationClaim) (*core.ArbitrationDecision, error) {
	if service == nil {
		return nil, errors.New("arbiter demo service is required")
	}
	if claim == nil || claim.Ticket == nil {
		return nil, errors.New("arbitration claim and ticket are required")
	}
	evidence, err := core.ValidateArbitrationClaim(claim, service.now(), service.ticketVerifier)
	if err != nil {
		return nil, fmt.Errorf("invalid evidence: %w", err)
	}
	if !evidence.PayloadVerified && service.payloadResolver != nil {
		payload, recoverErr := service.payloadResolver.RecoverPayload(ctx, claim.Ticket)
		if recoverErr == nil {
			claim = &core.ArbitrationClaim{Ticket: claim.Ticket, Payload: payload, ClaimantRole: claim.ClaimantRole}
			evidence, err = core.ValidateArbitrationClaim(claim, service.now(), service.ticketVerifier)
			if err != nil {
				return nil, fmt.Errorf("recovered payload invalid: %w", err)
			}
		}
	}
	poolRef, err := service.sessionResolver.ResolveSessionPool(ctx, claim.Ticket.SessionID, claim.Ticket.SellerPubkey)
	if err != nil {
		return nil, fmt.Errorf("session pool not found: %w", err)
	}
	if len(poolRef.SpendTxID) != 32 {
		return nil, errors.New("resolved spend_txid is empty")
	}
	decision, err := service.buildDecision(claim, evidence, poolRef)
	if err != nil {
		return nil, err
	}
	if err := service.settle(ctx, poolRef.SpendTxID, decision); err != nil {
		return nil, err
	}
	state := core.ArbitrationStateClosed
	if !decision.Approved {
		state = core.ArbitrationStateRejected
	}
	now := service.now().Unix()
	service.store(&core.ArbitrationRecord{SessionID: decision.SessionID, Sequence: decision.Sequence, State: state, Claim: claim, Decision: decision, CreatedAtUnix: now, UpdatedAtUnix: now})
	return decision, nil
}

func (service *Service) GetArbitration(sessionID string, sequence uint64) (*core.ArbitrationRecord, error) {
	if service == nil {
		return nil, errors.New("arbiter demo service is required")
	}
	if sessionID == "" {
		return nil, errors.New("session_id is required")
	}
	service.mu.RLock()
	record := service.records[recordKey(sessionID, sequence)]
	service.mu.RUnlock()
	if record == nil {
		return nil, errors.New("arbitration record not found")
	}
	return record, nil
}

func (service *Service) ListArbitrations(sessionID string) ([]*core.ArbitrationRecord, error) {
	if service == nil {
		return nil, errors.New("arbiter demo service is required")
	}
	if sessionID == "" {
		return nil, errors.New("session_id is required")
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	items := make([]*core.ArbitrationRecord, 0)
	for _, record := range service.records {
		if record.SessionID == sessionID {
			items = append(items, record)
		}
	}
	return items, nil
}

func (service *Service) buildDecision(claim *core.ArbitrationClaim, evidence *core.ArbitrationEvidence, poolRef SessionPoolRef) (*core.ArbitrationDecision, error) {
	if claim == nil || claim.Ticket == nil || evidence == nil {
		return nil, errors.New("claim evidence is required")
	}
	decision := &core.ArbitrationDecision{SessionID: claim.Ticket.SessionID, Sequence: claim.Ticket.Sequence, TicketID: evidence.TicketID, SellerPubkey: claim.Ticket.SellerPubkey}
	if !evidence.PayloadVerified {
		decision.ReasonCode = "payload_unavailable"
		return decision, nil
	}
	if poolRef.CurrentSellerAmountSat > math.MaxUint64-claim.Ticket.PriceSat {
		return nil, errors.New("final payout overflows uint64")
	}
	decision.Approved, decision.ReasonCode = true, "payload_verified"
	decision.FinalPayoutSat = poolRef.CurrentSellerAmountSat + claim.Ticket.PriceSat
	if claim.ClaimantRole == core.ArbitrationClaimantRoleBuyer {
		decision.RecoveredPayload = claim.Payload
	}
	return decision, nil
}

func (service *Service) settle(ctx context.Context, spendTxID []byte, decision *core.ArbitrationDecision) error {
	request := pool.NewArbitrationRequest(spendTxID, decision.Approved, decision.ReasonCode, []byte{1}, decision.FinalPayoutSat)
	digest, err := pool.ArbitrationSigningDigest(request)
	if err != nil {
		return err
	}
	decisionSignature, err := service.decisionSigner(ctx, digest)
	if err != nil {
		return fmt.Errorf("sign pool decision: %w", err)
	}
	request.ArbiterSignature = decisionSignature
	first, err := service.pool.StartArbitration(ctx, request)
	if err != nil {
		return fmt.Errorf("start pool arbitration: %w", err)
	}
	if first == nil {
		return errors.New("pool arbitration first phase was rejected")
	}
	sighash, err := decodeSighash(first.CloseSighash)
	if err != nil {
		return err
	}
	closeSignature, err := service.closeTxSigner(ctx, sighash)
	if err != nil {
		return fmt.Errorf("sign pool close transaction: %w", err)
	}
	second, err := service.pool.CompleteArbitration(ctx, &pool.CloseSignature{Version: pool.MajorVersion, MessageKind: pool.KindCloseSignature, SpendTxID: spendTxID, ArbitrationID: first.ArbitrationID, ArbiterSignatureOnCloseTransaction: closeSignature})
	if err != nil {
		return fmt.Errorf("finish pool arbitration: %w", err)
	}
	if second == nil || len(second.ClosingTransaction) == 0 {
		return errors.New("pool arbitration second phase was rejected")
	}
	return nil
}

func (service *Service) store(record *core.ArbitrationRecord) {
	service.mu.Lock()
	service.records[recordKey(record.SessionID, record.Sequence)] = record
	service.mu.Unlock()
}
func recordKey(sessionID string, sequence uint64) string {
	return fmt.Sprintf("%s\x00%d", sessionID, sequence)
}

func decodeSighash(raw []byte) ([32]byte, error) {
	var sighash [32]byte
	if len(raw) != len(sighash) {
		return sighash, fmt.Errorf("closing transaction sighash length must be %d, got %d", len(sighash), len(raw))
	}
	copy(sighash[:], raw)
	return sighash, nil
}
