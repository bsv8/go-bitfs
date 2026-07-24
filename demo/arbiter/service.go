// Package arbiter 提供仅用于测试与协议演示的最小仲裁服务端。
package arbiter

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	core "github.com/bsv8/go-bitfs/bitfs"
	bitfspb "github.com/bsv8/go-bitfs/proto/bitfspb"
	pool2of3pb "github.com/bsv8/go-bitfs/proto/pool2of3pb"
)

// PoolClient 是 demo 在业务裁决后调用的正式 2-of-3 结算客户端。
type PoolClient interface {
	ArbitrateSessionPool(context.Context, *pool2of3pb.ArbitrateSessionPoolRequestV1) (*pool2of3pb.ArbitrateSessionPoolResponseV1, error)
}

// SessionPoolRef 是仲裁服务执行结算所需的最小会话映射真值。
type SessionPoolRef struct {
	SpendTxID              string
	CurrentSellerAmountSat uint64
}

// SessionResolver 将 BitFS 会话和 seller 绑定解析为对应费用池。
type SessionResolver interface {
	ResolveSessionPool(context.Context, string, []byte) (SessionPoolRef, error)
}

// PayloadResolver 在买方未收到 payload 时尝试恢复真实二进制。
type PayloadResolver interface {
	RecoverPayload(context.Context, *bitfspb.HashGetTicketV1) ([]byte, error)
}

// DecisionSigner 为 pool 层仲裁决定摘要生成仲裁方签名。
type DecisionSigner func(context.Context, [32]byte) ([]byte, error)

// CloseTxSigner 为第一阶段 close 交易 sighash 生成仲裁方签名。
type CloseTxSigner func(context.Context, [32]byte) ([]byte, error)

// Config 是 demo 仲裁服务的可测试运行配置。
type Config struct {
	Now            func() time.Time
	TicketVerifier core.TicketSignatureVerifier
	DecisionSigner DecisionSigner
	CloseTxSigner  CloseTxSigner
}

// Dependencies 是 demo 仲裁服务接入运行时的外部依赖。
type Dependencies struct {
	Pool            PoolClient
	SessionResolver SessionResolver
	PayloadResolver PayloadResolver
}

// Service 是 BitfsArbitrationService 的内存实现。
// 它只演示自动证据验证和正式 pool 收尾，不提供持久化、钱包或链广播。
type Service struct {
	bitfspb.UnimplementedBitfsArbitrationServiceServer

	pool            PoolClient
	sessionResolver SessionResolver
	payloadResolver PayloadResolver
	now             func() time.Time
	ticketVerifier  core.TicketSignatureVerifier
	decisionSigner  DecisionSigner
	closeTxSigner   CloseTxSigner

	mu      sync.RWMutex
	records map[string]*bitfspb.ArbitrationRecordV1
}

// New 构造最小仲裁 demo 服务。
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
	return &Service{
		pool:            dependencies.Pool,
		sessionResolver: dependencies.SessionResolver,
		payloadResolver: dependencies.PayloadResolver,
		now:             config.Now,
		ticketVerifier:  config.TicketVerifier,
		decisionSigner:  config.DecisionSigner,
		closeTxSigner:   config.CloseTxSigner,
		records:         make(map[string]*bitfspb.ArbitrationRecordV1),
	}, nil
}

// SubmitClaim 实现自动仲裁：验票、验证或恢复 payload、形成裁决并完成 pool 两阶段收尾。
func (service *Service) SubmitClaim(ctx context.Context, request *bitfspb.SubmitArbitrationClaimRequestV1) (*bitfspb.SubmitArbitrationClaimResponseV1, error) {
	if service == nil {
		return nil, errors.New("arbiter demo service is required")
	}
	if request == nil || request.GetClaim() == nil || request.GetClaim().GetTicket() == nil {
		return submitError("invalid_claim", "arbitration claim and ticket are required"), nil
	}
	claim := request.GetClaim()
	evidence, err := core.ValidateArbitrationClaim(claim, service.now(), service.ticketVerifier)
	if err != nil {
		return submitError("invalid_evidence", err.Error()), nil
	}
	if !evidence.PayloadVerified && service.payloadResolver != nil {
		recoveredPayload, recoverErr := service.payloadResolver.RecoverPayload(ctx, claim.GetTicket())
		if recoverErr == nil {
			claim = &bitfspb.ArbitrationClaimV1{
				Ticket:       claim.GetTicket(),
				Payload:      recoveredPayload,
				ClaimantRole: claim.GetClaimantRole(),
			}
			evidence, err = core.ValidateArbitrationClaim(claim, service.now(), service.ticketVerifier)
			if err != nil {
				return submitError("recovered_payload_invalid", err.Error()), nil
			}
		}
	}
	poolRef, err := service.sessionResolver.ResolveSessionPool(ctx, claim.GetTicket().GetSessionId(), claim.GetTicket().GetSellerPubkey())
	if err != nil {
		return submitError("session_pool_not_found", err.Error()), nil
	}
	if poolRef.SpendTxID == "" {
		return submitError("session_pool_not_found", "resolved spend_txid is empty"), nil
	}
	decision, err := service.buildDecision(claim, evidence, poolRef)
	if err != nil {
		return submitError("decision_invalid", err.Error()), nil
	}
	if err := service.settle(ctx, poolRef.SpendTxID, decision); err != nil {
		return submitError("pool_settlement_failed", err.Error()), nil
	}
	state := bitfspb.ArbitrationStateV1_ARBITRATION_STATE_CLOSED
	if !decision.GetApproved() {
		state = bitfspb.ArbitrationStateV1_ARBITRATION_STATE_REJECTED
	}
	nowUnix := service.now().Unix()
	record := &bitfspb.ArbitrationRecordV1{
		SessionId:     decision.GetSessionId(),
		Sequence:      decision.GetSequence(),
		State:         state,
		Claim:         claim,
		Decision:      decision,
		CreatedAtUnix: nowUnix,
		UpdatedAtUnix: nowUnix,
	}
	service.store(record)
	return &bitfspb.SubmitArbitrationClaimResponseV1{Submitted: true, Decision: decision}, nil
}

// GetArbitration 返回一个指定会话和 sequence 的仲裁记录。
func (service *Service) GetArbitration(_ context.Context, request *bitfspb.GetArbitrationRequestV1) (*bitfspb.GetArbitrationResponseV1, error) {
	if service == nil {
		return nil, errors.New("arbiter demo service is required")
	}
	if request == nil || request.GetSessionId() == "" {
		return &bitfspb.GetArbitrationResponseV1{Error: &bitfspb.BitfsErrorV1{Code: "invalid_request", Message: "session_id is required"}}, nil
	}
	service.mu.RLock()
	record := service.records[recordKey(request.GetSessionId(), request.GetSequence())]
	service.mu.RUnlock()
	if record == nil {
		return &bitfspb.GetArbitrationResponseV1{Error: &bitfspb.BitfsErrorV1{Code: "not_found", Message: "arbitration record not found"}}, nil
	}
	return &bitfspb.GetArbitrationResponseV1{Record: record}, nil
}

// ListArbitrations 返回一个会话下的全部内存仲裁记录。
func (service *Service) ListArbitrations(_ context.Context, request *bitfspb.ListArbitrationsRequestV1) (*bitfspb.ListArbitrationsResponseV1, error) {
	if service == nil {
		return nil, errors.New("arbiter demo service is required")
	}
	if request == nil || request.GetSessionId() == "" {
		return &bitfspb.ListArbitrationsResponseV1{Error: &bitfspb.BitfsErrorV1{Code: "invalid_request", Message: "session_id is required"}}, nil
	}
	service.mu.RLock()
	items := make([]*bitfspb.ArbitrationRecordV1, 0)
	for _, record := range service.records {
		if record.GetSessionId() == request.GetSessionId() {
			items = append(items, record)
		}
	}
	service.mu.RUnlock()
	return &bitfspb.ListArbitrationsResponseV1{Items: items}, nil
}

// buildDecision 把已验证证据转换为业务裁决。
func (service *Service) buildDecision(claim *bitfspb.ArbitrationClaimV1, evidence *core.ArbitrationEvidence, poolRef SessionPoolRef) (*bitfspb.ArbitrationDecisionV1, error) {
	if claim == nil || claim.GetTicket() == nil || evidence == nil {
		return nil, errors.New("claim evidence is required")
	}
	decision := &bitfspb.ArbitrationDecisionV1{
		SessionId:    claim.GetTicket().GetSessionId(),
		Sequence:     claim.GetTicket().GetSequence(),
		TicketId:     evidence.TicketID,
		SellerPubkey: claim.GetTicket().GetSellerPubkey(),
	}
	if !evidence.PayloadVerified {
		decision.Approved = false
		decision.ReasonCode = "payload_unavailable"
		return decision, nil
	}
	if poolRef.CurrentSellerAmountSat > math.MaxUint64-claim.GetTicket().GetPriceSat() {
		return nil, errors.New("final payout overflows uint64")
	}
	decision.Approved = true
	decision.ReasonCode = "payload_verified"
	decision.FinalPayoutSat = poolRef.CurrentSellerAmountSat + claim.GetTicket().GetPriceSat()
	if claim.GetClaimantRole() == bitfspb.ArbitrationClaimantRoleV1_ARBITRATION_CLAIMANT_ROLE_BUYER {
		decision.RecoveredPayload = claim.GetPayload()
	}
	return decision, nil
}

// settle 调用正式 pool 仲裁接口，完成两阶段 close。
func (service *Service) settle(ctx context.Context, spendTxID string, decision *bitfspb.ArbitrationDecisionV1) error {
	digest := core.PoolArbitrationSigningDigest(spendTxID, decision.GetApproved(), decision.GetReasonCode(), decision.GetFinalPayoutSat())
	decisionSignature, err := service.decisionSigner(ctx, digest)
	if err != nil {
		return fmt.Errorf("sign pool decision: %w", err)
	}
	first, err := service.pool.ArbitrateSessionPool(ctx, &pool2of3pb.ArbitrateSessionPoolRequestV1{
		SpendTxid:        spendTxID,
		Approved:         decision.GetApproved(),
		Reason:           decision.GetReasonCode(),
		ArbiterSignature: decisionSignature,
		FinalPayoutSat:   decision.GetFinalPayoutSat(),
	})
	if err != nil {
		return fmt.Errorf("start pool arbitration: %w", err)
	}
	if !first.GetSuccess() || first.GetError() != nil {
		return errors.New("pool arbitration first phase was rejected")
	}
	if !first.GetNeedsArbiterSignature() {
		return nil
	}
	sighash, err := decodeSighash(first.GetClosingTxSighashHex())
	if err != nil {
		return err
	}
	closeSignature, err := service.closeTxSigner(ctx, sighash)
	if err != nil {
		return fmt.Errorf("sign pool close transaction: %w", err)
	}
	second, err := service.pool.ArbitrateSessionPool(ctx, &pool2of3pb.ArbitrateSessionPoolRequestV1{
		SpendTxid:                 spendTxID,
		Approved:                  decision.GetApproved(),
		Reason:                    decision.GetReasonCode(),
		ArbiterSignature:          decisionSignature,
		FinalPayoutSat:            decision.GetFinalPayoutSat(),
		ArbiterSignatureOnCloseTx: closeSignature,
	})
	if err != nil {
		return fmt.Errorf("finish pool arbitration: %w", err)
	}
	if !second.GetSuccess() || second.GetError() != nil || second.GetClosingTxHex() == "" {
		return errors.New("pool arbitration second phase was rejected")
	}
	return nil
}

// store 保存一条仲裁记录。
func (service *Service) store(record *bitfspb.ArbitrationRecordV1) {
	service.mu.Lock()
	service.records[recordKey(record.GetSessionId(), record.GetSequence())] = record
	service.mu.Unlock()
}

// recordKey 生成内存记录的复合键。
func recordKey(sessionID string, sequence uint64) string {
	return fmt.Sprintf("%s\x00%d", sessionID, sequence)
}

// submitError 构造不产生裁决的标准申诉响应。
func submitError(code string, message string) *bitfspb.SubmitArbitrationClaimResponseV1 {
	return &bitfspb.SubmitArbitrationClaimResponseV1{Error: &bitfspb.BitfsErrorV1{Code: code, Message: message}}
}

// decodeSighash 把 pool 第一阶段返回的 32 字节十六进制 sighash 解析为摘要。
func decodeSighash(value string) ([32]byte, error) {
	var sighash [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil {
		return sighash, fmt.Errorf("decode closing transaction sighash: %w", err)
	}
	if len(raw) != len(sighash) {
		return sighash, fmt.Errorf("closing transaction sighash length must be %d, got %d", len(sighash), len(raw))
	}
	copy(sighash[:], raw)
	return sighash, nil
}
