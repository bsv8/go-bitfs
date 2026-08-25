// 授权链一致性测试：同一张 003 在 004、005、007 中必须携带完全相同的
// PaymentAuthorizationID（SHA-256(exact payment_authorization_cbor)，typed
// ID 文本带 pa_ 前缀）；AuthorizationCheckpoint 是最小 Kind 7 的路由键，
// 任何错配的授权/凭证组合都必须稳定返回分类错误。
package integration

import (
	"strings"
	"testing"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

// 同一授权在 004 交付包、005 最小凭证与合并后付款状态中的 ID 必须逐字节相等，
// 且都等于 PaymentAuthorizationID = SHA-256(exact payment_authorization_cbor)；
// ArbitrationClaimID 是另一个 typed 命名空间，绝不冒充付款授权哈希。
func TestAuthorizationIDIdenticalAcross004005And007(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)
	round := f.runPurchaseWithDeadline(t, f.buyerQuote, p, testBaseTime, f.DeliveryDeadline, true)

	authID := round.request.AuthorizationID
	if authID != round.request.Checkpoint.AuthorizationID() {
		t.Fatal("AuthorizationCheckpoint does not carry the request authorization id")
	}
	// typed ID 文本必须带 pa_ 前缀，且 Parse 往返一致。
	text := authID.String()
	if !strings.HasPrefix(text, "pa_") {
		t.Fatalf("typed id text %q is missing the pa_ prefix", text)
	}
	parsed, err := protocol.ParsePaymentAuthorizationID(text)
	if err != nil || parsed != authID {
		t.Fatalf("ParsePaymentAuthorizationID(%q) = %v, %v", text, parsed, err)
	}

	// checkpoint restore：从 exact Kind 5 bytes 恢复并重算 typed ID。
	openingProofCBOR, err := pool.EncodeOpeningProof(p.buyerPool.Opening())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := buyer.RestoreAuthorizationCheckpoint(f.quoteRaw, round.rawKind5, openingProofCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if restored.AuthorizationID() != authID || restored.Request() == nil {
		t.Fatal("restored authorization checkpoint lost the typed id or signed 003")
	}

	// 004：content_delivery_cbor 绑定值必须是同一个 ID。
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, round.rawKind6)
	if err != nil {
		t.Fatal(err)
	}
	deliveryDTO, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		t.Fatal(err)
	}
	deliveryBoundID, err := content.DecodeContentDeliveryDocument(deliveryDTO.ContentDeliveryCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if deliveryBoundID != authID {
		t.Fatal("004 content_delivery_cbor binds an ID other than SHA-256(payment_authorization_cbor)")
	}

	// 005：最小凭证只携带该 ID 与买方签名，无池 ID、无 raw tx。
	updateArtifact, err := wire.ParseAs(wire.PaymentUpdate, round.rawKind7)
	if err != nil {
		t.Fatal(err)
	}
	update, err := wire.DecodePaymentUpdate(updateArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if update.PaymentAuthorizationID != authID {
		t.Fatal("005 carries an authorization ID other than SHA-256(payment_authorization_cbor)")
	}

	// 授权 ID 是卖方本地注记：它必须落在合并后的本地 checkpoint 状态里；
	// 完整交易的 Verified 值来自 raw 重验，只携带链上可验证字段。
	nextState := round.completedPay.NextPool.Payment()
	if nextState == nil || nextState.PaymentAuthorizationID != authID {
		t.Fatal("next pool checkpoint lost the payment authorization id annotation")
	}

	// 007：ArbitrationClaimID = SHA-256(exact claim_cbor)，与 pa_ 命名空间互斥。
	rawKind8, err := f.Seller.PrepareArbitration(f.ctx, testFacts(testBaseTime), seller.ArbitrationCommand{
		Pool:        p.sellerPool,
		Request:     round.request.Checkpoint.Request(),
		DeliveryRaw: round.rawKind6,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.Arbiter.PrepareArbitration(testFacts(testBaseTime), rawKind8.Bytes(), testArbitrationFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	claimID := prepared.ArbitrationClaimID()
	if !strings.HasPrefix(claimID.String(), "ac_") {
		t.Fatalf("claim id text %q is missing the ac_ prefix", claimID.String())
	}
	if claimID == (protocol.ArbitrationClaimID{}) || claimID == protocol.ArbitrationClaimID(authID) {
		t.Fatal("Claim ID must never impersonate or collapse into the payment authorization hash")
	}
	response9, err := f.Arbiter.SignPreparedArbitration(f.ctx, testFacts(testBaseTime), prepared)
	if err != nil {
		t.Fatal(err)
	}
	responseDTO, err := arbitration.UnmarshalResponse(response9.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(responseDTO.ArbitrationReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbitrationClaimID != claimID || receipt.ArbiterAmountSatoshis != uint64(testArbitrationFeeSatoshis) {
		t.Fatal("007 receipt does not bind the exact Claim ID and the frozen positive fee")
	}
}

// 最小 Kind 7 不携带池身份：应用按 PaymentAuthorizationID 从
// AuthorizationCheckpoint 取回 exact 已签 003 后交给卖方。任何错配——外来
// 授权或被篡改的凭证 ID——都必须在签名验证前后稳定返回 state_conflict 分类；
// 正常组合仍然完成，证明拒绝来自错配而非 harness 断裂。
func TestAuthorizationCheckpointRoutingRejectsMismatchedCredentials(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)

	roundA := f.runPurchaseWithDeadline(t, f.buyerQuote, p, testBaseTime, f.DeliveryDeadline, false)
	authIDA := roundA.request.AuthorizationID

	// 另一张合法 003（不同截止时间 → 不同 ID），用于构造外来路由。
	requestB, err := f.Buyer.RequestContent(f.ctx, testFacts(testBaseTime), buyer.RequestContentCommand{
		Quote:            f.buyerQuote,
		Pool:             p.buyerPool,
		ContentHashes:    [][]byte{masterseed.Sum256(f.Seed).Bytes()},
		DeliveryDeadline: content.UnixSeconds(int64(f.DeliveryDeadline) - 600),
	})
	if err != nil {
		t.Fatal(err)
	}
	if requestB.AuthorizationID == authIDA {
		t.Fatal("test premise broken: two batches share one authorization id")
	}

	// 1. 凭证 A 配授权 B：授权 ID 先行冲突 → state_conflict。
	if _, err := f.Seller.CompletePayment(f.ctx, testFacts(testBaseTime), seller.PaymentCommand{
		Pool:       p.sellerPool,
		Request:    requestB.Checkpoint.Request(),
		UpdateRaw:  roundA.rawKind7,
		Checkpoint: roundA.delivery,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("foreign authorization routing error = %v, want state_conflict", err)
	}

	// 2. 篡改凭证中的 authorization ID → state_conflict。
	updateArtifact, err := wire.ParseAs(wire.PaymentUpdate, roundA.rawKind7)
	if err != nil {
		t.Fatal(err)
	}
	tamperedUpdate, err := wire.DecodePaymentUpdate(updateArtifact)
	if err != nil {
		t.Fatal(err)
	}
	tamperedUpdate.PaymentAuthorizationID[0] ^= 0xff
	tamperedRaw, err := wire.EncodePaymentUpdate(tamperedUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seller.CompletePayment(f.ctx, testFacts(testBaseTime), seller.PaymentCommand{
		Pool:       p.sellerPool,
		Request:    roundA.request.Checkpoint.Request(),
		UpdateRaw:  tamperedRaw.Bytes(),
		Checkpoint: roundA.delivery,
	}); !protocol.IsCode(err, protocol.CodeStateConflict) {
		t.Fatalf("tampered credential id error = %v, want state_conflict", err)
	}

	// 正常组合仍然完成。
	completedPay, err := f.Seller.CompletePayment(f.ctx, testFacts(testBaseTime), seller.PaymentCommand{
		Pool:       p.sellerPool,
		Request:    roundA.request.Checkpoint.Request(),
		UpdateRaw:  roundA.rawKind7,
		Checkpoint: roundA.delivery,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completedPay.NextPool.Payment().PaymentAuthorizationID != authIDA {
		t.Fatal("clean completion lost the authorization id binding")
	}
}
