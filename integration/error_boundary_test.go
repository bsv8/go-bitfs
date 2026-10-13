package integration

import (
	"bytes"
	"context"
	"testing"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/internal/flowtest/buyer"
	"github.com/bsv8/go-bitfs/internal/flowtest/seller"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	wire "github.com/bsv8/go-bitfs/wire"
)

// TestPublicRoleErrorsAlwaysClassified 锁定统一错误模型的边界契约：
// 三个角色包每个公开方法的代表性拒绝路径都必须能经 protocol.CodeOf 稳定
// 取到分类，调用方绝不依赖错误文本匹配。任何新增分支若逃逸分类都会在此失败。
func TestPublicRoleErrorsAlwaysClassified(t *testing.T) {
	f := newProtocolFixture(t)
	p := f.openMainPool(t)
	ctx := f.ctx
	junk := bytes.Repeat([]byte{0xA5}, 200)

	assertCode := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
		if _, ok := protocol.CodeOf(err); !ok {
			t.Fatalf("%s: unclassified error: %v", name, err)
		}
	}
	// assertExactCode 比 assertCode 更严格：CodeOf 必须精确命中 want。
	// 退款门禁路径用它锁定"事实缺失 = invalid_evidence"，防止调用层包装
	// 把输入问题误报成 expired/not_matured 这类协议状态结论。
	assertExactCode := func(name string, err error, want protocol.ErrorCode) {
		t.Helper()
		assertCode(name, err)
		if code, _ := protocol.CodeOf(err); code != want {
			t.Fatalf("%s: error code = %v, want exactly %s", name, code, want)
		}
	}

	// ---- buyer ----
	b := f.Buyer
	_, err := b.AcceptQuote(protocol.Facts{}, f.quoteRaw)
	assertCode("buyer.AcceptQuote zero facts", err)
	{
		_, err = b.AcceptQuote(protocol.Facts{Now: testBaseTime}, junk[:10])
		assertCode("buyer.AcceptQuote malformed", err)
		_, err = b.PreparePoolOpening(context.Background(), buyer.PrepareOpeningCommand{})
		assertCode("buyer.PreparePoolOpening missing quote", err)
		_, err = b.CompletePoolOpening(nil, junk)
		assertCode("buyer.CompletePoolOpening nil checkpoint", err)
		_, err = b.RequestContent(ctx, protocol.Facts{}, buyer.RequestContentCommand{})
		assertExactCode("buyer.RequestContent zero facts", err, protocol.CodeInvalidEvidence)
		_, err = b.VerifyDeliveryAndPreparePayment(ctx, testFacts(testBaseTime), buyer.VerifyDeliveryCommand{DeliveryRaw: junk})
		assertCode("buyer.VerifyDelivery malformed kind6", err)
		_, err = b.PrepareClose(ctx, protocol.Facts{}, buyer.PrepareCloseCommand{})
		assertCode("buyer.PrepareClose zero facts", err)
		_, err = b.VerifyCompletedClose(buyer.VerifyCloseCommand{})
		assertCode("buyer.VerifyCompletedClose empty command", err)
		_, err = b.BuildMaturedRefund(protocol.Facts{}, p.buyerPool)
		assertExactCode("buyer.BuildMaturedRefund zero facts", err, protocol.CodeInvalidEvidence)
		_, err = b.RequestArbitratedContent(ctx, buyer.ArbitrationRetrievalCommand{})
		assertCode("buyer.RequestArbitratedContent empty command", err)
		_, err = b.VerifyArbitratedContent(ctx, buyer.ArbitratedContentCommand{RetrievalRequestRaw: junk, RetrievalResponseRaw: junk})
		assertCode("buyer.VerifyArbitratedContent junk", err)
	}

	// ---- seller ----
	s := f.Seller
	_, err = s.CreateQuote(ctx, protocol.Facts{}, seller.QuoteDraft{})
	assertCode("seller.CreateQuote zero facts", err)
	{
		_, err = s.PreparePoolOpening(context.Background(), junk)
		assertCode("seller.PreparePoolOpening junk kind2", err)
		_, err = s.VerifyFundingDelivery(nil, junk)
		assertCode("seller.VerifyFundingDelivery junk kind4", err)
		_, err = s.DeliverContent(ctx, protocol.Facts{}, seller.DeliveryCommand{})
		assertExactCode("seller.DeliverContent zero facts", err, protocol.CodeInvalidEvidence)
		_, err = s.CompletePayment(ctx, protocol.Facts{}, seller.PaymentCommand{UpdateRaw: junk})
		assertCode("seller.CompletePayment junk kind7", err)
		_, err = s.CompleteClose(ctx, protocol.Facts{}, seller.CloseCommand{})
		assertCode("seller.CompleteClose zero facts", err)
		_, err = s.PrepareArbitration(ctx, protocol.Facts{}, seller.ArbitrationCommand{})
		assertCode("seller.PrepareArbitration zero facts", err)
		_, err = s.CompleteArbitratedPayment(ctx, protocol.Facts{}, seller.ArbitratedPaymentCommand{RequestRaw: junk})
		assertCode("seller.CompleteArbitratedPayment junk kind8", err)
	}

	// ---- arbiter ----
	a := f.Arbiter
	_, err = a.PrepareArbitration(protocol.Facts{}, junk, 1)
	assertCode("arbiter.PrepareArbitration junk kind8", err)
	{
		_, err = a.PrepareArbitration(testFacts(testBaseTime), junk, 0)
		assertCode("arbiter.PrepareArbitration zero fee", err)
		_, err = a.SignPreparedArbitration(ctx, protocol.Facts{}, nil)
		assertCode("arbiter.SignPreparedArbitration nil prepared", err)
		err = a.AuthenticateRetrieval(junk, junk)
		assertCode("arbiter.AuthenticateRetrieval junk", err)
		_, err = a.VerifyRetrievableCustody(junk, junk, junk)
		assertCode("arbiter.VerifyRetrievableCustody junk", err)
		_, err = a.BuildUnavailableRetrieval(ctx, protocol.ContentRetrievalRequestID{}, arbitration.RetrievalSellerArbitrationNotReady)
		assertCode("arbiter.BuildUnavailableRetrieval zero id", err)
		_, err = a.BuildAvailableRetrieval(ctx, protocol.ContentRetrievalRequestID{}, nil)
		assertCode("arbiter.BuildAvailableRetrieval nil custody", err)
	}

	// ---- 领域层公开验证入口 ----
	{
		_, err = pool.VerifyOpeningProof(nil)
		assertCode("pool.VerifyOpeningProof nil", err)
		_, err = pool.VerifySignedTransaction(junk, &pool.OpeningProof{})
		assertCode("pool.VerifySignedTransaction junk", err)
		err = pool.VerifyRefundPresignRequestEvidence(nil)
		assertCode("pool.VerifyRefundPresignRequestEvidence nil", err)
		_, err = content.VerifyQuoteForBuyer(nil, protocol.Facts{}, make([]byte, 33))
		assertCode("content.VerifyQuoteForBuyer nil quote", err)
		_, err = wire.Parse(junk)
		assertCode("wire.Parse junk", err)
	}

}
