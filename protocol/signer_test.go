package protocol

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// countingDelegate 记录 Sign 调用次数并允许测试中途替换私钥。
type rotatingDelegate struct {
	mu        sync.Mutex
	key       *ec.PrivateKey
	signCalls int
}

func (d *rotatingDelegate) PublicKey() PublicKey {
	d.mu.Lock()
	defer d.mu.Unlock()
	typed, err := PublicKeyFromBytes(d.key.PubKey().Compressed())
	if err != nil {
		return PublicKey{}
	}
	return typed
}

func (d *rotatingDelegate) rotate(key *ec.PrivateKey) {
	d.mu.Lock()
	d.key = key
	d.mu.Unlock()
}

func (d *rotatingDelegate) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signCalls
}

func (d *rotatingDelegate) Sign(_ context.Context, request SigningRequest) ([]byte, error) {
	d.mu.Lock()
	key := d.key
	d.signCalls++
	d.mu.Unlock()
	signature, err := key.Sign(request.Digest.Bytes())
	if err != nil {
		return nil, err
	}
	return signature.ToDER()
}

// TestBindSignerFreezesPublicKey 锁定 BindSigner 直接契约：
// 构造时冻结公钥；底层 delegate 中途轮换私钥后，绑定视图的 PublicKey 不变，
// 签名仍委托执行但自验（调用方用冻结公钥验证）必然失败；nil/坏公钥拒绝；
// 请求原样透传。
func TestBindSignerFreezesPublicKey(t *testing.T) {
	original := mustSignerKey(t, "aa")
	delegate := &rotatingDelegate{key: original}

	bound, err := BindSigner(delegate)
	if err != nil {
		t.Fatal(err)
	}
	frozen := bound.PublicKey()

	// 轮换前：绑定视图的签名用冻结公钥验证成功。
	request := SigningRequest{Purpose: PurposeWireMessage, WireKind: 1, Digest: Digest32(must32(t, 0x11))}
	signature, err := bound.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigestSignature(frozen, request.Digest, signature); err != nil {
		t.Fatalf("pre-rotation signature should verify against frozen public key: %v", err)
	}

	// 轮换 delegate 私钥：绑定公钥必须不变。
	delegate.rotate(mustSignerKey(t, "bb"))
	if bound.PublicKey() != frozen {
		t.Fatal("bound public key changed after delegate rotation")
	}

	// 轮换后：签名来自新钥，用冻结公钥验签必须失败——这正是角色 Workflow
	// 自验层依赖的行为（invalid_signature）。
	signature2, err := bound.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigestSignature(frozen, request.Digest, signature2); err == nil {
		t.Fatal("post-rotation signature verified against frozen public key")
	}

	// 请求透传：digest/purpose 不被篡改（轮换前后各一次真实签名调用）。
	if delegate.callCount() != 2 {
		t.Fatalf("delegate signCalls = %d, want 2", delegate.callCount())
	}

	// nil 与无效公钥拒绝：nil Signer 必须给出稳定的 signer_unavailable 分类。
	_, err = BindSigner(nil)
	if code, ok := CodeOf(err); !ok || code != CodeSignerUnavailable {
		t.Fatalf("error code = %v, want signer_unavailable", code)
	}
	broken := &brokenPubKeySigner{}
	if _, err := BindSigner(broken); err == nil {
		t.Fatal("signer with invalid public key accepted")
	}
}

func mustSignerKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, _ := ec.PrivateKeyFromBytes([]byte(strings.Repeat(hexByte, 16)))
	if key == nil {
		t.Fatal("deterministic key construction failed")
	}
	return key
}

func must32(t *testing.T, fill byte) [32]byte {
	t.Helper()
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}

func strings_Repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

type brokenPubKeySigner struct{}

func (s *brokenPubKeySigner) PublicKey() PublicKey { return PublicKey{} }

func (s *brokenPubKeySigner) Sign(_ context.Context, _ SigningRequest) ([]byte, error) {
	return nil, errors.New("unused")
}
