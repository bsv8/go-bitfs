package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 上面的手写管道过于绕，改用顺序执行 + 文件中转的等价实现：
// TestDemo02OfflineEmptyStateSmoke 是 Demo 02 的自动化空状态验收：
// 以 DEMO_02_OFFLINE=1 从零状态顺序执行 0201→0205 五个命令；中间产物以
// 文件中转，模拟应用持久化 outbox 后再发送的 persist-before-send 语义。
func TestDemo02OfflineEmptyStateSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	type step struct {
		pkg        string
		inFile     string
		outFile    string
		wantStderr string
	}
	// 与手工演示一致：全部命令以仓库根为工作目录运行，checkpoint 相对路径
	// （demo/.state）在步骤间共享。
	steps := []step{
		{pkg: "./demo/02_pool_opening/0201_buyer_build_refund_request", outFile: "kind2.hex"},
		{pkg: "./demo/02_pool_opening/0202_seller_accept_refund_request", inFile: "kind2.hex", outFile: "kind3.hex"},
		{pkg: "./demo/02_pool_opening/0203_buyer_accept_refund_response", inFile: "kind3.hex", outFile: "kind4.hex"},
		{pkg: "./demo/02_pool_opening/0204_buyer_build_funding_delivery", inFile: "kind4.hex", outFile: "kind4b.hex"},
		{pkg: "./demo/02_pool_opening/0205_seller_accept_funding_delivery", inFile: "kind4b.hex", wantStderr: "pool opened"},
	}
	tmp := t.TempDir()
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	// 真空状态：状态目录必须预先不存在，且位于 t.TempDir 下——既证明流程
	// 从零开始，也保证不污染仓库工作树、并行运行互不覆盖。
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("state dir must not exist before the run: %v", err)
	}
	for i, s := range steps {
		cmd := exec.Command("go", "run", s.pkg)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(),
			"DEMO_02_OFFLINE=1",
			"DEMO_02_STATE_DIR="+stateDir,
		)
		if s.inFile != "" {
			in, err := os.Open(joinPath(tmp, s.inFile))
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			cmd.Stdin = in
			defer in.Close()
		}
		stderr := &strings.Builder{}
		cmd.Stderr = stderr
		if s.outFile != "" {
			out, err := os.Create(joinPath(tmp, s.outFile))
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout = out
			if err := cmd.Run(); err != nil {
				out.Close()
				t.Fatalf("step %d (%s) failed: %v\nstderr: %s", i, s.pkg, err, stderr.String())
			}
			out.Close()
			continue
		}
		if err := cmd.Run(); err != nil {
			t.Fatalf("step %d (%s) failed: %v\nstderr: %s", i, s.pkg, err, stderr.String())
		}
		if !strings.Contains(stderr.String(), s.wantStderr) {
			t.Fatalf("step %d (%s): stderr missing %q:\n%s", i, s.pkg, s.wantStderr, stderr.String())
		}
	}

	// 收尾断言：三个跨进程 checkpoint 全部落入临时状态目录，且不含任何私钥。
	for _, name := range []string{
		"buyer-opening-checkpoint.json",
		"buyer-pool-checkpoint.json",
		"seller-presign-checkpoint.json",
	} {
		raw, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			t.Fatalf("expected checkpoint %s in isolated state dir: %v", name, err)
		}
		if strings.Contains(strings.ToLower(string(raw)), "private_key") || strings.Contains(string(raw), "PRIVATE_KEY_HEX") {
			t.Fatalf("checkpoint %s must never contain private key material", name)
		}
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 3 {
		t.Fatalf("isolated state dir has %d entries, want >= 3 checkpoints", len(entries))
	}
}

func joinPath(base, name string) string {
	return base + string(os.PathSeparator) + name
}
