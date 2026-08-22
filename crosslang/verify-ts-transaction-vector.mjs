// TS 交易 → TS 自验：重算 sighash 摘要并用 @bsv/sdk ECDSA 验证 TS 生成的
// 交易 DER（Go 侧由 crosslang/transaction_vector_test.go 完成 TS 签 / Go 验）。
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction, LockingScript, PublicKey, Signature, BigNumber, ECDSA } from "@bsv/sdk";

const v = JSON.parse(readFileSync(new URL("./ts_to_go_transaction_vector.json", import.meta.url), "utf8"));
const bytes = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const sha256d = (data) => createHash("sha256").update(createHash("sha256").update(data).digest()).digest();

const spend = Transaction.fromHex(v.unsignedTxHex);
if (spend.inputs.length !== 1 || v.inputIndex !== 0) {
  console.error("FAIL: fixture must spend exactly one input at index 0"); process.exit(1);
}
const source = new Transaction();
source.addOutput({
  satoshis: v.sourceSatoshis,
  lockingScript: LockingScript.fromHex(v.sourceLockingScriptHex),
});
spend.inputs[0].sourceTransaction = source;

const preimage = Uint8Array.from(spend.preimage(v.inputIndex, v.sighashFlag));
if (sha256d(preimage).toString("hex") !== v.sighashDigestHex) {
  console.error("FAIL: sighash digest is not SHA-256d of the official preimage"); process.exit(1);
}
if (v.sighashFlag !== 65) {
  console.error("FAIL: unexpected sighash flag, want 65 (ForkID|All)"); process.exit(1);
}
const ok = ECDSA.verify(
  new BigNumber([...bytes(v.sighashDigestHex)]),
  Signature.fromDER([...bytes(v.tsDerSignatureHex)]),
  PublicKey.fromString(v.pubkeyHex),
);
if (!ok) { console.error("FAIL: TS self-verification failed"); process.exit(1); }
console.log("TS transaction -> TS verify OK");
