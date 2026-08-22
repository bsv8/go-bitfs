// Go 005 payment state → TS 验证：解析向量中的 expected unsigned raw（由 Go
// BuildPaymentUpdate 确定性重建的 005 状态交易，不是 RefundTemplate），用官方
// preimage 路径重算 sighash 摘要，并用 @bsv/sdk ECDSA 验证 Go 的 Buyer DER。
//
// 承诺边界：TS 在此只消费 Go 冻结的 raw，不从上下文独立重建交易；在 TS 补齐
// BuildPaymentUpdate 等价实现并通过向量之前，v4 005 只承诺 Go 实现互操作。
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction, LockingScript, PublicKey, Signature, BigNumber, ECDSA } from "@bsv/sdk";

const v = JSON.parse(readFileSync(new URL("./payment_state_sighash_vector.json", import.meta.url), "utf8"));
const bytes = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const sha256d = (data) => createHash("sha256").update(createHash("sha256").update(data).digest()).digest();

const spend = Transaction.fromHex(v.expectedUnsignedRawHex);
if (spend.inputs.length !== 1 || v.inputIndex !== 0) {
  console.error("FAIL: payment state must spend exactly one input at index 0"); process.exit(1);
}
const source = new Transaction();
source.addOutput({
  satoshis: v.sourceSatoshis,
  lockingScript: LockingScript.fromHex(v.sourceLockingScriptHex),
});
spend.inputs[0].sourceTransaction = source;

const preimage = Uint8Array.from(spend.preimage(v.inputIndex, v.sighashFlag));
if (Buffer.from(preimage).toString("hex") !== v.preimageHex) {
  console.error("FAIL: TS preimage differs from Go preimage"); process.exit(1);
}
if (sha256d(preimage).toString("hex") !== v.sighashDigestHex) {
  console.error("FAIL: TS sighash digest differs from Go sighashDigestHex"); process.exit(1);
}
if (v.sighashFlag !== 65) {
  console.error("FAIL: unexpected sighash flag, want 65 (ForkID|All)"); process.exit(1);
}
// 005 状态交易与 RefundTemplate 共用来源但不是同一笔交易。
if (v.expectedUnsignedRawHex === JSON.parse(readFileSync(new URL("./transaction_sighash_vector.json", import.meta.url), "utf8")).unsignedTxHex) {
  console.error("FAIL: payment state vector must not reuse the RefundTemplate transaction"); process.exit(1);
}

const ok = ECDSA.verify(
  new BigNumber([...bytes(v.sighashDigestHex)]),
  Signature.fromDER([...bytes(v.goDerSignatureHex)]),
  PublicKey.fromString(v.buyerPubkeyHex),
);
if (!ok) { console.error("FAIL: TS could not verify the Go buyer signature over the rebuilt payment state"); process.exit(1); }
console.log("Go 005 payment state -> TS verify OK");
