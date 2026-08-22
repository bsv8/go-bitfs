// Go 交易 → TS 验证：解析同一份 raw unsigned tx，用官方 preimage 路径重算
// sighash 摘要，比较 digest 与 flag，并用 @bsv/sdk ECDSA 验证 Go 的交易 DER。
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction, LockingScript, PublicKey, Signature, BigNumber, ECDSA } from "@bsv/sdk";

const v = JSON.parse(readFileSync(new URL("./transaction_sighash_vector.json", import.meta.url), "utf8"));
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
if (Buffer.from(preimage).toString("hex") !== v.preimageHex) {
  console.error("FAIL: TS preimage differs from Go preimage"); process.exit(1);
}
if (sha256d(preimage).toString("hex") !== v.sighashDigestHex) {
  console.error("FAIL: TS sighash digest differs from Go sighashDigestHex"); process.exit(1);
}
if (v.sighashFlag !== 65) {
  console.error("FAIL: unexpected sighash flag, want 65 (ForkID|All)"); process.exit(1);
}

const ok = ECDSA.verify(
  new BigNumber([...bytes(v.sighashDigestHex)]),
  Signature.fromDER([...bytes(v.goDerSignatureHex)]),
  PublicKey.fromString(v.buyerPubkeyHex),
);
if (!ok) { console.error("FAIL: TS could not verify the Go transaction signature over the sighash digest"); process.exit(1); }
console.log("Go transaction -> TS verify OK");
