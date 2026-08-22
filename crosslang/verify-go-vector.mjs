// 验证 Go→TS 向量：digest == 单次 SHA-256(message)，且 @bsv/sdk 验证 DER。
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { PublicKey, Signature } from "@bsv/sdk";

const v = JSON.parse(readFileSync(new URL("./go_to_ts_vector.json", import.meta.url), "utf8"));
const hex = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const message = hex(v.messageHex);
const digest = hex(v.digestHex);
if (createHash("sha256").update(message).digest().toString("hex") !== v.digestHex) {
  console.error("FAIL: digest is not single SHA-256 of message"); process.exit(1);
}
const ok = Signature.fromDER(hex(v.derSigHex)).verify(message, PublicKey.fromString(v.pubkeyHex));
if (!ok) { console.error("FAIL: TS could not verify Go signature"); process.exit(1); }
console.log("Go -> TS OK");
