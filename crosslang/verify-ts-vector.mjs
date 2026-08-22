// 验证 TS→Go 向量（TS 签 / TS 验链路；Go 侧由 vector_test.go 完成 TS 签/Go 验）。
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { PublicKey, Signature } from "@bsv/sdk";

const v = JSON.parse(readFileSync(new URL("./ts_to_go_vector.json", import.meta.url), "utf8"));
const hex = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const message = hex(v.messageHex);
if (createHash("sha256").update(message).digest().toString("hex") !== v.digestHex) {
  console.error("FAIL: digest is not single SHA-256 of message"); process.exit(1);
}
const ok = Signature.fromDER(hex(v.derSigHex)).verify(message, PublicKey.fromString(v.pubkeyHex));
if (!ok) { console.error("FAIL: TS self-verification failed"); process.exit(1); }
console.log("TS -> TS OK");
