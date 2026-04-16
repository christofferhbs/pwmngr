import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default class Vault {
  constructor(filePath = __dirname + "/vault.json") {
    this.filePath = filePath;
  }

  exists() {
    return fs.existsSync(this.filePath);
  }

  load() {
    const content = fs.readFileSync(this.filePath, "utf8"); // returnerer string (utf8)
    const obj = JSON.parse(content);

    // string -> bytes - crypto funktionerne forventer bytes
    return {
      salt: Buffer.from(obj.salt, "hex"),
      iv: Buffer.from(obj.iv, "hex"),
      authTag: Buffer.from(obj.authTag, "hex"),
      ciphertext: Buffer.from(obj.ciphertext, "hex"),
    };
  }

  save({ salt, iv, authTag, ciphertext }) {
    // opret et objekt til at holde data midlertidigt for at tilpasse det (cool)
    // bytes -> string - JSON forventer string
    const obj = {
      salt: salt.toString("hex"),
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
    };
    fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2));
  }
}
