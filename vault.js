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
      salt: Buffer.from(obj.salt, "base64"),
      iv: Buffer.from(obj.iv, "base64"),
      authTag: Buffer.from(obj.authTag, "base64"),
      ciphertext: Buffer.from(obj.ciphertext, "base64"),
    };
  }

  save({ salt, iv, authTag, ciphertext }) {
    // opret et objekt til at holde data midlertidigt for at tilpasse det (cool)
    // bytes -> string - JSON forventer string
    const obj = {
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2));
  }
}
