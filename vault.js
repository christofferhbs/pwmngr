import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Data fra vault-filen efter base64 er lavet om til Buffer-værdier.
 *
 * @typedef {object} VaultData
 * @property {Buffer} salt Salt til at udlede nøglen.
 * @property {Buffer} iv Initialiseringsvektor .
 * @property {Buffer} authTag Auth tag til integritetskontrol.
 * @property {Buffer} ciphertext Krypteret indhold.
 */

/**
 * Læser og gemmer vault-filen på disk.
 */
export class Vault {
  /**
   * Opretter en vault med en bestemt filsti.
   *
   * @param {string} [filePath=__dirname + "/vault.json"] Stien til vault-filen.
   */
  constructor(filePath = __dirname + "/vault.json") {
    this.filePath = filePath;
  }

  /**
   * Kontrollerer om vault-filen findes.
   *
   * @returns {boolean} `true` hvis filen findes.
   */
  exists() {
    return fs.existsSync(this.filePath);
  }

  /**
   * Læser vault-filen og laver base64 om til Buffer-værdier.
   *
   * @returns {VaultData} Data fra vault-filen klar til kryptering og dekryptering.
   */
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

  /**
   * Gemmer vault-data som JSON med base64 encodede værdier.
   *
   * @param {VaultData} data Data som skal gemmes i vault-filen.
   * @returns {void}
   */
  save({ salt, iv, authTag, ciphertext }) {
    // opret et objekt til at holde data midlertidigt for at tilpasse det (cool)
    // bytes -> string - JSON.stringify forventer string
    const obj = {
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2));
  }
}
