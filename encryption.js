import * as crypto from "node:crypto";

const AUTH_TAG_LENGTH = 16;

/**
 * Ciphertext med IV og auth tag, som kan gemmes i vault-filen.
 *
 * @typedef {object} EncryptedData
 * @property {Buffer} ciphertext Krypteret indhold.
 * @property {Buffer} iv Initialiseringsvektor brugt til AES-GCM.
 * @property {Buffer} authTag Autentificeringstag brugt til integritetskontrol.
 */

/**
 * Genererer et tilfældigt salt til nøgleafledning.
 *
 * @returns {Buffer} Et nyt salt.
 */
export function generateSalt() {
  return crypto.randomBytes(16); // stor nok til at være unik (og konventionen)
}

/**
 * Udleder en AES-256 nøgle fra et master password og et salt.
 *
 * @param {string} masterPassword Master password i plaintext.
 * @param {Buffer} salt Salt gemt i vaulten.
 * @returns {Buffer} Den afledte nøgle.
 */
export function deriveKey(masterPassword, salt) {
  const ITERATIONS = 100000; // OWASP anbefaler 600000
  const KEY_LENGTH = 32; // AES-256 kræver en key på 32 bytes (256 bits = 32 bytes)

  const key = crypto.pbkdf2Sync(
    masterPassword,
    salt,
    ITERATIONS,
    KEY_LENGTH,
    "sha256",
  );

  return key;
}

/**
 * Krypterer plaintext med AES-256-GCM.
 *
 * @param {string} plaintext Tekst som skal krypteres.
 * @param {Buffer} key Afledt nøgle.
 * @returns {EncryptedData} Krypterede data (ciphertext) med det, der skal bruges til dekryptering (iv, authTag).
 */
export function encrypt(plaintext, key) {
  // iv skal være unik for hver kryptering med samme nøgle
  // ellers kan man begynde at udlede information om de oprindelige tekster
  const iv = crypto.randomBytes(12); // aes-gcm krav (counter mode: hardcoded til 12 bytes iv + 4 bytes counter)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  }); //createCipheriv: Opretter og returnerer et cipher objekt

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]); // final: lukker for cipher objekt

  const authTag = cipher.getAuthTag(); // Auth Tag: skal bruges til at verificere at data ikke er ændret

  return {
    ciphertext,
    iv,
    authTag,
  };
}

/**
 * Dekrypterer tidligere gemte krypterede data.
 *
 * @param {EncryptedData} encryptedData Ciphertext med IV og auth tag.
 * @param {Buffer} key Afledt nøgle.
 * @returns {string} Dekrypteret tekst i UTF-8.
 */
export function decrypt(encryptedData, key) {
  const { ciphertext, iv, authTag } = encryptedData;

  if (authTag.length !== AUTH_TAG_LENGTH) {
    throw new Error("Ugyldig auth tag length");
  }

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}
