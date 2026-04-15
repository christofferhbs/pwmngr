import * as crypto from "node:crypto";

export function generateSalt() {
  return crypto.randomBytes(16); // stor nok til at være unik (og konventionen)
}

export function createKey(masterPassword, salt) {
  return crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, "sha256"); // AES-256 kræver en key på 32 bytes (256 bits = 32 bytes)
}

export function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12); // skal være 12 bytes iv til aes-gcm (counter mode: hardcoded til 12 bytes iv + 4 bytes counter)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv); //createCipheriv: Opretter og returnerer et cipher objekt

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]); // final: lukker for cipher objekt

  const authTag = cipher.getAuthTag();

  return {
    ciphertext,
    iv,
    authTag,
  };
}

export function decrypt({ ciphertext, iv, authTag }, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}
