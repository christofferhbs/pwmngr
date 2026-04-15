import * as crypto from "node:crypto";

const masterPassword = "the master password";
const plaintext = "data to be encrypted";

function createKey(masterPassword) {
  const salt = crypto.randomBytes(16);

  const key = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, "sha256"); // AES-256 kræver en key på 32 byte

  return { key, salt };
}

export function encrypt(plaintext, key) {
  const algorithm = "aes-256-gcm";
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(algorithm, key, iv); //createCipheriv: Opretter og returnerer et cipher objekt

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

export function decrypt(ciphertext, iv, authTag, key) {
  const algorithm = "aes-256-gcm";

  const decipher = crypto.createDecipheriv(algorithm, key, iv);

  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext, "utf8"),
    decipher.final(),
  ]);

  console.log("decrypted: " + plaintext);

  return plaintext;
}
