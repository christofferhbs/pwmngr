import { generateSalt, createKey, encrypt, decrypt } from "./encryption.js";
import Vault from "./vault.js";

const vault = new Vault();

function create(masterPassword) {
  // beslutning: understøt kun een vault, men med mulighed for udvidelse til flere senere
  if (vault.exists()) {
    throw new Error("En vault eksisterer allerede");
  }

  const salt = generateSalt(); // unikt salt per udførsel
  const key = createKey(masterPassword, salt); // opret ny key
  const { ciphertext, iv, authTag } = encrypt("[]", key); // krypter tomt array for at få props (og fordi array forventes i openVault funktionen)
  vault.save({ salt, iv, authTag, ciphertext });
}

function openVault(masterPassword) {
  if (!vault.exists()) {
    throw new Error("Ingen vault fundet: brug 'create' kommandoen først");
  }

  const vaultContent = vault.load();
  // udled key fra master pw og vaultens gemte salt
  // det gemte salt skal være samme salt som ved create, ellers oprettes en anden nøgle
  const key = createKey(masterPassword, vaultContent.salt); // ikke ny key, men udledning af key

  let plaintext;
  try {
    plaintext = decrypt(vaultContent, key);
  } catch {
    throw new Error("Forkert master password");
  }

  let entries;
  try {
    entries = JSON.parse(plaintext);
  } catch {
    throw new Error(
      "Vault er korrupteret: dekrypteret data er ikke gyldig JSON",
    );
  }

  return { entries, key, salt: vaultContent.salt };
}

function saveVault(entries, key, salt) {
  const { ciphertext, iv, authTag } = encrypt(JSON.stringify(entries), key);
  vault.save({ salt, iv, authTag, ciphertext });
}

function add(masterPassword, name, username, password) {
  const { entries, key, salt } = openVault(masterPassword);
  entries.push({ name, username, password });
  saveVault(entries, key, salt);
}

function get(masterPassword, name) {
  const { entries } = openVault(masterPassword);
  return entries.find((e) => e.name === name) ?? null;
}

const [, , command, ...args] = process.argv;

try {
  switch (command) {
    case "create": {
      const [masterPassword] = args;
      create(masterPassword);
      console.log("Vault oprettet");
      break;
    }

    case "add": {
      const [masterPassword, name, username, password] = args;
      add(masterPassword, name, username, password);
      console.log(`Tilføjede entry "${name}"`);
      break;
    }

    case "get": {
      const [masterPassword, name] = args;
      const entry = get(masterPassword, name);

      if (!entry) {
        console.log(`Fandt intet entry med navnet "${name}"`);
        break;
      }

      console.log(`username: ${entry.username}`);
      console.log(`password: ${entry.password}`);
      break;
    }

    default:
      throw new Error("Ukendt kommando. Brug: create | add | get");
  }
} catch (err) {
  console.log(err.message);
  process.exit(1);
}
