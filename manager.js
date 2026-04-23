import { generateSalt, deriveKey, encrypt, decrypt } from "./encryption.js";
import Vault from "./vault.js";

const vault = new Vault();

/**
 * Et enkelt login gemt i vaulten.
 *
 * @typedef {object} VaultEntry
 * @property {string} entryName Navn brugt til opslag.
 * @property {string} username Brugernavn til tjenesten.
 * @property {string} password Password til tjenesten.
 */

/**
 * Resultatet af at åbne vaulten.
 *
 * @typedef {object} OpenVaultResult
 * @property {VaultEntry[]} entries Dekrypterede entries.
 * @property {Buffer} key Den udledte nøgle.
 * @property {Buffer} salt Salt læst fra vault-filen.
 */

/**
 * Opretter en ny tom vault.
 *
 * @param {string} masterPassword Master password til vaulten.
 * @returns {void}
 * @throws {Error} Hvis der allerede findes en vault.
 */
function create(masterPassword) {
  // beslutning: understøt kun een vault, men med mulighed for udvidelse til flere senere
  if (vault.exists()) {
    throw new Error("En vault eksisterer allerede");
  }

  const salt = generateSalt(); // unikt salt per udførsel
  const key = deriveKey(masterPassword, salt); // udled key
  const { ciphertext, iv, authTag } = encrypt("[]", key); // krypter tomt array for at få props (og fordi array forventes i openVault())
  vault.save({ salt, iv, authTag, ciphertext });
}

/**
 * Åbner vaulten og returnerer entries sammen med de data, der skal bruges for at gemme igen.
 *
 * @param {string} masterPassword Master password til vaulten.
 * @returns {OpenVaultResult} Dekrypterede entries og data til senere gemning.
 * @throws {Error} Hvis vaulten ikke er oprettet, master password er forkert eller data er ugyldige.
 */
function openVault(masterPassword) {
  if (!vault.exists()) {
    throw new Error("Ingen vault fundet: brug 'create' kommandoen først");
  }

  const vaultContent = vault.load();
  // det gemte salt skal være samme salt som ved create(), ellers udledes en anden nøgle
  const key = deriveKey(masterPassword, vaultContent.salt); // udled key fra master pw og vaultens gemte salt

  let plaintext;
  try {
    plaintext = decrypt(vaultContent, key);
  } catch {
    throw new Error("Forkert master password");
  }

  let vaultEntries;
  try {
    vaultEntries = JSON.parse(plaintext);
  } catch {
    throw new Error(
      "Vault er korrupteret: dekrypteret data er ikke gyldig JSON",
    );
  }

  // key og salt returneres mhp at give mulighed for at kryptere entries uden at skulle udlede key, og læse salt igen
  return { entries: vaultEntries, key, salt: vaultContent.salt };
}

/**
 * Gemmer entries ved at lave dem om til JSON og kryptere dem.
 *
 * @param {VaultEntry[]} vaultEntries Entries som skal gemmes.
 * @param {Buffer} key Den udledte nøgle.
 * @param {Buffer} salt Salt der hører til vaulten.
 * @returns {void}
 */
function saveVault(vaultEntries, key, salt) {
  const plaintext = JSON.stringify(vaultEntries);
  const { ciphertext, iv, authTag } = encrypt(plaintext, key);
  vault.save({ salt, iv, authTag, ciphertext });
}

/**
 * Tilføjer et nyt entry til vaulten.
 *
 * @param {string} masterPassword Master password til vaulten.
 * @param {string} entryName Navn på det entry der skal gemmes.
 * @param {string} username Brugernavn der skal gemmes.
 * @param {string} password Password der skal gemmes.
 * @returns {void}
 */
function add(masterPassword, entryName, username, password) {
  const { entries, key, salt } = openVault(masterPassword);
  entries.push({ entryName: entryName, username, password });
  saveVault(entries, key, salt);
}

/**
 * Finder et entry ud fra dets navn.
 *
 * @param {string} masterPassword Master password til vaulten.
 * @param {string} entryName Navn på det entry der søges efter.
 * @returns {VaultEntry | null} Det fundne entry eller `null`.
 */
function get(masterPassword, entryName) {
  const { entries } = openVault(masterPassword);
  return entries.find((e) => e.entryName === entryName) ?? null;
}

/**
 * Finder alle entries hvor navnet indeholder søgeteksten.
 *
 * @param {string} masterPassword Master password til vaulten.
 * @param {string} query Tekst der søges efter i `entryName`.
 * @returns {VaultEntry[]} Alle entries der matcher søgningen.
 */
function search(masterPassword, query) {
  const { entries } = openVault(masterPassword);
  return entries.filter((e) => e.entryName.includes(query));
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
      const [masterPassword, entryName, username, password] = args;
      add(masterPassword, entryName, username, password);
      console.log(`Tilføjede entry "${entryName}"`);
      break;
    }

    case "get": {
      const [masterPassword, entryName] = args;
      const entry = get(masterPassword, entryName);

      if (!entry) {
        console.log(`Fandt intet vault entry med navnet "${entryName}"`);
        break;
      }

      console.log(`username: ${entry.username}`);
      console.log(`password: ${entry.password}`);
      break;
    }

    case "search": {
      const [masterPassword, query] = args;
      const entries = search(masterPassword, query);

      if (entries.length === 0) {
        console.log(`Fandt ingen vault entries indeholdende "${query}"`);
        break;
      }

      console.log(
        `Fandt ${entries.length} vault entries indeholdende "${query}":`,
      );
      console.log();

      for (const entry of entries) {
        console.log(`entryName: ${entry.entryName}`);
        console.log(`username: ${entry.username}`);
        console.log(`password: ${entry.password}`);
        console.log();
      }
      break;
    }

    default:
      throw new Error("Ukendt kommando. Brug: create | add | get | search");
  }
} catch (err) {
  console.log(err.message);
  process.exit(1);
}
