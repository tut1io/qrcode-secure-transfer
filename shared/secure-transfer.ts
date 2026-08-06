// Offline access gate for protected optical transfers.
//
// The TOTP secret is deliberately never put in the QR stream.  It is the same
// Base32 seed a recipient has enrolled in Google Authenticator (or another
// RFC 6238 authenticator).  TOTP proves possession locally; a separate
// passphrase derives the AES key.  Neither secret is persisted by this app.

const MAGIC = new Uint8Array([0x44, 0x53, 0x45, 0x31]); // DSE1
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERATIONS = 310_000;
const encoder = new TextEncoder();

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i]! ^ b[i]!;
  return difference === 0;
}

/** Decode the manual Base32 format shown by Google Authenticator. */
export function decodeTotpSecret(secret: string): Uint8Array {
  const normalized = secret.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  if (normalized.length < 16 || !/^[A-Z2-7]+$/.test(normalized)) {
    throw new Error("Enter a valid Base32 Google Authenticator secret.");
  }
  let buffer = 0;
  let bits = 0;
  const out: number[] = [];
  for (const character of normalized) {
    buffer = (buffer << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** Bind the encrypted transfer to both independently held offline secrets. */
export function credentialMaterial(passphrase: string, totpSecret: string): string {
  // Decoding also validates and canonicalises the human-entered Base32 form.
  return `${passphrase}\u0000${[...decodeTotpSecret(totpSecret)].join(",")}`;
}

async function totp(secret: Uint8Array, counter: number): Promise<string> {
  const message = new Uint8Array(8);
  const view = new DataView(message.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000), false);
  view.setUint32(4, counter >>> 0, false);
  const key = await crypto.subtle.importKey("raw", Uint8Array.from(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[mac.length - 1]! & 15;
  const value = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String((value >>> 0) % 1_000_000).padStart(6, "0");
}

/** Accept one adjacent 30-second window for normal device-clock drift. */
export async function verifyTotp(secretText: string, codeText: string, now = Date.now()): Promise<boolean> {
  const code = codeText.replace(/\s/g, "");
  if (!/^\d{6}$/.test(code)) return false;
  const secret = decodeTotpSecret(secretText);
  const counter = Math.floor(now / 30_000);
  const candidates = await Promise.all([-1, 0, 1].map((offset) => totp(secret, counter + offset)));
  return candidates.some((candidate) => equalBytes(encoder.encode(candidate), encoder.encode(code)));
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (passphrase.length < 12) throw new Error("Use a passphrase of at least 12 characters.");
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: Uint8Array.from(salt), iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function deriveFrameMacKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const labelledSalt = new Uint8Array(salt.length + 8);
  labelledSalt.set(salt);
  labelledSalt.set(encoder.encode("DSE1-MAC"), salt.length);
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: labelledSalt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"],
  );
}

export interface FrameAuthenticator {
  tag(input: Uint8Array): Promise<Uint8Array>;
  verify(input: Uint8Array, tag: Uint8Array): Promise<boolean>;
}

/** Tags make real and decoy frames structurally identical to non-holders. */
export async function createFrameAuthenticator(passphrase: string, salt: Uint8Array): Promise<FrameAuthenticator> {
  const key = await deriveFrameMacKey(passphrase, salt);
  const tag = async (input: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign("HMAC", key, Uint8Array.from(input))).subarray(0, 8);
  return {
    tag,
    async verify(input, claimedTag) {
      return equalBytes(await tag(input), claimedTag);
    },
  };
}

export function transferSalt(envelope: Uint8Array): Uint8Array {
  const headerLength = MAGIC.length + SALT_LEN + IV_LEN;
  if (envelope.length <= headerLength + 16 || !equalBytes(envelope.subarray(0, MAGIC.length), MAGIC)) {
    throw new Error("This is not a protected transfer.");
  }
  return envelope.slice(MAGIC.length, MAGIC.length + SALT_LEN);
}

/** Encrypt the complete existing optical container before fountain coding. */
export async function sealTransfer(container: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: Uint8Array.from(iv) }, key, Uint8Array.from(container)));
  const out = new Uint8Array(MAGIC.length + SALT_LEN + IV_LEN + ciphertext.length);
  out.set(MAGIC, 0);
  out.set(salt, MAGIC.length);
  out.set(iv, MAGIC.length + SALT_LEN);
  out.set(ciphertext, MAGIC.length + SALT_LEN + IV_LEN);
  return out;
}

/** Authentication failure and a modified payload deliberately look identical. */
export async function openTransfer(envelope: Uint8Array, passphrase: string): Promise<Uint8Array> {
  const headerLength = MAGIC.length + SALT_LEN + IV_LEN;
  const salt = transferSalt(envelope);
  const iv = envelope.subarray(MAGIC.length + SALT_LEN, headerLength);
  const key = await deriveKey(passphrase, salt);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: Uint8Array.from(iv) },
      key,
      Uint8Array.from(envelope.subarray(headerLength)),
    ));
  } catch {
    throw new Error("Authentication failed or the protected transfer was altered.");
  }
}
