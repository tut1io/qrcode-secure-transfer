// Temporary stand-in for the future payment service.
//
// It deliberately lives only in this browser. A production version must issue
// and validate opaque tokens on a server after a verified Stripe webhook.

const STORAGE_KEY = "securedrop.demo-access-pass.v1";
const HOUR_MS = 60 * 60 * 1000;

export interface AccessPass {
  token: string;
  expiresAt: number;
}

function read(): AccessPass | null {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    if (!value) return null;
    const pass = JSON.parse(value) as AccessPass;
    return typeof pass.token === "string" && typeof pass.expiresAt === "number" ? pass : null;
  } catch {
    return null;
  }
}

function write(pass: AccessPass): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(pass));
}

export function createDemoAccessPass(now = Date.now()): AccessPass {
  const pass = { token: crypto.randomUUID(), expiresAt: now + HOUR_MS };
  write(pass);
  return pass;
}

export function currentAccessPass(): AccessPass | null {
  return read();
}

export function accessPassState(now = Date.now()): "missing" | "ready" | "expired" {
  const pass = read();
  if (!pass) return "missing";
  return pass.expiresAt > now ? "ready" : "expired";
}

/** Authorize a new transfer within the paid time window. Existing streams do
 * not consult this again, so they keep running after the hour has ended. */
export function reserveAccessPass(now = Date.now()): AccessPass {
  const pass = read();
  if (!pass) throw new Error("Purchase a one-hour access pass before sending a file.");
  if (pass.expiresAt <= now) throw new Error("This access pass has expired. Purchase a new pass.");
  return pass;
}

export function formatAccessRemaining(now = Date.now()): string | null {
  const pass = read();
  if (!pass || pass.expiresAt <= now) return null;
  const seconds = Math.max(0, Math.ceil((pass.expiresAt - now) / 1000));
  return `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`;
}
