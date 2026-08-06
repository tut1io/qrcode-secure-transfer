import assert from "node:assert/strict";
import test from "node:test";
import {
  credentialMaterial,
  createFrameAuthenticator,
  openTransfer,
  sealTransfer,
  verifyTotp,
} from "../shared/secure-transfer.ts";

test("a protected transfer opens only with its passphrase", async () => {
  const source = new TextEncoder().encode("a complete file is encrypted before fountain coding");
  const credentials = credentialMaterial("correct horse battery staple", "JBSWY3DPEHPK3PXP");
  const envelope = await sealTransfer(source, credentials);
  assert.notDeepEqual(envelope.subarray(-source.length), source);
  assert.deepEqual(await openTransfer(envelope, credentials), source);
  await assert.rejects(
    openTransfer(envelope, credentialMaterial("correct horse battery staple", "KRUGS4ZANFZSAYJA")),
    /Authentication failed/,
  );
});

test("the authenticator accepts valid keyed frames and rejects decoys", async () => {
  const sender = await createFrameAuthenticator("correct horse battery staple", new Uint8Array(16).fill(7));
  const receiver = await createFrameAuthenticator("correct horse battery staple", new Uint8Array(16).fill(7));
  const input = new Uint8Array([1, 2, 3, 4]);
  const tag = await sender.tag(input);
  assert.equal(await receiver.verify(input, tag), true);
  tag[0] ^= 0xff;
  assert.equal(await receiver.verify(input, tag), false);
});

test("Google Authenticator-compatible RFC 6238 codes verify locally", async () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(await verifyTotp(secret, "287082", 59_000), true);
  assert.equal(await verifyTotp(secret, "287083", 59_000), false);
});
