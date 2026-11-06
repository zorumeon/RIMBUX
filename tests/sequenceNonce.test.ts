import test from "node:test";
import assert from "node:assert/strict";

import {
  decodeSequenceNonce,
  readNextSequenceNonce,
} from "../src/near/sequenceNonce";

const encode = (value: unknown): number[] =>
  Array.from(Buffer.from(JSON.stringify(value), "utf8"));

test("decodeSequenceNonce accepts a valid JSON string nonce", () => {
  assert.equal(decodeSequenceNonce(encode("1")), "1");
  assert.equal(decodeSequenceNonce(encode("42")), "42");
  assert.equal(decodeSequenceNonce(encode("9".repeat(40))), "9".repeat(40));
});

test("decodeSequenceNonce rejects values the contract would reject", () => {
  assert.throws(() => decodeSequenceNonce(encode("0")), /SEQUENCE_NONCE_INVALID/);
  assert.throws(() => decodeSequenceNonce(encode("01")), /SEQUENCE_NONCE_INVALID/);
  assert.throws(() => decodeSequenceNonce(encode("-1")), /SEQUENCE_NONCE_INVALID/);
  assert.throws(() => decodeSequenceNonce(encode("1".repeat(41))), /SEQUENCE_NONCE_INVALID/);
  assert.throws(() => decodeSequenceNonce(encode(1)), /SEQUENCE_NONCE_INVALID/);
  assert.throws(() => decodeSequenceNonce(encode(null)), /SEQUENCE_NONCE_INVALID/);
});

test("decodeSequenceNonce fails closed on malformed results", () => {
  assert.throws(() => decodeSequenceNonce(undefined), /SEQUENCE_NONCE_UNAVAILABLE/);
  assert.throws(() => decodeSequenceNonce("1"), /SEQUENCE_NONCE_UNAVAILABLE/);
  assert.throws(() => decodeSequenceNonce([300]), /SEQUENCE_NONCE_UNAVAILABLE/);
  assert.throws(
    () => decodeSequenceNonce(Array.from(Buffer.from("not json"))),
    /SEQUENCE_NONCE_UNAVAILABLE/
  );
});

test("readNextSequenceNonce queries the vault view with the expected request", async () => {
  let captured: any;
  const provider = {
    query: async (params: any) => {
      captured = params;
      return { result: encode("7"), logs: [], block_height: 1 };
    },
  } as any;

  const nonce = await readNextSequenceNonce(provider, "vault.testnet");

  assert.equal(nonce, "7");
  assert.equal(captured.request_type, "call_function");
  assert.equal(captured.account_id, "vault.testnet");
  assert.equal(captured.method_name, "get_next_sequence_nonce");
  assert.equal(
    Buffer.from(captured.args_base64, "base64").toString("utf8"),
    "{}"
  );
});

test("readNextSequenceNonce propagates RPC failures instead of defaulting", async () => {
  const provider = {
    query: async () => {
      throw new Error("RPC_DOWN");
    },
  } as any;

  await assert.rejects(readNextSequenceNonce(provider, "vault.testnet"), /RPC_DOWN/);
});
