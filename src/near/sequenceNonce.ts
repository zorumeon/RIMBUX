import type { Provider } from "@near-js/providers";

// Mirrors the validation in contract-v2.ts: /^[1-9][0-9]{0,39}$/
const SEQUENCE_NONCE_PATTERN = /^[1-9][0-9]{0,39}$/;

/**
 * Decodes the raw `call_function` result of the vault view
 * `get_next_sequence_nonce` (JSON-encoded string, e.g. `"1"` as bytes).
 * Fails closed: any unexpected shape throws instead of guessing a value.
 */
export function decodeSequenceNonce(result: unknown): string {
  const isByteArray =
    result instanceof Uint8Array ||
    (Array.isArray(result) &&
      result.every(
        (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255
      ));

  if (!isByteArray) {
    throw new Error("SEQUENCE_NONCE_UNAVAILABLE");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(
      Buffer.from(Array.from(result as ArrayLike<number>)).toString("utf8")
    );
  } catch {
    throw new Error("SEQUENCE_NONCE_UNAVAILABLE");
  }

  if (typeof parsed !== "string" || !SEQUENCE_NONCE_PATTERN.test(parsed)) {
    throw new Error("SEQUENCE_NONCE_INVALID");
  }

  return parsed;
}

/**
 * Reads the vault's current `nextSequenceNonce` from chain state.
 * A stale read is fail-safe: the contract rejects a mismatched nonce
 * before changing any state, so no funds can move.
 */
export async function readNextSequenceNonce(
  provider: Pick<Provider, "query">,
  vaultContractId: string
): Promise<string> {
  const response = (await provider.query({
    request_type: "call_function",
    finality: "final",
    account_id: vaultContractId,
    method_name: "get_next_sequence_nonce",
    args_base64: Buffer.from("{}", "utf8").toString("base64"),
  })) as unknown as { result?: unknown } | undefined;

  return decodeSequenceNonce(response?.result);
}
