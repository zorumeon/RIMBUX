// src/near/broadcast.ts
// Sends an already signed vault transaction and waits for the vault's own verdict.
// Only used when RIMBUX_BROADCAST=true (see signingBoundary.ts).

export interface BroadcastParams {
  signedTransaction: { encode(): Uint8Array };
  vaultContractId: string;
  intentNonce: string;
  txHash: string;
}

export interface BroadcastOutcome {
  lifecycleStatus: "BROADCAST" | "CONFIRMED_ONCHAIN";
  note: string;
}

function rpcUrl(): string {
  return process.env.NEAR_RPC_URL || "https://test.rpc.fastnear.com";
}

async function rpc(method: string, params: unknown): Promise<any> {
  const response = await fetch(rpcUrl(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "rimbux-broadcast", method, params }),
  });
  const body = (await response.json()) as any;
  if (body.error) {
    throw new Error(`${method}: ${JSON.stringify(body.error).slice(0, 400)}`);
  }
  return body.result;
}

async function viewPaymentStatus(vaultContractId: string, intentNonce: string): Promise<string> {
  const result = await rpc("query", {
    request_type: "call_function",
    finality: "final",
    account_id: vaultContractId,
    method_name: "get_payment_status",
    args_base64: Buffer.from(JSON.stringify({ intentNonce })).toString("base64"),
  });
  return JSON.parse(Buffer.from(result.result).toString()).status as string;
}

function contractMessage(failure: any): string {
  const text: unknown = failure?.ActionError?.kind?.FunctionCallError?.ExecutionError;
  if (typeof text === "string") return text.split("\n")[0];
  return JSON.stringify(failure).slice(0, 300);
}

export async function broadcastAndConfirm(p: BroadcastParams): Promise<BroadcastOutcome> {
  let sent: any;
  try {
    sent = await rpc("send_tx", {
      signed_tx_base64: Buffer.from(p.signedTransaction.encode()).toString("base64"),
      wait_until: "EXECUTED_OPTIMISTIC",
    });
  } catch (error) {
    throw new Error(
      `BROADCAST_ERROR: ${error instanceof Error ? error.message : "unknown"} (tx ${p.txHash} may or may not have been accepted)`
    );
  }

  const failure = sent?.status?.Failure;
  if (failure) {
    throw new Error(`ONCHAIN_REJECTED: ${contractMessage(failure)}`);
  }

  let status = "PENDING";
  for (let i = 0; i < 10 && status === "PENDING"; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    status = await viewPaymentStatus(p.vaultContractId, p.intentNonce);
  }

  if (status === "CONFIRMED") {
    return {
      lifecycleStatus: "CONFIRMED_ONCHAIN",
      note: "Executed by the vault contract on NEAR Testnet; the transfer callback reported CONFIRMED.",
    };
  }
  if (status === "FAILED") {
    throw new Error("ONCHAIN_TRANSFER_FAILED: the vault accepted the call but the transfer failed; its quota was released.");
  }
  return {
    lifecycleStatus: "BROADCAST",
    note: `Broadcast and accepted by the vault; transfer status is still ${status} after waiting.`,
  };
}
