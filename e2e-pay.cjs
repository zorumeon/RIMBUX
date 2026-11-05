// e2e-pay.cjs - one real payment through the vault using ONLY the agent FunctionCall key.
//
//   node e2e-pay.cjs [recipient] [amountNear]          -> dry run: signs, prints, does NOT send
//   node e2e-pay.cjs [recipient] [amountNear] --yes    -> sends for real
require("dotenv").config();
const crypto = require("crypto");
const { KeyPair, InMemorySigner, transactions, utils } = require("near-api-js");

const args = process.argv.slice(2);
const SEND = args.includes("--yes");
const pos = args.filter((a) => !a.startsWith("--"));
const RECIPIENT = pos[0] || "rimbux-agent.testnet";
const AMOUNT_NEAR = pos[1] || "0.1";

const RPC = process.env.E2E_RPC_URL || "https://test.rpc.fastnear.com";
const NETWORK = process.env.NEAR_NETWORK_ID || "testnet";
const VAULT = process.env.NEAR_VAULT_CONTRACT_ID;
const AGENT = process.env.NEAR_AGENT_ACCOUNT_ID;
const KEY = process.env.NEAR_AGENT_FUNCTION_CALL_PRIVATE_KEY;
const GAS = 100_000_000_000_000n; // 100 Tgas: execution + transfer + 30 Tgas callback
const METHOD = "execute_agent_payment";

function die(msg) { console.error("ERROR: " + msg); process.exit(1); }

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "e2e", method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(method + ": " + JSON.stringify(body.error).slice(0, 500));
  return body.result;
}

async function view(contract, method, argsObj) {
  const r = await rpc("query", {
    request_type: "call_function",
    finality: "final",
    account_id: contract,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(argsObj || {})).toString("base64"),
  });
  return JSON.parse(Buffer.from(r.result).toString());
}

(async () => {
  if (!VAULT || !AGENT) die("NEAR_VAULT_CONTRACT_ID / NEAR_AGENT_ACCOUNT_ID missing in .env");
  if (!KEY || !KEY.startsWith("ed25519:")) die("NEAR_AGENT_FUNCTION_CALL_PRIVATE_KEY missing in .env");

  const keyPair = KeyPair.fromString(KEY);
  const publicKey = keyPair.getPublicKey().toString();
  const amountYocto = utils.format.parseNearAmount(AMOUNT_NEAR);
  if (!amountYocto) die("bad amount: " + AMOUNT_NEAR);

  console.log("RPC:       ", RPC);
  console.log("Vault:     ", VAULT);
  console.log("Agent key: ", publicKey);
  console.log("Recipient: ", RECIPIENT);
  console.log("Amount:    ", AMOUNT_NEAR, "NEAR");
  console.log("Mode:      ", SEND ? "SEND FOR REAL" : "DRY RUN (add --yes to send)");

  const before = await view(VAULT, "get_vault_status");
  console.log("\nVault before: paused=%s dailySpentYocto=%s", before.paused, before.currentDaySpendYocto);
  if (before.authorizedAgentKey !== publicKey) die("this key is not the vault's authorizedAgentKey");

  const ak = await rpc("query", { request_type: "view_access_key", finality: "final", account_id: AGENT, public_key: publicKey });
  const fc = ak.permission && ak.permission.FunctionCall;
  if (!fc || fc.receiver_id !== VAULT || !fc.method_names.includes(METHOD)) die("on-chain key permission mismatch");
  console.log("Key check:  FunctionCall -> %s %j allowance=%s", fc.receiver_id, fc.method_names, fc.allowance);

  const block = await rpc("block", { finality: "final" });
  const intentNonce = "e2e_" + crypto.randomBytes(8).toString("hex");
  const purposeDigest = crypto.createHash("sha256").update("e2e test payment " + intentNonce).digest("hex");
  const callArgs = { recipientId: RECIPIENT, amountYocto, intentNonce, purposeDigest };

  const signer = await InMemorySigner.fromKeyPair(NETWORK, AGENT, keyPair);
  const action = transactions.functionCall(METHOD, callArgs, GAS, 0n);
  const [txHashBytes, signedTx] = await transactions.signTransaction(
    VAULT,
    BigInt(ak.nonce) + 1n,
    [action],
    utils.serialize.base_decode(block.header.hash),
    signer,
    AGENT,
    NETWORK
  );
  const txHash = utils.serialize.base_encode(txHashBytes);
  console.log("\nSigned. intentNonce=%s txHash=%s", intentNonce, txHash);

  if (!SEND) { console.log("\nDry run only. Nothing was sent."); return; }

  const sent = await rpc("send_tx", {
    signed_tx_base64: Buffer.from(signedTx.encode()).toString("base64"),
    wait_until: "EXECUTED_OPTIMISTIC",
  });
  const st = sent.final_execution_status;
  const failure = sent.status && sent.status.Failure;
  console.log("\nsend_tx: %s%s", st, failure ? "  FAILURE: " + JSON.stringify(failure).slice(0, 600) : "  (call itself accepted)");
  console.log("Explorer: https://testnet.nearblocks.io/txns/" + txHash);
  if (failure) process.exit(2);

  let status = "PENDING";
  for (let i = 0; i < 15 && status === "PENDING"; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    status = (await view(VAULT, "get_payment_status", { intentNonce })).status;
    console.log("payment status:", status);
  }
  const after = await view(VAULT, "get_vault_status");
  console.log("\nVault after:  dailySpentYocto=%s", after.currentDaySpendYocto);
  console.log(status === "CONFIRMED" ? "\nOK: payment confirmed through the vault." : "\nNOT CONFIRMED: status=" + status);
})().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
