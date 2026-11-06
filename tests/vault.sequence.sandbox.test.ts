import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import { Worker, KeyPair } from "near-workspaces";

const WASM_PATH = path.resolve(
  "contracts/rimbux-vault/artifacts/rimbux-vault-v4.wasm"
);
const CALL_OPTS = (key: KeyPair) => ({
  signWithKey: key,
  gas: BigInt("100000000000000"),
});
const ONE_NEAR = "1000000000000000000000000";

async function setup() {
  const worker = await Worker.init();
  const root = worker.rootAccount;
  const agent = await root.devCreateAccount();
  const merchant = await root.devCreateAccount();
  const agentKey = KeyPair.fromRandom("ed25519");

  const vault = await root.devDeploy(WASM_PATH, {
    method: "init",
    args: {
      ownerId: root.accountId,
      agentAccountId: agent.accountId,
      authorizedAgentKey: agentKey.getPublicKey().toString(),
      maxPerTxNear: 5,
      dailyLimitNear: 15,
    },
  });

  await agent.updateAccessKey(agentKey, {
    nonce: 0,
    permission: {
      FunctionCall: {
        allowance: "100000000000000000000000",
        receiver_id: vault.accountId,
        method_names: ["execute_agent_payment"],
      },
    },
  });

  await root.call(vault, "update_recipient_policy", {
    accountId: merchant.accountId,
    allowed: true,
    blocked: false,
  });

  return { worker, root, agent, merchant, agentKey, vault };
}

test("RIMBUX Vault starts at sequence nonce 1 and rejects a mismatched nonce", async () => {
  const { worker, agent, merchant, agentKey, vault } = await setup();
  try {
    assert.equal(await vault.view("get_next_sequence_nonce", {}), "1");

    const payment = (sequenceNonce: string) => ({
      recipientId: merchant.accountId,
      amountYocto: ONE_NEAR,
      intentNonce: "rimbux-seq-mismatch-0001",
      sequenceNonce,
      purposeDigest: "a".repeat(64),
    });

    // Ahead of the contract's expected value.
    await assert.rejects(
      agent.call(vault, "execute_agent_payment", payment("2"), CALL_OPTS(agentKey))
    );
    // Not a valid positive integer string.
    await assert.rejects(
      agent.call(vault, "execute_agent_payment", payment("0"), CALL_OPTS(agentKey))
    );

    // A rejected call must not advance the nonce or consume allowance.
    assert.equal(await vault.view("get_next_sequence_nonce", {}), "1");
    const status = await vault.view<{ currentDaySpendYocto: string }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.currentDaySpendYocto, "0");
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault advances sequence nonce and rejects stale sequence and replayed intent nonce independently", async () => {
  const { worker, agent, merchant, agentKey, vault } = await setup();
  try {
    const base = {
      recipientId: merchant.accountId,
      amountYocto: ONE_NEAR,
      purposeDigest: "b".repeat(64),
    };
    const first = { ...base, intentNonce: "rimbux-seq-intent-a-0001", sequenceNonce: "1" };

    await agent.call(vault, "execute_agent_payment", first, CALL_OPTS(agentKey));
    assert.equal(await vault.view("get_next_sequence_nonce", {}), "2");

    // Replay of the same intent nonce with the CORRECT sequence nonce:
    // isolates the intent-nonce replay check from the sequence check.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        { ...first, sequenceNonce: "2" },
        CALL_OPTS(agentKey)
      )
    );
    assert.equal(await vault.view("get_next_sequence_nonce", {}), "2");

    // A fresh intent nonce with the already-used (stale) sequence nonce.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        { ...base, intentNonce: "rimbux-seq-intent-b-0001", sequenceNonce: "1" },
        CALL_OPTS(agentKey)
      )
    );
    assert.equal(await vault.view("get_next_sequence_nonce", {}), "2");

    // Fresh intent nonce + correct sequence nonce succeeds and advances again.
    await agent.call(
      vault,
      "execute_agent_payment",
      { ...base, intentNonce: "rimbux-seq-intent-b-0001", sequenceNonce: "2" },
      CALL_OPTS(agentKey)
    );
    assert.equal(await vault.view("get_next_sequence_nonce", {}), "3");

    const statusA = await vault.view<{ status: string }>("get_payment_status", {
      intentNonce: "rimbux-seq-intent-a-0001",
    });
    assert.equal(statusA.status, "CONFIRMED");
  } finally {
    await worker.tearDown();
  }
});
