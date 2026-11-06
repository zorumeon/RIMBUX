import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { Worker, KeyPair } from "near-workspaces";

const ONE_NEAR_YOCTO = "1000000000000000000000000";
const GAS = BigInt("100000000000000");

test("RIMBUX Vault releases the daily reservation and marks the payment FAILED when the transfer fails", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agent = await root.devCreateAccount();
    const merchant = await root.devCreateAccount();
    const agentKey = KeyPair.fromRandom("ed25519");

    // A syntactically valid account ID that is never created, so the transfer must fail.
    const ghostRecipient = `ghost-recipient-${Date.now()}.${root.accountId}`;

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux-vault-v4.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: agent.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 1,
        dailyLimitNear: 1,
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

    for (const recipient of [ghostRecipient, merchant.accountId]) {
      await root.call(vault, "update_recipient_policy", {
        accountId: recipient,
        allowed: true,
        blocked: false,
      });
    }

    const readSpend = async () =>
      (
        await vault.view<{ currentDaySpendYocto: string }>(
          "get_vault_status",
          {}
        )
      ).currentDaySpendYocto;

    const readStatus = async (intentNonce: string) =>
      (
        await vault.view<{ status: string }>("get_payment_status", {
          intentNonce,
        })
      ).status;

    assert.equal(await readSpend(), "0");

    const failingArgs = {
      recipientId: ghostRecipient,
      amountYocto: ONE_NEAR_YOCTO,
      intentNonce: "rimbux-failed-transfer-0001",
      sequenceNonce: "1",
      purposeDigest: "b".repeat(64),
    };

    // callRaw does not throw on failed receipts; the failure is the point of this test.
    await agent.callRaw(vault, "execute_agent_payment", failingArgs, {
      signWithKey: agentKey,
      gas: GAS,
    });

    assert.equal(
      await readStatus(failingArgs.intentNonce),
      "FAILED",
      "A failed transfer must end in FAILED, not stay PENDING or become CONFIRMED."
    );

    assert.equal(
      await readSpend(),
      "0",
      "The reserved daily spend must be released after a failed transfer."
    );

    // A failed payment must not be replayable with the same nonce.
    await assert.rejects(
      agent.call(vault, "execute_agent_payment", failingArgs, {
        signWithKey: agentKey,
        gas: GAS,
      })
    );

    assert.equal(await readStatus(failingArgs.intentNonce), "FAILED");

    // The daily limit equals one payment, so this only succeeds if the reservation was released.
    const retryArgs = {
      recipientId: merchant.accountId,
      amountYocto: ONE_NEAR_YOCTO,
      intentNonce: "rimbux-failed-transfer-0002",
      sequenceNonce: "2",
      purposeDigest: "c".repeat(64),
    };

    await agent.call(vault, "execute_agent_payment", retryArgs, {
      signWithKey: agentKey,
      gas: GAS,
    });

    assert.equal(await readStatus(retryArgs.intentNonce), "CONFIRMED");
    assert.equal(await readSpend(), ONE_NEAR_YOCTO);
  } finally {
    await worker.tearDown();
  }
});
