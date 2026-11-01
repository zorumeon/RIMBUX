import test from "node:test";
import assert from "node:assert/strict";
import { RimbuxAutonomousAgent } from "../src/agent/rimbuxAgent";

function makeFailingSigningBoundary() {
  return {
    signAuthorizedVaultIntent: async () => {
      throw new Error("TEST_SIGNING_FAILURE");
    },
    getPublicMetadata: () => ({}),
    revokeKey: async () => undefined,
  };
}

test("direct signing failure releases spending reservation", async () => {
  const agent = new RimbuxAutonomousAgent({
    signingBoundary: makeFailingSigningBoundary() as any,
  });

  await assert.rejects(
    agent.processInstruction("Send 1 NEAR to alice.testnet"),
    /TEST_SIGNING_FAILURE/
  );

  const metrics = agent.spendingController.getMetricsSnapshot();

  assert.equal(metrics.activeConcurrentLocks, 0);
  assert.equal(metrics.totalSpentNear, 0);
});

test("approval signing failure releases reservation and removes pending approval", async () => {
  const agent = new RimbuxAutonomousAgent({
    signingBoundary: makeFailingSigningBoundary() as any,
  });

  const pending = await agent.processInstruction(
    "Send 3 NEAR to alice.testnet"
  );

  assert.equal(pending.evaluation.decision, "REQUIRE_APPROVAL");
  assert.equal(agent.getPendingApprovals().length, 1);

  await assert.rejects(
    agent.approvePendingIntent(pending.intent.intentId, true),
    /TEST_SIGNING_FAILURE/
  );

  const metrics = agent.spendingController.getMetricsSnapshot();
  const record = agent.getTransactionHistory().find(
    (item) => item.intentId === pending.intent.intentId
  );

  assert.equal(metrics.activeConcurrentLocks, 0);
  assert.equal(metrics.totalSpentNear, 0);
  assert.equal(agent.getPendingApprovals().length, 0);
  assert.equal(record?.status, "FAILED_VERIFICATION");
  assert.ok(
    record?.reasons.some((reason) => reason.includes("SIGNING_FAILED"))
  );
});

test("duplicate concurrent approval cannot trigger signing twice", async () => {
  let signingCalls = 0;

  const signingBoundary = {
    signAuthorizedVaultIntent: async () => {
      signingCalls++;
      await new Promise((resolve) => setTimeout(resolve, 50));

      return {
        lifecycleStatus: "SIGNED_SANDBOX",
        txHash: "test-only-hash",
        unsignedPayloadDigest: "test-only-digest",
        signerPublicKey: "test-only-public-key",
        explorerUrl: "https://testnet.nearblocks.io",
        verificationNote: "Test-only mock signature.",
        receiverContractId: "rimbux-vault.testnet",
      };
    },
    getPublicMetadata: () => ({}),
    revokeKey: async () => undefined,
  };

  const agent = new RimbuxAutonomousAgent({
    signingBoundary: signingBoundary as any,
  });

  const pending = await agent.processInstruction(
    "Send 3 NEAR to alice.testnet"
  );

  assert.equal(pending.evaluation.decision, "REQUIRE_APPROVAL");

  const results = await Promise.allSettled([
    agent.approvePendingIntent(pending.intent.intentId, true),
    agent.approvePendingIntent(pending.intent.intentId, true),
  ]);

  assert.equal(
    signingCalls,
    1,
    "The same intent must never enter the signing boundary twice."
  );

  assert.equal(
    results.filter((result) => result.status === "fulfilled").length,
    1
  );

  assert.equal(
    results.filter((result) => result.status === "rejected").length,
    1
  );
});
