import test from "node:test";
import assert from "node:assert/strict";
import { RimbuxAutonomousAgent } from "../src/agent/rimbuxAgent";
import {
  MockNearTestnetClient,
  TEST_AUDIT_SECRET,
  TestSigningBoundary,
  createDelayedSigningBoundary,
  createFailingSigningBoundary,
} from "./helpers/fixtures";

function makeAgent(signingBoundary: TestSigningBoundary) {
  return new RimbuxAutonomousAgent({
    nearClient: new MockNearTestnetClient(),
    auditSecret: TEST_AUDIT_SECRET,
    signingBoundary,
  });
}

test("direct signing failure releases spending reservation", async () => {
  const agent = makeAgent(createFailingSigningBoundary());

  await assert.rejects(
    agent.processInstruction("Send 1 NEAR to alice.testnet"),
    /TEST_SIGNING_FAILURE/
  );

  const metrics = agent.spendingController.getMetricsSnapshot();
  assert.equal(metrics.activeConcurrentLocks, 0);
  assert.equal(metrics.totalSpentNear, 0);
});

test("approval signing failure releases reservation and removes pending approval", async () => {
  const agent = makeAgent(createFailingSigningBoundary());

  const pending = await agent.processInstruction("Send 3 NEAR to alice.testnet");
  assert.equal(pending.evaluation.decision, "REQUIRE_APPROVAL");
  assert.equal(agent.getPendingApprovals().length, 1);

  await assert.rejects(
    agent.approvePendingIntent(pending.intent.intentId, true),
    /TEST_SIGNING_FAILURE/
  );

  const metrics = agent.spendingController.getMetricsSnapshot();
  const record = agent
    .getTransactionHistory()
    .find((item) => item.intentId === pending.intent.intentId);

  assert.equal(metrics.activeConcurrentLocks, 0);
  assert.equal(metrics.totalSpentNear, 0);
  assert.equal(agent.getPendingApprovals().length, 0);
  assert.equal(record?.status, "FAILED_VERIFICATION");
  assert.ok(record?.reasons.some((reason) => reason.includes("SIGNING_FAILED")));
});

test("duplicate concurrent approval cannot trigger signing twice", async () => {
  const { boundary, getCallCount } = createDelayedSigningBoundary(50);
  const agent = makeAgent(boundary);

  const pending = await agent.processInstruction("Send 3 NEAR to alice.testnet");
  assert.equal(pending.evaluation.decision, "REQUIRE_APPROVAL");

  const results = await Promise.allSettled([
    agent.approvePendingIntent(pending.intent.intentId, true),
    agent.approvePendingIntent(pending.intent.intentId, true),
  ]);

  assert.equal(getCallCount(), 1, "The same intent must never enter the signing boundary twice.");
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(results.filter((r) => r.status === "rejected").length, 1);
});
