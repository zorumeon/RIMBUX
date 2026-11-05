import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RimbuxPersistence } from "../src/security/persistence";
import { SpendingController } from "../src/security/spendingController";
import { ExtractedTransactionIntent } from "../src/types";

function makeIntent(
  intentId: string,
  amountNear = 1
): ExtractedTransactionIntent {
  return {
    intentId,
    rawInstruction: `Send ${amountNear} NEAR to alice.testnet`,
    recipientId: "alice.testnet",
    amountNear,
    amountYocto: "1000000000000000000000000",
    actionType: "VAULT_TRANSFER",
    extractedAt: Date.now(),
  };
}

test("reservation remains active after five minutes", async () => {
  const controller = new SpendingController();
  const originalNow = Date.now;
  let clock = originalNow();

  try {
    Date.now = () => clock;

    const result = await controller.evaluateAndReserve(makeIntent("expiry-test"));
    assert.equal(result.passed, true);
    assert.ok(result.reservationId);

    clock += 6 * 60 * 1000;

    const metrics = controller.getMetricsSnapshot();
    assert.equal(metrics.activeConcurrentLocks, 1);
    assert.equal(metrics.totalSpentNear, 1);
  } finally {
    Date.now = originalNow;
  }
});

test("concurrent requests cannot both reserve spending", async () => {
  const controller = new SpendingController();

  const results = await Promise.all([
    controller.evaluateAndReserve(makeIntent("concurrent-a")),
    controller.evaluateAndReserve(makeIntent("concurrent-b")),
  ]);

  assert.equal(results.filter((result) => result.passed).length, 1);
  assert.equal(results.filter((result) => !result.passed).length, 1);

  const rejected = results.find((result) => !result.passed);
  assert.ok(rejected?.violations.some((v) => v.includes("CONCURRENT_SPEND_LOCKED")));
});

test("commit changes a reservation to committed", async () => {
  const controller = new SpendingController();

  const result = await controller.evaluateAndReserve(makeIntent("commit-test"));
  assert.equal(result.passed, true);
  assert.ok(result.reservationId);

  await controller.commitReservation(result.reservationId);

  const metrics = controller.getMetricsSnapshot();
  assert.equal(metrics.activeConcurrentLocks, 0);
  assert.equal(metrics.totalSpentNear, 1);
});

test("release removes a reservation from active spending and final states stay unchanged", async () => {
  const controller = new SpendingController();

  const result = await controller.evaluateAndReserve(makeIntent("release-test"));
  assert.equal(result.passed, true);
  assert.ok(result.reservationId);

  await controller.releaseReservation(result.reservationId);

  let metrics = controller.getMetricsSnapshot();
  assert.equal(metrics.activeConcurrentLocks, 0);
  assert.equal(metrics.totalSpentNear, 0);

  await controller.commitReservation(result.reservationId);
  metrics = controller.getMetricsSnapshot();

  assert.equal(metrics.totalSpentNear, 0);
  assert.equal(metrics.activeConcurrentLocks, 0);
});


test("committed spending survives database restart", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rimbux-spending-"));
  const databasePath = path.join(directory, "test.sqlite");

  try {
    const firstPersistence = new RimbuxPersistence(databasePath);
    const firstController = new SpendingController(undefined, firstPersistence);

    const result = await firstController.evaluateAndReserve(
      makeIntent("restart-persistence-test", 1.5)
    );

    assert.equal(result.passed, true);
    assert.ok(result.reservationId);

    await firstController.commitReservation(result.reservationId);
    firstPersistence.close();

    const secondPersistence = new RimbuxPersistence(databasePath);
    const secondController = new SpendingController(undefined, secondPersistence);

    const metrics = secondController.getMetricsSnapshot();
    assert.equal(metrics.totalSpentNear, 1.5);
    assert.equal(metrics.activeConcurrentLocks, 0);

    secondPersistence.close();
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("initial config cannot expand the live NEAR FunctionCall method allowlist", () => {
  const controller = new SpendingController({
    allowedContractMethods: [
      "execute_agent_payment",
      "ft_transfer",
      "storage_deposit",
      "add_key",
    ],
  });

  const config = (
    controller as unknown as {
      config: { allowedContractMethods: string[] };
    }
  ).config;

  assert.deepEqual(config.allowedContractMethods, ["execute_agent_payment"]);
});

test("policy updates cannot expand the live NEAR FunctionCall method allowlist", () => {
  const controller = new SpendingController();

  const updated = controller.updateConfig({
    allowedContractMethods: [
      "execute_agent_payment",
      "ft_transfer",
      "storage_deposit",
      "add_key",
    ],
  });

  assert.deepEqual(updated.allowedContractMethods, ["execute_agent_payment"]);
  assert.deepEqual(
    controller.getConfig().allowedContractMethods,
    ["execute_agent_payment"]
  );
});

test("policy updates preserve valid spending limits and lockdown settings", () => {
  const controller = new SpendingController();

  const updated = controller.updateConfig({
    dailySpendingLimitNear: 20,
    emergencyLockdown: true,
  });

  assert.equal(updated.dailySpendingLimitNear, 20);
  assert.equal(updated.emergencyLockdown, true);
  assert.deepEqual(updated.allowedContractMethods, ["execute_agent_payment"]);
});


// Spending quota enforcement tests

test("blocks a transaction above the per-transaction maximum", async () => {
  const controller = new SpendingController({
    maxTransactionAmountNear: 0.5,
  });

  const result = await controller.evaluateAndReserve(
    makeIntent("quota-max-transaction", 1)
  );

  assert.equal(result.passed, false);
  assert.ok(result.violations.length > 0);
  assert.equal(controller.getMetricsSnapshot().totalSpentNear, 0);
});

test("blocks spending that would exceed the rolling 24-hour daily limit", async () => {
  const controller = new SpendingController({
    dailySpendingLimitNear: 1.5,
  });

  const first = await controller.evaluateAndReserve(
    makeIntent("quota-daily-first", 1)
  );
  assert.equal(first.passed, true);
  assert.ok(first.reservationId);
  await controller.commitReservation(first.reservationId);

  const second = await controller.evaluateAndReserve(
    makeIntent("quota-daily-second", 1)
  );

  assert.equal(second.passed, false);
  assert.ok(second.violations.length > 0);
  assert.equal(controller.getMetricsSnapshot().dailySpentNear, 1);
});

test("blocks spending that would exceed the lifetime wallet cap", async () => {
  const controller = new SpendingController({
    totalWalletSpendingCapNear: 1.5,
  });

  const first = await controller.evaluateAndReserve(
    makeIntent("quota-lifetime-first", 1)
  );
  assert.equal(first.passed, true);
  assert.ok(first.reservationId);
  await controller.commitReservation(first.reservationId);

  const second = await controller.evaluateAndReserve(
    makeIntent("quota-lifetime-second", 1)
  );

  assert.equal(second.passed, false);
  assert.ok(second.violations.length > 0);
  assert.equal(controller.getMetricsSnapshot().totalSpentNear, 1);
});

test("blocks spending that would exceed the per-recipient daily cap", async () => {
  const controller = new SpendingController({
    perRecipientDailyLimitNear: 1.5,
  });

  const first = await controller.evaluateAndReserve(
    makeIntent("quota-recipient-first", 1)
  );
  assert.equal(first.passed, true);
  assert.ok(first.reservationId);
  await controller.commitReservation(first.reservationId);

  const second = await controller.evaluateAndReserve(
    makeIntent("quota-recipient-second", 1)
  );

  assert.equal(second.passed, false);
  assert.ok(second.violations.length > 0);
  assert.equal(
    controller.getMetricsSnapshot("alice.testnet").recipientSpentTodayNear,
    1
  );
});

test("blocks transactions above the configured per-minute rate", async () => {
  const controller = new SpendingController({
    maxTxPerMinute: 1,
  });

  const first = await controller.evaluateAndReserve(
    makeIntent("quota-rate-first", 1)
  );
  assert.equal(first.passed, true);
  assert.ok(first.reservationId);
  await controller.commitReservation(first.reservationId);

  const second = await controller.evaluateAndReserve(
    makeIntent("quota-rate-second", 1)
  );

  assert.equal(second.passed, false);
  assert.ok(second.violations.length > 0);
  assert.equal(controller.getMetricsSnapshot().recentTxCountLastMinute, 1);
});
