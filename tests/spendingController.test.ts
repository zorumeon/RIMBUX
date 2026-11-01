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
