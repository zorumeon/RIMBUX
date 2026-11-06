import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { RimbuxPersistence } from "../src/security/persistence";
import { TransactionRecord } from "../src/types";

function createTemporaryDatabase(): string {
  return path.join(
    os.tmpdir(),
    `rimbux-transaction-history-${Date.now()}-${Math.random()}.sqlite`
  );
}

function removeDatabase(file: string): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    const target = file + suffix;
    if (fs.existsSync(target)) fs.unlinkSync(target);
  }
}

test("transaction history persists with all fields after database restart", () => {
  const file = createTemporaryDatabase();

  const record: TransactionRecord = {
    intentId: "intent_persistence_test",
    timestamp: 1793600000000,
    rawInstruction: "Send 1.25 NEAR to alice.testnet",
    recipientId: "alice.testnet",
    amountNear: 1.25,
    status: "SIGNED",
    policyDecision: "ALLOW",
    riskClassification: "LOW",
    reasons: ["Recipient passed reputation checks."],
    reputationScore: 92,
    scamWarningsCount: 0,
    txHash: "local-signature-test-hash",
    unsignedTxPayloadDigest: "test-payload-digest",
    signerPublicKey: "test-public-key",
    explorerUrl: "https://testnet.nearblocks.io/",
    verificationNote: "Locally signed; not broadcast or confirmed on-chain.",
  };

  try {
    const firstDb = new RimbuxPersistence(file);
    firstDb.saveTransactionRecord(record);
    firstDb.close();

    const secondDb = new RimbuxPersistence(file);
    const history = secondDb.getTransactionHistory();

    assert.equal(history.length, 1);
    assert.deepEqual(history[0], record);

    secondDb.close();
  } finally {
    removeDatabase(file);
  }
});

test("agent restores transaction history after database restart", () => {
  const file = createTemporaryDatabase();

  const record: TransactionRecord = {
    intentId: "intent_agent_restore_test",
    timestamp: 1793600000001,
    rawInstruction: "Send 0.5 NEAR to alice.testnet",
    recipientId: "alice.testnet",
    amountNear: 0.5,
    status: "SIGNED",
    policyDecision: "ALLOW",
    riskClassification: "LOW",
    reasons: [],
    reputationScore: 90,
    scamWarningsCount: 0,
    verificationNote: "Locally signed; not broadcast or confirmed on-chain.",
  };

  try {
    const firstDb = new RimbuxPersistence(file);
    firstDb.saveTransactionRecord(record);
    firstDb.close();

    const secondDb = new RimbuxPersistence(file);
    const { RimbuxAutonomousAgent } = require("../src/agent/rimbuxAgent");
    const agent = new RimbuxAutonomousAgent({
      auditPersistence: secondDb,
      signingBoundary: {} as any,
    });

    assert.deepEqual(agent.getTransactionHistory(), [record]);

    secondDb.close();
  } finally {
    removeDatabase(file);
  }
});
