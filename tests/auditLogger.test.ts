import assert from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import Database from "better-sqlite3";
import test from "node:test";
import { RimbuxPersistence } from "../src/security/persistence";
import { TamperEvidentAuditLogger } from "../src/security/auditLogger";

const secret = "a".repeat(64);

function createTemporaryDatabase(): string {
  return path.join(
    os.tmpdir(),
    `rimbux-audit-test-${Date.now()}-${Math.random()}.sqlite`
  );
}

function removeDatabase(file: string): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    const target = file + suffix;
    if (fs.existsSync(target)) fs.unlinkSync(target);
  }
}

test("audit log persists and verifies after restart", () => {
  const file = createTemporaryDatabase();

  try {
    let db = new RimbuxPersistence(file);
    let logger = new TamperEvidentAuditLogger(db, secret);

    logger.record("TEST_EVENT", "INFO", { amount: 1 }, "intent_test");
    assert.strictEqual(logger.verifyChainIntegrity().intact, true);
    db.close();

    db = new RimbuxPersistence(file);
    logger = new TamperEvidentAuditLogger(db, secret);

    assert.strictEqual(logger.getLogs().length, 1);
    assert.strictEqual(logger.verifyChainIntegrity().intact, true);
    db.close();
  } finally {
    removeDatabase(file);
  }
});

test("audit logger detects database tampering", () => {
  const file = createTemporaryDatabase();

  try {
    let db = new RimbuxPersistence(file);
    let logger = new TamperEvidentAuditLogger(db, secret);

    logger.record("TEST_EVENT", "INFO", { amount: 1 });
    db.close();

    const rawDb = new Database(file);
    rawDb.prepare(
      "UPDATE audit_events SET details = ? WHERE sequence = 1"
    ).run(JSON.stringify({ amount: 999 }));
    rawDb.close();

    db = new RimbuxPersistence(file);
    logger = new TamperEvidentAuditLogger(db, secret);

    assert.strictEqual(logger.verifyChainIntegrity().intact, false);
    db.close();
  } finally {
    removeDatabase(file);
  }
});

test("audit logger fails closed on an empty or too-short secret", () => {
  for (const invalidSecret of ["", "a".repeat(63)]) {
    assert.throws(
      () => new TamperEvidentAuditLogger(undefined, invalidSecret),
      /RIMBUX_AUDIT_SECRET is missing or invalid\. A secret of at least 64 characters is required\./
    );
  }
});

test("audit logger rejects an incorrect HMAC secret", () => {
  const file = createTemporaryDatabase();

  try {
    const db = new RimbuxPersistence(file);
    const logger = new TamperEvidentAuditLogger(db, secret);

    logger.record("TEST_EVENT", "INFO", { amount: 1 });
    db.close();

    const wrongDb = new RimbuxPersistence(file);
    const wrongLogger = new TamperEvidentAuditLogger(
      wrongDb,
      "b".repeat(64)
    );

    assert.strictEqual(
      wrongLogger.verifyChainIntegrity().intact,
      false
    );
    wrongDb.close();
  } finally {
    removeDatabase(file);
  }
});
