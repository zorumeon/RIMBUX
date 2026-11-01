import fs from "fs";
import path from "path";
import Database from "better-sqlite3";
import { TransactionRecord } from "../types";

export interface StoredAuditEvent {
  sequence: number;
  timestamp: string;
  event_type: string;
  severity: string;
  intent_id: string | null;
  details: string;
  prev_hash: string;
  entry_hash: string;
}

const dataDirectory = path.resolve(process.cwd(), "data");

if (!fs.existsSync(dataDirectory)) {
  fs.mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
}

const databasePath = path.join(dataDirectory, "rimbux.sqlite");

export class RimbuxPersistence {
  private readonly db: Database.Database;

  constructor(filePath = databasePath) {
    this.db = new Database(filePath);

    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("busy_timeout = 5000");

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS pending_approvals (
        intent_id TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (
          status IN ('PENDING', 'APPROVED', 'REJECTED', 'QUARANTINED')
        )
      );

      CREATE TABLE IF NOT EXISTS spending_reservations (
        reservation_id TEXT PRIMARY KEY,
        intent_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        amount_near REAL NOT NULL CHECK (amount_near >= 0),
        created_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (
          status IN ('RESERVED', 'COMMITTED', 'RELEASED', 'QUARANTINED')
        )
      );

      CREATE INDEX IF NOT EXISTS idx_reservations_intent
      ON spending_reservations(intent_id);

      CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        intent_id TEXT,
        details TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS transaction_history (
        intent_id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        payload TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_transaction_history_timestamp
      ON transaction_history(timestamp DESC);
    `);
  }

  public getAuditEvents(): StoredAuditEvent[] {
    return this.db
      .prepare("SELECT * FROM audit_events ORDER BY sequence ASC")
      .all() as StoredAuditEvent[];
  }

  public appendAuditEvent(entry: StoredAuditEvent): void {
    this.db.prepare(`
      INSERT INTO audit_events (
        sequence, timestamp, event_type, severity,
        intent_id, details, prev_hash, entry_hash
      ) VALUES (
        @sequence, @timestamp, @event_type, @severity,
        @intent_id, @details, @prev_hash, @entry_hash
      )
    `).run(entry);
  }

  public quarantineUnresolvedReservations(): number {
    const result = this.db.prepare(`
      UPDATE spending_reservations
      SET status = 'QUARANTINED'
      WHERE status = 'RESERVED'
    `).run();

    return result.changes;
  }

  public getSpendingReservations(): Array<{
    reservationId: string;
    intentId: string;
    recipientId: string;
    amountNear: number;
    timestamp: number;
    status: "RESERVED" | "COMMITTED" | "RELEASED" | "QUARANTINED";
  }> {
    return this.db.prepare(`
      SELECT
        reservation_id AS reservationId,
        intent_id AS intentId,
        recipient_id AS recipientId,
        amount_near AS amountNear,
        created_at AS timestamp,
        status
      FROM spending_reservations
      WHERE status IN ('RESERVED', 'COMMITTED', 'RELEASED', 'QUARANTINED')
      ORDER BY created_at ASC
    `).all() as Array<{
      reservationId: string;
      intentId: string;
      recipientId: string;
      amountNear: number;
      timestamp: number;
      status: "RESERVED" | "COMMITTED" | "RELEASED" | "QUARANTINED";
    }>;
  }

  public saveSpendingReservation(entry: {
    reservationId: string;
    intentId: string;
    recipientId: string;
    amountNear: number;
    timestamp: number;
    status: "RESERVED" | "COMMITTED" | "RELEASED" | "QUARANTINED";
  }): void {
    this.db.prepare(`
      INSERT INTO spending_reservations (
        reservation_id, intent_id, recipient_id,
        amount_near, created_at, status
      ) VALUES (
        @reservationId, @intentId, @recipientId,
        @amountNear, @timestamp, @status
      )
      ON CONFLICT(reservation_id) DO UPDATE SET
        status = excluded.status
    `).run(entry);
  }

  public getTransactionHistory(): TransactionRecord[] {
    const rows = this.db.prepare(`
      SELECT payload
      FROM transaction_history
      ORDER BY timestamp DESC
    `).all() as Array<{ payload: string }>;

    return rows.map((row) => JSON.parse(row.payload) as TransactionRecord);
  }

  public saveTransactionRecord(record: TransactionRecord): void {
    this.db.prepare(`
      INSERT INTO transaction_history (intent_id, timestamp, payload)
      VALUES (@intentId, @timestamp, @payload)
      ON CONFLICT(intent_id) DO UPDATE SET
        timestamp = excluded.timestamp,
        payload = excluded.payload
    `).run({
      intentId: record.intentId,
      timestamp: record.timestamp,
      payload: JSON.stringify(record),
    });
  }

  public close(): void {
    this.db.close();
  }

  public healthCheck(): boolean {
    const result = this.db.prepare("PRAGMA quick_check").get() as {
      quick_check: string;
    };

    return result.quick_check === "ok";
  }
}
