import fs from "fs";
import path from "path";
import Database from "better-sqlite3";

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
