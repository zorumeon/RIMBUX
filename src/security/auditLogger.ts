import crypto from "crypto";
import dotenv from "dotenv";
import {
  RimbuxPersistence,
  StoredAuditEvent,
} from "./persistence";

dotenv.config();

export interface AuditLogEntry {
  sequence: number;
  timestamp: string;
  eventType: string;
  severity: "INFO" | "WARNING" | "HIGH" | "CRITICAL";
  intentId?: string;
  details: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
}

const GENESIS_HASH = "0".repeat(64);

export class TamperEvidentAuditLogger {
  private logs: AuditLogEntry[] = [];
  private readonly persistence: RimbuxPersistence;
  private readonly secret: string;

  constructor(
    persistence?: RimbuxPersistence,
    secret: string = process.env.RIMBUX_AUDIT_SECRET ?? ""
  ) {
    if (!secret || secret.length < 64) {
      throw new Error(
        "RIMBUX_AUDIT_SECRET is missing or invalid. A secret of at least 32 bytes is required."
      );
    }

    this.secret = secret;
    this.persistence = persistence ?? new RimbuxPersistence();

    this.logs = this.persistence.getAuditEvents().map((row) => ({
      sequence: row.sequence,
      timestamp: row.timestamp,
      eventType: row.event_type,
      severity: row.severity as AuditLogEntry["severity"],
      intentId: row.intent_id ?? undefined,
      details: JSON.parse(row.details) as Record<string, unknown>,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
    }));
  }

  private calculateHash(entry: Omit<AuditLogEntry, "entryHash">): string {
    const payload = JSON.stringify({
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      eventType: entry.eventType,
      severity: entry.severity,
      intentId: entry.intentId,
      details: entry.details,
      prevHash: entry.prevHash,
    });

    return crypto
      .createHmac("sha256", this.secret)
      .update(payload)
      .digest("hex");
  }

  public record(
    eventType: string,
    severity: AuditLogEntry["severity"],
    details: Record<string, unknown>,
    intentId?: string
  ): AuditLogEntry {
    const previous = this.logs[this.logs.length - 1];

    // Immutable snapshots ensure audit data cannot change after recording.
    const safeDetails = JSON.parse(JSON.stringify(details)) as Record<string, unknown>;

    const entryData = {
      sequence: previous ? previous.sequence + 1 : 1,
      timestamp: new Date().toISOString(),
      eventType,
      severity,
      intentId,
      details: safeDetails,
      prevHash: previous?.entryHash ?? GENESIS_HASH,
    };

    const entryHash = this.calculateHash(entryData);

    const entry: AuditLogEntry = {
      ...entryData,
      entryHash,
    };

    const storedEntry: StoredAuditEvent = {
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      event_type: entry.eventType,
      severity: entry.severity,
      intent_id: entry.intentId ?? null,
      details: JSON.stringify(entry.details),
      prev_hash: entry.prevHash,
      entry_hash: entry.entryHash,
    };

    this.persistence.appendAuditEvent(storedEntry);
    this.logs.push(entry);

    return entry;
  }

  public getLogs(): AuditLogEntry[] {
    return [...this.logs].reverse();
  }

  public verifyChainIntegrity(): {
    intact: boolean;
    totalEntries: number;
  } {
    for (let i = 0; i < this.logs.length; i++) {
      const current = this.logs[i];

      const expectedPrev = i === 0
        ? GENESIS_HASH
        : this.logs[i - 1].entryHash;

      if (
        current.sequence !== i + 1 ||
        current.prevHash !== expectedPrev
      ) {
        return {
          intact: false,
          totalEntries: this.logs.length,
        };
      }

      const { entryHash, ...entryData } = current;
      const expectedHash = this.calculateHash(entryData);

      const actualBuffer = Buffer.from(entryHash, "hex");
      const expectedBuffer = Buffer.from(expectedHash, "hex");

      if (
        actualBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
      ) {
        return {
          intact: false,
          totalEntries: this.logs.length,
        };
      }
    }

    return {
      intact: true,
      totalEntries: this.logs.length,
    };
  }
}
