// src/security/auditLogger.ts
import crypto from "crypto";

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

export class TamperEvidentAuditLogger {
  private logs: AuditLogEntry[] = [];

  public record(
    eventType: string,
    severity: AuditLogEntry["severity"],
    details: Record<string, unknown>,
    intentId?: string
  ): AuditLogEntry {
    const sequence = this.logs.length + 1;
    const timestamp = new Date().toISOString();
    const prevHash = this.logs.length > 0 ? this.logs[this.logs.length - 1].entryHash : "0".repeat(64);

    const payload = JSON.stringify({ sequence, timestamp, eventType, severity, intentId, details, prevHash });
    const entryHash = crypto.createHmac("sha256", "rimbux-audit-chain").update(payload).digest("hex");

    const entry: AuditLogEntry = {
      sequence,
      timestamp,
      eventType,
      severity,
      intentId,
      details,
      prevHash,
      entryHash,
    };

    this.logs.push(entry);
    return entry;
  }

  public getLogs(): AuditLogEntry[] {
    return [...this.logs].reverse();
  }

  public verifyChainIntegrity(): { intact: boolean; totalEntries: number } {
    for (let i = 0; i < this.logs.length; i++) {
      const current = this.logs[i];
      const expectedPrev = i === 0 ? "0".repeat(64) : this.logs[i - 1].entryHash;
      if (current.prevHash !== expectedPrev) {
        return { intact: false, totalEntries: this.logs.length };
      }
    }
    return { intact: true, totalEntries: this.logs.length };
  }
}