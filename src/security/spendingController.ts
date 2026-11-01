// src/security/spendingController.ts
import crypto from "crypto";
import { ExtractedTransactionIntent, SpendingCheckResult, SpendingPolicyConfig } from "../types";

interface LedgerEntry {
  reservationId: string;
  intentId: string;
  recipientId: string;
  amountNear: number;
  timestamp: number;
  status: "RESERVED" | "COMMITTED" | "RELEASED";
}

export class SpendingController {
  private config: SpendingPolicyConfig;
  private ledger: LedgerEntry[] = [];
  private mutexLocked: boolean = false;
  private waitQueue: Array<() => void> = [];

  constructor(initialConfig?: Partial<SpendingPolicyConfig>) {
    this.config = {
      maxTransactionAmountNear: 5.0,
      dailySpendingLimitNear: 15.0,
      totalWalletSpendingCapNear: 50.0,
      perRecipientDailyLimitNear: 8.0,
      humanApprovalThresholdNear: 2.0,
      maxTxPerMinute: 4,
      allowedDestinations: [
        "alice.testnet",
        "bob.testnet",
        "wrap.testnet",
        "ref-finance-101.testnet",
        "dev-bounty.testnet",
      ],
      blockedDestinations: [
        "drainer-vault.testnet",
        "phishing-airdrop.testnet",
        "malicious-mixer.testnet",
        "attacker.testnet",
      ],
      requireAllowlistForContracts: true,
      allowedContractMethods: ["execute_agent_payment", "ft_transfer", "storage_deposit"],
      emergencyLockdown: false,
      ...initialConfig,
    };
  }

  private async acquireLock(): Promise<void> {
    if (!this.mutexLocked) {
      this.mutexLocked = true;
      return;
    }
    return new Promise((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  private releaseLock(): void {
    const next = this.waitQueue.shift();
    if (next) {
      next();
    } else {
      this.mutexLocked = false;
    }
  }

  public getConfig(): SpendingPolicyConfig {
    return { ...this.config };
  }

  public updateConfig(patch: Partial<SpendingPolicyConfig>): SpendingPolicyConfig {
    this.config = { ...this.config, ...patch };
    return this.getConfig();
  }

  public resetLedger(): void {
    this.ledger = [];
  }

  public getMetricsSnapshot(recipientId?: string) {
    const now = Date.now();
    const dayAgo = now - 24 * 60 * 60 * 1000;
    const minuteAgo = now - 60 * 1000;

    for (const entry of this.ledger) {
      if (entry.status === "RESERVED" && now - entry.timestamp > 5 * 60 * 1000) {
        entry.status = "RELEASED";
      }
    }

    const activeEntries = this.ledger.filter(
      (e) => e.status === "COMMITTED" || e.status === "RESERVED"
    );

    const dailySpentNear = Number(
      activeEntries
        .filter((e) => e.timestamp >= dayAgo)
        .reduce((sum, e) => sum + e.amountNear, 0)
        .toFixed(6)
    );

    const totalSpentNear = Number(
      activeEntries.reduce((sum, e) => sum + e.amountNear, 0).toFixed(6)
    );

    const recipientSpentTodayNear = recipientId
      ? Number(
          activeEntries
            .filter((e) => e.recipientId === recipientId && e.timestamp >= dayAgo)
            .reduce((sum, e) => sum + e.amountNear, 0)
            .toFixed(6)
        )
      : 0;

    const recentTxCountLastMinute = activeEntries.filter((e) => e.timestamp >= minuteAgo).length;
    const activeConcurrentLocks = activeEntries.filter((e) => e.status === "RESERVED").length;

    return {
      dailySpentNear,
      totalSpentNear,
      recipientSpentTodayNear,
      recentTxCountLastMinute,
      activeConcurrentLocks,
    };
  }

  public async evaluateAndReserve(intent: ExtractedTransactionIntent): Promise<SpendingCheckResult> {
    await this.acquireLock();
    try {
      const violations: string[] = [];
      let requiresHumanApproval = false;
      const snapshot = this.getMetricsSnapshot(intent.recipientId);

      if (this.config.emergencyLockdown) {
        violations.push("EMERGENCY_LOCKDOWN: Wallet spending is globally locked by the human operator.");
      }

      if (!Number.isFinite(intent.amountNear) || intent.amountNear <= 0) {
        violations.push(`INVALID_AMOUNT: Requested amount (${intent.amountNear} NEAR) must be greater than zero.`);
      }

      if (this.config.blockedDestinations.includes(intent.recipientId.toLowerCase())) {
        violations.push(`BLOCKED_DESTINATION: Recipient '${intent.recipientId}' is on the explicit blocklist.`);
      }

      if (intent.amountNear > this.config.maxTransactionAmountNear) {
        violations.push(
          `MAX_TX_EXCEEDED: Requested ${intent.amountNear} NEAR exceeds single-transaction cap (${this.config.maxTransactionAmountNear} NEAR).`
        );
      }

      if (snapshot.dailySpentNear + intent.amountNear > this.config.dailySpendingLimitNear) {
        violations.push(
          `DAILY_LIMIT_EXCEEDED: Requested ${intent.amountNear} NEAR + ${snapshot.dailySpentNear} NEAR spent today exceeds 24h limit (${this.config.dailySpendingLimitNear} NEAR).`
        );
      }

      if (snapshot.totalSpentNear + intent.amountNear > this.config.totalWalletSpendingCapNear) {
        violations.push(
          `TOTAL_CAP_EXCEEDED: Requested ${intent.amountNear} NEAR + ${snapshot.totalSpentNear} NEAR total spent exceeds lifetime wallet cap (${this.config.totalWalletSpendingCapNear} NEAR).`
        );
      }

      if (snapshot.recipientSpentTodayNear + intent.amountNear > this.config.perRecipientDailyLimitNear) {
        violations.push(
          `PER_RECIPIENT_LIMIT_EXCEEDED: Recipient '${intent.recipientId}' would receive ${
            snapshot.recipientSpentTodayNear + intent.amountNear
          } NEAR today, exceeding per-recipient limit (${this.config.perRecipientDailyLimitNear} NEAR).`
        );
      }

      if (snapshot.recentTxCountLastMinute >= this.config.maxTxPerMinute) {
        violations.push(
          `RATE_LIMIT_EXCEEDED: ${snapshot.recentTxCountLastMinute} transactions in the last 60s meets/exceeds max frequency (${this.config.maxTxPerMinute}/min).`
        );
      }

      if (snapshot.activeConcurrentLocks >= 1) {
        violations.push(
          `CONCURRENT_SPEND_LOCKED: ${snapshot.activeConcurrentLocks} transaction is currently in-flight/reserved. Concurrent spending is blocked to prevent race conditions.`
        );
      }

      const isAllowlisted = this.config.allowedDestinations.includes(intent.recipientId.toLowerCase());
      if (!isAllowlisted) {
        requiresHumanApproval = true;
      }
      if (intent.amountNear >= this.config.humanApprovalThresholdNear) {
        requiresHumanApproval = true;
      }

      if (violations.length > 0) {
        return {
          passed: false,
          requiresHumanApproval: false,
          violations,
          snapshot,
        };
      }

      const reservationId = `rsv_${crypto.randomBytes(8).toString("hex")}`;
      this.ledger.push({
        reservationId,
        intentId: intent.intentId,
        recipientId: intent.recipientId,
        amountNear: intent.amountNear,
        timestamp: Date.now(),
        status: "RESERVED",
      });

      return {
        passed: true,
        requiresHumanApproval,
        violations: [],
        reservationId,
        snapshot: this.getMetricsSnapshot(intent.recipientId),
      };
    } finally {
      this.releaseLock();
    }
  }

  public commitReservation(reservationId?: string): void {
    if (!reservationId) return;
    const item = this.ledger.find((e) => e.reservationId === reservationId);
    if (item && item.status === "RESERVED") {
      item.status = "COMMITTED";
    }
  }

  public releaseReservation(reservationId?: string): void {
    if (!reservationId) return;
    const item = this.ledger.find((e) => e.reservationId === reservationId);
    if (item && item.status === "RESERVED") {
      item.status = "RELEASED";
    }
  }
}