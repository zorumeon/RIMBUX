// src/agent/rimbuxAgent.ts
import crypto from "crypto";
import {
  ExtractedTransactionIntent,
  PolicyEvaluationResult,
  TransactionRecord,
} from "../types";
import { SpendingController } from "../security/spendingController";
import { DeterministicPolicyEngine } from "../security/policyEngine";
import { ReputationIntelligenceEngine } from "../intelligence/reputationEngine";
import { ScamDetectionEngine } from "../intelligence/scamDetector";
import { NearTestnetClient } from "../near/nearClient";
import { SandboxedSigningBoundary, SignedTransactionEnvelope } from "../near/signingBoundary";
import { TamperEvidentAuditLogger } from "../security/auditLogger";
import { RimbuxPersistence } from "../security/persistence";

export interface PendingApprovalItem {
  intent: ExtractedTransactionIntent;
  evaluation: PolicyEvaluationResult;
  createdAt: number;
  simulationOnly?: boolean;
}

export interface AgentExecutionResponse {
  intent: ExtractedTransactionIntent;
  evaluation: PolicyEvaluationResult;
  transactionRecord: TransactionRecord;
  signedEnvelope?: SignedTransactionEnvelope;
  agentExplanation: string;
}

export interface AgentDependencies {
  nearClient?: NearTestnetClient;
  signingBoundary?: Pick<
    SandboxedSigningBoundary,
    "signAuthorizedVaultIntent" | "getPublicMetadata" | "revokeKey"
  > & {
    armApprovedOneShotBroadcast?: (intentId: string) => void;
    disarmOneShotBroadcast?: (intentId: string) => void;
  };
  auditPersistence?: RimbuxPersistence;
  auditSecret?: string;
  broadcastEnabled?: boolean;
}

export class RimbuxAutonomousAgent {
  public readonly nearClient: NearTestnetClient;
  public readonly spendingController: SpendingController;
  public readonly policyEngine: DeterministicPolicyEngine;
  public readonly reputationEngine: ReputationIntelligenceEngine;
  public readonly scamDetector: ScamDetectionEngine;
  public readonly signingBoundary: Pick<
    SandboxedSigningBoundary,
    "signAuthorizedVaultIntent" | "getPublicMetadata" | "revokeKey"
  > & {
    armApprovedOneShotBroadcast?: (intentId: string) => void;
    disarmOneShotBroadcast?: (intentId: string) => void;
  };
  public readonly auditLogger: TamperEvidentAuditLogger;

  private pendingApprovals: Map<string, PendingApprovalItem> = new Map();
  private approvalInFlight: Set<string> = new Set();
  private transactionHistory: TransactionRecord[] = [];
  private readonly auditPersistence?: RimbuxPersistence;

  private persistTransactionRecord(record: TransactionRecord): void {
    this.auditPersistence?.saveTransactionRecord(record);
  }

  constructor(dependencies: AgentDependencies = {}) {
    this.auditPersistence = dependencies.auditPersistence;
    this.transactionHistory =
      dependencies.auditPersistence?.getTransactionHistory() ?? [];
    this.nearClient = dependencies.nearClient ?? new NearTestnetClient();
    // Restore reservations of still-pending approvals BEFORE the controller loads its
    // ledger, so the in-memory status matches the database.
    dependencies.auditPersistence?.restorePendingApprovalReservations();
    this.spendingController = new SpendingController(undefined, dependencies.auditPersistence);
    this.policyEngine = new DeterministicPolicyEngine();
    this.reputationEngine = new ReputationIntelligenceEngine(this.nearClient);
    this.scamDetector = new ScamDetectionEngine();
    this.signingBoundary =
      dependencies.signingBoundary ??
      new SandboxedSigningBoundary(
        this.nearClient.agentAccountId,
        this.nearClient.vaultContractId,
        process.env.NEAR_AGENT_FUNCTION_CALL_PRIVATE_KEY,
        undefined,
        dependencies.broadcastEnabled
      );
    this.auditLogger = new TamperEvidentAuditLogger(
      dependencies.auditPersistence ?? new RimbuxPersistence(":memory:"),
      dependencies.auditSecret
    );

    this.auditPersistence?.restorePendingApprovalReservations();

    const restoredApprovals =
      this.auditPersistence?.getPendingApprovals<PendingApprovalItem>() ?? [];

    for (const approval of restoredApprovals) {
      this.pendingApprovals.set(approval.intentId, approval.payload);
    }
  }

  public parseNaturalLanguageInstruction(instruction: string): ExtractedTransactionIntent {
    const intentId = `intent_${crypto.randomBytes(6).toString("hex")}`;

    const amountMatch = instruction.match(/(\d+(?:\.\d+)?)\s*near\b/i);
    const amountNear = amountMatch ? Number(amountMatch[1]) : 0;

    const toAccountMatch =
      // NOTE: "ke" is Indonesian for "to"; keeps recipient parsing working for Indonesian instructions.
      instruction.match(/(?:to|ke|into|recipient|account)\s+([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)/i) ||
      instruction.match(/\b([a-z0-9_-]+\.(?:testnet|near))\b/i);
    const recipientId = toAccountMatch ? toAccountMatch[1].toLowerCase() : "unknown.testnet";

    const methodMatch = instruction.match(/method\s+['"]?([a-zA-Z0-9_]+)['"]?/i);
    let contractMethod = methodMatch ? methodMatch[1] : "execute_agent_payment";
    let actionType: ExtractedTransactionIntent["actionType"] = "VAULT_TRANSFER";

    if (/\b(addKey|add_key|deleteAccount|delete_account|deployContract|deploy_contract)\b/i.test(instruction)) {
      actionType = "RAW_ACTION_ATTEMPT";
      const rawMatch = instruction.match(
        /\b(addKey|add_key|deleteAccount|delete_account|deployContract|deploy_contract)\b/i
      );
      if (rawMatch) contractMethod = rawMatch[1];
    }

    return {
      intentId,
      rawInstruction: instruction,
      recipientId,
      amountNear,
      amountYocto: NearTestnetClient.nearToYocto(amountNear),
      actionType,
      contractMethod,
      extractedAt: Date.now(),
    };
  }

  public armApprovedOneShotBroadcast(intentId: string): void {
    const arm = this.signingBoundary.armApprovedOneShotBroadcast;
    if (!arm) {
      throw new Error("ONE_SHOT_BROADCAST_UNAVAILABLE");
    }
    arm.call(this.signingBoundary, intentId);
  }

  public async processInstruction(instruction: string, simulationOnly = false): Promise<AgentExecutionResponse> {
    const intent = this.parseNaturalLanguageInstruction(instruction);

    this.auditLogger.record(
      "INTENT_RECEIVED",
      "INFO",
      { rawInstruction: instruction, recipientId: intent.recipientId, amountNear: intent.amountNear },
      intent.intentId
    );

    // PRE-FLIGHT SECURITY GATE: reject prompt injection before reputation,
    // spending reservations, approval creation, or transaction signing.
    const preflightReputation = {
      accountId: intent.recipientId,
      classification: "NEUTRAL_UNKNOWN" as const,
      score: 0,
      confidence: 0,
      accountExistsOnChain: null,
      hasDeployedContract: null,
      rpcReachable: false,
      evidence: [],
      summary: "Reputation assessment skipped because the pre-flight security gate ran first.",
    };

    const preflightScamReport = this.scamDetector.analyze(
      intent,
      preflightReputation,
      this.spendingController.getConfig()
    );

    if (
      preflightScamReport.promptInjectionDetected ||
      preflightScamReport.policyBypassAttemptDetected ||
      preflightScamReport.paramSmugglingDetected
    ) {
      const reasons = [
        ...(preflightScamReport.promptInjectionDetected
          ? ["PROMPT_INJECTION_BLOCKED: Instruction contains a prompt-injection attempt."]
          : []),
        ...(preflightScamReport.policyBypassAttemptDetected
          ? ["POLICY_BYPASS_BLOCKED: Instruction attempts to bypass security policy."]
          : []),
        ...(preflightScamReport.paramSmugglingDetected
          ? ["PARAM_SMUGGLING_BLOCKED: Multiple transfer amounts or recipient clauses detected in one instruction."]
          : []),
      ];

      const spendingCheck = {
        passed: false,
        requiresHumanApproval: false,
        violations: reasons,
        snapshot: this.spendingController.getMetricsSnapshot(intent.recipientId),
      };

      const evaluation = {
        intentId: intent.intentId,
        decision: "BLOCK" as const,
        riskClassification: "CRITICAL" as const,
        reasons,
        spendingCheck,
        reputation: preflightReputation,
        scamReport: preflightScamReport,
        evaluatedAt: Date.now(),
      };

      const record: TransactionRecord = {
        intentId: intent.intentId,
        timestamp: Date.now(),
        rawInstruction: instruction,
        recipientId: intent.recipientId,
        amountNear: intent.amountNear,
        status: "BLOCKED_BY_POLICY",
        policyDecision: "BLOCK",
        riskClassification: "CRITICAL",
        reasons,
        reputationScore: 0,
        scamWarningsCount: preflightScamReport.warnings.length,
        verificationNote:
          "Rejected by the pre-flight security gate before reputation lookup, spending reservation, approval, or signing.",
      };

      this.transactionHistory.unshift(record);
      this.persistTransactionRecord(record);
      this.auditLogger.record(
        "TRANSACTION_BLOCKED",
        "CRITICAL",
        { reasons, stage: "PRE_FLIGHT_SECURITY_GATE" },
        intent.intentId
      );

      return {
        intent,
        evaluation,
        transactionRecord: record,
        agentExplanation: `Request rejected (CRITICAL risk): ${reasons.join(" | ")}`,
      };
    }

    const reputation = await this.reputationEngine.assessAccount(intent.recipientId);
    const spendingCheck = await this.spendingController.evaluateAndReserve(intent);
    const scamReport = this.scamDetector.analyze(
      intent,
      reputation,
      this.spendingController.getConfig()
    );

    const evaluation = this.policyEngine.evaluate(
      intent,
      spendingCheck,
      reputation,
      scamReport,
      this.spendingController.getConfig()
    );

    if (evaluation.decision === "BLOCK") {
      await this.spendingController.releaseReservation(spendingCheck.reservationId);
      const record: TransactionRecord = {
        intentId: intent.intentId,
        timestamp: Date.now(),
        rawInstruction: instruction,
        recipientId: intent.recipientId,
        amountNear: intent.amountNear,
        status: "BLOCKED_BY_POLICY",
        policyDecision: "BLOCK",
        riskClassification: evaluation.riskClassification,
        reasons: evaluation.reasons,
        reputationScore: reputation.score,
        scamWarningsCount: scamReport.warnings.length,
        verificationNote: "Independently rejected by the Deterministic Security Gate before transaction construction.",
      };
      this.transactionHistory.unshift(record);
      this.persistTransactionRecord(record);
      this.auditLogger.record("TRANSACTION_BLOCKED", "CRITICAL", { reasons: evaluation.reasons }, intent.intentId);

      return {
        intent,
        evaluation,
        transactionRecord: record,
        agentExplanation: `Request rejected (${evaluation.riskClassification} risk): ${evaluation.reasons.join(" | ")}`,
      };
    }

    if (evaluation.decision === "REQUIRE_APPROVAL" && simulationOnly) {
      const pendingApproval: PendingApprovalItem = {
        intent,
        evaluation,
        createdAt: Date.now(),
        simulationOnly: true,
      };

      this.pendingApprovals.set(intent.intentId, pendingApproval);
      this.auditPersistence?.savePendingApproval(
        intent.intentId,
        pendingApproval,
        pendingApproval.createdAt
      );

      const record: TransactionRecord = {
        intentId: intent.intentId,
        timestamp: Date.now(),
        rawInstruction: instruction,
        recipientId: intent.recipientId,
        amountNear: intent.amountNear,
        status: "AWAITING_HUMAN_APPROVAL",
        policyDecision: "REQUIRE_APPROVAL",
        riskClassification: evaluation.riskClassification,
        reasons: evaluation.reasons,
        reputationScore: reputation.score,
        scamWarningsCount: scamReport.warnings.length,
        verificationNote:
          "Demo approval pending. No signing or broadcast is permitted; spending capacity is reserved until the demo decision.",
      };

      this.transactionHistory.unshift(record);
      this.persistTransactionRecord(record);
      this.auditLogger.record(
        "DEMO_APPROVAL_REQUIRED",
        "INFO",
        { decision: "REQUIRE_APPROVAL", amountNear: intent.amountNear, simulationOnly: true },
        intent.intentId
      );

      return {
        intent,
        evaluation,
        transactionRecord: record,
        agentExplanation:
          "Human approval required. DEMO ONLY — approval will never sign or broadcast a transaction.",
      };
    }

    if (evaluation.decision === "REQUIRE_APPROVAL") {
      const pendingApproval: PendingApprovalItem = {
        intent,
        evaluation,
        createdAt: Date.now(),
      };

      this.pendingApprovals.set(intent.intentId, pendingApproval);
      this.auditPersistence?.savePendingApproval(
        intent.intentId,
        pendingApproval,
        pendingApproval.createdAt
      );

      const record: TransactionRecord = {
        intentId: intent.intentId,
        timestamp: Date.now(),
        rawInstruction: instruction,
        recipientId: intent.recipientId,
        amountNear: intent.amountNear,
        status: "AWAITING_HUMAN_APPROVAL",
        policyDecision: "REQUIRE_APPROVAL",
        riskClassification: evaluation.riskClassification,
        reasons: evaluation.reasons,
        reputationScore: reputation.score,
        scamWarningsCount: scamReport.warnings.length,
        verificationNote:
          "Transaction remains unsigned (CONSTRUCTED_UNSIGNED); spending capacity is reserved pending human approval.",
      };
      this.transactionHistory.unshift(record);
      this.persistTransactionRecord(record);
      this.auditLogger.record("APPROVAL_REQUIRED", "WARNING", { reasons: evaluation.reasons }, intent.intentId);

      return {
        intent,
        evaluation,
        transactionRecord: record,
        agentExplanation: `Awaiting Human Approval (${evaluation.riskClassification} risk): ${evaluation.reasons.join(" | ")}`,
      };
    }

    // Public read-only demo: evaluate the policy, but never sign or broadcast.
    if (simulationOnly || !this.signingBoundary.getPublicMetadata().publicKey) {
      await this.spendingController.releaseReservation(spendingCheck.reservationId);

      const record: TransactionRecord = {
        intentId: intent.intentId,
        timestamp: Date.now(),
        rawInstruction: instruction,
        recipientId: intent.recipientId,
        amountNear: intent.amountNear,
        status: "SIMULATED",
        policyDecision: "ALLOW",
        riskClassification: evaluation.riskClassification,
        reasons: evaluation.reasons,
        reputationScore: reputation.score,
        scamWarningsCount: scamReport.warnings.length,
        verificationNote:
          "Read-only demo: security evaluation passed. No signing, broadcast, or spending reservation was performed.",
      };

      this.transactionHistory.unshift(record);
      this.persistTransactionRecord(record);
      this.auditLogger.record(
        "TRANSACTION_SIMULATED_READ_ONLY",
        "INFO",
        { decision: "ALLOW", amountNear: intent.amountNear },
        intent.intentId
      );

      return {
        intent,
        evaluation,
        transactionRecord: record,
        agentExplanation:
          "Security checks passed. SIMULATED ONLY — no transaction was signed or broadcast.",
      };
    }

    const signedEnvelope = await this.signingBoundary.signAuthorizedVaultIntent(
      intent,
      evaluation.authorizationToken,
      this.policyEngine
    ).catch(async (error: unknown) => {
      await this.spendingController.releaseReservation(spendingCheck.reservationId);
      this.auditLogger.record(
        "TRANSACTION_SIGNING_FAILED",
        "HIGH",
        { error: error instanceof Error ? error.message : "Unknown signing error" },
        intent.intentId
      );
      throw error;
    });
    await this.spendingController.commitReservation(spendingCheck.reservationId);

    const record: TransactionRecord = {
      intentId: intent.intentId,
      timestamp: Date.now(),
      rawInstruction: instruction,
      recipientId: intent.recipientId,
      amountNear: intent.amountNear,
      status: signedEnvelope.lifecycleStatus,
      policyDecision: "ALLOW",
      riskClassification: evaluation.riskClassification,
      reasons: evaluation.reasons,
      reputationScore: reputation.score,
      scamWarningsCount: scamReport.warnings.length,
      txHash: signedEnvelope.txHash,
      unsignedTxPayloadDigest: signedEnvelope.unsignedPayloadDigest,
      signerPublicKey: signedEnvelope.signerPublicKey,
      explorerUrl: signedEnvelope.explorerUrl,
      verificationNote: signedEnvelope.verificationNote,
    };

    this.transactionHistory.unshift(record);
    this.persistTransactionRecord(record);
    this.auditLogger.record(
      "TRANSACTION_SIGNED_SANDBOX",
      "INFO",
      {
        txHash: signedEnvelope.txHash,
        signerPublicKey: signedEnvelope.signerPublicKey,
        receiverContractId: signedEnvelope.receiverContractId,
        amountNear: intent.amountNear,
      },
      intent.intentId
    );

    return {
      intent,
      evaluation,
      transactionRecord: record,
      signedEnvelope,
      agentExplanation: `Authorized and signed within the FunctionCall sandbox (${signedEnvelope.txHash}).`,
    };
  }

  public async approveDemoPendingIntent(
    intentId: string,
    approve: boolean
  ): Promise<AgentExecutionResponse> {
    if (this.approvalInFlight.has(intentId)) {
      throw new Error(`Approval for intent '${intentId}' is already in progress.`);
    }

    const pending = this.pendingApprovals.get(intentId);
    if (!pending || pending.simulationOnly !== true) {
      throw new Error("DEMO_PENDING_INTENT_NOT_FOUND");
    }

    this.approvalInFlight.add(intentId);
    try {
      const record = this.transactionHistory.find((item) => item.intentId === intentId);
      if (!record) throw new Error("DEMO_TRANSACTION_RECORD_NOT_FOUND");

      await this.spendingController.releaseReservation(
        pending.evaluation.spendingCheck.reservationId
      );

      this.pendingApprovals.delete(intentId);
      this.auditPersistence?.updatePendingApprovalStatus(
        intentId,
        approve ? "APPROVED" : "REJECTED"
      );

      if (approve) {
        record.status = "SIMULATED";
        record.policyDecision = "ALLOW";
        record.verificationNote =
          "Demo approval recorded. No signing, broadcast, or spending occurred.";
      } else {
        record.status = "BLOCKED_BY_POLICY";
        record.policyDecision = "BLOCK";
        record.reasons.push("DEMO_APPROVAL_REJECTED: The demo approval was rejected.");
        record.verificationNote =
          "Demo approval rejected. No signing, broadcast, or spending occurred.";
      }

      this.persistTransactionRecord(record);
      this.auditLogger.record(
        approve ? "DEMO_APPROVAL_ACCEPTED" : "DEMO_APPROVAL_REJECTED",
        "INFO",
        { intentId, simulationOnly: true, signingSkipped: true, broadcasted: false },
        intentId
      );

      return {
        intent: pending.intent,
        evaluation: pending.evaluation,
        transactionRecord: record,
        agentExplanation: approve
          ? "Demo approval recorded. SIMULATED ONLY — no transaction was signed or broadcast."
          : "Demo approval rejected. SIMULATED ONLY — no transaction was signed or broadcast.",
      };
    } finally {
      this.approvalInFlight.delete(intentId);
    }
  }

  public async approvePendingIntent(intentId: string, approve: boolean): Promise<AgentExecutionResponse> {
    if (this.approvalInFlight.has(intentId)) {
      throw new Error(`Approval for intent '${intentId}' is already in progress.`);
    }

    const pending = this.pendingApprovals.get(intentId);
    if (!pending) {
      throw new Error(`Pending intent '${intentId}' was not found.`);
    }
    if (pending.simulationOnly === true) {
      throw new Error("DEMO_INTENT_REQUIRES_SIMULATION_APPROVAL");
    }

    this.approvalInFlight.add(intentId);

    try {
      const existingRecord = this.transactionHistory.find((r) => r.intentId === intentId);
      if (!existingRecord) {
        throw new Error(`Transaction record for pending intent '${intentId}' was not found.`);
      }

      if (!approve) {
        this.pendingApprovals.delete(intentId);
        this.auditPersistence?.updatePendingApprovalStatus(intentId, "REJECTED");
        await this.spendingController.releaseReservation(pending.evaluation.spendingCheck.reservationId);

        if (existingRecord) {
          existingRecord.status = "BLOCKED_BY_POLICY";
          existingRecord.policyDecision = "BLOCK";
          existingRecord.reasons.push("HUMAN_OPERATOR_REJECTED: Human operator rejected the transaction request.");
          existingRecord.verificationNote = "Rejected by the human operator; spending reservation released.";
          this.persistTransactionRecord(existingRecord);
        }

        this.auditLogger.record("HUMAN_APPROVAL_DENIED", "WARNING", { intentId }, intentId);

        return {
          intent: pending.intent,
          evaluation: pending.evaluation,
          transactionRecord: existingRecord,
          agentExplanation: "The human operator rejected the transaction and released the reserved funds.",
        };
      }

      // Public read-only demo approval: record the decision without signing.
      if (!this.signingBoundary.getPublicMetadata().publicKey) {
        await this.spendingController.releaseReservation(
          pending.evaluation.spendingCheck.reservationId
        );
        this.pendingApprovals.delete(intentId);
        this.auditPersistence?.updatePendingApprovalStatus(intentId, "APPROVED");

        if (existingRecord) {
          existingRecord.status = "SIMULATED";
          existingRecord.policyDecision = "ALLOW";
          existingRecord.verificationNote =
            "Human approval recorded in public read-only demo. No signing, broadcast, or spending occurred.";
          this.persistTransactionRecord(existingRecord);
        }

        this.auditLogger.record(
          "HUMAN_APPROVAL_SIMULATED",
          "INFO",
          { intentId, signingSkipped: true },
          intentId
        );

        return {
          intent: pending.intent,
          evaluation: pending.evaluation,
          transactionRecord: existingRecord,
          agentExplanation:
            "Human approval recorded. SIMULATED ONLY — no transaction was signed or broadcast.",
        };
      }

      const humanToken = this.policyEngine.issueAuthorizationToken(pending.intent, "HUMAN_OPERATOR");
      pending.evaluation.authorizationToken = humanToken;

      const signedEnvelope = await this.signingBoundary.signAuthorizedVaultIntent(
        pending.intent,
        humanToken,
        this.policyEngine
      ).catch(async (error: unknown) => {
        await this.spendingController.releaseReservation(
          pending.evaluation.spendingCheck.reservationId
        );
        this.pendingApprovals.delete(intentId);
        this.auditPersistence?.updatePendingApprovalStatus(intentId, "QUARANTINED");

        if (existingRecord) {
          existingRecord.status = "FAILED_VERIFICATION";
          existingRecord.reasons.push("SIGNING_FAILED: The signing operation did not complete.");
          existingRecord.verificationNote =
            "Signing failed. No successful signing result was recorded; the spending reservation was released.";
          this.persistTransactionRecord(existingRecord);
        }

        this.auditLogger.record(
          "APPROVED_TRANSACTION_SIGNING_FAILED",
          "HIGH",
          { error: error instanceof Error ? error.message : "Unknown signing error" },
          intentId
        );
        throw error;
      });

      await this.spendingController.commitReservation(
        pending.evaluation.spendingCheck.reservationId
      );
      this.pendingApprovals.delete(intentId);
      this.auditPersistence?.updatePendingApprovalStatus(intentId, "APPROVED");

      if (existingRecord) {
        existingRecord.status = signedEnvelope.lifecycleStatus;
        existingRecord.policyDecision = "ALLOW";
        existingRecord.txHash = signedEnvelope.txHash;
        existingRecord.unsignedTxPayloadDigest = signedEnvelope.unsignedPayloadDigest;
        existingRecord.signerPublicKey = signedEnvelope.signerPublicKey;
        existingRecord.explorerUrl = signedEnvelope.explorerUrl;
        existingRecord.reasons.push("HUMAN_OPERATOR_APPROVED: Explicitly approved by the human operator.");
        existingRecord.verificationNote = signedEnvelope.verificationNote;
        this.persistTransactionRecord(existingRecord);
      }

      this.auditLogger.record(
        "HUMAN_APPROVAL_GRANTED",
        "INFO",
        { txHash: signedEnvelope.txHash, intentId },
        intentId
      );

      return {
        intent: pending.intent,
        evaluation: pending.evaluation,
        transactionRecord: existingRecord,
        signedEnvelope,
        agentExplanation: `The human operator approved the transaction; signed through the FunctionCall sandbox (${signedEnvelope.txHash}).`,
      };
    } finally {
      this.approvalInFlight.delete(intentId);
    }
  }

  public async approvePendingIntentOneShot(
    intentId: string
  ): Promise<AgentExecutionResponse> {
    const pending = this.pendingApprovals.get(intentId);
    if (!pending) throw new Error("PENDING_INTENT_NOT_FOUND");

    if (
      this.nearClient.networkId !== "testnet" ||
      pending.intent.actionType !== "VAULT_TRANSFER" ||
      pending.intent.contractMethod !== "execute_agent_payment" ||
      pending.intent.recipientId !== "rimbuxreceiver.testnet" ||
      pending.intent.amountYocto !== "1000000000000000000000"
    ) {
      throw new Error("ONE_SHOT_TRANSACTION_SCOPE_MISMATCH");
    }

    this.armApprovedOneShotBroadcast(intentId);
    try {
      return await this.approvePendingIntent(intentId, true);
    } finally {
      this.signingBoundary.disarmOneShotBroadcast?.(intentId);
    }
  }

  public async releaseQuarantinedReservation(
    reservationId: string
  ): Promise<{ released: boolean; reason: string }> {
    const entry = this.auditPersistence
      ?.getSpendingReservations()
      .find((r) => r.reservationId === reservationId);
    if (!entry) return { released: false, reason: "RESERVATION_NOT_FOUND" };
    if (this.pendingApprovals.has(entry.intentId)) {
      return { released: false, reason: "APPROVAL_STILL_PENDING" };
    }
    const record = this.transactionHistory.find((r) => r.intentId === entry.intentId);
    if (record && record.status !== "BLOCKED_BY_POLICY") {
      return { released: false, reason: `INTENT_NOT_BLOCKED:${record.status}` };
    }
    const result = await this.spendingController.releaseQuarantinedReservation(reservationId);
    if (result.released) {
      this.auditLogger.record(
        "QUARANTINED_RESERVATION_RELEASED",
        "WARNING",
        { reservationId, intentId: entry.intentId },
        entry.intentId
      );
    }
    return result;
  }

  public getPendingApprovals(): PendingApprovalItem[] {
    return Array.from(this.pendingApprovals.values());
  }

  public getTransactionHistory(): TransactionRecord[] {
    return [...this.transactionHistory];
  }
}