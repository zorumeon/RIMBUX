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
  >;
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
  >;
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
  }

  public parseNaturalLanguageInstruction(instruction: string): ExtractedTransactionIntent {
    const intentId = `intent_${crypto.randomBytes(6).toString("hex")}`;

    const amountMatch = instruction.match(/(\d+(?:\.\d+)?)\s*near\b/i);
    const amountNear = amountMatch ? Number(amountMatch[1]) : 0;

    const toAccountMatch =
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

  public async processInstruction(instruction: string): Promise<AgentExecutionResponse> {
    const intent = this.parseNaturalLanguageInstruction(instruction);

    this.auditLogger.record(
      "INTENT_RECEIVED",
      "INFO",
      { rawInstruction: instruction, recipientId: intent.recipientId, amountNear: intent.amountNear },
      intent.intentId
    );

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

    if (evaluation.decision === "REQUIRE_APPROVAL") {
      this.pendingApprovals.set(intent.intentId, {
        intent,
        evaluation,
        createdAt: Date.now(),
      });

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

  public async approvePendingIntent(intentId: string, approve: boolean): Promise<AgentExecutionResponse> {
    if (this.approvalInFlight.has(intentId)) {
      throw new Error(`Approval for intent '${intentId}' is already in progress.`);
    }

    const pending = this.pendingApprovals.get(intentId);
    if (!pending) {
      throw new Error(`Pending intent '${intentId}' was not found.`);
    }

    this.approvalInFlight.add(intentId);

    try {
      const existingRecord = this.transactionHistory.find((r) => r.intentId === intentId);

      if (!approve) {
        this.pendingApprovals.delete(intentId);
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
          transactionRecord: existingRecord!,
          agentExplanation: "The human operator rejected the transaction and released the reserved funds.",
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
        transactionRecord: existingRecord!,
        signedEnvelope,
        agentExplanation: `The human operator approved the transaction; signed through the FunctionCall sandbox (${signedEnvelope.txHash}).`,
      };
    } finally {
      this.approvalInFlight.delete(intentId);
    }
  }

  public getPendingApprovals(): PendingApprovalItem[] {
    return Array.from(this.pendingApprovals.values());
  }

  public getTransactionHistory(): TransactionRecord[] {
    return [...this.transactionHistory];
  }
}