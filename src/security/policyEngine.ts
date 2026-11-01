// src/security/policyEngine.ts
import crypto from "crypto";
import {
  ExtractedTransactionIntent,
  PolicyAuthorizationToken,
  PolicyDecisionType,
  PolicyEvaluationResult,
  ReputationAssessment,
  RiskClassification,
  ScamDetectionReport,
  SpendingCheckResult,
  SpendingPolicyConfig,
} from "../types";

export class DeterministicPolicyEngine {
  private readonly hmacSecret: string;
  private issuedTokens: Map<string, PolicyAuthorizationToken> = new Map();
  private consumedTokenIds: Set<string> = new Set();
  private reservedTokenIds: Set<string> = new Set();

  constructor(hmacSecret?: string) {
    this.hmacSecret =
      hmacSecret || process.env.RIMBUX_GATE_HMAC_SECRET || crypto.randomBytes(32).toString("hex");
  }

  public evaluate(
    intent: ExtractedTransactionIntent,
    spendingCheck: SpendingCheckResult,
    reputation: ReputationAssessment,
    scamReport: ScamDetectionReport,
    policyConfig: SpendingPolicyConfig
  ): PolicyEvaluationResult {
    const reasons: string[] = [];
    let decision: PolicyDecisionType = "ALLOW";
    let riskClassification: RiskClassification = "LOW";

    if (scamReport.promptInjectionDetected || scamReport.policyBypassAttemptDetected) {
      decision = "BLOCK";
      riskClassification = "CRITICAL";
      reasons.push("CRITICAL_THREAT: Prompt injection attack or policy bypass attempt detected.");
    }

    for (const warning of scamReport.warnings) {
      if (warning.recommendedAction === "IMMEDIATE_BLOCK") {
        decision = "BLOCK";
        riskClassification = "CRITICAL";
        reasons.push(`SCAM_BLOCK [${warning.ruleId}]: ${warning.whatWasDetected}`);
      } else if (warning.recommendedAction === "REQUIRE_HUMAN_REVIEW" && decision !== "BLOCK") {
        decision = "REQUIRE_APPROVAL";
        if (riskClassification === "LOW") riskClassification = "HIGH";
        reasons.push(`SCAM_REVIEW [${warning.ruleId}]: ${warning.whatWasDetected}`);
      }
    }

    if (!spendingCheck.passed) {
      decision = "BLOCK";
      riskClassification = "HIGH";
      for (const v of spendingCheck.violations) {
        reasons.push(`SPENDING_POLICY_VIOLATION: ${v}`);
      }
    }

    const targetMethod = intent.contractMethod || "execute_agent_payment";
    if (!policyConfig.allowedContractMethods.includes(targetMethod)) {
      decision = "BLOCK";
      riskClassification = "CRITICAL";
      reasons.push(
        `SANDBOX_METHOD_VIOLATION: Metode '${targetMethod}' is outside the FunctionCall key permissions [${policyConfig.allowedContractMethods.join(
          ", "
        )}].`
      );
    }

    if (reputation.classification === "MALICIOUS") {
      decision = "BLOCK";
      riskClassification = "CRITICAL";
      reasons.push(
        `REPUTATION_BLOCK: Destination '${intent.recipientId}' has MALICIOUS status (Score: ${reputation.score}/100).`
      );
    } else if (reputation.classification === "SUSPICIOUS" && decision !== "BLOCK") {
      decision = "REQUIRE_APPROVAL";
      riskClassification = "HIGH";
      reasons.push(
        `REPUTATION_ESCALATION: Destination '${intent.recipientId}' has SUSPICIOUS reputation (Score: ${reputation.score}/100).`
      );
    } else if (reputation.classification === "NEUTRAL_UNKNOWN" && decision !== "BLOCK") {
      if (
        !reputation.rpcReachable ||
        !policyConfig.allowedDestinations.includes(intent.recipientId.toLowerCase())
      ) {
        decision = "REQUIRE_APPROVAL";
        if (riskClassification === "LOW") riskClassification = "MEDIUM";
        reasons.push(
          `UNKNOWN_COUNTERPARTY_GATE: '${intent.recipientId}' has NEUTRAL_UNKNOWN status (Score: ${reputation.score}/100). Human approval is required.`
        );
      }
    }

    if (spendingCheck.requiresHumanApproval && decision === "ALLOW") {
      decision = "REQUIRE_APPROVAL";
      if (riskClassification === "LOW") riskClassification = "MEDIUM";
      reasons.push(
        `APPROVAL_THRESHOLD: Transfer ${intent.amountNear} NEAR ke '${intent.recipientId}' requires human operator authorization.`
      );
    }

    if (decision === "ALLOW" && reasons.length === 0) {
      reasons.push(
        `VERIFIED_SAFE: Amount (${intent.amountNear} NEAR) is within limits, destination '${intent.recipientId}' is trusted (Score: ${reputation.score}/100), with 0 scam indicators.`
      );
    }

    let authorizationToken: PolicyAuthorizationToken | undefined;
    if (decision === "ALLOW") {
      authorizationToken = this.issueAuthorizationToken(intent, "DETERMINISTIC_POLICY_GATE");
    }

    return {
      intentId: intent.intentId,
      decision,
      riskClassification,
      reasons,
      spendingCheck,
      reputation,
      scamReport,
      authorizationToken,
      evaluatedAt: Date.now(),
    };
  }

  public issueAuthorizationToken(
    intent: ExtractedTransactionIntent,
    approvedBy: "DETERMINISTIC_POLICY_GATE" | "HUMAN_OPERATOR",
    ttlMs: number = 60_000
  ): PolicyAuthorizationToken {
    const tokenId = `pat_${crypto.randomBytes(10).toString("hex")}`;
    const issuedAt = Date.now();
    const expiresAt = issuedAt + ttlMs;
    const contractMethod = intent.contractMethod || "execute_agent_payment";

    const payload = `${tokenId}:${intent.intentId}:${intent.recipientId}:${intent.amountYocto}:${contractMethod}:${issuedAt}:${expiresAt}:${approvedBy}`;
    const hmacSignature = crypto.createHmac("sha256", this.hmacSecret).update(payload).digest("hex");

    const token: PolicyAuthorizationToken = {
      tokenId,
      intentId: intent.intentId,
      recipientId: intent.recipientId,
      amountYocto: intent.amountYocto,
      contractMethod,
      issuedAt,
      expiresAt,
      approvedBy,
      hmacSignature,
    };

    this.issuedTokens.set(tokenId, token);
    return token;
  }

  public reserveToken(
    token: PolicyAuthorizationToken | undefined,
    expectedIntentId: string,
    expectedRecipientId: string,
    expectedAmountYocto: string,
    expectedMethod: string
  ): { valid: boolean; reason?: string } {
    if (!token) {
      return { valid: false, reason: "MISSING_AUTH_TOKEN: No authorization token was provided." };
    }

    if (this.consumedTokenIds.has(token.tokenId)) {
      return { valid: false, reason: `REPLAY_BLOCKED: Token '${token.tokenId}' has already been used.` };
    }

    if (this.reservedTokenIds.has(token.tokenId)) {
      return { valid: false, reason: `TOKEN_ALREADY_RESERVED: Token '${token.tokenId}' is in use.` };
    }

    if (Date.now() > token.expiresAt) {
      return {
        valid: false,
        reason: `EXPIRED_AUTH_TOKEN: Token '${token.tokenId}' has expired.`,
      };
    }

    const issuedToken = this.issuedTokens.get(token.tokenId);
    if (!issuedToken) {
      return { valid: false, reason: "UNKNOWN_AUTH_TOKEN: Token was not issued by this policy engine." };
    }

    if (
      token.intentId !== expectedIntentId ||
      token.recipientId.toLowerCase() !== expectedRecipientId.toLowerCase() ||
      token.amountYocto !== expectedAmountYocto ||
      token.contractMethod !== expectedMethod
    ) {
      return {
        valid: false,
        reason: "PARAMETER_TAMPERING_DETECTED: Transaction payload does not match the authorization token.",
      };
    }

    const expectedPayload = `${token.tokenId}:${token.intentId}:${token.recipientId}:${token.amountYocto}:${token.contractMethod}:${token.issuedAt}:${token.expiresAt}:${token.approvedBy}`;
    const computedHmac = crypto.createHmac("sha256", this.hmacSecret).update(expectedPayload).digest();
    const suppliedHmac = Buffer.from(token.hmacSignature, "hex");

    if (
      suppliedHmac.length !== computedHmac.length ||
      !crypto.timingSafeEqual(computedHmac, suppliedHmac)
    ) {
      return { valid: false, reason: "INVALID_HMAC_SIGNATURE: Token authentication failed." };
    }

    if (
      issuedToken.hmacSignature !== token.hmacSignature ||
      issuedToken.intentId !== token.intentId ||
      issuedToken.recipientId !== token.recipientId ||
      issuedToken.amountYocto !== token.amountYocto ||
      issuedToken.contractMethod !== token.contractMethod ||
      issuedToken.issuedAt !== token.issuedAt ||
      issuedToken.expiresAt !== token.expiresAt ||
      issuedToken.approvedBy !== token.approvedBy
    ) {
      return { valid: false, reason: "TOKEN_RECORD_MISMATCH: Token does not match its issued record." };
    }

    this.reservedTokenIds.add(token.tokenId);
    return { valid: true };
  }

  public consumeToken(tokenId: string): { valid: boolean; reason?: string } {
    if (!this.reservedTokenIds.has(tokenId)) {
      return { valid: false, reason: "TOKEN_NOT_RESERVED: Token must be reserved before consumption." };
    }

    this.reservedTokenIds.delete(tokenId);
    this.consumedTokenIds.add(tokenId);
    return { valid: true };
  }

  public releaseToken(tokenId: string): void {
    this.reservedTokenIds.delete(tokenId);
  }

  public verifyAndConsumeToken(
    token: PolicyAuthorizationToken | undefined,
    expectedIntentId: string,
    expectedRecipientId: string,
    expectedAmountYocto: string,
    expectedMethod: string
  ): { valid: boolean; reason?: string } {
    const verification = this.reserveToken(
      token,
      expectedIntentId,
      expectedRecipientId,
      expectedAmountYocto,
      expectedMethod
    );

    if (!verification.valid || !token) {
      return verification;
    }

    return this.consumeToken(token.tokenId);
  }
}