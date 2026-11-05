// src/types/index.ts

export type PolicyDecisionType = "ALLOW" | "REQUIRE_APPROVAL" | "BLOCK";

export type TransactionLifecycleStatus =
  | "SIMULATED"
  | "CONSTRUCTED_UNSIGNED"
  | "AWAITING_HUMAN_APPROVAL"
  | "BLOCKED_BY_POLICY"
  | "SIGNED"
  | "BROADCAST"
  | "CONFIRMED_ONCHAIN"
  | "FAILED_VERIFICATION";

export type RiskClassification = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ExtractedTransactionIntent {
  intentId: string;
  rawInstruction: string;
  recipientId: string;
  amountNear: number;
  amountYocto: string;
  actionType: "VAULT_TRANSFER" | "CONTRACT_CALL" | "RAW_ACTION_ATTEMPT";
  contractMethod?: string;
  contractArgs?: Record<string, unknown>;
  attachedDepositNear?: number;
  memo?: string;
  extractedAt: number;
}

export interface SpendingPolicyConfig {
  maxTransactionAmountNear: number;
  dailySpendingLimitNear: number;
  totalWalletSpendingCapNear: number;
  perRecipientDailyLimitNear: number;
  humanApprovalThresholdNear: number;
  maxTxPerMinute: number;
  allowedDestinations: string[];
  blockedDestinations: string[];
  requireAllowlistForContracts: boolean;
  allowedContractMethods: string[];
  emergencyLockdown: boolean;
}

export interface SpendingCheckResult {
  passed: boolean;
  requiresHumanApproval: boolean;
  violations: string[];
  reservationId?: string;
  snapshot: {
    dailySpentNear: number;
    totalSpentNear: number;
    recipientSpentTodayNear: number;
    recentTxCountLastMinute: number;
    activeConcurrentLocks: number;
  };
}

export interface ReputationEvidenceItem {
  source: "NEAR_TESTNET_RPC" | "THREAT_INTEL_REGISTRY" | "BEHAVIORAL_HISTORY" | "CONTRACT_INSPECTION";
  indicator: string;
  detail: string;
  weight: number;
}

export interface ReputationAssessment {
  accountId: string;
  classification: "TRUSTED" | "NEUTRAL_UNKNOWN" | "SUSPICIOUS" | "MALICIOUS";
  score: number;
  confidence: number;
  accountExistsOnChain: boolean | null;
  hasDeployedContract: boolean | null;
  rpcReachable: boolean;
  evidence: ReputationEvidenceItem[];
  summary: string;
}

export interface ExplainableScamWarning {
  ruleId: string;
  severity: "INFO" | "WARNING" | "HIGH" | "CRITICAL";
  whatWasDetected: string;
  whySuspicious: string;
  supportingEvidence: string[];
  confidenceAndUncertainty: {
    confidenceScore: number;
    uncertaintyNotes: string;
  };
  recommendedAction: "ALLOW_WITH_MONITORING" | "REQUIRE_HUMAN_REVIEW" | "IMMEDIATE_BLOCK";
}

export interface ScamDetectionReport {
  triggered: boolean;
  highestSeverity: "NONE" | "INFO" | "WARNING" | "HIGH" | "CRITICAL";
  promptInjectionDetected: boolean;
  policyBypassAttemptDetected: boolean;
  paramSmugglingDetected: boolean;
  warnings: ExplainableScamWarning[];
}

export interface PolicyEvaluationResult {
  intentId: string;
  decision: PolicyDecisionType;
  riskClassification: RiskClassification;
  reasons: string[];
  spendingCheck: SpendingCheckResult;
  reputation: ReputationAssessment;
  scamReport: ScamDetectionReport;
  authorizationToken?: PolicyAuthorizationToken;
  evaluatedAt: number;
}

export interface PolicyAuthorizationToken {
  tokenId: string;
  intentId: string;
  recipientId: string;
  amountYocto: string;
  contractMethod: string;
  issuedAt: number;
  expiresAt: number;
  approvedBy: "DETERMINISTIC_POLICY_GATE" | "HUMAN_OPERATOR";
  hmacSignature: string;
}

export interface TransactionRecord {
  intentId: string;
  timestamp: number;
  rawInstruction: string;
  recipientId: string;
  amountNear: number;
  status: TransactionLifecycleStatus;
  policyDecision: PolicyDecisionType;
  riskClassification: RiskClassification;
  reasons: string[];
  reputationScore: number;
  scamWarningsCount: number;
  txHash?: string;
  unsignedTxPayloadDigest?: string;
  signerPublicKey?: string;
  explorerUrl?: string;
  verificationNote: string;
}