import assert from "node:assert/strict";
import test from "node:test";
import { DeterministicPolicyEngine } from "../src/security/policyEngine";
import {
  ExtractedTransactionIntent,
  ReputationAssessment,
  ScamDetectionReport,
  SpendingCheckResult,
  SpendingPolicyConfig,
} from "../src/types";

const intent: ExtractedTransactionIntent = {
  intentId: "policy-engine-direct-test",
  rawInstruction: "Test-only direct PolicyEngine invocation",
  recipientId: "vendor.testnet",
  amountNear: 0.1,
  amountYocto: "100000000000000000000000",
  actionType: "CONTRACT_CALL",
  contractMethod: "execute_agent_payment",
  extractedAt: Date.now(),
};

const spendingCheck: SpendingCheckResult = {
  passed: true,
  requiresHumanApproval: false,
  violations: [],
  snapshot: {
    dailySpentNear: 0,
    totalSpentNear: 0,
    recipientSpentTodayNear: 0,
    recentTxCountLastMinute: 0,
    activeConcurrentLocks: 0,
  },
};

const reputation: ReputationAssessment = {
  accountId: "vendor.testnet",
  classification: "TRUSTED",
  score: 100,
  confidence: 1,
  accountExistsOnChain: true,
  hasDeployedContract: false,
  rpcReachable: true,
  evidence: [],
  summary: "Test-only trusted fixture",
};

const scamReport: ScamDetectionReport = {
  triggered: false,
  highestSeverity: "NONE",
  promptInjectionDetected: false,
  policyBypassAttemptDetected: false,
  paramSmugglingDetected: false,
  warnings: [],
};

const forgedPolicyConfig: SpendingPolicyConfig = {
  maxTransactionAmountNear: 5,
  dailySpendingLimitNear: 15,
  totalWalletSpendingCapNear: 50,
  perRecipientDailyLimitNear: 8,
  humanApprovalThresholdNear: 2,
  maxTxPerMinute: 4,
  allowedDestinations: ["vendor.testnet"],
  blockedDestinations: [],
  requireAllowlistForContracts: true,
  allowedContractMethods: ["execute_agent_payment", "add_key", "delete_key"],
  emergencyLockdown: false,
};

test("direct PolicyEngine invocation blocks add_key despite forged method allowlist", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");
  const result = engine.evaluate(
    { ...intent, contractMethod: "add_key" },
    spendingCheck,
    reputation,
    scamReport,
    forgedPolicyConfig
  );

  assert.equal(result.decision, "BLOCK");
  assert.equal(result.riskClassification, "CRITICAL");
  assert.ok(result.reasons.some((reason) => reason.includes("SANDBOX_METHOD_VIOLATION")));
  assert.equal(result.authorizationToken, undefined);
});

test("direct PolicyEngine invocation allows the fixed execute_agent_payment method", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");
  const result = engine.evaluate(
    { ...intent, contractMethod: "execute_agent_payment" },
    spendingCheck,
    reputation,
    scamReport,
    forgedPolicyConfig
  );

  assert.equal(result.decision, "ALLOW");
  assert.ok(result.authorizationToken);
});


test("authorization token issuance rejects add_key", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");

  assert.throws(
    () =>
      engine.issueAuthorizationToken(
        { ...intent, contractMethod: "add_key" },
        "HUMAN_OPERATOR"
      ),
    /UNAUTHORIZED_CONTRACT_METHOD/
  );
});

test("token reservation independently rejects an unauthorized expected method", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");
  const token = engine.issueAuthorizationToken(intent, "HUMAN_OPERATOR");

  const result = engine.reserveToken(
    token,
    intent.intentId,
    intent.recipientId,
    intent.amountYocto,
    "add_key"
  );

  assert.equal(result.valid, false);
  assert.match(result.reason ?? "", /UNAUTHORIZED_CONTRACT_METHOD/);
});

test("human operator can still issue a token for execute_agent_payment", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");

  const token = engine.issueAuthorizationToken(intent, "HUMAN_OPERATOR");

  assert.equal(token.contractMethod, "execute_agent_payment");

  const result = engine.reserveToken(
    token,
    intent.intentId,
    intent.recipientId,
    intent.amountYocto,
    "execute_agent_payment"
  );

  assert.equal(result.valid, true);
});

test("consumed authorization token is explicitly rejected as replay", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");
  const token = engine.issueAuthorizationToken(intent, "HUMAN_OPERATOR");

  const reserved = engine.reserveToken(
    token,
    intent.intentId,
    intent.recipientId,
    intent.amountYocto,
    "execute_agent_payment"
  );
  assert.equal(reserved.valid, true);

  const consumed = engine.consumeToken(token.tokenId);
  assert.equal(consumed.valid, true);

  const replay = engine.reserveToken(
    token,
    intent.intentId,
    intent.recipientId,
    intent.amountYocto,
    "execute_agent_payment"
  );

  assert.equal(replay.valid, false);
  assert.match(replay.reason ?? "", /REPLAY_BLOCKED/);
});

test("authorization token with forged HMAC signature is rejected", () => {
  const engine = new DeterministicPolicyEngine("policy-engine-test-secret");
  const token = engine.issueAuthorizationToken(intent, "HUMAN_OPERATOR");

  const forgedToken = {
    ...token,
    hmacSignature: "00",
  };

  const result = engine.reserveToken(
    forgedToken,
    intent.intentId,
    intent.recipientId,
    intent.amountYocto,
    "execute_agent_payment"
  );

  assert.equal(result.valid, false);
  assert.match(result.reason ?? "", /INVALID_HMAC_SIGNATURE/);
});
