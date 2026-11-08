// src/intelligence/scamDetector.ts
import {
  ExplainableScamWarning,
  ExtractedTransactionIntent,
  ReputationAssessment,
  ScamDetectionReport,
  SpendingPolicyConfig,
} from "../types";

const PROTECTED_TARGETS = [
  "wrap.testnet",
  "ref-finance-101.testnet",
  "alice.testnet",
  "bob.testnet",
  "near.testnet",
  "rimbux-vault.testnet",
];

function levenshteinDistance(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}


function normalizeSecurityText(value: string): string {
  const confusables: Record<string, string> = {
    "і": "i", "а": "a", "е": "e", "о": "o",
    "р": "p", "с": "c", "х": "x", "у": "y",
    "к": "k", "м": "m", "т": "t", "в": "b",
    "н": "h",
  };

  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF]/g, " ")
    .replace(/\\u(?:200B|200C|200D|FEFF)/gi, " ")
    .replace(/[іаеорсхуктмн]/g, (char) => confusables[char] ?? char)
    .replace(/(?<=\p{L})[._-]+(?=\p{L})/gu, "");
}

export class ScamDetectionEngine {
  public analyze(
    intent: ExtractedTransactionIntent,
    reputation: ReputationAssessment,
    policyConfig: SpendingPolicyConfig
  ): ScamDetectionReport {
    const warnings: ExplainableScamWarning[] = [];
    let promptInjectionDetected = false;
    let policyBypassAttemptDetected = false;
    let paramSmugglingDetected = false;

    const rawLower = intent.rawInstruction.toLowerCase();
    const normalizedInstruction = normalizeSecurityText(intent.rawInstruction);

    const transferAmounts = intent.rawInstruction.match(/\b\d+(?:\.\d+)?\s*NEAR\b/gi) ?? [];
    const recipientMentions = intent.rawInstruction.match(
      // NOTE: "ke" is Indonesian for "to"; keeps recipient parsing working for Indonesian instructions.
      /\b(?:to|ke|into|recipient|account)\s+[a-z0-9_-]+(?:\.[a-z0-9_-]+)+/gi
    ) ?? [];

    if (transferAmounts.length > 1 || recipientMentions.length > 1) {
      paramSmugglingDetected = true;
      warnings.push({
        ruleId: "SCAM-PARAM-008",
        severity: "CRITICAL",
        whatWasDetected: "Multiple transfer parameters in one instruction",
        whySuspicious:
          "The instruction contains multiple transfer amounts or recipient clauses. Processing only the first match could silently omit or misrepresent part of the requested payment.",
        supportingEvidence: [
          `Transfer amount mentions detected: ${transferAmounts.length}.`,
          `Recipient clauses detected: ${recipientMentions.length}.`,
        ],
        confidenceAndUncertainty: {
          confidenceScore: 0.99,
          uncertaintyNotes: "Fail-closed parsing rule. Multiple transfer parameters require separate, explicit instructions.",
        },
        recommendedAction: "IMMEDIATE_BLOCK",
      });
    }

    const injectionPatterns: Array<{ pattern: RegExp; label: string }> = [
      { pattern: /ignore\s+(all\s+)?(previous|prior|system)\s+(instructions|rules|policies)/i, label: "Instruction Override Directive" },
      { pattern: /(system\s*override|admin\s*mode|developer\s*mode|sudo\s+allow)/i, label: "Fake System Privilege Escalation" },
      { pattern: /<\s*(system|admin|policy_override)\s*>/i, label: "Injected Control Tag Spoofing" },
      { pattern: /do\s+not\s+(check|verify|inspect)\s+(the\s+)?(reputation|policy|spending\s+limits|daily\s+limits|limits)/i, label: "Security Gate Suppression Request" },
      { pattern: /abaikan\s+(semua\s+)?(instruksi|aturan|kebijakan)\s+(sebelumnya|terdahulu)/i, label: "Indonesian Instruction Override" },
      // NOTE: Indonesian "jangan periksa/cek/verifikasi ..." = "do not check/verify ..."; detects injections that tell the agent to skip security checks.
      { pattern: /jangan\s+(periksa|cek|verifikasi)\s+(batas|limit|kebijakan|keamanan|aturan)/i, label: "Indonesian Security Gate Suppression" },
    ];

    const matchedInjections = injectionPatterns
      .filter((p) => p.pattern.test(normalizedInstruction))
      .map((p) => p.label);

    if (matchedInjections.length > 0) {
      promptInjectionDetected = true;
      warnings.push({
        ruleId: "SCAM-INJ-001",
        severity: "CRITICAL",
        whatWasDetected: "Adversarial prompt injection attempt in financial instructions",
        whySuspicious:
          "The instruction contains meta-control directives attempting to hijack agent reasoning or disable security checks.",
        supportingEvidence: matchedInjections.map(
          (m) => `Matches injection pattern: '${m}' within the instruction text.`
        ),
        confidenceAndUncertainty: {
          confidenceScore: 0.98,
          uncertaintyNotes: "Deterministic matching against system instruction hijacking phrases.",
        },
        recommendedAction: "IMMEDIATE_BLOCK",
      });
    }

    const bypassPatterns: Array<{ pattern: RegExp; label: string }> = [
      { pattern: /(set|change|increase|disable)\s+(daily\s+|max\s+|spending\s+)?limit/i, label: "Unauthorized Limit Mutation Attempt" },
      { pattern: /bypass\s+(approval|human|policy|sandbox|vault)/i, label: "Explicit Policy Bypass Request" },
      { pattern: /(export|print|reveal|dump)\s+(the\s+)?(private\s*key|secret\s*key|seed\s*phrase)/i, label: "Private Key Exfiltration Attempt" },
      { pattern: /(ungkapkan|tampilkan|cetak|ekspor|bocorkan)\s+(kunci\s+privat|kunci\s+rahasia|frasa\s+pemulihan|private\s+key|seed\s+phrase)/i, label: "Indonesian Private Key Exfiltration Attempt" },
    ];

    const matchedBypasses = bypassPatterns
      .filter((p) => p.pattern.test(normalizedInstruction))
      .map((p) => p.label);

    if (matchedBypasses.length > 0) {
      policyBypassAttemptDetected = true;
      warnings.push({
        ruleId: "SCAM-BYP-002",
        severity: "CRITICAL",
        whatWasDetected: "Wallet Policy Bypass or Private Key Exfiltration Attempt",
        whySuspicious:
          "AI agents are strictly prohibited from changing their own spending limits, bypassing approval gates, or accessing raw private keys.",
        supportingEvidence: matchedBypasses.map((m) => `Detected forbidden command pattern: '${m}'.`),
        confidenceAndUncertainty: {
          confidenceScore: 0.99,
          uncertaintyNotes: "High confidence; agent-initiated policy modification is prohibited by the architecture.",
        },
        recommendedAction: "IMMEDIATE_BLOCK",
      });
    }

    const recipient = intent.recipientId.toLowerCase();
    for (const target of PROTECTED_TARGETS) {
      if (recipient !== target) {
        const dist = levenshteinDistance(recipient, target);
        if (dist > 0 && dist <= 2) {
          warnings.push({
            ruleId: "SCAM-IMP-003",
            severity: "HIGH",
            whatWasDetected: `Lookalike Account Impersonation / Typosquatting ('${recipient}' resembles '${target}')`,
            whySuspicious:
              "An attacker registers a NEAR account differing by 1–2 characters (homoglyph/typosquat) to intercept funds intended for an official partner.",
            supportingEvidence: [
              `Destination '${recipient}' has a Levenshtein edit distance of ${dist} from protected account '${target}'.`,
              `Status allowlist: ${policyConfig.allowedDestinations.includes(recipient) ? "Listed" : "NOT Listed"}.`,
            ],
            confidenceAndUncertainty: {
              confidenceScore: 0.88,
              uncertaintyNotes:
                "A character distance of <= 2 from a trusted account requires automatic blocking to prevent misdirected transfers.",
            },
            recommendedAction: "IMMEDIATE_BLOCK",
          });
        }
      }
    }

    const forbiddenMethods = [
      "addkey",
      "add_key",
      "deleteaccount",
      "delete_account",
      "deploycontract",
      "deploy_contract",
      "set_pause",
      "init",
    ];
    if (
      intent.actionType === "RAW_ACTION_ATTEMPT" ||
      (intent.contractMethod && forbiddenMethods.includes(intent.contractMethod.toLowerCase()))
    ) {
      warnings.push({
        ruleId: "SCAM-PRIV-004",
        severity: "CRITICAL",
        whatWasDetected: `Forbidden Contract/Account Method Invocation ('${intent.contractMethod || intent.actionType}')`,
        whySuspicious:
          "Calling key management, contract deployment, or vault administration functions from an AI agent could permanently compromise wallet ownership.",
        supportingEvidence: [
          `Requested method: '${intent.contractMethod || intent.actionType}'.`,
          `Allowed sandbox methods: [${policyConfig.allowedContractMethods.join(", ")}].`,
        ],
        confidenceAndUncertainty: {
          confidenceScore: 1.0,
          uncertaintyNotes: "Deterministic protocol boundary check.",
        },
        recommendedAction: "IMMEDIATE_BLOCK",
      });
    }

    if (reputation.classification === "MALICIOUS") {
      warnings.push({
        ruleId: "SCAM-REP-005",
        severity: "CRITICAL",
        whatWasDetected: `Confirmed Malicious Destination Address ('${intent.recipientId}')`,
        whySuspicious:
          "The destination account is flagged as malicious in the threat intelligence database or failed protocol validation.",
        supportingEvidence: reputation.evidence.map((e) => `[${e.source}] ${e.indicator}: ${e.detail}`),
        confidenceAndUncertainty: {
          confidenceScore: reputation.confidence,
          uncertaintyNotes: "Based on verified evidence from threat registries and RPC inspection.",
        },
        recommendedAction: "IMMEDIATE_BLOCK",
      });
    }

    const threshold = policyConfig.humanApprovalThresholdNear;
    if (intent.amountNear >= threshold * 0.9 && intent.amountNear < threshold) {
      warnings.push({
        ruleId: "SCAM-STR-006",
        severity: "WARNING",
        whatWasDetected: "Potential Structuring / Smurfing Below Approval Threshold",
        whySuspicious: `Amount (${intent.amountNear} NEAR) is within 90%–99.9% of the human approval threshold (${threshold} NEAR), a common pattern used to avoid manual review.`,
        supportingEvidence: [
          `Requested amount: ${intent.amountNear} NEAR.`,
          `Human approval threshold: ${threshold} NEAR.`,
        ],
        confidenceAndUncertainty: {
          confidenceScore: 0.72,
          uncertaintyNotes: "This may be a legitimate transaction, so it is escalated for human approval rather than permanently blocked.",
        },
        recommendedAction: "REQUIRE_HUMAN_REVIEW",
      });
    }

    if (/(urgent|immediately|double\s+your\s+near|airdrop\s+claim|verify\s+wallet\s+now)/i.test(rawLower)) {
      warnings.push({
        ruleId: "SCAM-SOC-007",
        severity: "HIGH",
        whatWasDetected: "Social Engineering / False Urgency Language",
        whySuspicious:
          "Fraudulent payment requests often use artificial time pressure or promises of asset doubling.",
        supportingEvidence: [`Urgency or social engineering phrases detected in the instruction: "${intent.rawInstruction}".`],
        confidenceAndUncertainty: {
          confidenceScore: 0.82,
          uncertaintyNotes: "Linguistic heuristic indicator.",
        },
        recommendedAction: "REQUIRE_HUMAN_REVIEW",
      });
    }

    const severityOrder: Record<ScamDetectionReport["highestSeverity"], number> = {
      NONE: 0,
      INFO: 1,
      WARNING: 2,
      HIGH: 3,
      CRITICAL: 4,
    };

    let highestSeverity: ScamDetectionReport["highestSeverity"] = "NONE";
    for (const w of warnings) {
      if (severityOrder[w.severity] > severityOrder[highestSeverity]) {
        highestSeverity = w.severity;
      }
    }

    return {
      triggered: warnings.length > 0,
      highestSeverity,
      promptInjectionDetected,
      policyBypassAttemptDetected,
      paramSmugglingDetected,
      warnings,
    };
  }
}