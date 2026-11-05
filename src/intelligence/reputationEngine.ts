// src/intelligence/reputationEngine.ts
import { ReputationAssessment, ReputationEvidenceItem } from "../types";
import { NearTestnetClient } from "../near/nearClient";

interface KnownEntityRecord {
  category: "VERIFIED_PROTOCOL" | "KNOWN_PARTNER" | "REPORTED_SCAM" | "SANCTIONED_DRAINER";
  reason: string;
  reportedAt: string;
  source: string;
}

const KNOWN_INTELLIGENCE_DB: Record<string, KnownEntityRecord> = {
  "wrap.testnet": {
    category: "VERIFIED_PROTOCOL",
    reason: "Official Wrapped NEAR (wNEAR) NEP-141 contract on NEAR Testnet.",
    reportedAt: "2025-01-10",
    source: "NEAR Ecosystem Verified Registry",
  },
  "ref-finance-101.testnet": {
    category: "VERIFIED_PROTOCOL",
    reason: "Verified Ref Finance DEX router contract on NEAR Testnet.",
    reportedAt: "2025-02-14",
    source: "NEAR Ecosystem Verified Registry",
  },
  "alice.testnet": {
    category: "KNOWN_PARTNER",
    reason: "Allowlisted contributor account with a verified payment history.",
    reportedAt: "2026-09-01",
    source: "Operator Treasury Counterparty Log",
  },
  "bob.testnet": {
    category: "KNOWN_PARTNER",
    reason: "Partner developer account with a safe transaction history.",
    reportedAt: "2026-09-12",
    source: "Operator Treasury Counterparty Log",
  },
  "drainer-vault.testnet": {
    category: "SANCTIONED_DRAINER",
    reason: "Confirmed drainer contract that steals wallet access authorization.",
    reportedAt: "2026-10-15",
    source: "NEAR Security Threat Feed #4812",
  },
  "phishing-airdrop.testnet": {
    category: "REPORTED_SCAM",
    reason: "Fake airdrop scam contract designed to trick users into signing transactions.",
    reportedAt: "2026-10-20",
    source: "Community Scam Alert Registry",
  },
  "attacker.testnet": {
    category: "SANCTIONED_DRAINER",
    reason: "Malicious destination address associated with prompt injection exploitation.",
    reportedAt: "2026-10-28",
    source: "RIMBUX Adversarial Threat Feed",
  },
};

export class ReputationIntelligenceEngine {
  private nearClient: NearTestnetClient;
  private simulateOfflineIntel: boolean = false;

  constructor(nearClient: NearTestnetClient) {
    this.nearClient = nearClient;
  }

  public setSimulateOfflineIntel(offline: boolean): void {
    this.simulateOfflineIntel = offline;
  }

  public async assessAccount(accountId: string): Promise<ReputationAssessment> {
    const normalizedId = accountId.trim().toLowerCase();
    const evidence: ReputationEvidenceItem[] = [];
    let score = 50; // Netral: Unknown != Malicious
    let confidence = 0.5;

    const validNearAccountRegex = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
    if (!validNearAccountRegex.test(normalizedId) || normalizedId.length < 2 || normalizedId.length > 64) {
      return {
        accountId: normalizedId,
        classification: "MALICIOUS",
        score: 0,
        confidence: 1.0,
        accountExistsOnChain: false,
        hasDeployedContract: false,
        rpcReachable: true,
        evidence: [
          {
            source: "BEHAVIORAL_HISTORY",
            indicator: "INVALID_NEAR_ACCOUNT_SYNTAX",
            detail: `Account format '${normalizedId}' violates NEAR Protocol account naming requirements.`,
            weight: -100,
          },
        ],
        summary: "Invalid NEAR account ID format.",
      };
    }

    if (this.simulateOfflineIntel) {
      evidence.push({
        source: "THREAT_INTEL_REGISTRY",
        indicator: "THREAT_INTEL_UNAVAILABLE",
        detail: "External threat intelligence service is unreachable. Switching to cautious fail-closed mode.",
        weight: -10,
      });
      return {
        accountId: normalizedId,
        classification: "NEUTRAL_UNKNOWN",
        score: 40,
        confidence: 0.25,
        accountExistsOnChain: null,
        hasDeployedContract: null,
        rpcReachable: false,
        evidence,
        summary:
          "Threat intelligence service is unavailable; fail-closed policy requires human approval before execution.",
      };
    }

    const intel = KNOWN_INTELLIGENCE_DB[normalizedId];
    if (intel) {
      if (intel.category === "SANCTIONED_DRAINER" || intel.category === "REPORTED_SCAM") {
        score -= 45;
        confidence = 0.95;
        evidence.push({
          source: "THREAT_INTEL_REGISTRY",
          indicator: intel.category,
          detail: `${intel.reason} (Source: ${intel.source}, Reported: ${intel.reportedAt})`,
          weight: -45,
        });
      } else if (intel.category === "VERIFIED_PROTOCOL" || intel.category === "KNOWN_PARTNER") {
        score += 35;
        confidence = 0.9;
        evidence.push({
          source: "THREAT_INTEL_REGISTRY",
          indicator: intel.category,
          detail: `${intel.reason} (Source: ${intel.source})`,
          weight: +35,
        });
      }
    } else {
      evidence.push({
        source: "THREAT_INTEL_REGISTRY",
        indicator: "NO_PRIOR_THREAT_REPORTS",
        detail: `No threat reports or verified partner records found for '${normalizedId}'.`,
        weight: 0,
      });
    }

    const onChainState = await this.nearClient.inspectAccount(normalizedId);
    let accountExistsOnChain: boolean | null = null;
    let hasDeployedContract: boolean | null = null;

    if (onChainState.rpcReachable) {
      accountExistsOnChain = onChainState.exists;
      hasDeployedContract = onChainState.hasContract;

      if (onChainState.exists) {
        score += 10;
        confidence = Math.min(1.0, confidence + 0.2);
        evidence.push({
          source: "NEAR_TESTNET_RPC",
          indicator: "ACCOUNT_EXISTS_ONCHAIN",
          detail: `Verified active account on NEAR Testnet (Balance: ${onChainState.balanceNear} NEAR, Storage: ${onChainState.storageUsage} bytes).`,
          weight: +10,
        });

        if (onChainState.hasContract) {
          evidence.push({
            source: "CONTRACT_INSPECTION",
            indicator: "SMART_CONTRACT_DEPLOYED",
            detail: `Account has deployed Wasm contract bytecode (code_hash: ${onChainState.codeHash?.slice(0, 12)}...).`,
            weight: intel?.category === "VERIFIED_PROTOCOL" ? +5 : -5,
          });
          if (!intel) {
            score -= 5;
          }
        }
      } else {
        score -= 10;
        confidence = Math.min(1.0, confidence + 0.15);
        evidence.push({
          source: "NEAR_TESTNET_RPC",
          indicator: "ACCOUNT_NOT_FOUND_ON_TESTNET",
          detail: `Account '${normalizedId}' is not registered in the NEAR Testnet RPC state.`,
          weight: -10,
        });
      }
    } else {
      evidence.push({
        source: "NEAR_TESTNET_RPC",
        indicator: "RPC_OFFLINE_FALLBACK",
        detail: "NEAR Testnet RPC did not respond during inspection; relying on the local threat registry.",
        weight: 0,
      });
    }

    score = Math.max(0, Math.min(100, score));

    let classification: ReputationAssessment["classification"] = "NEUTRAL_UNKNOWN";
    if (intel?.category === "SANCTIONED_DRAINER" || intel?.category === "REPORTED_SCAM" || score <= 20) {
      classification = "MALICIOUS";
    } else if (score < 40) {
      classification = "SUSPICIOUS";
    } else if (score >= 75) {
      classification = "TRUSTED";
    } else {
      classification = "NEUTRAL_UNKNOWN";
    }

    return {
      accountId: normalizedId,
      classification,
      score,
      confidence: Number(confidence.toFixed(2)),
      accountExistsOnChain,
      hasDeployedContract,
      rpcReachable: onChainState.rpcReachable,
      evidence,
      summary: `Account '${normalizedId}' is classified as ${classification} (Score: ${score}/100, Confidence: ${Math.round(
        confidence * 100
      )}%).`,
    };
  }
}