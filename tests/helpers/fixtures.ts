import { AgentDependencies } from "../../src/agent/rimbuxAgent";
import {
  AccountInspectionResult,
  NearTestnetClient,
} from "../../src/near/nearClient";
import { SignedTransactionEnvelope } from "../../src/near/signingBoundary";

/**
 * Test-only HMAC secret for the tamper-evident audit logger.
 * Tests inject it explicitly so they behave identically on a developer
 * machine (which may have a local .env) and in CI (which does not).
 * It is a dummy value and must never be used outside automated tests.
 * The audit logger requires at least 64 characters.
 */
export const TEST_AUDIT_SECRET = "test-only-audit-secret-".repeat(3);

export type TestSigningBoundary = NonNullable<AgentDependencies["signingBoundary"]>;

export class MockNearTestnetClient extends NearTestnetClient {
  public override async inspectAccount(
    accountId: string
  ): Promise<AccountInspectionResult> {
    return {
      accountId,
      rpcReachable: true,
      exists: true,
      balanceNear: "100",
      storageUsage: 100,
      hasContract: false,
    };
  }
}

function testPublicMetadata() {
  return {
    publicKey: "ed25519:TEST_ONLY",
    permissionScope: "FunctionCall" as const,
    receiverContractId: "mock-vault.testnet",
    allowedMethods: ["execute_agent_payment"],
    gasAllowanceNear: 0.25,
    canTransferNativeNearDirectly: false as const,
    canDeployContracts: false as const,
    canModifyAccessKeys: false as const,
    revoked: false,
  };
}

/** Holds no key material; any attempt to sign fails loudly. */
export function createUnusedSigningBoundary(): TestSigningBoundary {
  return {
    async signAuthorizedVaultIntent() {
      throw new Error("TEST_ONLY: signing must not be reached in this test");
    },
    getPublicMetadata: testPublicMetadata,
    revokeKey() {},
  };
}

export function createFailingSigningBoundary(
  message = "TEST_SIGNING_FAILURE"
): TestSigningBoundary {
  return {
    async signAuthorizedVaultIntent() {
      throw new Error(message);
    },
    getPublicMetadata: testPublicMetadata,
    revokeKey() {},
  };
}

export function createDelayedSigningBoundary(delayMs = 50): {
  boundary: TestSigningBoundary;
  getCallCount: () => number;
} {
  let calls = 0;
  return {
    getCallCount: () => calls,
    boundary: {
      async signAuthorizedVaultIntent(intent) {
        calls++;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        const envelope: SignedTransactionEnvelope = {
          lifecycleStatus: "SIGNED",
          signerAccountId: "mock-agent.testnet",
          signerPublicKey: "ed25519:TEST_ONLY",
          receiverContractId: "mock-vault.testnet",
          methodName: intent.contractMethod || "execute_agent_payment",
          args: {
            recipientId: intent.recipientId,
            amountYocto: intent.amountYocto,
            intentNonce: intent.intentId,
          sequenceNonce: "1",
            purposeDigest: "test-only-purpose-digest",
          },
          gasTgas: 30,
          attachedDepositYocto: "0",
          unsignedPayloadDigest: "test-only-digest",
          ed25519SignatureBase64: "TEST_ONLY_MOCK_SIGNATURE",
          txHash: `TEST_ONLY_${intent.intentId}`,
          verificationNote: "TEST ONLY: mock signature, nothing broadcast.",
        };
        return envelope;
      },
      getPublicMetadata: testPublicMetadata,
      revokeKey() {},
    },
  };
}
