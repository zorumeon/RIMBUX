import assert from "node:assert/strict";
import test from "node:test";
import {
  AgentDependencies,
  RimbuxAutonomousAgent,
} from "../src/agent/rimbuxAgent";
import { NearTestnetClient } from "../src/near/nearClient";

test("multiple transfer parameters are blocked before reputation, reservation, and signing", async () => {
  let reputationCalls = 0;
  let reservationCalls = 0;
  let signingCalls = 0;

  const agent = new RimbuxAutonomousAgent({
    nearClient: new NearTestnetClient(),
    signingBoundary: {
      async signAuthorizedVaultIntent() {
        signingCalls++;
        throw new Error("Signing must not be reached");
      },
      getPublicMetadata() {
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
      },
      revokeKey() {},
    } satisfies NonNullable<AgentDependencies["signingBoundary"]>,
  });

  const originalAssess = agent.reputationEngine.assessAccount.bind(
    agent.reputationEngine
  );
  agent.reputationEngine.assessAccount = async (...args) => {
    reputationCalls++;
    return originalAssess(...args);
  };

  const originalReserve = agent.spendingController.evaluateAndReserve.bind(
    agent.spendingController
  );
  agent.spendingController.evaluateAndReserve = async (...args) => {
    reservationCalls++;
    return originalReserve(...args);
  };

  const prompt =
    "Send 1.0 NEAR to alice.testnet and 2.0 NEAR to attacker.testnet";

  const result = await agent.processInstruction(prompt);

  assert.equal(result.evaluation.decision, "BLOCK");
  assert.equal(result.transactionRecord.status, "BLOCKED_BY_POLICY");
  assert.equal(result.evaluation.scamReport.paramSmugglingDetected, true);
  assert.ok(
    result.evaluation.scamReport.warnings.some(
      (warning) => warning.ruleId === "SCAM-PARAM-008"
    ),
    "SCAM-PARAM-008 warning must be present"
  );

  assert.equal(reputationCalls, 0, "Reputation lookup must not run");
  assert.equal(reservationCalls, 0, "Spending reservation must not run");
  assert.equal(signingCalls, 0, "Signing must not run");
});
