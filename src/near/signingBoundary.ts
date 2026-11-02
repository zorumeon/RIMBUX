import crypto from "crypto";
import { JsonRpcProvider, Provider } from "@near-js/providers";
import { InMemorySigner, KeyPair, transactions, utils } from "near-api-js";
import {
  ExtractedTransactionIntent,
  PolicyAuthorizationToken,
  TransactionLifecycleStatus,
} from "../types";
import { DeterministicPolicyEngine } from "../security/policyEngine";

const GAS = BigInt("30000000000000");
const ZERO_DEPOSIT = BigInt(0);

export function assertSufficientFunctionCallAllowance(
  allowance: unknown,
  gasPrice: unknown
): void {
  if (typeof allowance !== "string" || !/^[0-9]+$/.test(allowance)) {
    throw new Error("ACCESS_KEY_ALLOWANCE_UNAVAILABLE");
  }

  if (typeof gasPrice !== "string" || !/^[0-9]+$/.test(gasPrice)) {
    throw new Error("GAS_PRICE_UNAVAILABLE");
  }

  const requiredAllowance = GAS * BigInt(gasPrice);
  const availableAllowance = BigInt(allowance);

  if (availableAllowance < requiredAllowance) {
    throw new Error("INSUFFICIENT_ACCESS_KEY_ALLOWANCE");
  }
}

export interface SandboxKeyMetadata {
  publicKey: string;
  permissionScope: "FunctionCall";
  receiverContractId: string;
  allowedMethods: string[];
  gasAllowanceNear: number;
  canTransferNativeNearDirectly: false;
  canDeployContracts: false;
  canModifyAccessKeys: false;
  revoked: boolean;
}

export interface SignedTransactionEnvelope {
  lifecycleStatus: TransactionLifecycleStatus;
  signerAccountId: string;
  signerPublicKey: string;
  receiverContractId: string;
  methodName: string;
  args: {
    recipientId: string;
    amountYocto: string;
    intentNonce: string;
    purposeDigest: string;
  };
  gasTgas: number;
  attachedDepositYocto: "0";
  unsignedPayloadDigest: string;
  ed25519SignatureBase64: string;
  txHash: string;
  explorerUrl?: string;
  verificationNote: string;
}

export class SandboxedSigningBoundary {
  private readonly keyPair: KeyPair;
  private readonly provider: Pick<Provider, "query" | "block"> & {
    gasPrice: (blockId: any) => ReturnType<Provider["gasPrice"]>;
  };
  private revoked = false;
  private readonly agentAccountId: string;
  private readonly vaultContractId: string;
  private readonly networkId: string;
  private readonly broadcastEnabled: boolean;
  private readonly allowedMethods = ["execute_agent_payment"];
  private readonly gasAllowanceNear = 0.25;
  private signingQueue: Promise<void> = Promise.resolve();

  constructor(
    agentAccountId: string,
    vaultContractId: string,
    privateKeyEnv?: string,
    provider?: Pick<Provider, "query" | "block"> & {
      gasPrice: (blockId: any) => ReturnType<Provider["gasPrice"]>;
    },
    broadcastEnabled = process.env.RIMBUX_BROADCAST === "true"
  ) {
    if (!privateKeyEnv || !privateKeyEnv.startsWith("ed25519:")) {
      throw new Error("SIGNING_KEY_MISSING: A valid NEAR FunctionCall private key is required.");
    }

    if (!agentAccountId || !vaultContractId || agentAccountId !== vaultContractId) {
      throw new Error("SIGNING_CONFIGURATION_INVALID: The FunctionCall key account must match the vault contract account.");
    }

    this.agentAccountId = agentAccountId;
    this.vaultContractId = vaultContractId;
    this.networkId = process.env.NEAR_NETWORK_ID || "testnet";
    this.broadcastEnabled = broadcastEnabled;
    this.keyPair = KeyPair.fromString(privateKeyEnv as any);
    this.provider = provider || new JsonRpcProvider({
      url: process.env.NEAR_RPC_URL || "https://rpc.testnet.near.org",
    });
  }

  public getPublicMetadata(): SandboxKeyMetadata {
    return {
      publicKey: this.keyPair.getPublicKey().toString(),
      permissionScope: "FunctionCall",
      receiverContractId: this.vaultContractId,
      allowedMethods: [...this.allowedMethods],
      gasAllowanceNear: this.gasAllowanceNear,
      canTransferNativeNearDirectly: false,
      canDeployContracts: false,
      canModifyAccessKeys: false,
      revoked: this.revoked,
    };
  }

  public revokeKey(): void {
    this.revoked = true;
  }

  public async signAuthorizedVaultIntent(
    intent: ExtractedTransactionIntent,
    authToken: PolicyAuthorizationToken | undefined,
    policyEngine: DeterministicPolicyEngine
  ): Promise<SignedTransactionEnvelope> {
    let release!: () => void;
    const previous = this.signingQueue;

    this.signingQueue = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous;

    try {
      return await this.signAuthorizedVaultIntentInternal(
        intent,
        authToken,
        policyEngine
      );
    } finally {
      release();
    }
  }

  private async signAuthorizedVaultIntentInternal(
    intent: ExtractedTransactionIntent,
    authToken: PolicyAuthorizationToken | undefined,
    policyEngine: DeterministicPolicyEngine
  ): Promise<SignedTransactionEnvelope> {
    if (this.revoked) {
      throw new Error("SANDBOX_KEY_REVOKED: The FunctionCall access key has been revoked locally.");
    }

    const methodName = intent.contractMethod || "execute_agent_payment";

    if (!this.allowedMethods.includes(methodName)) {
      throw new Error(`SANDBOX_BOUNDARY_VIOLATION: Method '${methodName}' is not permitted.`);
    }

    if (
      intent.actionType !== "VAULT_TRANSFER" ||
      !intent.recipientId ||
      intent.recipientId === "unknown.testnet" ||
      !/^[0-9]+$/.test(intent.amountYocto) ||
      BigInt(intent.amountYocto) <= ZERO_DEPOSIT
    ) {
      throw new Error("INVALID_TRANSACTION_INTENT: The transfer intent is incomplete or invalid.");
    }

    const tokenReservation = policyEngine.reserveToken(
      authToken,
      intent.intentId,
      intent.recipientId,
      intent.amountYocto,
      methodName
    );

    if (!tokenReservation.valid || !authToken) {
      throw new Error(`UNAUTHORIZED_SIGNING_ATTEMPT: ${tokenReservation.reason}`);
    }

    try {
      const publicKey = this.keyPair.getPublicKey().toString();

      const accessKey = await this.provider.query({
        request_type: "view_access_key",
        finality: "final",
        account_id: this.agentAccountId,
        public_key: publicKey,
      }) as any;

      const permission = accessKey.permission?.FunctionCall;

      if (
        !permission ||
        permission.receiver_id !== this.vaultContractId ||
        !Array.isArray(permission.method_names) ||
        !permission.method_names.includes(methodName)
      ) {
        throw new Error("ACCESS_KEY_PERMISSION_MISMATCH: The on-chain key is not authorized for this vault method.");
      }

      const gasPrice = await this.provider.gasPrice(null);
      assertSufficientFunctionCallAllowance(
        permission.allowance,
        gasPrice.gas_price
      );

      const block = await this.provider.block({ finality: "final" });
      const nonce = BigInt(accessKey.nonce) + BigInt(1);
      const blockHash = utils.serialize.base_decode(block.header.hash);

      const purposeDigest = crypto
        .createHash("sha256")
        .update(intent.rawInstruction, "utf8")
        .digest("hex");

      const args = {
        recipientId: intent.recipientId,
        amountYocto: intent.amountYocto,
        intentNonce: intent.intentId,
        purposeDigest,
      };

      const signer = await InMemorySigner.fromKeyPair(
        this.networkId,
        this.agentAccountId,
        this.keyPair
      );

      const action = transactions.functionCall(
        methodName,
        args,
        GAS,
        ZERO_DEPOSIT
      );

      const [transactionHash, signedTransaction] =
        await transactions.signTransaction(
          this.vaultContractId,
          nonce,
          [action],
          blockHash,
          signer,
          this.agentAccountId,
          this.networkId
        );

      const consumption = policyEngine.consumeToken(authToken.tokenId);
      if (!consumption.valid) {
        throw new Error(`AUTHORIZATION_CONSUMPTION_FAILED: ${consumption.reason}`);
      }

      const unsignedPayloadDigest = Buffer
        .from(transactionHash)
        .toString("hex");

      const txHash = utils.serialize.base_encode(transactionHash);

      return {
        lifecycleStatus: "SIGNED",
        signerAccountId: this.agentAccountId,
        signerPublicKey: publicKey,
        receiverContractId: this.vaultContractId,
        methodName,
        args,
        gasTgas: 30,
        attachedDepositYocto: "0",
        unsignedPayloadDigest,
        ed25519SignatureBase64: Buffer.from(
          signedTransaction.signature.data
        ).toString("base64"),
        txHash,
        explorerUrl: `https://testnet.nearblocks.io/txns/${txHash}`,
        verificationNote:
          "A valid NEAR Testnet transaction was signed locally. It has not been broadcast and no funds have been transferred.",
      };
    } catch (error) {
      policyEngine.releaseToken(authToken.tokenId);
      throw error;
    }
  }
}
