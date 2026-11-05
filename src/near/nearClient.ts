// src/near/nearClient.ts
import { utils } from "near-api-js";

export interface AccountInspectionResult {
  accountId: string;
  rpcReachable: boolean;
  exists: boolean;
  balanceNear: string;
  storageUsage: number;
  hasContract: boolean;
  codeHash?: string;
}

export class NearTestnetClient {
  public readonly rpcUrl: string;
  public readonly networkId: string;
  public readonly vaultContractId: string;
  public readonly agentAccountId: string;

  constructor() {
    this.networkId = process.env.NEAR_NETWORK_ID || "testnet";
    this.rpcUrl = process.env.NEAR_RPC_URL || "https://rpc.testnet.near.org";
    this.vaultContractId = process.env.NEAR_VAULT_CONTRACT_ID || "vault.rimbux.testnet";
    this.agentAccountId = process.env.NEAR_AGENT_ACCOUNT_ID || "agent.rimbux.testnet";
  }

  public static nearToYocto(amountNear: number): string {
    const clean = amountNear.toFixed(6);
    return utils.format.parseNearAmount(clean) || "0";
  }

  public static yoctoToNear(yocto: string): string {
    return utils.format.formatNearAmount(yocto, 4);
  }

  public async inspectAccount(accountId: string): Promise<AccountInspectionResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    try {
      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "rimbux-inspect",
          method: "query",
          params: {
            request_type: "view_account",
            finality: "final",
            account_id: accountId,
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
      const data = (await response.json()) as any;

      if (data.error) {
        return {
          accountId,
          rpcReachable: true,
          exists: false,
          balanceNear: "0",
          storageUsage: 0,
          hasContract: false,
        };
      }

      const result = data.result;
      const emptyCodeHash = "11111111111111111111111111111111";
      return {
        accountId,
        rpcReachable: true,
        exists: true,
        balanceNear: NearTestnetClient.yoctoToNear(result.amount),
        storageUsage: result.storage_usage,
        hasContract: Boolean(result.code_hash && result.code_hash !== emptyCodeHash),
        codeHash: result.code_hash,
      };
    } catch {
      clearTimeout(timeout);
      return {
        accountId,
        rpcReachable: false,
        exists: false,
        balanceNear: "0",
        storageUsage: 0,
        hasContract: false,
      };
    }
  }

  public async inspectAccessKeyPermissions(
    accountId: string,
    publicKey: string
  ): Promise<{
    verifiedOnChain: boolean;
    verificationStatus: "VERIFIED" | "NOT_FOUND" | "PERMISSION_MISMATCH" | "RPC_UNAVAILABLE";
    rpcReachable: boolean;
    permissionType: "FunctionCall" | "FullAccess" | "NotFound" | "Unknown";
    receiverId: string | null;
    methodNames: string[];
    allowanceNear: string | null;
    error?: string;
  }> {
    try {
      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "rimbux-key-check",
          method: "query",
          params: {
            request_type: "view_access_key",
            finality: "final",
            account_id: accountId,
            public_key: publicKey,
          },
        }),
      });

      if (!response.ok) {
        return {
          verifiedOnChain: false,
          verificationStatus: "RPC_UNAVAILABLE",
          rpcReachable: false,
          permissionType: "Unknown",
          receiverId: null,
          methodNames: [],
          allowanceNear: null,
          error: `RPC_HTTP_${response.status}`,
        };
      }

      const data = (await response.json()) as any;

      if (data.error) {
        const message = String(data.error.message || "NEAR_RPC_ERROR");
        if (/does not exist|not found|unknown access key/i.test(message)) {
          return {
            verifiedOnChain: false,
            verificationStatus: "NOT_FOUND",
            rpcReachable: true,
            permissionType: "NotFound",
            receiverId: null,
            methodNames: [],
            allowanceNear: null,
            error: message,
          };
        }

        return {
          verifiedOnChain: false,
          verificationStatus: "RPC_UNAVAILABLE",
          rpcReachable: true,
          permissionType: "Unknown",
          receiverId: null,
          methodNames: [],
          allowanceNear: null,
          error: message,
        };
      }

      const permission = data.result?.permission;

      if (permission?.FullAccess !== undefined) {
        return {
          verifiedOnChain: false,
          verificationStatus: "PERMISSION_MISMATCH",
          rpcReachable: true,
          permissionType: "FullAccess",
          receiverId: null,
          methodNames: [],
          allowanceNear: null,
          error: "ACCESS_KEY_IS_FULL_ACCESS",
        };
      }

      const fc = permission?.FunctionCall;
      if (!fc) {
        return {
          verifiedOnChain: false,
          verificationStatus: "PERMISSION_MISMATCH",
          rpcReachable: true,
          permissionType: "Unknown",
          receiverId: null,
          methodNames: [],
          allowanceNear: null,
          error: "ACCESS_KEY_PERMISSION_UNKNOWN",
        };
      }

      const methods = Array.isArray(fc.method_names) ? fc.method_names : [];
      const receiverMatches = fc.receiver_id === this.vaultContractId;
      const methodsMatch =
        methods.length === 1 && methods[0] === "execute_agent_payment";

      const verified = receiverMatches && methodsMatch;

      return {
        verifiedOnChain: verified,
        verificationStatus: verified ? "VERIFIED" : "PERMISSION_MISMATCH",
        rpcReachable: true,
        permissionType: "FunctionCall",
        receiverId: String(fc.receiver_id || ""),
        methodNames: methods,
        allowanceNear: fc.allowance
          ? NearTestnetClient.yoctoToNear(fc.allowance)
          : "Unlimited Gas",
        ...(verified ? {} : { error: "ACCESS_KEY_SCOPE_MISMATCH" }),
      };
    } catch (error: any) {
      return {
        verifiedOnChain: false,
        verificationStatus: "RPC_UNAVAILABLE",
        rpcReachable: false,
        permissionType: "Unknown",
        receiverId: null,
        methodNames: [],
        allowanceNear: null,
        error: String(error?.message || "RPC_REQUEST_FAILED"),
      };
    }
  }

  public async inspectLatestBlock(): Promise<{
    height: number;
    hash: string;
  }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "rimbux-live-block",
          method: "block",
          params: { finality: "final" },
        }),
        signal: controller.signal,
      });

      if (!response.ok) throw new Error(`NEAR RPC HTTP ${response.status}`);

      const data = await response.json() as any;
      if (data.error || !data.result?.header) {
        throw new Error("NEAR RPC block query failed.");
      }

      return {
        height: data.result.header.height,
        hash: data.result.header.hash,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  public async verifyTransactionStatus(txHash: string, senderAccountId: string): Promise<{
    confirmed: boolean;
    statusSummary: string;
  }> {
    try {
      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "rimbux-tx-status",
          method: "tx",
          params: [txHash, senderAccountId],
        }),
      });
      const data = (await response.json()) as any;
      if (data.result && data.result.status && "SuccessValue" in data.result.status) {
        return {
          confirmed: true,
          statusSummary: "CONFIRMED_ONCHAIN: Transaction execution verified on a NEAR Testnet block.",
        };
      }
      return {
        confirmed: false,
        statusSummary: "Transaction not found or failed on the NEAR Testnet RPC.",
      };
    } catch {
      return {
        confirmed: false,
        statusSummary: "Unable to reach the NEAR Testnet RPC to verify transaction status.",
      };
    }
  }
}