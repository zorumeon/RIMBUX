// contracts/rimbux-vault/src/contract.ts
import { NearBindgen, near, call, view, initialize, NearPromise, UnorderedMap } from "near-sdk-js";
import { PublicKey } from "near-sdk-js/lib/types/public_key.js";

const YOCTO_PER_NEAR = BigInt("1000000000000000000000000");
const DAY_NS = BigInt(24 * 60 * 60) * BigInt("1000000000");
const CALLBACK_GAS = BigInt("30000000000000");

function panic(message: string): never {
  near.panicUtf8(new TextEncoder().encode(message));
}

@NearBindgen({ requireInit: true })
export class RimbuxVaultContract {
  ownerId: string = "";
  authorizedAgentKey: string = "";
  paused: boolean = false;

  maxPerTxYocto: string = (BigInt(5) * YOCTO_PER_NEAR).toString();
  dailyLimitYocto: string = (BigInt(15) * YOCTO_PER_NEAR).toString();
  currentDaySpendYocto: string = "0";
  dayWindowStartNs: string = "0";

  allowedRecipients: UnorderedMap<boolean> = new UnorderedMap<boolean>("a");
  blockedRecipients: UnorderedMap<boolean> = new UnorderedMap<boolean>("b");
  usedNonces: UnorderedMap<boolean> = new UnorderedMap<boolean>("n");
  paymentStatuses: UnorderedMap<string> = new UnorderedMap<string>("p");

  @initialize({ privateFunction: true })
  init({
    ownerId,
    authorizedAgentKey,
    maxPerTxNear,
    dailyLimitNear,
  }: {
    ownerId: string;
    authorizedAgentKey: string;
    maxPerTxNear: number;
    dailyLimitNear: number;
  }) {
    const validAccountId =
      typeof ownerId === "string" &&
      ownerId.length >= 2 &&
      ownerId.length <= 64 &&
      /^([a-z0-9]+([-_][a-z0-9]+)*)(\.([a-z0-9]+([-_][a-z0-9]+)*))*$/.test(ownerId);

    if (!validAccountId) {
      panic("RIMBUX_VAULT: Invalid owner account ID.");
    }

    if (typeof authorizedAgentKey !== "string" || !authorizedAgentKey) {
      panic("RIMBUX_VAULT: Agent public key is required.");
    }

    try {
      PublicKey.fromString(authorizedAgentKey);
    } catch {
      panic("RIMBUX_VAULT: Invalid agent public key.");
    }

    const toScaledAmount = (value: number, label: string): bigint => {
      if (!Number.isFinite(value) || value <= 0) {
        panic(`RIMBUX_VAULT: ${label} must be a positive finite NEAR amount.`);
      }

      const scaled = Math.round(value * 1000);

      if (
        !Number.isSafeInteger(scaled) ||
        Math.abs(value * 1000 - scaled) > 1e-8
      ) {
        panic(`RIMBUX_VAULT: ${label} supports at most 3 decimal places.`);
      }

      return (BigInt(scaled) * YOCTO_PER_NEAR) / BigInt(1000);
    };

    const maxPerTx = toScaledAmount(maxPerTxNear, "Maximum per transaction");
    const dailyLimit = toScaledAmount(dailyLimitNear, "Daily limit");

    if (maxPerTx > dailyLimit) {
      panic("RIMBUX_VAULT: Per-transaction limit cannot exceed daily limit.");
    }

    this.ownerId = ownerId;
    this.authorizedAgentKey = authorizedAgentKey;
    this.maxPerTxYocto = maxPerTx.toString();
    this.dailyLimitYocto = dailyLimit.toString();
    this.dayWindowStartNs = near.blockTimestamp().toString();
  }

  private assertOwner() {
    if (near.predecessorAccountId() !== this.ownerId) {
      panic("RIMBUX_VAULT: Only the human owner is authorized to modify security parameters.");
    }
  }

  @call({})
  set_pause({ paused }: { paused: boolean }) {
    this.assertOwner();
    this.paused = paused;
  }

  @call({})
  update_authorized_agent_key({ newPublicKey }: { newPublicKey: string }) {
    this.assertOwner();

    if (typeof newPublicKey !== "string" || !newPublicKey) {
      panic("RIMBUX_VAULT: A new agent public key is required.");
    }

    try {
      PublicKey.fromString(newPublicKey);
    } catch {
      panic("RIMBUX_VAULT: Invalid agent public key.");
    }

    this.authorizedAgentKey = newPublicKey;

    near.log(JSON.stringify({
      event: "RIMBUX_AUTHORIZED_AGENT_KEY_UPDATED",
      publicKey: newPublicKey
    }));
  }

  @call({})
  update_recipient_policy({ accountId, allowed, blocked }: { accountId: string; allowed: boolean; blocked: boolean }) {
    this.assertOwner();
    this.allowedRecipients.set(accountId, allowed);
    this.blockedRecipients.set(accountId, blocked);
  }

  @call({})
  execute_agent_payment({
    recipientId,
    amountYocto,
    intentNonce,
    purposeDigest,
  }: {
    recipientId: string;
    amountYocto: string;
    intentNonce: string;
    purposeDigest: string;
  }): NearPromise {
    if (this.paused) {
      panic("RIMBUX_VAULT: Vault is currently paused under emergency lockdown.");
    }

    if (!this.authorizedAgentKey) {
      panic("RIMBUX_VAULT: Missing authorized agent FunctionCall key.");
    }

    const signerPk = near.signerAccountPk();
    const authorizedPk = PublicKey.fromString(this.authorizedAgentKey).data;
    const signerMatches =
      signerPk.length === authorizedPk.length &&
      signerPk.every((byte, index) => byte === authorizedPk[index]);

    if (!signerMatches) {
      panic("RIMBUX_VAULT: Unauthorized agent FunctionCall key.");
    }

    if (
      typeof recipientId !== "string" ||
      recipientId.length < 2 ||
      recipientId.length > 64 ||
      !/^([a-z0-9]+([-_][a-z0-9]+)*)(\.([a-z0-9]+([-_][a-z0-9]+)*))*$/.test(recipientId)
    ) {
      panic("RIMBUX_VAULT: Invalid recipient account ID.");
    }

    if (
      typeof intentNonce !== "string" ||
      !/^[A-Za-z0-9_-]{16,128}$/.test(intentNonce)
    ) {
      panic("RIMBUX_VAULT: Invalid intent nonce.");
    }

    if (
      typeof purposeDigest !== "string" ||
      !/^[a-fA-F0-9]{64}$/.test(purposeDigest)
    ) {
      panic("RIMBUX_VAULT: Purpose digest must be a SHA-256 hex string.");
    }

    if (this.usedNonces.get(intentNonce)) {
      panic("RIMBUX_VAULT: Replay attack detected — intentNonce has already been used.");
    }

    if (this.blockedRecipients.get(recipientId) === true) {
      panic(`RIMBUX_VAULT: Destination ${recipientId} is explicitly blocked on-chain.`);
    }

    if (this.allowedRecipients.get(recipientId) !== true) {
      panic(`RIMBUX_VAULT: Destination ${recipientId} is not approved by the owner.`);
    }

    if (
      typeof amountYocto !== "string" ||
      !/^[0-9]{1,30}$/.test(amountYocto)
    ) {
      panic("RIMBUX_VAULT: Amount must be a valid positive yoctoNEAR integer.");
    }

    const amount = BigInt(amountYocto);
    if (amount <= BigInt(0)) {
      panic("RIMBUX_VAULT: Transfer amount must be greater than zero.");
    }

    if (amount > BigInt(this.maxPerTxYocto)) {
      panic("RIMBUX_VAULT: Amount exceeds on-chain maximum per-transaction cap.");
    }

    const nowNs = near.blockTimestamp();
    const windowStart = BigInt(this.dayWindowStartNs);
    let spentToday = BigInt(this.currentDaySpendYocto);

    if (nowNs - windowStart >= DAY_NS) {
      spentToday = BigInt(0);
      this.dayWindowStartNs = nowNs.toString();
    }

    if (spentToday + amount > BigInt(this.dailyLimitYocto)) {
      panic("RIMBUX_VAULT: Amount exceeds on-chain fixed 24-hour spending window.");
    }

    this.usedNonces.set(intentNonce, true);
    this.paymentStatuses.set(intentNonce, "PENDING");
    this.currentDaySpendYocto = (spentToday + amount).toString();

    const reservationWindowStartNs = this.dayWindowStartNs;

    near.log(
      JSON.stringify({
        event: "RIMBUX_AGENT_PAYMENT_SUBMITTED",
        recipientId,
        amountYocto,
        intentNonce,
        purposeDigest,
        status: "PENDING",
      })
    );

    const callbackArgs = JSON.stringify({
      recipientId,
      amountYocto,
      intentNonce,
      purposeDigest,
      reservationWindowStartNs,
    });

    const transferPromise = NearPromise.new(recipientId).transfer(amount);
    const callbackPromise = NearPromise.new(near.currentAccountId()).functionCall(
      "on_transfer_complete",
      callbackArgs,
      BigInt(0),
      CALLBACK_GAS
    );

    return transferPromise.then(callbackPromise);
  }

  @call({ privateFunction: true })
  on_transfer_complete({
    recipientId,
    amountYocto,
    intentNonce,
    purposeDigest,
    reservationWindowStartNs,
  }: {
    recipientId: string;
    amountYocto: string;
    intentNonce: string;
    purposeDigest: string;
    reservationWindowStartNs: string;
  }) {
    if (near.promiseResultsCount() !== BigInt(1)) {
      panic("RIMBUX_VAULT: Expected exactly one transfer promise result.");
    }

    if (this.paymentStatuses.get(intentNonce) !== "PENDING") {
      panic("RIMBUX_VAULT: Payment callback is invalid or has already been processed.");
    }

    if (typeof amountYocto !== "string" || !/^[0-9]{1,30}$/.test(amountYocto)) {
      panic("RIMBUX_VAULT: Invalid callback amount.");
    }

    const amount = BigInt(amountYocto);
    let transferSucceeded = false;

    try {
      near.promiseResultRaw(BigInt(0));
      transferSucceeded = true;
    } catch {
      transferSucceeded = false;
    }

    if (transferSucceeded) {
      this.paymentStatuses.set(intentNonce, "CONFIRMED");

      near.log(
        JSON.stringify({
          event: "RIMBUX_AGENT_PAYMENT_CONFIRMED",
          recipientId,
          amountYocto,
          intentNonce,
          purposeDigest,
          status: "CONFIRMED",
        })
      );

      return;
    }

    let reservationReleased = false;

    if (this.dayWindowStartNs === reservationWindowStartNs) {
      const currentSpend = BigInt(this.currentDaySpendYocto);

      if (currentSpend >= amount) {
        this.currentDaySpendYocto = (currentSpend - amount).toString();
        reservationReleased = true;
      }
    }

    this.paymentStatuses.set(intentNonce, "FAILED");

    near.log(
      JSON.stringify({
        event: "RIMBUX_AGENT_PAYMENT_FAILED",
        recipientId,
        amountYocto,
        intentNonce,
        purposeDigest,
        status: "FAILED",
        reservationReleased,
        retryRequiresNewNonce: true,
      })
    );
  }

  @view({})
  get_payment_status({ intentNonce }: { intentNonce: string }) {
    return {
      intentNonce,
      status: this.paymentStatuses.get(intentNonce) || "NOT_FOUND",
    };
  }

  @view({})
  get_vault_status() {
    return {
      ownerId: this.ownerId,
      authorizedAgentKey: this.authorizedAgentKey,
      paused: this.paused,
      maxPerTxYocto: this.maxPerTxYocto,
      dailyLimitYocto: this.dailyLimitYocto,
      currentDaySpendYocto: this.currentDaySpendYocto,
      dayWindowStartNs: this.dayWindowStartNs,
    };
  }
}