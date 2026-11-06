// contracts/rimbux-vault/src/contract.ts
import { NearBindgen, near, call, view, initialize, NearPromise, UnorderedMap } from "near-sdk-js";
import { PublicKey } from "near-sdk-js/lib/types/public_key.js";

const YOCTO_PER_NEAR = BigInt("1000000000000000000000000");
const DAY_NS = BigInt(24 * 60 * 60) * BigInt("1000000000");
const CALLBACK_GAS = BigInt("30000000000000");

function panic(message: string): never {
  throw new Error(message);
}

@NearBindgen({ requireInit: true })
export class RimbuxVaultContract {
  ownerId: string = "";
  agentAccountId: string = "";
  authorizedAgentKey: string = "";
  paused: boolean = false;

  maxPerTxYocto: string = (BigInt(1) * YOCTO_PER_NEAR).toString();
  dailyLimitYocto: string = (BigInt(3) * YOCTO_PER_NEAR).toString();
  currentDaySpendYocto: string = "0";
  dayWindowStartNs: string = "0";

  allowedRecipients: UnorderedMap<boolean> = new UnorderedMap<boolean>("a");
  blockedRecipients: UnorderedMap<boolean> = new UnorderedMap<boolean>("b");
  usedNonces: UnorderedMap<boolean> = new UnorderedMap<boolean>("n");
  paymentStatuses: UnorderedMap<string> = new UnorderedMap<string>("p");

  // Bounded replay protection and payment lifecycle state.
  nextSequenceNonce: string = "1";

  activePaymentSequence: string = "";
  activePaymentIntentNonce: string = "";
  activePaymentRecipientId: string = "";
  activePaymentAmountYocto: string = "";
  activePaymentPurposeDigest: string = "";
  activePaymentReservationWindowStartNs: string = "";

  lastPaymentSequence: string = "0";
  lastPaymentIntentNonce: string = "";
  lastPaymentStatus: string = "NONE";
  lastPaymentTxRecipientId: string = "";
  lastPaymentAmountYocto: string = "";
  lastPaymentPurposeDigest: string = "";

  @initialize({ privateFunction: true })
  init({
    ownerId,
    agentAccountId,
    authorizedAgentKey,
    maxPerTxNear,
    dailyLimitNear,
  }: {
    ownerId: string;
    agentAccountId: string;
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

    const validAgentAccountId =
      typeof agentAccountId === "string" &&
      agentAccountId.length >= 2 &&
      agentAccountId.length <= 64 &&
      /^([a-z0-9]+([-_][a-z0-9]+)*)(\.([a-z0-9]+([-_][a-z0-9]+)*))*$/.test(agentAccountId);

    if (!validAgentAccountId) {
      panic("RIMBUX_VAULT: Invalid agent account ID.");
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
    this.agentAccountId = agentAccountId;
    this.authorizedAgentKey = authorizedAgentKey;
    this.maxPerTxYocto = maxPerTx.toString();
    this.dailyLimitYocto = dailyLimit.toString();
    this.dayWindowStartNs = near.blockTimestamp().toString();
  }

  @call({})
  migrate_v2_state() {
    this.assertOwner();

    if (this.nextSequenceNonce !== undefined) {
      panic("RIMBUX_VAULT: State migration has already been completed.");
    }

    if (
      (this.activePaymentSequence !== undefined && this.activePaymentSequence !== "") ||
      (this.activePaymentIntentNonce !== undefined && this.activePaymentIntentNonce !== "") ||
      (this.activePaymentRecipientId !== undefined && this.activePaymentRecipientId !== "") ||
      (this.activePaymentAmountYocto !== undefined && this.activePaymentAmountYocto !== "") ||
      (this.activePaymentPurposeDigest !== undefined && this.activePaymentPurposeDigest !== "") ||
      (this.activePaymentReservationWindowStartNs !== undefined &&
        this.activePaymentReservationWindowStartNs !== "")
    ) {
      panic("RIMBUX_VAULT: Unexpected active payment state; migration aborted.");
    }

    this.nextSequenceNonce = "1";

    if (this.activePaymentSequence === undefined) this.activePaymentSequence = "";
    if (this.activePaymentIntentNonce === undefined) this.activePaymentIntentNonce = "";
    if (this.activePaymentRecipientId === undefined) this.activePaymentRecipientId = "";
    if (this.activePaymentAmountYocto === undefined) this.activePaymentAmountYocto = "";
    if (this.activePaymentPurposeDigest === undefined) this.activePaymentPurposeDigest = "";
    if (this.activePaymentReservationWindowStartNs === undefined) {
      this.activePaymentReservationWindowStartNs = "";
    }

    if (this.lastPaymentSequence === undefined) this.lastPaymentSequence = "0";
    if (this.lastPaymentIntentNonce === undefined) this.lastPaymentIntentNonce = "";
    if (this.lastPaymentStatus === undefined) this.lastPaymentStatus = "NONE";
    if (this.lastPaymentTxRecipientId === undefined) this.lastPaymentTxRecipientId = "";
    if (this.lastPaymentAmountYocto === undefined) this.lastPaymentAmountYocto = "";
    if (this.lastPaymentPurposeDigest === undefined) this.lastPaymentPurposeDigest = "";

    near.log(JSON.stringify({
      event: "RIMBUX_V2_STATE_MIGRATED",
      nextSequenceNonce: this.nextSequenceNonce,
    }));
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
    sequenceNonce,
    purposeDigest,
  }: {
    recipientId: string;
    amountYocto: string;
    intentNonce: string;
    sequenceNonce: string;
    purposeDigest: string;
  }): NearPromise {
    if (this.paused) panic("RIMBUX_VAULT: Vault is paused.");
    if (this.activePaymentSequence !== "") {
      panic("RIMBUX_VAULT: Another payment is still pending.");
    }
    if (near.signerAccountId() !== this.agentAccountId) {
      panic("RIMBUX_VAULT: Unauthorized agent account.");
    }

    const signerPk = near.signerAccountPk();
    const authorizedPk = PublicKey.fromString(this.authorizedAgentKey).data;
    if (
      signerPk.length !== authorizedPk.length ||
      !signerPk.every((byte, index) => byte === authorizedPk[index])
    ) {
      panic("RIMBUX_VAULT: Unauthorized agent FunctionCall key.");
    }

    if (
      typeof recipientId !== "string" ||
      recipientId.length < 2 ||
      recipientId.length > 64 ||
      !/^([a-z0-9]+([-_][a-z0-9]+)*)(\.([a-z0-9]+([-_][a-z0-9]+)*))*$/.test(recipientId)
    ) panic("RIMBUX_VAULT: Invalid recipient account ID.");

    if (
      typeof intentNonce !== "string" ||
      !/^[A-Za-z0-9_-]{16,128}$/.test(intentNonce)
    ) panic("RIMBUX_VAULT: Invalid intent nonce.");

    if (
      typeof sequenceNonce !== "string" ||
      !/^[1-9][0-9]{0,39}$/.test(sequenceNonce) ||
      BigInt(sequenceNonce) !== BigInt(this.nextSequenceNonce)
    ) panic("RIMBUX_VAULT: Invalid or stale sequence nonce.");

    if (
      typeof purposeDigest !== "string" ||
      !/^[a-fA-F0-9]{64}$/.test(purposeDigest)
    ) panic("RIMBUX_VAULT: Invalid purpose digest.");

    if (this.usedNonces.get(intentNonce) === true) {
      panic("RIMBUX_VAULT: Replay attack detected — intent nonce has already been used.");
    }

    if (this.blockedRecipients.get(recipientId) === true) {
      panic(`RIMBUX_VAULT: Destination ${recipientId} is blocked.`);
    }
    if (this.allowedRecipients.get(recipientId) !== true) {
      panic(`RIMBUX_VAULT: Destination ${recipientId} is not approved.`);
    }

    if (
      typeof amountYocto !== "string" ||
      !/^[0-9]{1,30}$/.test(amountYocto)
    ) panic("RIMBUX_VAULT: Invalid transfer amount.");

    const amount = BigInt(amountYocto);
    if (amount <= BigInt(0)) panic("RIMBUX_VAULT: Amount must be positive.");
    if (amount > BigInt(this.maxPerTxYocto)) {
      panic("RIMBUX_VAULT: Amount exceeds per-transaction limit.");
    }

    const nowNs = near.blockTimestamp();
    const windowStart = BigInt(this.dayWindowStartNs);
    let spentToday = BigInt(this.currentDaySpendYocto);

    if (nowNs - windowStart >= DAY_NS) {
      spentToday = BigInt(0);
      this.dayWindowStartNs = nowNs.toString();
    }
    if (spentToday + amount > BigInt(this.dailyLimitYocto)) {
      panic("RIMBUX_VAULT: Amount exceeds the 24-hour spending limit.");
    }

    // Preserve existing storage and reserve capacity for the next state writes.
    const STORAGE_GROWTH_BUFFER_BYTES = BigInt(4096);
    const GAS_RESERVE_YOCTO = BigInt("10000000000000000000000");
    const storageReserve =
      (near.storageUsage() + STORAGE_GROWTH_BUFFER_BYTES) *
      near.storageByteCost();
    const requiredBalance = amount + storageReserve + GAS_RESERVE_YOCTO;
    const liquidBalance = near.accountBalance();

    if (liquidBalance < requiredBalance) {
      panic("RIMBUX_VAULT: Insufficient balance after storage and gas reserves.");
    }

    const reservationWindowStartNs = this.dayWindowStartNs;

    this.usedNonces.set(intentNonce, true);
    this.paymentStatuses.set(intentNonce, "PENDING");

    this.activePaymentSequence = sequenceNonce;
    this.activePaymentIntentNonce = intentNonce;
    this.activePaymentRecipientId = recipientId;
    this.activePaymentAmountYocto = amountYocto;
    this.activePaymentPurposeDigest = purposeDigest;
    this.activePaymentReservationWindowStartNs = reservationWindowStartNs;

    this.lastPaymentSequence = sequenceNonce;
    this.lastPaymentIntentNonce = intentNonce;
    this.lastPaymentStatus = "PENDING";
    this.lastPaymentTxRecipientId = recipientId;
    this.lastPaymentAmountYocto = amountYocto;
    this.lastPaymentPurposeDigest = purposeDigest;

    this.nextSequenceNonce = (BigInt(sequenceNonce) + BigInt(1)).toString();
    this.currentDaySpendYocto = (spentToday + amount).toString();

    near.log(JSON.stringify({
      event: "RIMBUX_AGENT_PAYMENT_SUBMITTED",
      sequenceNonce,
      intentNonce,
      recipientId,
      amountYocto,
      purposeDigest,
      status: "PENDING",
    }));

    const callbackArgs = JSON.stringify({
      sequenceNonce,
      intentNonce,
      recipientId,
      amountYocto,
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
    sequenceNonce,
    intentNonce,
    recipientId,
    amountYocto,
    purposeDigest,
    reservationWindowStartNs,
  }: {
    sequenceNonce: string;
    intentNonce: string;
    recipientId: string;
    amountYocto: string;
    purposeDigest: string;
    reservationWindowStartNs: string;
  }) {
    if (near.promiseResultsCount() !== BigInt(1)) {
      panic("RIMBUX_VAULT: Expected exactly one transfer result.");
    }

    if (
      sequenceNonce !== this.activePaymentSequence ||
      intentNonce !== this.activePaymentIntentNonce ||
      recipientId !== this.activePaymentRecipientId ||
      amountYocto !== this.activePaymentAmountYocto ||
      purposeDigest !== this.activePaymentPurposeDigest ||
      reservationWindowStartNs !== this.activePaymentReservationWindowStartNs
    ) {
      panic("RIMBUX_VAULT: Callback does not match the active payment.");
    }

    if (this.paymentStatuses.get(intentNonce) !== "PENDING") {
      panic("RIMBUX_VAULT: Payment callback is invalid or has already been processed.");
    }

    const amount = BigInt(amountYocto);
    let transferSucceeded = false;

    try {
      near.promiseResultRaw(BigInt(0));
      transferSucceeded = true;
    } catch {
      transferSucceeded = false;
    }

    if (!transferSucceeded && this.dayWindowStartNs === reservationWindowStartNs) {
      const currentSpend = BigInt(this.currentDaySpendYocto);
      if (currentSpend >= amount) {
        this.currentDaySpendYocto = (currentSpend - amount).toString();
      }
    }

    this.lastPaymentStatus = transferSucceeded ? "CONFIRMED" : "FAILED";
    this.paymentStatuses.set(intentNonce, this.lastPaymentStatus);

    near.log(JSON.stringify({
      event: transferSucceeded
        ? "RIMBUX_AGENT_PAYMENT_CONFIRMED"
        : "RIMBUX_AGENT_PAYMENT_FAILED",
      sequenceNonce,
      intentNonce,
      recipientId,
      amountYocto,
      purposeDigest,
      status: this.lastPaymentStatus,
      reservationReleased: !transferSucceeded &&
        this.dayWindowStartNs === reservationWindowStartNs,
    }));

    this.activePaymentSequence = "";
    this.activePaymentIntentNonce = "";
    this.activePaymentRecipientId = "";
    this.activePaymentAmountYocto = "";
    this.activePaymentPurposeDigest = "";
    this.activePaymentReservationWindowStartNs = "";
  }

  @view({})
  get_payment_status({ intentNonce }: { intentNonce: string }) {
    if (intentNonce === this.activePaymentIntentNonce && this.activePaymentSequence !== "") {
      return {
        intentNonce,
        sequenceNonce: this.activePaymentSequence,
        status: "PENDING",
      };
    }

    const isLastPayment = this.lastPaymentIntentNonce === intentNonce;
    const storedStatus = this.paymentStatuses.get(intentNonce);

    return {
      intentNonce,
      sequenceNonce: isLastPayment
        ? this.lastPaymentSequence
        : null,
      status: isLastPayment
        ? this.lastPaymentStatus
        : storedStatus || "NOT_FOUND",
    };
  }

  @view({})
  get_next_sequence_nonce() {
    return this.nextSequenceNonce;
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