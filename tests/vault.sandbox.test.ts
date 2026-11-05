import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { Worker, KeyPair } from "near-workspaces";

test("RIMBUX Vault deploys and initializes on NEAR Sandbox", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agentKey = KeyPair.fromRandom("ed25519");
    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: root.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 5,
        dailyLimitNear: 15,
      },
    });

    const status = await vault.view<{
      ownerId: string;
      authorizedAgentKey: string;
      paused: boolean;
      maxPerTxYocto: string;
      dailyLimitYocto: string;
      currentDaySpendYocto: string;
      dayWindowStartNs: string;
    }>("get_vault_status", {});

    assert.equal(status.ownerId, root.accountId);
    assert.equal(
      status.authorizedAgentKey,
      agentKey.getPublicKey().toString()
    );
    assert.equal(status.paused, false);
    assert.equal(status.maxPerTxYocto, "5000000000000000000000000");
    assert.equal(status.dailyLimitYocto, "15000000000000000000000000");
    assert.equal(status.currentDaySpendYocto, "0");
    assert.ok(BigInt(status.dayWindowStartNs) > 0n);
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault enforces owner-only emergency pause", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agentKey = KeyPair.fromRandom("ed25519");
    const attacker = await root.devCreateAccount();

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: root.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 5,
        dailyLimitNear: 15,
      },
    });

    await assert.rejects(
      attacker.call(vault, "set_pause", { paused: true })
    );

    let status = await vault.view<{ paused: boolean }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.paused, false);

    await root.call(vault, "set_pause", { paused: true });
    status = await vault.view<{ paused: boolean }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.paused, true);

    await root.call(vault, "set_pause", { paused: false });
    status = await vault.view<{ paused: boolean }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.paused, false);
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault restricts agent key and recipient policy updates to owner", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const attacker = await root.devCreateAccount();
    const initialKey = KeyPair.fromRandom("ed25519");
    const replacementKey = KeyPair.fromRandom("ed25519");

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: root.accountId,
        authorizedAgentKey: initialKey.getPublicKey().toString(),
        maxPerTxNear: 5,
        dailyLimitNear: 15,
      },
    });

    const originalStatus = await vault.view<{
      authorizedAgentKey: string;
    }>("get_vault_status", {});

    await assert.rejects(
      attacker.call(vault, "update_authorized_agent_key", {
        newPublicKey: replacementKey.getPublicKey().toString(),
      })
    );

    let status = await vault.view<{ authorizedAgentKey: string }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.authorizedAgentKey, originalStatus.authorizedAgentKey);

    await root.call(vault, "update_authorized_agent_key", {
      newPublicKey: replacementKey.getPublicKey().toString(),
    });

    status = await vault.view<{ authorizedAgentKey: string }>(
      "get_vault_status",
      {}
    );
    assert.equal(
      status.authorizedAgentKey,
      replacementKey.getPublicKey().toString()
    );

    await assert.rejects(
      attacker.call(vault, "update_recipient_policy", {
        accountId: "merchant.test",
        allowed: true,
        blocked: false,
      })
    );

    await root.call(vault, "update_recipient_policy", {
      accountId: "merchant.test",
      allowed: true,
      blocked: false,
    });

    await root.call(vault, "update_recipient_policy", {
      accountId: "merchant.test",
      allowed: true,
      blocked: true,
    });
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault executes payment only through authorized agent FunctionCall key and prevents nonce replay", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agent = await root.devCreateAccount();
    const attacker = await root.devCreateAccount();
    const merchant = await root.devCreateAccount();
    const agentKey = KeyPair.fromRandom("ed25519");

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: agent.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 5,
        dailyLimitNear: 15,
      },
    });

    await agent.updateAccessKey(agentKey, {
      nonce: 0,
      permission: {
        FunctionCall: {
          allowance: "100000000000000000000000",
          receiver_id: vault.accountId,
          method_names: ["execute_agent_payment"],
        },
      },
    });

    await root.call(vault, "update_recipient_policy", {
      accountId: merchant.accountId,
      allowed: true,
      blocked: false,
    });

    const paymentArgs = {
      recipientId: merchant.accountId,
      amountYocto: "1000000000000000000000000",
      intentNonce: "rimbux-payment-0001",
      purposeDigest: "a".repeat(64),
    };

    // An unrelated account must not execute agent payments.
    await assert.rejects(
      attacker.call(vault, "execute_agent_payment", paymentArgs)
    );

    // The agent account's ordinary key must not bypass the authorized key.
    await assert.rejects(
      agent.call(vault, "execute_agent_payment", paymentArgs)
    );

    // The explicitly authorized FunctionCall key must succeed.
    await agent.call(
      vault,
      "execute_agent_payment",
      paymentArgs,
      { signWithKey: agentKey, gas: BigInt("100000000000000") }
    );

    const paymentStatus = await vault.view<{ status: string }>(
      "get_payment_status",
      { intentNonce: paymentArgs.intentNonce }
    );

    assert.equal(paymentStatus.status, "CONFIRMED");

    let vaultStatus = await vault.view<{
      currentDaySpendYocto: string;
    }>("get_vault_status", {});

    assert.equal(
      vaultStatus.currentDaySpendYocto,
      paymentArgs.amountYocto
    );

    // Reusing the same nonce must be rejected.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        paymentArgs,
        { signWithKey: agentKey, gas: BigInt("100000000000000") }
      )
    );

    const replayStatus = await vault.view<{ status: string }>(
      "get_payment_status",
      { intentNonce: paymentArgs.intentNonce }
    );

    assert.equal(replayStatus.status, "CONFIRMED");

    vaultStatus = await vault.view<{
      currentDaySpendYocto: string;
    }>("get_vault_status", {});

    assert.equal(
      vaultStatus.currentDaySpendYocto,
      paymentArgs.amountYocto
    );
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault enforces per-transaction and daily spending limits", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agent = await root.devCreateAccount();
    const merchant = await root.devCreateAccount();
    const agentKey = KeyPair.fromRandom("ed25519");

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: agent.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 2,
        dailyLimitNear: 3,
      },
    });

    await agent.updateAccessKey(agentKey, {
      nonce: 0,
      permission: {
        FunctionCall: {
          allowance: "100000000000000000000000",
          receiver_id: vault.accountId,
          method_names: ["execute_agent_payment"],
        },
      },
    });

    await root.call(vault, "update_recipient_policy", {
      accountId: merchant.accountId,
      allowed: true,
      blocked: false,
    });

    const gas = { signWithKey: agentKey, gas: BigInt("100000000000000") };
    const digest = "b".repeat(64);

    // 3 NEAR must exceed the 2 NEAR per-transaction cap.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        {
          recipientId: merchant.accountId,
          amountYocto: "3000000000000000000000000",
          intentNonce: "rimbux-limit-over-0001",
          purposeDigest: digest,
        },
        gas
      )
    );

    // First 2 NEAR payment must succeed.
    await agent.call(
      vault,
      "execute_agent_payment",
      {
        recipientId: merchant.accountId,
        amountYocto: "2000000000000000000000000",
        intentNonce: "rimbux-limit-valid-0001",
        purposeDigest: digest,
      },
      gas
    );

    const firstPayment = await vault.view<{ status: string }>(
      "get_payment_status",
      { intentNonce: "rimbux-limit-valid-0001" }
    );
    assert.equal(firstPayment.status, "CONFIRMED");

    // Another 2 NEAR would exceed the 3 NEAR daily limit.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        {
          recipientId: merchant.accountId,
          amountYocto: "2000000000000000000000000",
          intentNonce: "rimbux-limit-daily-0001",
          purposeDigest: digest,
        },
        gas
      )
    );

    const status = await vault.view<{
      currentDaySpendYocto: string;
    }>("get_vault_status", {});

    assert.equal(
      status.currentDaySpendYocto,
      "2000000000000000000000000"
    );
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault enforces recipient allowlist and blocklist", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agent = await root.devCreateAccount();
    const merchant = await root.devCreateAccount();
    const agentKey = KeyPair.fromRandom("ed25519");

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: agent.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 5,
        dailyLimitNear: 15,
      },
    });

    await agent.updateAccessKey(agentKey, {
      nonce: 0,
      permission: {
        FunctionCall: {
          allowance: "100000000000000000000000",
          receiver_id: vault.accountId,
          method_names: ["execute_agent_payment"],
        },
      },
    });

    const gas = { signWithKey: agentKey, gas: BigInt("100000000000000") };
    const amountYocto = "1000000000000000000000000";
    const digest = "c".repeat(64);

    const payment = (nonce: string) => ({
      recipientId: merchant.accountId,
      amountYocto,
      intentNonce: nonce,
      purposeDigest: digest,
    });

    // A recipient not approved by the owner must be rejected.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        payment("rimbux-recipient-unapproved-01"),
        gas
      )
    );

    // Explicitly block the recipient.
    await root.call(vault, "update_recipient_policy", {
      accountId: merchant.accountId,
      allowed: true,
      blocked: true,
    });

    // A blocked recipient must be rejected even if allowlisted.
    await assert.rejects(
      agent.call(
        vault,
        "execute_agent_payment",
        payment("rimbux-recipient-blocked-001"),
        gas
      )
    );

    // Owner removes the block; the allowlisted recipient can now receive payment.
    await root.call(vault, "update_recipient_policy", {
      accountId: merchant.accountId,
      allowed: true,
      blocked: false,
    });

    await agent.call(
      vault,
      "execute_agent_payment",
      payment("rimbux-recipient-approved-01"),
      gas
    );

    const status = await vault.view<{ status: string }>(
      "get_payment_status",
      { intentNonce: "rimbux-recipient-approved-01" }
    );

    assert.equal(status.status, "CONFIRMED");
  } finally {
    await worker.tearDown();
  }
});

test("RIMBUX Vault blocks agent payments during emergency pause", async () => {
  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;
    const agent = await root.devCreateAccount();
    const merchant = await root.devCreateAccount();
    const agentKey = KeyPair.fromRandom("ed25519");

    const wasmPath = path.resolve(
      "contracts/rimbux-vault/build/rimbux_vault.wasm"
    );

    const vault = await root.devDeploy(wasmPath, {
      method: "init",
      args: {
        ownerId: root.accountId,
        agentAccountId: agent.accountId,
        authorizedAgentKey: agentKey.getPublicKey().toString(),
        maxPerTxNear: 5,
        dailyLimitNear: 15,
      },
    });

    await agent.updateAccessKey(agentKey, {
      nonce: 0,
      permission: {
        FunctionCall: {
          allowance: "100000000000000000000000",
          receiver_id: vault.accountId,
          method_names: ["execute_agent_payment"],
        },
      },
    });

    await root.call(vault, "update_recipient_policy", {
      accountId: merchant.accountId,
      allowed: true,
      blocked: false,
    });

    const paymentArgs = {
      recipientId: merchant.accountId,
      amountYocto: "1000000000000000000000000",
      intentNonce: "rimbux-emergency-pause-01",
      purposeDigest: "d".repeat(64),
    };

    const gas = { signWithKey: agentKey, gas: BigInt("100000000000000") };

    // Owner activates emergency lockdown.
    await root.call(vault, "set_pause", { paused: true });

    // Agent payment must be rejected while the vault is paused.
    await assert.rejects(
      agent.call(vault, "execute_agent_payment", paymentArgs, gas)
    );

    let status = await vault.view<{ paused: boolean }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.paused, true);

    // Owner lifts emergency lockdown.
    await root.call(vault, "set_pause", { paused: false });

    // The same nonce can now be used because the paused attempt was rejected.
    await agent.call(vault, "execute_agent_payment", paymentArgs, gas);

    const paymentStatus = await vault.view<{ status: string }>(
      "get_payment_status",
      { intentNonce: paymentArgs.intentNonce }
    );
    assert.equal(paymentStatus.status, "CONFIRMED");

    status = await vault.view<{ paused: boolean }>(
      "get_vault_status",
      {}
    );
    assert.equal(status.paused, false);
  } finally {
    await worker.tearDown();
  }
});
