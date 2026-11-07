# RIMBUX

### A guardian that stands between an AI agent and your NEAR wallet

> **Trust, but verify.** Let an AI agent pay for things without giving it the keys to everything.

Submission for the **NEAR Hackathon 2026, AI Security & Defense track**. Built solo.

![RIMBUX dashboard](docs/screenshots/01-overview.png)

### Dashboard overview

The home screen lets you try to drain a wallet and watch RIMBUX stop it:

- **Pick your attack:** Choose a ready-made case (hidden prompt injection, fake address, oversized send, unknown wallet, big send, or a legit send) or type your own transaction.
- **What the agent got told:** Shows the untrusted input the agent received, which is how agents get hijacked.
- **Four policy gates:** Parse the request, policy and attack check, human approval, and dry-run signing. If one gate stops the payment, the rest are halted.
- **Guardian verdict:** The final decision is made by fixed rules, not by the AI.
- **Live risk gauges:** Attack risk, daily limit used, and recipient trust, recalculated on every check.
- **Public read-only:** The public demo can be explored without granting access to live signing or transaction broadcasting.

<!-- TODO: add demo video link -->
<!-- **Demo video:** https://... -->

## In 30 seconds

**The problem.** AI agents can now pay on your behalf. But an agent can be tricked: a hidden instruction in a web page or message can make it send money to a scammer, or change its own rules.

**Our answer.** RIMBUX checks every payment *before* it is signed and gives one of three answers:

| Answer | What it means | Example from our tests |
|---|---|---|
| **Allow** | Safe and within policy. Simulated in public read-only mode. | Send 1.2 NEAR to `alice.testnet` |
| **Ask a human** | Big or unfamiliar. Waits for a person to approve. | Send 3.5 NEAR, or pay an unknown account |
| **Block** | Looks like an attack. Never signed. | Pay `al1ce.testnet` (a fake lookalike of `alice.testnet`) |

Every decision is saved in a log that shows if anyone tries to change it later.

**Safe to try.** The public dashboard runs in read-only demo mode. Payment decisions and human approvals are simulated; no transaction is signed or broadcast and no funds move.

## What you will see

Open the dashboard, pick an attack (or type your own transaction), and press **Check payment**. You will watch the four policy gates decide: RIMBUX allows the good payments, pauses the risky ones for a human, and stops the attacks, with the reason for each decision. You can also run the full **12 attack tests**.

Below the attack arena, the control panel shows the spending rules you set (per payment, daily, per recipient, and the approval threshold), the human approval queue where a risky payment waits for you to approve or reject, and the limited key the agent uses instead of your main key.

![Spending rules and approval queue](docs/screenshots/02-controls.png)

## How it works

Think of RIMBUX as a security guard at the door. The agent can ask for a payment, but the guard decides.

```
Agent asks: "Send 3.5 NEAR to alice.testnet"
        |
        v
1. Understand the request   (spots hidden instructions and tricks)
        |
        v
2. Check the recipient      (scam list, lookalike names, on-chain history)
        |
        v
3. Check your rules         (spending limits, daily totals)
        |
        +---- Dangerous ---------> BLOCK
        +---- Unsure or large ---> ASK A HUMAN (approve / reject)
        |
        v
4. Execute only when live signing is explicitly configured; otherwise simulate the decision in public read-only mode
        |
        v
NEAR Testnet (live mode only)

Public demo mode stops at simulation. Every decision is written to the audit log.
```

## What RIMBUX protects against

- **Spending too much**: limits per payment, per recipient per day, and per day overall.
- **Fake lookalike accounts**: `al1ce.testnet` pretending to be `alice.testnet`.
- **Known scam addresses**: a blocklist, for example `drainer-vault.testnet`.
- **Prompt injection**: "Ignore all previous instructions..." is caught and blocked.
- **Rule tampering**: "set daily limit to 99999 NEAR" is blocked.
- **Split payments**: several amounts or recipients hidden in one instruction.
- **Giving itself more power**: the agent cannot add a new key to the account.
- **Two payments at once**: while one payment is waiting, a second one is blocked.
- **Missing safety data**: if the threat check is offline, RIMBUX asks a human instead of allowing the payment ("fail-closed").
- **Skipping the guard**: the signing step rejects any payment that has no valid or unexpired pass.

## Proof: 12 attack tests, all handled correctly

Run them from the dashboard, or call `POST /api/audit/run-suite`. Each test shows the gate that decided and the verdict.

| # | Attack or situation | Gate | Result |
|---|---|---|---|
| 1 | Homoglyph spoof (`al1ce`) | 02 | Blocked |
| 2 | Hidden prompt injection | 01 | Blocked |
| 3 | Single-payment limit (9 NEAR) | 02 | Blocked |
| 4 | Daily cap breach (18 NEAR) | 02 | Blocked |
| 5 | Unknown recipient (trust 50) | 03 | Ask a human |
| 6 | Zero-width Unicode | 01 | Blocked |
| 7 | System prompt override | 01 | Blocked |
| 8 | Gas allowance overflow | 02 | Blocked |
| 9 | Replay nonce attack | 04 | Blocked |
| 10 | Micro-split burst (Sybil) | 03 | Ask a human |
| 11 | Unauthorized DeleteAccount | 02 | Blocked |
| 12 | Lockdown bypass attempt | 01 | Blocked |

Latest run: **12 of 12 handled as expected: 10 blocked, 2 sent to a human for approval. Audit log intact.**

![12 attack tests](docs/screenshots/03-attack-tests.png)

## The agent's key: limited on purpose

The AI agent never gets the master key to the account. It gets a **function-call key**: a restricted NEAR key that can do one thing only.

| | |
|---|---|
| Agent account | `agent.rimbux.testnet` |
| Key type | FunctionCall (restricted) |
| Can call | `execute_agent_payment` on `vault.rimbux.testnet`, nothing else |
| Gas allowance | 0.25 NEAR |

The dashboard checks this key directly on NEAR Testnet (read-only) and shows it as verified.


**What the key cannot do**

- Send NEAR straight out of the agent account.
- Add or remove keys.
- Call any other contract or method.

**Limits you should know**

- The key has a limited gas allowance. When it runs out, the agent can no longer sign, and a new key must be added by the account owner.
- The emergency **Revoke Key** button stops RIMBUX from using the key, but it does **not** delete the key on NEAR.
- On-chain key rotation is not built yet.

## The audit log

Every decision is saved as a numbered entry. Each entry includes a fingerprint of the one before it, so if someone edits or deletes an old record, the **Verify Chain** button shows that the log was changed.

This makes the log *tamper-evident*: it cannot stop changes, but it makes them visible.

![Audit log](docs/screenshots/04-audit-log.png)

## How this fits the track

| What the track asks for | What RIMBUX does |
|---|---|
| Allow, warn, or block, with reasons | Allow, ask a human, or block, each with a reason code |
| Refuse to sign on block, ask a human on warn | The signing step needs a valid pass; risky payments wait in an approval queue |
| Function-call key limited to one contract, with its limits explained | See "The agent's key" above |
| An attack demo with a log | 12 attack tests plus the audit log |
| Reputation signals | Blocklist, on-chain account check, balance, contract check, trusted-partner list, lookalike detection |

## Run it yourself

You need: Node.js 20 or newer, npm, git, and a NEAR Testnet account.

```bash
git clone https://github.com/zorumeon/RIMBUX.git
cd RIMBUX
npm install
cp .env.example .env
```

Create the secret that protects the audit log (it must be at least 64 characters), then paste it into `.env` as `RIMBUX_AUDIT_SECRET`:

```bash
openssl rand -hex 48
```

Run the tests, then start the app:

```bash
npm test
npm run dev
```

Open `http://localhost:3000`.

### On Windows (Ubuntu in WSL)

1. In PowerShell as Administrator: `wsl --install -d Ubuntu`. Restart if asked. Check with `wsl -l -v`; the version should be 2.
2. In the Ubuntu terminal:
   ```bash
   sudo apt update && sudo apt install -y git curl build-essential python3 openssl
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
   source ~/.bashrc
   nvm install 20
   ```
3. Clone the repo into your Linux home folder (`~`), not `/mnt/c`, then follow the steps above.
4. Open `http://localhost:3000` in your Windows browser. To check the backend: `curl http://localhost:3000/api/status`.

| Problem | Fix |
|---|---|
| Node version is not 20 | `nvm install 20 && nvm use 20` |
| Build error during `npm install` | `sudo apt install -y build-essential python3`, then run `npm install` again |
| `localhost:3000` does not open | Check the server is running, or restart WSL with `wsl --shutdown` |
| Port 3000 is already used | Change `PORT` in `.env` |
| Secret rejected | `RIMBUX_AUDIT_SECRET` must be at least 64 characters |
| Errors about `\r` | `sudo apt install dos2unix && dos2unix .env` |

### Settings (`.env`)

| Variable | What it is |
|---|---|
| `PORT` | Port for the server (default 3000) |
| `NEAR_NETWORK_ID` | `testnet` |
| `NEAR_RPC_URL` | NEAR Testnet RPC address |
| `NEAR_VAULT_CONTRACT_ID` | The vault contract the agent key is limited to |
| `NEAR_AGENT_ACCOUNT_ID` | The agent's NEAR account |
| `NEAR_AGENT_FUNCTION_CALL_PRIVATE_KEY` | The agent's restricted key. **Never commit this.** |
| `RIMBUX_AUDIT_SECRET` | Protects the audit log, at least 64 characters. **Never commit this.** |
| `RIMBUX_BROADCAST` | `false` by default: sign locally, do not send to the network |

`.env` is listed in `.gitignore`. Only `.env.example` is in the repo.

## API

| Method | Endpoint | What it does |
|---|---|---|
| GET | `/api/status` | System and audit status |
| POST | `/api/agent/instruct` | Send a payment instruction |
| POST | `/api/approvals/:intentId` | Approve or reject a waiting payment |
| POST | `/api/policy/update` | Change spending rules |
| POST | `/api/sandbox/revoke` | Revoke local signing |
| POST | `/api/sandbox/rotate` | Key rotation status |
| GET | `/api/reputation/:accountId` | Check how trustworthy an account looks |
| POST | `/api/audit/run-suite` | Run the attack tests |

### Public demo and operator access

The public dashboard is available in read-only demo mode without operator login. Payment evaluations and human approval decisions are simulated; they do not sign or broadcast transactions.

Live operator controls and signing operations require the appropriate authenticated configuration. Never expose private keys or operator credentials in a public demo.

## Honest limits

- **In live mode, "signed" means signed locally.** It does not mean sent to the network or confirmed.
- **Revoking a key is local.** It does not remove the key from NEAR.
- **Risk scores are signals, not guarantees.** They come from NEAR Testnet RPC data plus a local list, not a network-wide threat feed.
- **The audit log shows tampering; it does not prevent it.**
- **No TEE attestation yet.** This is the next step, to prove the guard's own code has not been changed.
- **This is a hackathon prototype**, not an audited production wallet.

## What's next

- TEE attestation for the policy engine.
- A shared blocklist that other agents can report to, with evidence.
- More recipient checks: account age, recent contract changes, past payments between agent and recipient.
- On-chain key rotation.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Testnet Transaction Evidence

RIMBUX has been tested with real transactions on NEAR Testnet.

| Evidence | Result | NEAR Explorer |
|---|---|---|
| Test payment — 0.01 NEAR | FINAL / SuccessValue | [View transaction](https://testnet.nearblocks.io/txns/8Z4eHUx7M2pWG3H7XUgX2QLtym7VZtTtWTi1gDboq6Aq) |
| Recipient allowlist update | FINAL / SuccessValue | [View transaction](https://testnet.nearblocks.io/txns/DmQCXcZxgt1BT8XJqoYq3JppeJPnk3h8dGHdPvCXGB9R) |

**Testnet accounts**
- Vault contract: `vault.rimbux.testnet`
- Agent: `agent.rimbux.testnet`
- Owner: `rimbux.testnet`

These links provide on-chain evidence of testnet activity. Public demo actions remain read-only or simulated and do not broadcast transactions.
