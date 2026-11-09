# RIMBUX — Judge Guide

This guide lets judges review the public demo, automated security tests, and NEAR Testnet evidence without receiving operator credentials or private keys.

## 1. Start the public demo

Requirements: Node.js 20+, npm, and Git.

```bash
git clone https://github.com/zorumeon/RIMBUX.git
cd RIMBUX
npm install
cp .env.example .env
```

Set `RIMBUX_AUDIT_SECRET` in `.env` to a random value of at least 64 characters:

```bash
openssl rand -hex 48
```

Then start the app:

```bash
npm run dev
```

Open **http://localhost:3000**.

The public dashboard is designed to be explored without operator login. Public-mode payment checks and approval decisions are simulations: they do not sign or broadcast transactions and no funds move.

## 2. Explore the dashboard

Suggested review path:

1. In **Security check**, pick a scenario in the **Threat lab** sidebar (for example *Prompt injection* or *Lookalike address*) and press **Run check**. Watch the four policy gates and the decision.
2. In the **Rules** section, review the spending limits, the human approval queue, and the agent's limited key. **Check on-chain** reads that key live from NEAR Testnet.
3. In the **Audit log** section, press **Verify chain**, then **Simulate tampering** to see the tampering detected.
4. Optional: open **Run all 12 attack tests**. This panel runs a built-in engine in your browser against the default policy. The authoritative suite is `POST /api/audit/run-suite` and the automated tests in step 3 below.

Do not enter a private key or operator password supplied by anyone. Judges do not need either to review public demo mode.

## 3. Run the automated security tests

In a second terminal, from the repository root:

```bash
RIMBUX_BROADCAST=false npm test
```

The README documents 12 security scenarios. The suite covers normal payments, spending limits, blocked and lookalike recipients, unknown recipients, dangerous methods, prompt injection, policy tampering, concurrent payment attempts, unavailable threat checks, expired passes, and signing without a valid pass.

To build-check the TypeScript project:

```bash
npm run build
```

## 4. Review real NEAR Testnet evidence

Open [Testnet verification evidence](docs/TESTNET-VERIFICATION.md). It records the test date, account roles, transaction links, finalized outcomes, and the scope of each test.

Key evidence includes:

- A 0.01 NEAR agent payment that finalized successfully.
- An on-chain recipient allowlist update.
- An explicitly blocked recipient payment rejected by the vault contract.
- A 1.01 NEAR payment rejected when the configured per-transaction maximum was 1 NEAR.

The document distinguishes real Testnet transactions from local NEAR Sandbox tests. Use the linked NEAR Explorer pages to inspect transaction details independently.

## 5. Important scope and safety notes

- Public demo mode is read-only/simulated. It is not the live signing environment.
- Testnet evidence is historical evidence of the transactions listed in the verification document; it does not mean the public demo is broadcasting.
- Never request, publish, or commit `.env`, private keys, or operator credentials.
- A local signing result is not the same as a transaction being broadcast or finalized.
- RIMBUX is a hackathon prototype, not an audited production wallet.

## Useful links

- [Repository](https://github.com/zorumeon/RIMBUX)
- [README](../README.md)
- [NEAR Testnet verification](TESTNET-VERIFICATION.md)
- [MIT License](../LICENSE)
