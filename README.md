# RIMBUX
### Autonomous AI Wallet Security & Defense on NEAR

RIMBUX is an AI-powered wallet security backend for NEAR Testnet. It evaluates transaction instructions, enforces spending policies, detects suspicious destinations, controls signing permissions, and maintains a tamper-evident audit trail.

## Core Features

- Natural-language transaction instruction processing.
- Spending limits and policy enforcement.
- Account reputation assessment and scam detection.
- Typosquatting and suspicious destination detection.
- Human approval workflow for uncertain transactions.
- Restricted NEAR FunctionCall signing boundary.
- Emergency local signing-key revocation.
- SQLite-backed HMAC-SHA256 audit integrity verification.

## Architecture

```text
User Instruction
      |
      v
RIMBUX Autonomous Agent
      |
      v
Reputation + Scam Detection
      |
      v
Spending Controller + Policy Engine
      |
      +---- BLOCK / REJECT
      |
      +---- REQUIRE APPROVAL
      |
      v
NEAR Signing Boundary
      |
      v
NEAR Testnet

Security Events --> SQLite --> HMAC Audit Chain

## Technology Stack

- Node.js 22+
- TypeScript
- Express
- NEAR API JS
- NEAR Testnet RPC
- SQLite
- HMAC-SHA256

## Installation

Requirements: Node.js 22+, npm, and a NEAR Testnet account.

## Environment Configuration

Create `.env` from `.env.example`:

    cp .env.example .env

Set `RIMBUX_AUDIT_SECRET` to a secret of at least 64 characters. Keep private keys and secrets out of Git.

### Demo accounts (NEAR Testnet)

- Vault contract: `vault.rimbux.testnet`. Its on-chain code hash matches `contracts/rimbux-vault/build/rimbux-vault-v4.wasm`.
- Agent signer: `agent.rimbux.testnet`.

`.env.example` already uses these account IDs. To sign transactions you must provide your own FunctionCall access key for the agent account in `NEAR_AGENT_FUNCTION_CALL_PRIVATE_KEY`. The automated tests run without any key (they use mocks and a local sandbox) and never broadcast to NEAR Testnet.

## Run

Install dependencies with `npm install`.

Start the server with `npm run dev`.

Build with `npm run build`.

Run automated tests with `npm test`.

The server listens at `http://localhost:3000`.

## API Reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/status` | System and audit status |
| POST | `/api/agent/instruct` | Process an instruction |
| POST | `/api/approvals/:intentId` | Approve or reject an intent |
| POST | `/api/policy/update` | Update spending policy |
| POST | `/api/sandbox/revoke` | Revoke local signing capability |
| POST | `/api/sandbox/rotate` | Key rotation status |
| GET | `/api/reputation/:accountId` | Assess account reputation |
| POST | `/api/audit/run-suite` | Run security simulations |

## Security Boundaries

- `SIGNED` means locally signed, not broadcast or confirmed on-chain.
- Local key revocation does not remove the key from NEAR.
- On-chain key rotation is not implemented.
- Reputation and scam detection provide risk signals, not guarantees.
- This is a hackathon prototype, not an independently audited production wallet.

## License

No open-source license has been specified.
