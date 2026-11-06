# RIMBUX — NEAR Testnet Verification

**Test date:** 2026-11-05
**Network:** NEAR Testnet
**Verification type:** Real on-chain execution

## Account Roles

| Role | Account |
|---|---|
| Vault contract | `vault.rimbux.testnet` |
| Authorized agent | `agent.rimbux.testnet` |
| Owner | `rimbux.testnet` |
| Payment recipient | `recipient.rimbux.testnet` |

## Test 1 — Recipient Account Creation

- Account: `recipient.rimbux.testnet`
- Initial balance: 0.1 NEAR
- Transaction:
  https://testnet.nearblocks.io/txns/bw9naEKUJdL8UitzACmPJ6AC9Mqn2Zb1B5ab5N5DzeF

## Test 2 — Recipient Allowlist

- Method: `update_recipient_policy`
- Recipient: `recipient.rimbux.testnet`
- Allowed: `true`
- Blocked: `false`
- Transaction:
  https://testnet.nearblocks.io/txns/DmQCXcZxgt1BT8XJqoYq3JppeJPnk3h8dGHdPvCXGB9R
- Verification: FINAL, SuccessValue

## Test 3 — Agent Wallet Authorization

- Agent: `agent.rimbux.testnet`
- Receiver: `vault.rimbux.testnet`
- Permission: FunctionCall
- Authorized method: `execute_agent_payment`
- On-chain authorization: VERIFIED

## Test 4 — Real Agent Payment

- Recipient: `recipient.rimbux.testnet`
- Amount: 0.01 NEAR
- Intent nonce: `e2e_afb7ca61651b28ea`
- Transaction:
  https://testnet.nearblocks.io/txns/8Z4eHUx7M2pWG3H7XUgX2QLtym7VZtTtWTi1gDboq6Aq
- Final execution status: FINAL
- Transaction status: SuccessValue
- Payment status from contract: CONFIRMED

### Recipient Balance Verification

- Initial funded balance: 0.1 NEAR
- Payment received: 0.01 NEAR
- Final observed balance: 0.11 NEAR
- Finalized block height: 276365810

### Vault Spending Verification

- Daily spend before payment: 0.001 NEAR
- Daily spend after payment: 0.011 NEAR
- Increase: 0.01 NEAR
- Configured maximum per transaction: 1 NEAR
- Configured daily limit: 3 NEAR

## Evidence Scope

This document records actual NEAR Testnet transactions and finalized account state.

NEAR Sandbox tests are separate evidence and must not be presented as real Testnet transactions.

## Security Notes

- No private keys or `.env` contents belong in this document.
- Testnet only. Do not interpret this evidence as mainnet deployment.
- A successful payment does not by itself prove every security scenario; adversarial tests are documented separately.

## Test 5 — Blocked Recipient Enforcement

- Recipient: `recipient.rimbux.testnet`
- Policy before attack: `allowed=true`, `blocked=true`
- Block transaction:
  https://testnet.nearblocks.io/txns/8rvejD3BRwmiu23A8fyCKFUx5X2qnrgbcBziSxSu5frM
- Block transaction status: FINAL, SuccessValue

### Rejected Agent Payment

- Attempted amount: 0.01 NEAR
- Intent nonce: `e2e_7008cc0814547ac1`
- Transaction:
  https://testnet.nearblocks.io/txns/FN1uHRLPXkNjcBXJDVPzh6ZXNkES6mmPWgDjf54xBym
- Final execution status: FINAL
- Transaction status: Failure / ActionError
- Contract rejection:
  `RIMBUX_VAULT: Destination recipient.rimbux.testnet is explicitly blocked on-chain.`
- Expected result: payment rejected by the vault contract.

### Recipient Policy Restoration

- Recipient: `recipient.rimbux.testnet`
- Restored policy: `allowed=true`, `blocked=false`
- Restoration transaction:
  https://testnet.nearblocks.io/txns/C7dqPZnznVyAEXjbAsBnbCsraQZWGWY3DwQeq6nLKJiU
- Final execution status: FINAL
- Transaction status: SuccessValue


## Test 6 — Maximum Per-Transaction Cap

- Configured maximum: 1 NEAR
- Attempted payment: 1.01 NEAR
- Recipient: `recipient.rimbux.testnet`
- Intent nonce: `e2e_2c198b7070683392`
- Transaction:
  https://testnet.nearblocks.io/txns/CyR5chUxmWYKYoDybF3CGUWVDjytyf68nQFWNsACs85y
- Final execution status: FINAL
- Transaction status: Failure / ActionError
- Contract rejection:
  `RIMBUX_VAULT: Amount exceeds on-chain maximum per-transaction cap.`
- Expected result: payment rejected by the vault contract.
