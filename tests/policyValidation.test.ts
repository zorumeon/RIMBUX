import test from "node:test";
import assert from "node:assert/strict";
import { validatePolicyUpdate } from "../src/security/policyValidation";

test("policy accepts valid positive spending limits", () => {
  assert.deepEqual(
    validatePolicyUpdate({
      maxTransactionAmountNear: 1,
      dailySpendingLimitNear: 5,
    }),
    { valid: true }
  );
});

test("policy accepts boolean lockdown updates", () => {
  assert.deepEqual(validatePolicyUpdate({ emergencyLockdown: true }), { valid: true });
  assert.deepEqual(validatePolicyUpdate({ emergencyLockdown: false }), { valid: true });
});

test("policy rejects zero and negative spending limits", () => {
  for (const value of [0, -1]) {
    assert.equal(
      validatePolicyUpdate({ maxTransactionAmountNear: value }).valid,
      false
    );
  }
});

test("policy rejects non-finite and non-number spending limits", () => {
  for (const value of [NaN, Infinity, "2", null]) {
    assert.equal(
      validatePolicyUpdate({ dailySpendingLimitNear: value }).valid,
      false
    );
  }
});

test("policy rejects non-boolean lockdown values", () => {
  for (const value of ["true", 1, null]) {
    assert.equal(
      validatePolicyUpdate({ emergencyLockdown: value }).valid,
      false
    );
  }
});

test("policy rejects empty, array, null and unknown-field payloads", () => {
  for (const value of [{}, [], null, { unexpected: true }]) {
    assert.equal(validatePolicyUpdate(value).valid, false);
  }
});

test("policy accepts partial updates", () => {
  assert.deepEqual(
    validatePolicyUpdate({ dailySpendingLimitNear: 3 }),
    { valid: true }
  );
});
