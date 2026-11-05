export type PolicyValidation =
  | { valid: true }
  | { valid: false; error: string; field?: string };

export function validatePolicyUpdate(body: unknown): PolicyValidation {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { valid: false, error: "INVALID_POLICY_PAYLOAD" };
  }

  const value = body as Record<string, unknown>;
  const allowed = new Set([
    "maxTransactionAmountNear",
    "dailySpendingLimitNear",
    "emergencyLockdown",
  ]);

  const keys = Object.keys(value);
  if (keys.length === 0 || keys.some((key) => !allowed.has(key))) {
    return { valid: false, error: "INVALID_POLICY_FIELDS" };
  }

  for (const key of ["maxTransactionAmountNear", "dailySpendingLimitNear"]) {
    if (key in value && (
      typeof value[key] !== "number" ||
      !Number.isFinite(value[key]) ||
      value[key] <= 0
    )) {
      return { valid: false, error: "INVALID_SPENDING_LIMIT", field: key };
    }
  }

  if ("emergencyLockdown" in value && typeof value.emergencyLockdown !== "boolean") {
    return { valid: false, error: "INVALID_LOCKDOWN_VALUE" };
  }

  return { valid: true };
}
