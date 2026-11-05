import test from "node:test";
import assert from "node:assert/strict";
import {
  createOperatorSession,
  getOperatorSessionToken,
  isOperatorSessionValid,
  revokeOperatorSession,
} from "../src/security/operatorAuth";

test("operator session creates a cryptographically random token", () => {
  const first = createOperatorSession();
  const second = createOperatorSession();

  assert.match(first.token, /^[a-f0-9]{64}$/);
  assert.match(second.token, /^[a-f0-9]{64}$/);
  assert.notEqual(first.token, second.token);
  assert.ok(first.maxAgeMs >= 60 * 60 * 1000);
  assert.ok(first.maxAgeMs <= 24 * 60 * 60 * 1000);

  revokeOperatorSession(first.token);
  revokeOperatorSession(second.token);
});

test("operator session accepts a valid token", () => {
  const session = createOperatorSession();

  assert.equal(isOperatorSessionValid(session.token), true);

  revokeOperatorSession(session.token);
});

test("operator session rejects a revoked token", () => {
  const session = createOperatorSession();

  revokeOperatorSession(session.token);

  assert.equal(isOperatorSessionValid(session.token), false);
});

test("operator session reads its token from a cookie header", () => {
  const session = createOperatorSession();

  const token = getOperatorSessionToken(
    `other=value; rimbux_operator_session=${session.token}`
  );

  assert.equal(token, session.token);

  revokeOperatorSession(session.token);
});

test("operator session rejects missing and malformed cookies", () => {
  assert.equal(getOperatorSessionToken(undefined), null);
  assert.equal(getOperatorSessionToken("other=value"), null);
  assert.equal(
    getOperatorSessionToken("rimbux_operator_session=%E0%A4%A"),
    null
  );
});
