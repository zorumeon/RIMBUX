import {
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import type { RequestHandler } from "express";

const COOKIE_NAME = "rimbux_operator_session";
const DEFAULT_TTL_HOURS = 8;

const sessions = new Map<string, number>();

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;

    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return null;
      }
    }
  }

  return null;
}

export function verifyOperatorPassword(password: string): boolean {
  const configuredHash = process.env.RIMBUX_OPERATOR_PASSWORD_HASH;
  if (!configuredHash) return false;

  const separator = configuredHash.indexOf(":");
  if (separator < 1) return false;

  const salt = configuredHash.slice(0, separator);
  const expectedHex = configuredHash.slice(separator + 1);

  if (!/^[a-f0-9]{128}$/i.test(expectedHex)) return false;

  try {
    const expected = Buffer.from(expectedHex, "hex");
    const actual = scryptSync(password, salt, expected.length);

    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function createOperatorSession(): {
  token: string;
  maxAgeMs: number;
} {
  const configuredHours = Number(process.env.RIMBUX_SESSION_TTL_HOURS);
  const ttlHours =
    Number.isFinite(configuredHours) && configuredHours >= 1 && configuredHours <= 24
      ? configuredHours
      : DEFAULT_TTL_HOURS;

  const maxAgeMs = ttlHours * 60 * 60 * 1000;
  const token = randomBytes(32).toString("hex");

  sessions.set(hashToken(token), Date.now() + maxAgeMs);

  return { token, maxAgeMs };
}

export function getOperatorSessionToken(
  cookieHeader: string | undefined
): string | null {
  return readCookie(cookieHeader, COOKIE_NAME);
}

export function isOperatorSessionValid(token: string | null): boolean {
  if (!token) return false;

  clearExpiredOperatorSessions();

  const expiresAt = sessions.get(hashToken(token));
  return Boolean(expiresAt && expiresAt > Date.now());
}

export function revokeOperatorSession(token: string | null): void {
  if (token) sessions.delete(hashToken(token));
}

export function clearExpiredOperatorSessions(): void {
  const now = Date.now();

  for (const [tokenHash, expiresAt] of sessions) {
    if (expiresAt <= now) sessions.delete(tokenHash);
  }
}

export const requireOperator: RequestHandler = (req, res, next) => {
  clearExpiredOperatorSessions();

  const token = getOperatorSessionToken(req.headers.cookie);
  if (!token) {
    res.status(401).json({ error: "OPERATOR_AUTH_REQUIRED" });
    return;
  }

  const expiresAt = sessions.get(hashToken(token));
  if (!expiresAt || expiresAt <= Date.now()) {
    revokeOperatorSession(token);
    res.status(401).json({ error: "OPERATOR_SESSION_EXPIRED" });
    return;
  }

  next();
};

export const requireSameOrigin: RequestHandler = (req, res, next) => {
  const origin = req.get("origin");
  const host = req.get("host");

  if (!origin || !host) {
    res.status(403).json({ error: "ORIGIN_CHECK_FAILED" });
    return;
  }

  try {
    const parsedOrigin = new URL(origin);

    if (
      (parsedOrigin.protocol !== "http:" && parsedOrigin.protocol !== "https:") ||
      parsedOrigin.host !== host
    ) {
      res.status(403).json({ error: "CROSS_ORIGIN_REQUEST_BLOCKED" });
      return;
    }
  } catch {
    res.status(403).json({ error: "INVALID_ORIGIN" });
    return;
  }

  next();
};

export function getOperatorCookieName(): string {
  return COOKIE_NAME;
}
