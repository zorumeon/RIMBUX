// Generates a value for RIMBUX_OPERATOR_PASSWORD_HASH.
// Usage: node scripts/hash-operator-password.js "<password>"
const { randomBytes, scryptSync } = require("node:crypto");

const password = process.argv[2];
if (!password || password.length > 256) {
  console.error('Usage: node scripts/hash-operator-password.js "<password>" (1-256 characters)');
  process.exit(1);
}

const salt = randomBytes(16).toString("hex");
const hash = scryptSync(password, salt, 64).toString("hex");
console.log(`${salt}:${hash}`);
