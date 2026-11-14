# Deploying the demo on Vercel (free plan)

RIMBUX is built for a long-running server with a disk (see "Deploying" in the README).
Vercel runs it as a serverless function instead, so this works **as a public demo only**.

## What to expect

- **Data is temporary.** The SQLite file is written to the OS temp directory
  (`/tmp/rimbux-data`), because the deployment directory is read-only. Audit log,
  reservations and history reset when the function instance is recycled.
- **State lives per instance.** Operator sessions and rate limits are in memory, so two
  requests can land on different instances and see different data.
- **Keep it read-only.** Do not set `NEAR_AGENT_FUNCTION_CALL_PRIVATE_KEY` on a public demo.
  Everything stays simulated, as the README recommends for public deployments.
- Not for real funds. This is the hackathon prototype, not an audited wallet.

## Steps

1. Push this branch to GitHub and import the repository in Vercel (Framework Preset: Express,
   detected automatically). Leave the build and install commands at their defaults.
2. Add one environment variable: `RIMBUX_AUDIT_SECRET`, at least 64 characters
   (generate with `openssl rand -hex 48`). Without it every API call fails at startup.
3. Deploy. The static dashboard (`public/`) is served by Vercel's CDN; the API runs as one function.
4. Check it from outside:

   ```bash
   curl -X POST https://YOUR-PROJECT.vercel.app/api/audit/run-suite
   ```

   The response should report `"passedCount": 12`. The endpoint allows 3 calls per 5 minutes
   per client and instance, then answers `429 PUBLIC_AUDIT_RATE_LIMITED`.

## Notes

- `package.json` limits `engines.node` to `>=20 <23`. With the old open-ended `>=20`, Vercel picks
  the newest Node major (26 at the time of writing) instead of 22, which CI uses.
- `RIMBUX_DATA_DIR` overrides the database folder on any platform.
- Prefer a Git-connected deploy. If you use `vercel deploy` from your computer, `.vercelignore`
  keeps `.env` and `data/` out of the upload; avoid `--prebuilt` from a checkout that has real data.
