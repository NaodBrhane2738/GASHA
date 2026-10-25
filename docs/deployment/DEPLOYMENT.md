# Deploying GASHA (Render + Vercel)

Two pieces get deployed. The order matters because each one needs the other's URL.

| Piece | Folder | Host | Why |
| --- | --- | --- | --- |
| API (FastAPI) | `apps/api` | **Render** | Long-running process: keeps rate limits, locks and incidents in memory, streams live events (SSE), runs background tasks. Vercel's serverless functions can't do this. |
| Dashboard (Next.js) | `apps/web` | **Vercel** | Static/edge-friendly frontend. |

Whoever owns the GitHub repo should do this, because both Render and Vercel need to be
granted access to the repo. Total time: about 20 minutes.

---

## 0. Merge the code

Merge the `feature/backend-soc-monitoring` pull request into `main` (or deploy that branch
directly if you want to try it first: pick it in steps 1 and 2 instead of `main`).

---

## 1. Deploy the API on Render

1. Sign in at <https://dashboard.render.com> with GitHub.
2. **New → Blueprint**, then connect the `GASHA` repository. Render reads `render.yaml` from the repo root.
3. Pick the branch (`main`) and click **Apply**. Render creates a web service called `gasha-api`,
   installs `apps/api/requirements.txt` and starts uvicorn. It also generates random values for
   `JWT_SECRET`, `INTERNAL_API_KEY` and `GASHA_TELEMETRY_API_KEY`.
4. Wait for the deploy to go green, then copy the service URL, e.g. `https://gasha-api.onrender.com`.
5. Check it: open `https://gasha-api.onrender.com/health`. Expected:
   `{"status":"ok","service":"gasha-api","version":"0.1.0"}`

> **Free plan note:** the service sleeps after ~15 minutes without traffic and takes ~30–60 s to
> wake. Because SOC state is in memory, a restart or sleep clears incidents and locks. Use a paid
> instance for anything beyond a demo. Keep **one** instance (`numInstances: 1`).

---

## 2. Deploy the dashboard on Vercel

1. Sign in at <https://vercel.com> with GitHub. **Add New → Project**, import `GASHA`.
2. **Root Directory → Edit → `apps/web`.** (Required: this is a monorepo.) Framework preset: Next.js.
3. **Environment Variables**, add:

   | Name | Value |
   | --- | --- |
   | `NEXT_PUBLIC_API_URL` | `https://gasha-api.onrender.com/api/v1` (your Render URL + `/api/v1`) |

4. **Deploy.** Copy the production URL, e.g. `https://gasha.vercel.app`.

> `NEXT_PUBLIC_*` values are baked in at build time. If you change it later, redeploy.

---

## 3. Connect them (CORS)

Back in Render → `gasha-api` → **Environment**, edit:

| Name | Value |
| --- | --- |
| `CORS_ORIGINS` | `["https://gasha.vercel.app"]` (JSON list; add custom domains too) |
| `WEB_URL` | `https://gasha.vercel.app` (used for links in alert emails) |

Save. Render redeploys automatically.

---

## 4. Sign in to the SOC dashboard (temporary)

The SOC endpoints require an analyst bearer token, and there is no sign-in page yet. Until
there is, issue a token manually:

1. Render → `gasha-api` → **Environment** → reveal and copy `JWT_SECRET`.
2. On your own machine, from the repo:

   ```bash
   cd apps/api
   pip install -r requirements.txt
   JWT_SECRET='<paste>' python -m app.core.issue_token your-name --hours 8
   ```

3. Open `https://gasha.vercel.app/soc`, open the browser console (F12) and run:

   ```js
   sessionStorage.setItem('gasha.accessToken', '<token from step 2>'); location.reload();
   ```

The token lives only in that browser tab and expires after the hours you chose. Never post
`JWT_SECRET` or tokens in chat, issues or commits; anyone holding `JWT_SECRET` can mint tokens.

---

## 5. Optional: email alerts

High-severity enforcement (locks) sends an email. By default (`ALERT_EMAIL_PROVIDER=log`) the
alert is only written to Render's logs. To send real email, add in Render → **Environment**:

**Resend** (simplest): create an API key at resend.com and verify a sending domain, then

| Name | Value |
| --- | --- |
| `ALERT_EMAIL_PROVIDER` | `resend` |
| `RESEND_API_KEY` | `re_...` |
| `ALERT_EMAIL_FROM` | `GASHA SOC <alerts@your-verified-domain>` |
| `ALERT_EMAIL_TO` | `["oncall@example.com"]` (JSON list) |

**SMTP**: `ALERT_EMAIL_PROVIDER=smtp` plus `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USERNAME`,
`SMTP_PASSWORD`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`.

---

## 6. Optional: send telemetry from a defended app

Apps instrumented with the GASHA SDK post to `https://gasha-api.onrender.com/api/v1/telemetry/ingest`
with header `X-GASHA-TELEMETRY-KEY: <GASHA_TELEMETRY_API_KEY from Render>`. The response's
`enforcement` list tells the app which sources to throttle (429) or lock (423).

---

## Tuning (Render → Environment)

| Variable | Default | Meaning |
| --- | --- | --- |
| `SOC_RATE_LIMIT_REQUESTS` / `SOC_RATE_LIMIT_WINDOW_SECONDS` | 60 / 60 | Per-source limit before HTTP 429 |
| `SOC_ESCALATION_COUNT` | 3 | Throttle episodes (within 300 s) before HTTP 423 lock |
| `SOC_LOCK_DURATION_SECONDS` | 900 | Lock length |
| `SOC_LOCK_ON_SEVERITY` | HIGH | Findings at/above this lock immediately |
| `SOC_TRUST_PROXY_HEADERS` / `SOC_TRUSTED_PROXY_HOPS` | true / 1 on Render | Read client IP from the proxy's `X-Forwarded-For` entry |

Full list: `.env.example`. Architecture: `docs/architecture/soc-monitoring.md`.

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Dashboard shows zeros / "reconnecting…" | Check `NEXT_PUBLIC_API_URL` (needs `/api/v1`), redeploy Vercel; check step 4 token. |
| Browser console shows a CORS error | `CORS_ORIGINS` in Render must exactly match the Vercel URL (scheme, no trailing slash). |
| API returns 401 on `/soc/*` | Token missing/expired, or minted with a different `JWT_SECRET`. |
| Render deploy fails on startup with a JSON error | `CORS_ORIGINS` / `ALERT_EMAIL_TO` must be JSON lists, e.g. `["https://a.com"]`. |
| First request is slow | Free Render instance waking from sleep. |
