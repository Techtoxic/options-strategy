# Options Strategy — Live FX/XAU Options Chain Dashboard

Real-time options chain viewer (strikes, deltas, IV, put/call prices) for FX pairs
and XAU/USD, sourced directly from a live pricing API — no browser automation,
no scraping.

## Local run

```bash
pip install -r requirements.txt
python scraper_api.py
```

Open http://localhost:8080

Optional flags:
```bash
python scraper_api.py --pair EUR-USD --expiry 1W --interval 1
```

## Deploy on Render

1. Push this repo to GitHub.
2. In Render: **New +** → **Blueprint** → connect this repo. Render will read
   `render.yaml` and provision both the web service and the keep-alive cron job.
3. After the web service deploys, copy its URL (e.g. `https://options-strategy.onrender.com`).
4. Go to the `options-strategy-keepalive` cron job → **Environment** → set
   `PING_URL` to `https://options-strategy.onrender.com/healthz`.

Render's free tier spins down web services after ~15 minutes idle. The cron
job pings `/healthz` every 10 minutes to keep it warm. If you're on a paid
plan this isn't needed, but it's harmless either way.

## Endpoints

| Route | Purpose |
|---|---|
| `/` | Dashboard UI |
| `/options_live.json` | Current chain data (polled by the frontend) |
| `/config` | POST to switch pair/expiry/refresh interval |
| `/healthz` | Uptime check — used by the keep-alive cron job |

## Notes

- The `.cert_cache/` folder is generated at runtime (SSL intermediate cert
  chain workaround) and is gitignored — don't commit it.
- Credentials for the upstream pricing API are embedded in `scraper_api.py`
  as they were reverse-engineered from a public widget's own client-side
  requests, not secrets issued to this project. If they ever rotate, the
  fetch will start failing with 401/403 and need re-capturing from the
  widget's network tab.
