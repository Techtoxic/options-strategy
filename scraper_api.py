# -*- coding: utf-8 -*-
"""
Real-time Options Chain Dashboard — Direct API version.
No browser, no Playwright, no DOM scraping.
Talks directly to widget2.sentryd.com's Pricing API.
"""

import argparse
import asyncio
import json
import os
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
import certifi
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

# -- SSL fix: widget2.sentryd.com's server doesn't send its full chain
# (missing intermediate CA), which browsers work around via AIA chasing
# but Python's ssl module does not. We replicate AIA chasing here.
_CERT_CACHE_DIR = Path(__file__).parent / ".cert_cache"
MAX_CHAIN_HOPS = 5

def _fetch_der_cert(host: str, port: int = 443) -> bytes:
    import socket
    print(f"[SSL SETUP] Connecting to {host}:{port} to read leaf cert...")
    ctx = ssl._create_unverified_context()
    sock = socket.create_connection((host, port), timeout=8)
    sock.settimeout(8)
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=True)
            print("[SSL SETUP] Leaf cert obtained.")
            return cert
    finally:
        try:
            sock.close()
        except Exception:
            pass

def _aia_issuer_url(cert: x509.Certificate):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None

def _walk_chain_and_build_bundle(host: str) -> str:
    with open(certifi.where(), "r") as f:
        bundle = f.read()

    collected_pems = []
    try:
        der = _fetch_der_cert(host)
        cert = x509.load_der_x509_certificate(der, default_backend())

        for hop in range(MAX_CHAIN_HOPS):
            url = _aia_issuer_url(cert)
            if not url:
                print(f"[SSL SETUP] No further AIA issuer URL at hop {hop} — chain complete.")
                break
            print(f"[SSL SETUP] Hop {hop}: fetching intermediate from {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                issuer_der = resp.read()
            issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
            pem = issuer_cert.public_bytes(Encoding.PEM).decode()
            collected_pems.append(pem)
            print(f"[SSL SETUP] Hop {hop}: got intermediate, subject={issuer_cert.subject.rfc4514_string()}")

            if issuer_cert.subject == issuer_cert.issuer:
                print("[SSL SETUP] Reached self-signed root — stopping.")
                break
            cert = issuer_cert

    except Exception as e:
        print(f"[SSL SETUP] AIA chase failed ({type(e).__name__}): {e}")
        print("[SSL SETUP] Falling back to certifi-only bundle — connection may still fail.")

    return bundle + "\n" + "\n".join(collected_pems)

def build_ssl_context() -> ssl.SSLContext:
    _CERT_CACHE_DIR.mkdir(exist_ok=True)
    combined_path = _CERT_CACHE_DIR / "combined_ca_bundle.pem"

    if not combined_path.exists():
        bundle_text = _walk_chain_and_build_bundle("widget2.sentryd.com")
        with open(combined_path, "w") as f:
            f.write(bundle_text)
        print(f"[SSL SETUP] Built combined trust bundle at {combined_path}")

    return ssl.create_default_context(cafile=str(combined_path))

# -- Constants --------------------------------------------------------------
PRICING_URL = "https://widget2.sentryd.com/widget/sentry/api/Pricing"

# Confirmed via raw captured browser request — decodes to
# currency_widget:currency_widget. Specific to /sentry/api/Pricing.
AUTH_HEADER = "Basic Y3VycmVuY3lfd2lkZ2V0OmN1cnJlbmN5X3dpZGdldA=="

POST_ACCESS_CODE = "sentryPricingApi"

def get_post_access_password() -> str:
    """
    The access password rotates daily: 'sentrypricingapi_' + day-of-year (UTC).
    Confirmed empirically:
      - 2026-07-21 (day 202, UTC) used suffix '_202'
      - 2026-08-06 (day 218, UTC) used suffix '_218'
    Not zero-padded based on observed 3-digit values. If single/double-digit
    early-year days ever fail, try zero-padding to 3 digits as a fallback.
    """
    day_of_year = datetime.now(timezone.utc).timetuple().tm_yday
    return f"sentrypricingapi_{day_of_year}"

PRODUCTS = [
    "EUR/USD", "USD/JPY", "GBP/USD", "USD/CHF", "USD/CAD",
    "AUD/USD", "NZD/USD", "EUR/CAD", "EUR/CHF", "EUR/GBP",
    "EUR/JPY", "EUR/AUD", "GBP/JPY", "USD/CNH", "USD/ILS",
    "USD/MXN", "USD/TRY", "XAU/USD",
]

def to_api_pair(pair: str) -> str:
    return pair.replace("-", "/")

TENOR_MAP = {
    "O/N": "ON", "1W": "1W", "2W": "2W",
    "1M":  "1M", "2M": "2M", "3M": "3M",
    "6M":  "6M", "12M": "12M",
}

PORT         = int(os.environ.get("PORT", 8080))
MIN_INTERVAL = 0.2

# -- API fetch ---------------------------------------------------------------
async def fetch_pricing(session: aiohttp.ClientSession) -> dict:
    """Fetch the full pricing surface for ALL products in one call."""
    headers = {
        "Authorization":   AUTH_HEADER,
        "Content-Type":    "application/x-www-form-urlencoded",
        "Accept":          "*/*",
        "Origin":          "https://widget2.sentryd.com",
        "Referer":         "https://widget2.sentryd.com/widget/",
        "Sec-Fetch-Dest":  "empty",
        "Sec-Fetch-Mode":  "cors",
        "Sec-Fetch-Site":  "same-origin",
        "Cache-Control":   "no-cache",
        "Pragma":          "no-cache",
        "User-Agent":      (
            "Mozilla/5.0 (Linux; Android 8.0.0; SM-G955U Build/R16NW) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/147.0.0.0 Mobile Safari/537.36"
        ),
    }
    payload = {
        "Type":                "Pricing",
        "Products":            ",".join(PRODUCTS),
        "POSTAccessCode":      POST_ACCESS_CODE,
        "POSTAccessPassword":  get_post_access_password(),
        "timestamp":           str(int(time.time() * 1000)),
    }

    # Cache-bust via URL query param too, in case a CDN/reverse-proxy in
    # front of the API caches by URL+body and ignores the body's timestamp
    # field for cache-key purposes.
    url = f"{PRICING_URL}?_cb={int(time.time() * 1000)}"

    async with session.post(url, headers=headers, data=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
        if resp.status != 200:
            body_text = await resp.text()
            print(f"[FETCH ERROR] Status {resp.status}. Response headers: {dict(resp.headers)}")
            print(f"[FETCH ERROR] Response body: {body_text[:500]}")
            resp.raise_for_status()

        result = await resp.json()

        # Server double-encodes: outer layer is JSON, but the value is
        # itself a JSON string that needs a second parse.
        if isinstance(result, str):
            result = json.loads(result)

        return result

# Fast spot feed — confirmed via Network tab to update every few seconds,
# unlike Pricing which is a rare/heavy full-chain recalculation.
INSTRUMENTS_URL = "https://widget2.sentryd.com/widget/api/instruments/latest/" + \
    ",".join(p.replace("/", "_") for p in [
        "EUR/USD", "USD/JPY", "GBP/USD", "USD/CHF", "USD/CAD",
        "AUD/USD", "NZD/USD", "EUR/CAD", "EUR/CHF", "EUR/GBP",
        "EUR/JPY", "EUR/AUD", "GBP/JPY", "USD/CNH", "USD/ILS",
        "USD/MXN", "USD/TRY", "XAU/USD",
    ])

async def fetch_spots(session: aiohttp.ClientSession) -> dict:
    """
    Fetch just the live spot prices — this endpoint updates every few
    seconds (confirmed via Network tab), unlike Pricing which only
    recalculates the full chain rarely. Returns {pair: mid_price}.
    """
    headers = {
        "Authorization":  AUTH_HEADER,
        "Accept":         "*/*",
        "Origin":         "https://widget2.sentryd.com",
        "Referer":        "https://widget2.sentryd.com/widget/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent":     (
            "Mozilla/5.0 (Linux; Android 8.0.0; SM-G955U Build/R16NW) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/147.0.0.0 Mobile Safari/537.36"
        ),
    }
    url = f"{INSTRUMENTS_URL}?ts={int(time.time() * 1000)}"

    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
        resp.raise_for_status()
        result = await resp.json()
        if isinstance(result, str):
            result = json.loads(result)

    spots = {}
    for api_pair, info in result.items():
        currency = info.get("currency")  # mid price field, per earlier capture
        if currency is not None:
            spots[api_pair] = float(currency)
    return spots

def extract_chain(raw: dict, pair: str, expiry: str) -> dict:
    """Pull one product/tenor's chain out of the full Pricing response."""
    api_pair   = to_api_pair(pair)
    tenor_code = TENOR_MAP.get(expiry, "ON")

    products = raw.get("Products", [])
    product = next((p for p in products if p.get("Product") == api_pair), None)

    if product is None:
        return {
            "pair": pair, "expiry": expiry, "spot": None,
            "chain": [], "ready": True,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    spot_data = product.get("Spot", {})
    spot_bid = spot_data.get("Bid", {}).get("Rate")
    spot_ask = spot_data.get("Ask", {}).get("Rate")
    spot = None
    if spot_bid is not None and spot_ask is not None:
        spot = (spot_bid + spot_ask) / 2

    upstream_ts = product.get("TradeDate")
    print(f"[EXTRACT] {pair} upstream TradeDate={upstream_ts} bid={spot_bid} ask={spot_ask} spot={spot}")

    tenor = next((t for t in product.get("Tenors", []) if t.get("Tenor") == tenor_code), None)
    chain = []
    if tenor:
        for sp in tenor.get("StrikePrices", []):
            try:
                put_bid  = sp["Put"]["Bid"]
                put_ask  = sp["Put"]["Ask"]
                call_bid = sp["Call"]["Bid"]
                call_ask = sp["Call"]["Ask"]

                # CoreRate is more precise than Rate (Rate appears rounded/
                # display-truncated in some captures, e.g. 0.0 vs 0.000054).
                put_price  = (put_bid.get("CoreRate", put_bid["Rate"])  + put_ask.get("CoreRate", put_ask["Rate"]))  / 2
                call_price = (call_bid.get("CoreRate", call_bid["Rate"]) + call_ask.get("CoreRate", call_ask["Rate"])) / 2

                # Bid and Ask carry meaningfully different Greeks/Volatility
                # (wide spread), and the widget appears to display mid-market
                # values rather than bid-side only. Average both sides.
                put_delta_bid  = put_bid["Greeks"]["Delta"]
                put_delta_ask  = put_ask["Greeks"]["Delta"]
                call_delta_bid = call_bid["Greeks"]["Delta"]
                call_delta_ask = call_ask["Greeks"]["Delta"]
                put_delta  = (put_delta_bid  + put_delta_ask)  / 2
                call_delta = (call_delta_bid + call_delta_ask) / 2

                iv_bid = put_bid.get("Volatility", 0)
                iv_ask = put_ask.get("Volatility", 0)
                iv = ((iv_bid + iv_ask) / 2) * 100

                chain.append({
                    "put_delta":  round(put_delta, 4),
                    "put_price":  round(put_price, 6),
                    "strike":     round(sp["Strike"], 6),
                    "call_price": round(call_price, 6),
                    "call_delta": round(call_delta, 4),
                    "iv":         f"{iv:.2f}%",
                    "iv_float":   round(iv, 2),
                })
            except (KeyError, TypeError):
                continue

    return {
        "pair":      pair,
        "expiry":    expiry,
        "spot":      spot,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "chain":     chain,
        "ready":     True,
    }

# -- State & background poller -----------------------------------------------
scraper_state = {
    "pair":         "XAU-USD",
    "expiry":       "O/N",
    "interval":     1.0,
    "data":         None,
    "running":      True,
    "raw_cache":    None,
    "raw_cache_ts": 0,
    "live_spots":   {},   # api_pair -> latest mid price, updated frequently
}

_wakeup     = asyncio.Event()
_state_lock = asyncio.Lock()

CHAIN_REFRESH_INTERVAL = 15.0  # Pricing endpoint is heavier than instruments/latest,
                                 # but 60s left the chain (deltas/IV) visibly stale
                                 # relative to the live spot. 15s balances freshness
                                 # against not hammering an endpoint the widget itself
                                 # treats as expensive.

async def _build_ssl_context_safe():
    try:
        loop = asyncio.get_event_loop()
        ssl_ctx = await asyncio.wait_for(
            loop.run_in_executor(None, build_ssl_context),
            timeout=20.0,
        )
        print("[POLLER] SSL context ready.")
        return ssl_ctx
    except asyncio.TimeoutError:
        print("[POLLER] SSL setup timed out after 20s — falling back to plain certifi context.")
        return ssl.create_default_context(cafile=certifi.where())
    except Exception as e:
        print(f"[POLLER] SSL setup failed ({type(e).__name__}: {e}) — falling back to plain certifi context.")
        return ssl.create_default_context(cafile=certifi.where())

async def spot_poller_task(session: aiohttp.ClientSession):
    """Fast loop — refreshes live spot prices for all pairs frequently."""
    print("[SPOT POLLER] Starting.")
    while scraper_state["running"]:
        async with _state_lock:
            interval = scraper_state["interval"]

        try:
            spots = await fetch_spots(session)
            async with _state_lock:
                scraper_state["live_spots"] = spots

                # If we already have chain data for the current pair, patch
                # its spot in place so the frontend sees a live-moving spot
                # even between full chain recalculations.
                data = scraper_state["data"]
                if data is not None:
                    api_pair = to_api_pair(scraper_state["pair"])
                    fresh_spot = spots.get(api_pair)
                    if fresh_spot is not None:
                        data["spot"] = fresh_spot

            print(f"[SPOT] fetched {len(spots)} pairs, XAU/USD={spots.get('XAU/USD')}")

        except Exception as e:
            print(f"[SPOT ERROR] {e}")

        await asyncio.sleep(max(MIN_INTERVAL, interval))

async def chain_poller_task(session: aiohttp.ClientSession):
    """Slow loop — refreshes the full options chain (strikes/deltas/IV/Greeks)."""
    print("[CHAIN POLLER] Starting.")
    while scraper_state["running"]:
        async with _state_lock:
            pair   = scraper_state["pair"]
            expiry = scraper_state["expiry"]

        try:
            raw = await fetch_pricing(session)
            data = extract_chain(raw, pair, expiry)

            async with _state_lock:
                if scraper_state["pair"] == pair and scraper_state["expiry"] == expiry:
                    # Overlay the freshest known spot immediately, in case
                    # the spot poller has more recent data than this chain
                    # snapshot's embedded spot.
                    api_pair = to_api_pair(pair)
                    fresher = scraper_state["live_spots"].get(api_pair)
                    if fresher is not None:
                        data["spot"] = fresher

                    scraper_state["data"]         = data
                    scraper_state["raw_cache"]    = raw
                    scraper_state["raw_cache_ts"] = time.time()

            print(f"[CHAIN] {pair} {expiry} spot={data['spot']} rows={len(data['chain'])}")

        except Exception as e:
            print(f"[CHAIN ERROR] {e}")

        try:
            await asyncio.wait_for(_wakeup.wait(), timeout=CHAIN_REFRESH_INTERVAL)
        except asyncio.TimeoutError:
            pass
        finally:
            _wakeup.clear()

async def poller_task():
    """Sets up shared SSL/session, then runs fast spot + slow chain loops concurrently."""
    print("[POLLER] Starting poller_task, building SSL context...")
    ssl_ctx = await _build_ssl_context_safe()

    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        print("[POLLER] Session ready, launching spot + chain loops.")
        await asyncio.gather(
            spot_poller_task(session),
            chain_poller_task(session),
        )

async def apply_config(new_pair=None, new_expiry=None, new_interval=None):
    async with _state_lock:
        if new_pair:
            scraper_state["pair"] = new_pair
        if new_expiry:
            scraper_state["expiry"] = new_expiry
        if new_interval is not None:
            scraper_state["interval"] = max(MIN_INTERVAL, float(new_interval))

        raw = scraper_state["raw_cache"]
        if raw is not None and (time.time() - scraper_state["raw_cache_ts"]) < 2.0:
            data = extract_chain(raw, scraper_state["pair"], scraper_state["expiry"])
            fresher = scraper_state["live_spots"].get(to_api_pair(scraper_state["pair"]))
            if fresher is not None:
                data["spot"] = fresher
            scraper_state["data"] = data
        else:
            scraper_state["data"] = None

    _wakeup.set()
    print(f"[CONFIG] {scraper_state['pair']} / {scraper_state['expiry']} @ {scraper_state['interval']}s")

# -- HTTP server --------------------------------------------------------------
async def healthz(request):
    """Lightweight endpoint for uptime pings / cron jobs to prevent Render free-tier sleep."""
    return web.json_response({
        "status": "ok",
        "time":   datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "pair":   scraper_state["pair"],
        "expiry": scraper_state["expiry"],
    })

async def index(request):
    html_path = Path(__file__).parent / "dashboard.html"
    if html_path.exists():
        return web.FileResponse(html_path)
    return web.Response(text="dashboard.html not found.", content_type="text/html")

async def get_data(request):
    async with _state_lock:
        data = scraper_state["data"]
        if data is None:
            payload = {"ready": False, "pair": scraper_state["pair"], "expiry": scraper_state["expiry"]}
        else:
            payload = data
    return web.json_response(payload, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache", "Expires": "0",
    })

async def set_config(request):
    try:
        body     = await request.json()
        pair     = body.get("pair")
        expiry   = body.get("expiry")
        interval = body.get("interval")

        if pair and to_api_pair(pair) not in PRODUCTS:
            return web.json_response({"error": f"Unknown pair: {pair}"}, status=400)
        if expiry and expiry not in TENOR_MAP:
            return web.json_response({"error": f"Unknown expiry: {expiry}"}, status=400)
        if interval is not None:
            interval = float(interval)
            if interval < MIN_INTERVAL or interval > 300:
                return web.json_response({"error": f"Interval must be {MIN_INTERVAL}-300"}, status=400)

        await apply_config(pair, expiry, interval)
        return web.json_response({
            "status": "ok", "pair": scraper_state["pair"],
            "expiry": scraper_state["expiry"], "interval": scraper_state["interval"],
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

async def start_server():
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/options_live.json", get_data)
    app.router.add_post("/config", set_config)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    print(f"\n\033[1;32mDashboard -> http://0.0.0.0:{PORT}\033[0m\n")
    return runner

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pair", default="XAU-USD")
    parser.add_argument("--expiry", default="O/N")
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()

    scraper_state.update({
        "pair": args.pair, "expiry": args.expiry,
        "interval": max(MIN_INTERVAL, args.interval),
    })

    poll_task = asyncio.create_task(poller_task())
    runner    = await start_server()

    try:
        await poll_task
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
