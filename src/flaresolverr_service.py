import asyncio
import json
import logging
import os
import platform
import sys
import time
from datetime import timedelta
from html import escape
from urllib.parse import unquote, quote, urlparse
from typing import Optional

from func_timeout import FunctionTimedOut, func_timeout
from pydoll.browser import Chrome
from pydoll.browser.tab import Tab

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage, run_in_background_loop

# Track whether we've run diagnostics this session (only need once)
_diagnostics_logged = False

# Base directory for user data dirs (cookie persistence)
USER_DATA_BASE_DIR = os.environ.get('USER_DATA_DIR', '/tmp/flaresolverr-sessions')

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare
    'Just a moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]

TURNSTILE_SELECTORS = [
    "input[name='cf-turnstile-response']"
]

SHORT_TIMEOUT = 1
CHALLENGE_RELOAD_AFTER = 10  # Reload page after this many stuck challenge attempts
SESSIONS_STORAGE = SessionsStorage()


async def _navigate_with_cf_bypass(tab: Tab, url: str, has_cf_cookie: bool = False):
    """
    Navigate to URL. Always try direct navigation first, then detect if CF bypass needed.
    """
    # Log current state before navigation
    current_url = None
    try:
        current_url = await tab.current_url
        logging.debug(f"Current URL before navigation: {current_url}")
    except Exception as e:
        logging.debug(f"Could not get current URL: {e}")

    if has_cf_cookie:
        logging.debug(f"Has cf_clearance cookie, expecting no challenge")

    # If we're already on the target URL with a valid cookie, just refresh
    # This avoids potential proxy/network issues from full navigation
    same_url = current_url and current_url.rstrip('/') == url.rstrip('/')
    if same_url and has_cf_cookie:
        logging.debug("Already on target URL with cookie, refreshing page")
        try:
            await asyncio.wait_for(tab.refresh(), timeout=20)
        except asyncio.TimeoutError:
            raise Exception("Page refresh timed out")
    else:
        # Full navigation
        try:
            await asyncio.wait_for(tab.go_to(url), timeout=20)
        except asyncio.TimeoutError:
            raise Exception("Page load timed out")

    # Check page title for challenge
    try:
        title_result = await tab.execute_script('return document.title')
        page_title = title_result.get('result', {}).get('result', {}).get('value', '')
        cf_challenge = any(t.lower() in page_title.lower() for t in CHALLENGE_TITLES)
    except Exception as e:
        logging.debug(f"Could not check page title: {e}")
        return

    # If we have cf_clearance but still got challenged, the cookie is invalid (IP changed)
    if cf_challenge and has_cf_cookie:
        logging.warning(f"CF challenge despite having cf_clearance cookie - IP likely changed, will re-solve")
        has_cf_cookie = False  # Treat as if we don't have a valid cookie

    # Try to solve challenge if detected
    if cf_challenge:
        logging.info(f"Cloudflare challenge detected (title: {page_title}), attempting bypass...")
        try:
            async with tab.expect_and_bypass_cloudflare_captcha(
                time_before_click=2,
                time_to_wait_captcha=15,
            ):
                await asyncio.wait_for(tab.go_to(url), timeout=30)
            # Note: pydoll's bypass exits successfully even if it didn't find/click the captcha
            # The actual success is verified below by checking if challenge title changed
            logging.debug("Pydoll bypass context exited (does not guarantee success)")
        except asyncio.TimeoutError:
            logging.warning("Cloudflare bypass navigation timed out")
        except Exception as e:
            logging.debug(f"Cloudflare bypass error: {e}")


async def _log_browser_diagnostics(tab: Tab):
    """Log browser fingerprint properties for debugging environment differences."""
    try:
        diag_js = """
        (function() {
            var d = {};
            try { d.userAgent = navigator.userAgent; } catch(e) { d.userAgent = 'error'; }
            try { d.platform = navigator.platform; } catch(e) { d.platform = 'error'; }
            try { d.hardwareConcurrency = navigator.hardwareConcurrency; } catch(e) { d.hardwareConcurrency = 'error'; }
            try { d.deviceMemory = navigator.deviceMemory; } catch(e) { d.deviceMemory = 'N/A'; }
            try { d.languages = navigator.languages.join(','); } catch(e) { d.languages = 'error'; }
            try { d.pluginCount = navigator.plugins.length; } catch(e) { d.pluginCount = 'error'; }
            try { d.screenRes = screen.width + 'x' + screen.height; } catch(e) { d.screenRes = 'error'; }
            try { d.colorDepth = screen.colorDepth; } catch(e) { d.colorDepth = 'error'; }
            try { d.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch(e) { d.timezone = 'error'; }
            try {
                var canvas = document.createElement('canvas');
                var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    d.webglVendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'no debug ext';
                    d.webglRenderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'no debug ext';
                } else { d.webglVendor = 'no webgl'; d.webglRenderer = 'no webgl'; }
            } catch(e) { d.webglVendor = 'error'; d.webglRenderer = 'error'; }
            try {
                var c = document.createElement('canvas');
                c.width = 200; c.height = 50;
                var ctx = c.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(0, 0, 200, 50);
                ctx.fillStyle = '#069';
                ctx.fillText('fingerprint', 2, 15);
                d.canvasHash = c.toDataURL().length;
            } catch(e) { d.canvasHash = 'error'; }
            try { d.webdriver = navigator.webdriver; } catch(e) { d.webdriver = 'error'; }
            try { d.maxTouchPoints = navigator.maxTouchPoints; } catch(e) { d.maxTouchPoints = 'error'; }
            return JSON.stringify(d);
        })()
        """
        result = await tab.execute_script(diag_js)
        diag_str = result.get('result', {}).get('result', {}).get('value', '{}')
        diag = json.loads(diag_str)
        logging.info(f"Browser diagnostics: platform={diag.get('platform')}, "
                     f"cores={diag.get('hardwareConcurrency')}, "
                     f"memory={diag.get('deviceMemory')}GB, "
                     f"screen={diag.get('screenRes')}, "
                     f"webdriver={diag.get('webdriver')}, "
                     f"webgl={diag.get('webglRenderer')}, "
                     f"canvas_len={diag.get('canvasHash')}, "
                     f"plugins={diag.get('pluginCount')}, "
                     f"tz={diag.get('timezone')}, "
                     f"langs={diag.get('languages')}, "
                     f"touch={diag.get('maxTouchPoints')}")
    except Exception as e:
        logging.warning(f"Could not collect browser diagnostics: {e}")


async def _verify_proxy(tab: Tab, expected_proxy: dict = None):
    """Check the browser's apparent external IP to verify proxy is working."""
    try:
        # Navigate to a lightweight IP check endpoint
        await asyncio.wait_for(tab.go_to('https://httpbin.org/ip'), timeout=15)
        await asyncio.sleep(1)

        result = await tab.execute_script('return document.body.innerText')
        body = result.get('result', {}).get('result', {}).get('value', '')
        try:
            ip_data = json.loads(body)
            external_ip = ip_data.get('origin', 'unknown')
        except (json.JSONDecodeError, ValueError):
            external_ip = body.strip()[:100]

        logging.info(f"Proxy verification: external IP = {external_ip}")
        if expected_proxy and expected_proxy.get('url'):
            logging.info(f"Proxy verification: configured proxy = {expected_proxy['url']}")

        # Navigate back to blank page to clean state
        await tab.go_to('about:blank')
        await asyncio.sleep(0.5)
        return external_ip
    except asyncio.TimeoutError:
        logging.warning("Proxy verification: timeout checking external IP (proxy may be blocking httpbin)")
        try:
            await tab.go_to('about:blank')
        except Exception:
            pass
        return None
    except Exception as e:
        logging.warning(f"Proxy verification: error checking external IP: {e}")
        try:
            await tab.go_to('about:blank')
        except Exception:
            pass
        return None


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None or chrome_exe_path == '':
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.warning("Chrome / Chromium version not detected!")
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    # Log response without HTML content to keep logs readable
    res_summary = {
        'status': res.status,
        'message': res.message,
        'cookies': [c.get('name') for c in (res.solution.cookies if res.solution and res.solution.cookies else [])] if hasattr(res, 'solution') and res.solution else [],
    }
    logging.debug(f"Response => POST /v1 summary: {res_summary}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def cleanup_auto_sessions() -> int:
    """Cleanup stale auto-sessions"""
    try:
        cleaned = SESSIONS_STORAGE.cleanup_stale_sessions()
        if cleaned > 0:
            logging.info(f"Cleaned up {cleaned} stale auto-sessions")
        return cleaned
    except Exception as e:
        logging.error(f"Error during auto-session cleanup: {e}")
        return 0


def _get_cookie_file_for_url(url: str) -> Optional[str]:
    """Get a cookie file path for cookie persistence based on domain."""
    auto_session_enabled = utils.get_env_bool('AUTO_SESSION_MANAGEMENT', False)
    if not auto_session_enabled:
        return None

    try:
        domain = urlparse(url).netloc
        if not domain:
            return None
        # Sanitize domain for filesystem
        safe_domain = domain.replace(':', '_').replace('/', '_')
        cookie_dir = os.path.join(USER_DATA_BASE_DIR, 'cookies')
        os.makedirs(cookie_dir, exist_ok=True)
        return os.path.join(cookie_dir, f'{safe_domain}.json')
    except Exception as e:
        logging.warning(f"Error getting cookie file path: {e}")
        return None


def _load_cf_cookies_from_file(cookie_file: str) -> list:
    """Load cookies from a JSON file, but ONLY if it contains cf_clearance."""
    import json
    try:
        if os.path.exists(cookie_file):
            with open(cookie_file, 'r') as f:
                cookies = json.load(f)
                # Only return cookies if we have a cf_clearance cookie
                if any(c.get('name') == 'cf_clearance' for c in cookies):
                    return cookies
    except Exception as e:
        logging.warning(f"Error loading cookies from {cookie_file}: {e}")
    return []


def _save_cf_cookies_to_file(cookie_file: str, cookies: list):
    """Save cookies to a JSON file, but ONLY if it contains cf_clearance."""
    import json
    # Only save if we have a cf_clearance cookie - no point saving other cookies
    if not any(c.get('name') == 'cf_clearance' for c in cookies):
        return
    try:
        with open(cookie_file, 'w') as f:
            json.dump(cookies, f)
    except Exception as e:
        logging.warning(f"Error saving cookies to {cookie_file}: {e}")


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    """Resolve Cloudflare challenge - runs everything in a single event loop."""
    timeout = int(req.maxTimeout) / 1000

    # Run the entire async workflow in a single event loop
    # This is critical - pydoll's CDP connection is tied to the event loop
    try:
        result = func_timeout(timeout, _run_challenge_sync, (req, method))
        return result
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))


def _run_challenge_sync(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    """Sync wrapper that runs in the persistent background event loop with auto-retry."""
    # Use persistent background loop - pydoll connections are event-loop-bound
    max_retries = 3
    last_error = None

    for attempt in range(max_retries):
        try:
            return run_in_background_loop(_run_challenge_complete(req, method))
        except Exception as e:
            last_error = e
            error_msg = str(e)
            # Only retry on challenge-related failures, not general errors
            if "Challenge solving failed" in error_msg or "IP likely changed" in error_msg:
                if attempt < max_retries - 1:
                    logging.warning(f"Challenge failed (attempt {attempt + 1}/{max_retries}), retrying with fresh browser...")
                    continue
            # Non-retryable error or max retries reached
            raise

    # Should not reach here, but just in case
    raise last_error


async def _run_challenge_complete(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    """Complete async workflow - browser creation, challenge resolution, and cleanup."""
    browser: Optional[Chrome] = None
    tab: Optional[Tab] = None
    using_session = False  # Track if we're using a reusable session
    auto_session_id = None  # Track auto-session ID for cleanup on failure

    try:
        if req.session:
            # Manual session management - use SessionsStorage (legacy)
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            browser = session.browser
            tab = session.tab
            cookie_file = None
            saved_cookies = []
            using_session = True
        elif SESSIONS_STORAGE.auto_session_enabled:
            # Auto session management - reuse browser per domain
            session, fresh = await SESSIONS_STORAGE.get_or_create_auto_session_async(req.url, req.proxy)
            if session:
                auto_session_id = session.session_id  # Track for cleanup on failure
                if fresh:
                    logging.debug(f"new auto-session created for domain (session_id={auto_session_id})")
                else:
                    logging.debug(f"reusing auto-session (session_id={auto_session_id}, lifetime={str(session.lifetime())})")
                # All operations run in same event loop, no connection refresh needed
                tab = session.get_tab()
                browser = session.browser
                using_session = True
                saved_cookies = []
                cookie_file = None
            else:
                # Fallback if auto-session creation failed
                logging.warning("Auto-session creation failed, using one-off browser")
                browser, tab = await utils.get_browser_and_tab(req.proxy)
                saved_cookies = []
                cookie_file = None
        else:
            # No session management - create one-off browser with file-based cookies
            cookie_file = _get_cookie_file_for_url(req.url)

            # Don't pass user_data_dir - uses incognito mode for fast startup
            browser, tab = await utils.get_browser_and_tab(req.proxy)

            # Load saved cookies ONLY if we have cf_clearance (skip for non-CF sites)
            saved_cookies = []
            if cookie_file:
                saved_cookies = _load_cf_cookies_from_file(cookie_file)

        # Run the challenge resolution (pass saved cookies for auto-session)
        result = await _evil_logic(req, browser, tab, method, saved_cookies)

        # Save cookies after resolution ONLY if we got cf_clearance (for file-based mode)
        if cookie_file and tab:
            try:
                cookies = await tab.get_cookies()
                if cookies:
                    _save_cf_cookies_to_file(cookie_file, cookies)
            except Exception as e:
                logging.debug(f"Error saving cookies: {e}")

        return result

    except Exception as e:
        # On challenge solving failure, destroy the auto-session so next request starts fresh
        if auto_session_id:
            logging.warning(f"Challenge failed, destroying auto-session {auto_session_id} for fresh retry")
            SESSIONS_STORAGE.destroy(auto_session_id)
        raise

    finally:
        # Cleanup browser only if NOT using a reusable session
        if not using_session and browser is not None:
            try:
                await asyncio.wait_for(browser.stop(), timeout=5.0)
            except Exception:
                pass  # Tab cleanup errors are not critical


async def _evil_logic(req: V1RequestBase, browser: Chrome, tab: Tab, method: str, saved_cookies: list = None) -> ChallengeResolutionT:
    """Main challenge resolution logic using pydoll."""
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # Run diagnostics on first request (proxy verification + browser fingerprint)
    global _diagnostics_logged
    if not _diagnostics_logged:
        _diagnostics_logged = True
        logging.info("Running first-request diagnostics...")
        await _verify_proxy(tab, req.proxy)
        await _log_browser_diagnostics(tab)

    # Restore saved cookies BEFORE navigation using CDP (for file-based sessions)
    if saved_cookies:
        try:
            # Use CDP Network.setCookies to set cookies without needing page context
            conn = tab._connection_handler
            await conn.execute_command({
                'method': 'Network.setCookies',
                'params': {'cookies': saved_cookies}
            }, timeout=10)
        except Exception as e:
            logging.debug(f"Could not restore cookies: {e}")

    # Check if we have a cf_clearance cookie in browser (for auto-sessions, cookies persist in browser)
    has_cf_cookie = any(c.get('name') == 'cf_clearance' for c in saved_cookies) if saved_cookies else False

    # For auto-sessions, also check browser's actual cookies for the target URL
    if not has_cf_cookie:
        try:
            from pydoll.commands import NetworkCommands
            response = await tab._execute_command(NetworkCommands.get_cookies(urls=[req.url]))
            browser_cookies = response.get('result', {}).get('cookies', [])
            cookie_names = [c.get('name') for c in browser_cookies]
            logging.debug(f"Browser cookies for {req.url}: {cookie_names}")
            has_cf_cookie = any(c.get('name') == 'cf_clearance' for c in browser_cookies)
            if has_cf_cookie:
                logging.debug("Found cf_clearance cookie in browser, will skip CF bypass")
            else:
                logging.debug("No cf_clearance cookie found in browser")
        except Exception as e:
            logging.debug(f"Could not check browser cookies: {e}")

    # Navigate to the page
    turnstile_token = None

    if method == "POST":
        await _post_request(req, tab)
    else:
        if req.tabs_till_verify is not None:
            turnstile_token = await _resolve_turnstile_captcha(req, tab)
        else:
            # Navigate with built-in Cloudflare bypass
            await _navigate_with_cf_bypass(tab, req.url, has_cf_cookie=has_cf_cookie)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        # Convert cookies to pydoll format
        pydoll_cookies = []
        for cookie in req.cookies:
            pydoll_cookies.append({
                'name': cookie['name'],
                'value': cookie['value'],
                'domain': cookie.get('domain'),
                'path': cookie.get('path', '/'),
            })
        await tab.set_cookies(pydoll_cookies)
        # reload the page
        if method == 'POST':
            await _post_request(req, tab)
        else:
            await _navigate_with_cf_bypass(tab, req.url)

    # Check if we hit a Cloudflare challenge
    challenge_found = False

    # Check title for challenge indicators
    try:
        title_result = await tab.execute_script('return document.title')
        page_title = title_result.get('result', {}).get('result', {}).get('value', '')
        for challenge_title in CHALLENGE_TITLES:
            if challenge_title.lower() in page_title.lower():
                challenge_found = True
                logging.info(f"Challenge detected! Title: {page_title}")
                break
    except Exception as e:
        logging.debug(f"Could not get title: {e}")

    # Check for challenge selectors if title didn't match
    if not challenge_found:
        for selector in CHALLENGE_SELECTORS:
            try:
                element = await tab.query(selector, timeout=0, raise_exc=False)
                if element:
                    challenge_found = True
                    logging.info(f"Challenge detected! Selector: {selector}")
                    break
            except Exception:
                pass

    attempt = 0
    has_reloaded = False
    max_challenge_attempts = 30  # Max attempts before giving up (~30 seconds with 1s sleep)
    if challenge_found:
        while attempt < max_challenge_attempts:
            try:
                attempt = attempt + 1

                # Check for turnstile/iframe elements (detailed on first few + after reload)
                if attempt <= 3 or (has_reloaded and attempt == CHALLENGE_RELOAD_AFTER + 1):
                    try:
                        turnstile = await tab.query('.cf-turnstile', timeout=0, raise_exc=False)
                        iframe = await tab.query('iframe[src*="challenges.cloudflare.com"]', timeout=0, raise_exc=False)
                        logging.debug(f"Challenge page state: cf-turnstile={turnstile is not None}, cf-iframe={iframe is not None}")
                    except Exception as e:
                        logging.debug(f"Error checking challenge elements: {e}")

                logging.debug("Waiting for challenge to complete (attempt " + str(attempt) + "/" + str(max_challenge_attempts) + ")")

                # Check if challenge is still present
                still_challenging = False

                # Check title
                title_result = await tab.execute_script('return document.title')
                current_title = title_result.get('result', {}).get('result', {}).get('value', '')

                for title in CHALLENGE_TITLES:
                    if title.lower() == current_title.lower():
                        still_challenging = True
                        break

                # Check selectors
                if not still_challenging:
                    for selector in CHALLENGE_SELECTORS:
                        try:
                            element = await tab.query(selector, timeout=0, raise_exc=False)
                            if element:
                                still_challenging = True
                                break
                        except Exception:
                            pass

                if not still_challenging:
                    # Challenge resolved
                    break

                # Recovery: after CHALLENGE_RELOAD_AFTER stuck attempts, try re-navigating
                # with the bypass context (the JS challenge may have stalled)
                if attempt == CHALLENGE_RELOAD_AFTER and not has_reloaded:
                    has_reloaded = True
                    logging.warning(f"Challenge stuck after {attempt} attempts, re-navigating with bypass...")
                    # Dump page excerpt for debugging
                    try:
                        html_result = await tab.execute_script(
                            'return document.documentElement.outerHTML.substring(0, 2000)')
                        page_excerpt = html_result.get('result', {}).get('result', {}).get('value', '')
                        logging.debug(f"Stuck challenge page excerpt: {page_excerpt[:500]}")
                    except Exception:
                        pass
                    # Try a fresh navigation with bypass
                    try:
                        async with tab.expect_and_bypass_cloudflare_captcha(
                            time_before_click=2,
                            time_to_wait_captcha=15,
                        ):
                            await asyncio.wait_for(tab.go_to(req.url), timeout=30)
                        logging.debug("Re-navigation bypass context exited")
                    except asyncio.TimeoutError:
                        logging.warning("Re-navigation bypass timed out")
                    except Exception as e:
                        logging.debug(f"Re-navigation bypass error: {e}")
                    continue

                # Try to click the Cloudflare verify checkbox using pydoll's method
                await _click_verify_pydoll(tab)

                await asyncio.sleep(SHORT_TIMEOUT)

            except asyncio.TimeoutError:
                logging.debug("Timeout waiting for challenge")
                await _click_verify_pydoll(tab)

        if attempt >= max_challenge_attempts:
            logging.error(f"Challenge solving failed after {max_challenge_attempts} attempts")
            # Dump page content for debugging
            try:
                html_result = await tab.execute_script(
                    'return document.documentElement.outerHTML.substring(0, 5000)')
                page_content = html_result.get('result', {}).get('result', {}).get('value', '')
                logging.error(f"Failed challenge page content (first 2000 chars): {page_content[:2000]}")
            except Exception as e:
                logging.debug(f"Could not dump page content: {e}")
            # Save debug screenshot
            try:
                screenshot_b64 = await tab.take_screenshot(as_base64=True)
                import base64
                screenshot_path = '/tmp/flaresolverr-challenge-fail.png'
                with open(screenshot_path, 'wb') as f:
                    f.write(base64.b64decode(screenshot_b64))
                logging.error(f"Debug screenshot saved to {screenshot_path}")
            except Exception as e:
                logging.debug(f"Could not save debug screenshot: {e}")
            raise Exception(f"Challenge solving failed after {max_challenge_attempts} attempts - Cloudflare may be blocking this request")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    # Build result
    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = await tab.current_url

    # Get cookies for the target URL specifically (not just current page)
    # This ensures we get cookies even if page navigated away
    try:
        from pydoll.commands import NetworkCommands
        response = await tab._execute_command(NetworkCommands.get_cookies(urls=[req.url]))
        challenge_res.cookies = response.get('result', {}).get('cookies', [])
    except Exception as e:
        logging.debug(f"Error getting cookies for URL, falling back to page cookies: {e}")
        challenge_res.cookies = await tab.get_cookies()
    logging.debug(f"Final cookies: {[c.get('name') for c in challenge_res.cookies]}")
    challenge_res.status = 200
    challenge_res.userAgent = utils.get_user_agent()
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            await asyncio.sleep(req.waitInSeconds)

        try:
            challenge_res.response = await tab.page_source
        except Exception as e:
            logging.warning(f"Error getting page source: {e}")
            # Try alternative method - execute script to get HTML
            try:
                html_result = await tab.execute_script('return document.documentElement.outerHTML')
                challenge_res.response = html_result.get('result', {}).get('result', {}).get('value', '')
            except Exception as e2:
                logging.warning(f"Fallback page source also failed: {e2}")
                challenge_res.response = ""

    if req.returnScreenshot:
        try:
            challenge_res.screenshot = await tab.take_screenshot(as_base64=True)
        except Exception as e:
            logging.warning(f"Error taking screenshot: {e}")
            challenge_res.screenshot = ""

    res.result = challenge_res
    return res


async def _click_verify_pydoll(tab: Tab):
    """Try to click the Cloudflare verify checkbox using pydoll's human-like interactions."""
    try:
        # Try multiple selectors for Cloudflare challenge elements
        selectors_to_try = [
            ('class', 'cf-turnstile'),
            ('css', '#turnstile-wrapper'),
            ('css', 'input[type="checkbox"]'),
            ('css', '.ctp-checkbox-label'),
            ('css', '#challenge-stage'),
        ]

        for selector_type, selector_value in selectors_to_try:
            try:
                if selector_type == 'class':
                    element = await tab.find(class_name=selector_value, timeout=1, raise_exc=False)
                else:
                    element = await tab.query(selector_value, timeout=1, raise_exc=False)

                if element:
                    logging.debug(f"Found element with {selector_type}={selector_value}, attempting click...")
                    # Adjust the external div size to shadow root width (usually 300px)
                    try:
                        await element.execute_script('this.style="width: 300px"')
                    except Exception:
                        pass
                    await asyncio.sleep(1)
                    await element.click()
                    logging.debug(f"Clicked element with {selector_type}={selector_value}")
                    return
            except Exception as e:
                logging.debug(f"Error with selector {selector_type}={selector_value}: {e}")

        # Try iframe-based approach
        try:
            iframe = await tab.query('iframe[src*="challenges.cloudflare.com"]', timeout=1, raise_exc=False)
            if iframe:
                logging.debug("Found cloudflare iframe, attempting click...")
                await iframe.click()
                logging.debug("Clicked cloudflare iframe")
                return
            else:
                logging.debug("No Cloudflare elements found on page")
        except Exception as e:
            logging.debug(f"Error finding/clicking iframe: {e}")
    except Exception as e:
        logging.debug(f"Unexpected error in _click_verify_pydoll: {e}")


async def _resolve_turnstile_captcha(req: V1RequestBase, tab: Tab) -> Optional[str]:
    """Resolve Turnstile captcha and return the token."""
    turnstile_token = None
    if req.tabs_till_verify is not None:
        await _navigate_with_cf_bypass(tab, req.url)

        turnstile_challenge_found = False
        for selector in TURNSTILE_SELECTORS:
            try:
                element = await tab.query(selector, timeout=2, raise_exc=False)
                if element:
                    turnstile_challenge_found = True
                    logging.info("Turnstile challenge detected")
                    break
            except Exception:
                pass

        if turnstile_challenge_found:
            turnstile_token = await _get_turnstile_token(tab, req.tabs_till_verify)
    return turnstile_token


async def _get_turnstile_token(tab: Tab, tabs: int) -> Optional[str]:
    """Get the turnstile token by clicking the checkbox."""
    try:
        token_input = await tab.query("input[name='cf-turnstile-response']", timeout=5)
        current_value_result = await token_input.execute_script('return this.value')
        current_value = current_value_result.get('result', {}).get('result', {}).get('value', '')

        max_attempts = 10
        for attempt in range(max_attempts):
            await _click_verify_pydoll(tab)

            # Check if token changed
            token_result = await token_input.execute_script('return this.value')
            turnstile_token = token_result.get('result', {}).get('result', {}).get('value', '')

            if turnstile_token and turnstile_token != current_value:
                logging.info("Turnstile token obtained")
                return turnstile_token

            # Reset focus
            await tab.execute_script("""
                let el = document.createElement('button');
                el.style.position='fixed';
                el.style.top='0';
                el.style.left='0';
                document.body.prepend(el);
                el.focus();
            """)
            await asyncio.sleep(1)

    except Exception as e:
        logging.error(f"Error getting turnstile token: {e}")

    return None


async def _post_request(req: V1RequestBase, tab: Tab):
    """Perform a POST request by creating a form and submitting it."""
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData and req.postData[0] != '?' else req.postData[1:] if req.postData else ''
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value = value.replace('"', '&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    await tab.go_to("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))
