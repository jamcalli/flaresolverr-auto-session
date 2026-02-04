import asyncio
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
from sessions import SessionsStorage

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
SESSIONS_STORAGE = SessionsStorage()


async def _navigate_with_cf_bypass(tab: Tab, url: str, has_cf_cookie: bool = False):
    """
    Navigate to URL. Always try direct navigation first, then detect if CF bypass needed.
    """
    # Always do direct navigation first - fast for most sites
    # Wrap in wait_for since pydoll's timeout parameter may not work reliably
    try:
        await asyncio.wait_for(tab.go_to(url), timeout=20)
    except asyncio.TimeoutError:
        raise Exception("Page load timed out")

    # Check if we hit a Cloudflare challenge (only if no cf_clearance cookie)
    if not has_cf_cookie:
        try:
            title_result = await tab.execute_script('return document.title')
            page_title = title_result.get('result', {}).get('result', {}).get('value', '')

            # Check for CF challenge titles
            cf_challenge = any(t.lower() in page_title.lower() for t in CHALLENGE_TITLES)

            if cf_challenge:
                logging.info(f"Cloudflare challenge detected (title: {page_title}), solving...")
                # Use pydoll's CF bypass to solve the challenge
                try:
                    async with tab.expect_and_bypass_cloudflare_captcha(
                        time_before_click=2,
                        time_to_wait_captcha=15,
                    ):
                        await asyncio.wait_for(tab.go_to(url), timeout=30)
                    logging.info("Cloudflare challenge solved")
                except asyncio.TimeoutError:
                    logging.warning("Cloudflare bypass navigation timed out")
                except Exception as e:
                    logging.debug(f"Cloudflare bypass error: {e}")
        except Exception as e:
            logging.debug(f"Could not check for challenge: {e}")


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
    auto_session_enabled = os.environ.get('AUTO_SESSION_MANAGEMENT', 'false').lower() == 'true'
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
    """Sync wrapper that runs everything in a single asyncio.run()."""
    return asyncio.run(_run_challenge_complete(req, method))


async def _run_challenge_complete(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    """Complete async workflow - browser creation, challenge resolution, and cleanup."""
    browser: Optional[Chrome] = None
    tab: Optional[Tab] = None

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
        else:
            # Use file-based cookies for persistence (fast incognito mode)
            cookie_file = _get_cookie_file_for_url(req.url)

            # Don't pass user_data_dir - uses incognito mode for fast startup
            browser, tab = await utils.get_browser_and_tab(req.proxy)

            # Load saved cookies ONLY if we have cf_clearance (skip for non-CF sites)
            saved_cookies = []
            if cookie_file:
                saved_cookies = _load_cf_cookies_from_file(cookie_file)

        # Run the challenge resolution (pass saved cookies for auto-session)
        result = await _evil_logic(req, browser, tab, method, saved_cookies)

        # Save cookies after resolution ONLY if we got cf_clearance
        if cookie_file and tab:
            try:
                cookies = await tab.get_cookies()
                if cookies:
                    _save_cf_cookies_to_file(cookie_file, cookies)
            except Exception as e:
                logging.debug(f"Error saving cookies: {e}")

        return result

    finally:
        # Cleanup browser (unless using manual session)
        if not req.session and browser is not None:
            try:
                await asyncio.wait_for(browser.stop(), timeout=5.0)
            except Exception:
                pass  # Browser cleanup errors are not critical


async def _evil_logic(req: V1RequestBase, browser: Chrome, tab: Tab, method: str, saved_cookies: list = None) -> ChallengeResolutionT:
    """Main challenge resolution logic using pydoll."""
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # Restore saved cookies BEFORE navigation using CDP (for auto-session)
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

    # Check if we have a cf_clearance cookie (skip slow CF bypass if we do)
    has_cf_cookie = any(c.get('name') == 'cf_clearance' for c in saved_cookies) if saved_cookies else False

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
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1

                # Wait for title to change
                logging.debug("Waiting for challenge to complete (attempt " + str(attempt) + ")")

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

                # Try to click the Cloudflare verify checkbox using pydoll's method
                await _click_verify_pydoll(tab)

                await asyncio.sleep(SHORT_TIMEOUT)

            except asyncio.TimeoutError:
                logging.debug("Timeout waiting for challenge")
                await _click_verify_pydoll(tab)

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    # Build result
    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = await tab.current_url
    challenge_res.cookies = await tab.get_cookies()
    challenge_res.status = 200
    challenge_res.userAgent = utils.get_user_agent()
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            await asyncio.sleep(req.waitInSeconds)

        challenge_res.response = await tab.page_source

    if req.returnScreenshot:
        challenge_res.screenshot = await tab.take_screenshot(as_base64=True)

    res.result = challenge_res
    return res


async def _click_verify_pydoll(tab: Tab):
    """Try to click the Cloudflare verify checkbox using pydoll's human-like interactions."""
    try:
        # Try to find the cf-turnstile element
        try:
            element = await tab.find(class_name='cf-turnstile', timeout=2, raise_exc=False)
            if element:
                # Adjust the external div size to shadow root width (usually 300px)
                await element.execute_script('this.style="width: 300px"')
                await asyncio.sleep(2)
                # Click with pydoll's human-like click
                await element.click()
                return
        except Exception:
            pass

        # Try alternative: find iframe and click inside it
        try:
            iframe = await tab.query('iframe[src*="challenges.cloudflare.com"]', timeout=1, raise_exc=False)
            if iframe:
                await iframe.click()
                return
        except Exception:
            pass
    except Exception:
        pass


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
