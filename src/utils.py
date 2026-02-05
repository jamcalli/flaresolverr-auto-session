import asyncio
import json
import logging
import os
import platform
import re
import sys
from typing import Optional, Tuple

from pydoll.browser import Chrome
from pydoll.browser.options import ChromiumOptions
from pydoll.browser.tab import Tab

FLARESOLVERR_VERSION = None
PLATFORM_VERSION = None
CHROME_EXE_PATH = None
CHROME_MAJOR_VERSION = None
USER_AGENT = None
XVFB_DISPLAY = None


def get_env_bool(name: str, default: bool = False) -> bool:
    """Parse boolean environment variable, handling quoted values and various formats."""
    val = os.environ.get(name, str(default).lower())
    # Strip quotes that users might accidentally include in docker-compose
    val = val.strip().strip('"').strip("'").lower()
    return val in ('true', '1', 'yes', 'on')


def get_config_log_html() -> bool:
    return get_env_bool('LOG_HTML', False)


def get_config_headless() -> bool:
    return get_env_bool('HEADLESS', True)


def get_config_disable_media() -> bool:
    return get_env_bool('DISABLE_MEDIA', False)


def get_flaresolverr_version() -> str:
    global FLARESOLVERR_VERSION
    if FLARESOLVERR_VERSION is not None:
        return FLARESOLVERR_VERSION

    package_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, 'package.json')
    if not os.path.isfile(package_path):
        package_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'package.json')
    with open(package_path) as f:
        FLARESOLVERR_VERSION = json.loads(f.read())['version']
        return FLARESOLVERR_VERSION


def get_current_platform() -> str:
    global PLATFORM_VERSION
    if PLATFORM_VERSION is not None:
        return PLATFORM_VERSION
    PLATFORM_VERSION = os.name
    return PLATFORM_VERSION


async def get_browser_and_tab(proxy: dict = None, user_data_dir: str = None) -> Tuple[Chrome, Tab]:
    """
    Create a pydoll Chrome browser instance and return the browser and initial tab.

    Args:
        proxy: Optional proxy configuration dict with 'url' and optionally 'username'/'password'
        user_data_dir: Optional path to Chrome user data directory for cookie persistence

    Returns:
        Tuple of (Browser, Tab)
    """
    options = ChromiumOptions()

    # Set Chrome binary location
    chrome_path = get_chrome_exe_path()
    if chrome_path:
        options.binary_location = chrome_path

    # User data directory for cookie persistence
    if user_data_dir:
        os.makedirs(user_data_dir, exist_ok=True)
        options.add_argument(f'--user-data-dir={user_data_dir}')
    else:
        # Use incognito mode for fast browser startup (avoids ~25s profile init delay)
        # Cookies will still persist during the browser session lifetime
        options.add_argument('--incognito')

    # Basic arguments
    options.add_argument('--no-sandbox')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--disable-search-engine-choice-screen')

    # Anti-detection flags
    options.add_argument('--disable-blink-features=AutomationControlled')

    # Disable WebRTC to prevent real IP leak when using proxy
    options.add_argument('--disable-webrtc')
    options.add_argument('--webrtc-ip-handling-policy=disable_non_proxied_udp')

    # Stealth browser preferences (simulate aged profile)
    import time as _time
    current_time = int(_time.time())
    options.browser_preferences = {
        'profile': {
            'exited_cleanly': True,
            'exit_type': 'Normal',
        },
        'safebrowsing': {'enabled': True},
    }
    options.add_argument('--disable-setuid-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-zygote')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')

    # ARM architecture specific
    IS_ARMARCH = platform.machine().startswith(('arm', 'aarch'))
    if IS_ARMARCH:
        options.add_argument('--disable-gpu-sandbox')

    # Language setting
    language = os.environ.get('LANG', None)
    if language is not None:
        options.add_argument('--accept-lang=%s' % language)

    # User agent
    global USER_AGENT
    if USER_AGENT is not None:
        options.add_argument('--user-agent=%s' % USER_AGENT)

    # Proxy configuration
    if proxy and 'url' in proxy:
        proxy_url = proxy['url']
        if proxy.get('username') and proxy.get('password'):
            # pydoll handles proxy auth via the URL format: scheme://user:pass@host:port
            # Parse the proxy URL and inject credentials
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(proxy_url)
            proxy_url = urlunparse((
                parsed.scheme,
                f"{proxy['username']}:{proxy['password']}@{parsed.hostname}:{parsed.port}",
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
        options.add_argument('--proxy-server=%s' % proxy_url)

    # Headless mode - use --headless=new for Chrome 109+
    # OR use xvfb for better anti-detection (virtual display instead of true headless)
    use_xvfb = os.environ.get('USE_XVFB', 'false').lower() == 'true'

    if get_config_headless():
        if use_xvfb:
            # Use xvfb virtual display instead of headless mode
            # This avoids headless browser fingerprinting
            start_xvfb_display()
            # Don't add --headless flag, run headed in virtual display
        else:
            options.add_argument('--headless=new')

    # Create browser and start
    browser = Chrome(options=options)
    tab = await browser.start()

    return browser, tab


def get_webdriver_sync(proxy: dict = None, user_data_dir: str = None) -> Tuple[Chrome, Tab]:
    """
    Synchronous wrapper for get_browser_and_tab.
    Creates a new event loop if needed.

    Args:
        proxy: Optional proxy configuration
        user_data_dir: Optional path to Chrome user data directory for cookie persistence

    Returns:
        Tuple of (Browser, Tab)
    """
    return asyncio.run(get_browser_and_tab(proxy, user_data_dir))


def get_chrome_exe_path() -> str:
    global CHROME_EXE_PATH
    if CHROME_EXE_PATH is not None:
        return CHROME_EXE_PATH

    # Check common locations
    if os.name == 'nt':
        # Windows
        paths = [
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
        ]
    elif platform.system() == 'Darwin':
        # macOS
        paths = [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        ]
    else:
        # Linux
        paths = [
            '/usr/bin/google-chrome',
            '/usr/bin/google-chrome-stable',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
        ]

    # Also check bundled chrome in src directory
    src_chrome = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chrome', 'chrome')
    if os.name == 'nt':
        src_chrome += '.exe'
    paths.insert(0, src_chrome)

    for path in paths:
        if os.path.exists(path):
            if os.name != 'nt' and not os.access(path, os.X_OK):
                continue
            CHROME_EXE_PATH = path
            return CHROME_EXE_PATH

    # Fallback: let pydoll find it
    CHROME_EXE_PATH = ''
    return CHROME_EXE_PATH


def get_chrome_major_version() -> str:
    global CHROME_MAJOR_VERSION
    if CHROME_MAJOR_VERSION is not None:
        return CHROME_MAJOR_VERSION

    if os.name == 'nt':
        try:
            complete_version = extract_version_nt_executable(get_chrome_exe_path())
        except Exception:
            try:
                complete_version = extract_version_nt_registry()
            except Exception:
                complete_version = extract_version_nt_folder()
    else:
        chrome_path = get_chrome_exe_path()
        if chrome_path:
            process = os.popen(f'"{chrome_path}" --version')
            complete_version = process.read()
            process.close()
        else:
            complete_version = ''

    if complete_version:
        CHROME_MAJOR_VERSION = complete_version.split('.')[0].split(' ')[-1]
    else:
        CHROME_MAJOR_VERSION = ''
    return CHROME_MAJOR_VERSION


def extract_version_nt_executable(exe_path: str) -> str:
    try:
        import pefile
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        return pe.FileInfo[0][0].StringTable[0].entries[b"FileVersion"].decode('utf-8')
    except ImportError:
        # pefile not installed, skip this method
        raise Exception("pefile not installed")


def extract_version_nt_registry() -> str:
    stream = os.popen(
        'reg query "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome"')
    output = stream.read()
    google_version = ''
    for letter in output[output.rindex('DisplayVersion    REG_SZ') + 24:]:
        if letter != '\n':
            google_version += letter
        else:
            break
    return google_version.strip()


def extract_version_nt_folder() -> str:
    for i in range(2):
        path = 'C:\\Program Files' + (' (x86)' if i else '') + '\\Google\\Chrome\\Application'
        if os.path.isdir(path):
            paths = [f.path for f in os.scandir(path) if f.is_dir()]
            for path in paths:
                filename = os.path.basename(path)
                pattern = r'\d+\.\d+\.\d+\.\d+'
                match = re.search(pattern, filename)
                if match and match.group():
                    return match.group(0)
    return ''


async def get_user_agent_async(tab: Tab = None) -> str:
    """Get user agent from browser, optionally using an existing tab."""
    global USER_AGENT
    if USER_AGENT is not None:
        return USER_AGENT

    browser = None
    try:
        if tab is None:
            browser, tab = await get_browser_and_tab()

        result = await tab.execute_script('return navigator.userAgent')
        USER_AGENT = result.get('result', {}).get('result', {}).get('value', '')

        # Fix for headless detection
        USER_AGENT = re.sub('HEADLESS', '', USER_AGENT, flags=re.IGNORECASE)
        return USER_AGENT
    except Exception as e:
        raise Exception("Error getting browser User-Agent. " + str(e))
    finally:
        if browser is not None:
            await browser.stop()


def get_user_agent(tab: Tab = None) -> str:
    """Synchronous wrapper for get_user_agent_async."""
    global USER_AGENT
    if USER_AGENT is not None:
        return USER_AGENT
    return asyncio.run(get_user_agent_async(tab))


def start_xvfb_display():
    global XVFB_DISPLAY
    if XVFB_DISPLAY is None:
        from xvfbwrapper import Xvfb
        XVFB_DISPLAY = Xvfb()
        XVFB_DISPLAY.start()


def object_to_dict(_object):
    json_dict = json.loads(json.dumps(_object, default=lambda o: o.__dict__))
    # remove hidden fields
    return {k: v for k, v in json_dict.items() if not k.startswith('__')}
