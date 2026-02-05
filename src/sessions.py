import asyncio
import atexit
import logging
import os
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple
from urllib.parse import urlparse
from uuid import uuid1

from pydoll.browser import Chrome
from pydoll.browser.tab import Tab

import utils


# =============================================================================
# Persistent Event Loop for Pydoll
# =============================================================================
# Pydoll requires a single persistent event loop - connections are loop-bound.
# We run one event loop in a background thread and queue all async operations to it.

_background_loop: Optional[asyncio.AbstractEventLoop] = None
_background_thread: Optional[threading.Thread] = None
_loop_lock = threading.Lock()


def _run_background_loop(loop: asyncio.AbstractEventLoop):
    """Run the event loop forever in a background thread."""
    asyncio.set_event_loop(loop)
    loop.run_forever()


def get_background_loop() -> asyncio.AbstractEventLoop:
    """Get or create the persistent background event loop."""
    global _background_loop, _background_thread

    with _loop_lock:
        if _background_loop is None or not _background_loop.is_running():
            _background_loop = asyncio.new_event_loop()
            _background_thread = threading.Thread(
                target=_run_background_loop,
                args=(_background_loop,),
                daemon=True,
                name="pydoll-event-loop"
            )
            _background_thread.start()
            logging.info("Started persistent background event loop for pydoll")

    return _background_loop


def run_in_background_loop(coro) -> any:
    """
    Run a coroutine in the persistent background event loop.
    Blocks until the coroutine completes and returns its result.
    """
    loop = get_background_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()  # Block until done


@atexit.register
def _cleanup_background_loop():
    """Stop the background event loop on exit."""
    global _background_loop
    if _background_loop is not None and _background_loop.is_running():
        _background_loop.call_soon_threadsafe(_background_loop.stop)
        logging.debug("Stopped background event loop")


@dataclass
class Session:
    session_id: str
    browser: Chrome
    tab: Tab  # Initial tab, reused for all requests
    created_at: datetime

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at

    def get_tab(self) -> Tab:
        """Get the tab for a request. Reuses existing tab - cookies persist in browser."""
        # No connection refresh needed - all operations run in same event loop
        return self.tab


class SessionsStorage:
    """SessionsStorage creates, stores and process all the sessions"""

    def __init__(self):
        self.sessions = {}
        self.domain_sessions = {}  # domain -> session_id mapping for auto sessions
        self.auto_session_enabled = utils.get_env_bool('AUTO_SESSION_MANAGEMENT', False)
        self.session_per_domain = utils.get_env_bool('SESSION_PER_DOMAIN', True)
        self.auto_session_ttl = int(os.environ.get('AUTO_SESSION_TTL', '30'))
        self.max_auto_sessions = int(os.environ.get('MAX_AUTO_SESSIONS', '10'))
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        self._request_count = 0  # Track requests for periodic cleanup
        self._cleanup_interval = int(os.environ.get('AUTO_SESSION_CLEANUP_INTERVAL', '50'))  # Cleanup every N requests

    def create(self, session_id: Optional[str] = None, proxy: Optional[dict] = None,
               force_new: Optional[bool] = False) -> Tuple[Session, bool]:
        """create creates new instance of Browser/Tab if necessary,
        assign defined (or newly generated) session_id to the instance
        and returns the session object. If a new session has been created
        second argument is set to True.

        Note: The function is idempotent, so in case if session_id
        already exists in the storage a new instance won't be created
        and existing session will be returned. Second argument defines if
        new session has been created (True) or an existing one was used (False).
        """
        with self._lock:
            session_id = session_id or str(uuid1())

            if force_new:
                self.destroy(session_id)

            if self.exists(session_id):
                return self.sessions[session_id], False

            # Create browser in persistent background event loop
            browser, tab = run_in_background_loop(utils.get_browser_and_tab(proxy))
            created_at = datetime.now()
            session = Session(session_id, browser, tab, created_at)

            self.sessions[session_id] = session

            return session, True

    def exists(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self.sessions

    def destroy(self, session_id: str) -> bool:
        """destroy closes the browser instance and removes session from the storage.
        The function is noop if session_id doesn't exist.
        The function returns True if session was found and destroyed,
        and False if session_id wasn't found.
        """
        with self._lock:
            if not self.exists(session_id):
                return False

            session = self.sessions.pop(session_id)
            try:
                # Stop the browser in the persistent background event loop
                async def stop_browser():
                    try:
                        await asyncio.wait_for(session.browser.stop(), timeout=5.0)
                    except asyncio.TimeoutError:
                        logging.debug(f"Browser stop timed out for session {session_id}")
                    except Exception as e:
                        logging.debug(f"Browser stop error for session {session_id}: {e}")
                run_in_background_loop(stop_browser())
            except Exception as e:
                logging.debug(f"Error in browser cleanup for session {session_id}: {e}")
            return True

    def get(self, session_id: str, ttl: Optional[timedelta] = None) -> Tuple[Session, bool]:
        with self._lock:
            session, fresh = self.create(session_id)

            if ttl is not None and not fresh and session.lifetime() > ttl:
                logging.debug(f'session\'s lifetime has expired, so the session is recreated (session_id={session_id})')
                session, fresh = self.create(session_id, force_new=True)

            return session, fresh

    async def create_async(self, session_id: Optional[str] = None, proxy: Optional[dict] = None,
                           force_new: Optional[bool] = False) -> Tuple[Session, bool]:
        """Async version of create() for use within async contexts."""
        with self._lock:
            session_id = session_id or str(uuid1())

            if force_new:
                self.destroy(session_id)

            if self.exists(session_id):
                return self.sessions[session_id], False

        # Run browser creation outside the lock (it's slow)
        browser, tab = await utils.get_browser_and_tab(proxy)
        created_at = datetime.now()
        session = Session(session_id, browser, tab, created_at)

        with self._lock:
            # Check again in case another thread created it while we were starting browser
            if self.exists(session_id):
                # Another thread beat us, stop our browser and return existing
                try:
                    await browser.stop()
                except Exception:
                    pass
                return self.sessions[session_id], False

            self.sessions[session_id] = session
            return session, True

    def session_ids(self) -> list[str]:
        with self._lock:
            return list(self.sessions.keys())

    def _maybe_cleanup_periodic(self) -> None:
        """Perform periodic cleanup based on request count"""
        if not self.auto_session_enabled or self._cleanup_interval <= 0:
            return

        self._request_count += 1
        if self._request_count >= self._cleanup_interval:
            self._request_count = 0
            cleaned = self.cleanup_stale_sessions()
            if cleaned > 0:
                logging.debug(f"Periodic cleanup removed {cleaned} stale auto-sessions")

    def get_or_create_auto_session(self, url: str, proxy: Optional[dict] = None) -> Tuple[Optional[Session], bool]:
        """Get or create an automatic session for a URL"""
        if not self.auto_session_enabled:
            return None, False

        # Extract domain from URL
        try:
            domain = urlparse(url).netloc
            if not domain:
                logging.warning(f"Could not extract domain from URL: {url}")
                return None, False
        except Exception as e:
            logging.warning(f"Error parsing URL {url}: {e}")
            return None, False

        with self._lock:
            # Trigger periodic cleanup
            self._maybe_cleanup_periodic()

            # If not using per-domain sessions, use a single shared auto-session
            if not self.session_per_domain:
                shared_session_id = "auto_shared"
                if self.exists(shared_session_id):
                    session = self.sessions[shared_session_id]
                    if session.lifetime() < timedelta(minutes=self.auto_session_ttl):
                        logging.debug(f"Reusing shared auto-session {shared_session_id}")
                        return session, False
                    else:
                        # Session expired, destroy it
                        logging.info(f"Shared auto-session {shared_session_id} expired, creating new one")
                        self.destroy(shared_session_id)

                # Create new shared session
                session, fresh = self.create(shared_session_id, proxy)
                logging.info(f"Created new shared auto-session {shared_session_id}")
                return session, fresh

            # Check if we have a session for this domain
            if domain in self.domain_sessions:
                session_id = self.domain_sessions[domain]
                if self.exists(session_id):
                    # Check if session hasn't expired
                    session = self.sessions[session_id]
                    if session.lifetime() < timedelta(minutes=self.auto_session_ttl):
                        logging.debug(f"Reusing auto-session {session_id} for domain {domain}")
                        return session, False
                    else:
                        # Session expired, destroy it
                        logging.info(f"Auto-session {session_id} for domain {domain} expired, creating new one")
                        self.destroy(session_id)
                        del self.domain_sessions[domain]
                else:
                    # Session was destroyed, remove from mapping
                    del self.domain_sessions[domain]

            # Check if we've hit the session limit
            auto_session_count = sum(1 for sid in self.sessions.keys() if sid.startswith('auto_'))
            if auto_session_count >= self.max_auto_sessions:
                # Remove oldest auto-session
                oldest_session = min(
                    ((sid, s) for sid, s in self.sessions.items() if sid.startswith('auto_')),
                    key=lambda x: x[1].created_at,
                    default=None
                )
                if oldest_session:
                    oldest_sid, _ = oldest_session
                    logging.info(f"Max auto-sessions reached, removing oldest: {oldest_sid}")
                    self.destroy(oldest_sid)
                    # Remove from domain mapping
                    self.domain_sessions = {d: s for d, s in self.domain_sessions.items() if s != oldest_sid}

            # Create new session for this domain
            session_id = f"auto_{domain.replace('.', '_').replace(':', '_')}_{str(uuid1())[:8]}"
            session, fresh = self.create(session_id, proxy)
            self.domain_sessions[domain] = session_id
            logging.info(f"Auto-created session {session_id} for domain {domain}")
            return session, fresh

    async def get_or_create_auto_session_async(self, url: str, proxy: Optional[dict] = None) -> Tuple[Optional[Session], bool]:
        """Async version of get_or_create_auto_session for use within async contexts."""
        if not self.auto_session_enabled:
            return None, False

        # Extract domain from URL
        try:
            domain = urlparse(url).netloc
            if not domain:
                logging.warning(f"Could not extract domain from URL: {url}")
                return None, False
        except Exception as e:
            logging.warning(f"Error parsing URL {url}: {e}")
            return None, False

        with self._lock:
            # Trigger periodic cleanup
            self._maybe_cleanup_periodic()

            # If not using per-domain sessions, use a single shared auto-session
            if not self.session_per_domain:
                shared_session_id = "auto_shared"
                if self.exists(shared_session_id):
                    session = self.sessions[shared_session_id]
                    if session.lifetime() < timedelta(minutes=self.auto_session_ttl):
                        logging.debug(f"Reusing shared auto-session {shared_session_id}")
                        return session, False
                    else:
                        # Session expired, destroy it
                        logging.info(f"Shared auto-session {shared_session_id} expired, creating new one")
                        self.destroy(shared_session_id)

                # Need to create - release lock first
                session_id_to_create = shared_session_id
            else:
                # Check if we have a session for this domain
                if domain in self.domain_sessions:
                    session_id = self.domain_sessions[domain]
                    if self.exists(session_id):
                        # Check if session hasn't expired
                        session = self.sessions[session_id]
                        if session.lifetime() < timedelta(minutes=self.auto_session_ttl):
                            logging.debug(f"Reusing auto-session {session_id} for domain {domain}")
                            return session, False
                        else:
                            # Session expired, destroy it
                            logging.info(f"Auto-session {session_id} for domain {domain} expired, creating new one")
                            self.destroy(session_id)
                            del self.domain_sessions[domain]
                    else:
                        # Session was destroyed, remove from mapping
                        del self.domain_sessions[domain]

                # Check if we've hit the session limit
                auto_session_count = sum(1 for sid in self.sessions.keys() if sid.startswith('auto_'))
                if auto_session_count >= self.max_auto_sessions:
                    # Remove oldest auto-session
                    oldest_session = min(
                        ((sid, s) for sid, s in self.sessions.items() if sid.startswith('auto_')),
                        key=lambda x: x[1].created_at,
                        default=None
                    )
                    if oldest_session:
                        oldest_sid, _ = oldest_session
                        logging.info(f"Max auto-sessions reached, removing oldest: {oldest_sid}")
                        self.destroy(oldest_sid)
                        # Remove from domain mapping
                        self.domain_sessions = {d: s for d, s in self.domain_sessions.items() if s != oldest_sid}

                # Need to create new session
                session_id_to_create = f"auto_{domain.replace('.', '_').replace(':', '_')}_{str(uuid1())[:8]}"

        # Create session outside lock (browser creation is slow)
        session, fresh = await self.create_async(session_id_to_create, proxy)

        with self._lock:
            if self.session_per_domain:
                self.domain_sessions[domain] = session_id_to_create
            logging.info(f"Auto-created session {session_id_to_create} for domain {domain}")

        return session, fresh

    def cleanup_stale_sessions(self, max_lifetime_minutes: Optional[int] = None):
        """Remove auto-sessions older than max_lifetime"""
        if max_lifetime_minutes is None:
            max_lifetime_minutes = self.auto_session_ttl

        with self._lock:
            current_time = datetime.now()
            sessions_to_remove = []

            # Clean up per-domain sessions
            for domain, session_id in list(self.domain_sessions.items()):
                if session_id in self.sessions:
                    session = self.sessions[session_id]
                    if session.lifetime() > timedelta(minutes=max_lifetime_minutes):
                        sessions_to_remove.append((domain, session_id))

            # Clean up shared session if expired
            if not self.session_per_domain and self.exists("auto_shared"):
                shared_session = self.sessions["auto_shared"]
                if shared_session.lifetime() > timedelta(minutes=max_lifetime_minutes):
                    sessions_to_remove.append((None, "auto_shared"))

            for domain, session_id in sessions_to_remove:
                if domain is None:
                    logging.info(f"Cleaning up stale shared auto-session {session_id}")
                else:
                    logging.info(f"Cleaning up stale auto-session {session_id} for domain {domain}")

                self.destroy(session_id)

                if domain and domain in self.domain_sessions:
                    del self.domain_sessions[domain]

            return len(sessions_to_remove)
