"""
Synchronous EPP Connection Pool

Thread-safe connection pool with keep-alive for CLI shell mode.
Mirrors ARI C++ toolkit SessionPool behavior:
- Pool of persistent connections (login once, run many commands)
- Background keep-alive thread sends hello at 40% of server timeout
- Auto-reconnect on dead connections
- Retry logic on command failures
"""

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, List, Optional, TypeVar

from epp_client.client import EPPClient
from epp_client.exceptions import EPPConnectionError, EPPError

logger = logging.getLogger("epp.sync_pool")

T = TypeVar("T")


@dataclass
class SyncPoolConfig:
    """Synchronous connection pool configuration."""
    host: str
    port: int = 700
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    timeout: float = 30.0
    verify_server: bool = True
    client_id: str = ""
    password: str = ""

    # Pool settings
    min_connections: int = 1
    max_connections: int = 3
    keepalive_interval: float = 600.0  # 40% of 25-min server timeout
    command_retries: int = 3


@dataclass
class _PooledConnection:
    """Internal wrapper tracking connection state."""
    client: EPPClient
    created_at: float
    last_used_at: float
    in_use: bool = False

    def is_healthy(self) -> bool:
        """Check if the connection is still usable."""
        return self.client.is_connected and self.client.is_logged_in


class SyncEPPConnectionPool:
    """
    Thread-safe synchronous EPP connection pool.

    Maintains persistent connections with automatic keep-alive,
    matching the ARI C++ toolkit's SessionPool pattern.

    Example:
        config = SyncPoolConfig(
            host="epp.registry.ae",
            port=700,
            cert_file="client.crt",
            key_file="client.key",
            client_id="registrar1",
            password="password123",
        )

        pool = SyncEPPConnectionPool(config)
        pool.start()

        with pool.acquire() as client:
            result = client.domain_check(["example.ae"])

        pool.stop()
    """

    def __init__(self, config: SyncPoolConfig):
        self.config = config
        self._connections: List[_PooledConnection] = []
        self._lock = threading.Lock()
        self._started = False
        self._keepalive_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def size(self) -> int:
        """Current number of connections in the pool."""
        with self._lock:
            return len(self._connections)

    @property
    def available(self) -> int:
        """Number of idle connections."""
        with self._lock:
            return sum(1 for c in self._connections if not c.in_use)

    @property
    def in_use(self) -> int:
        """Number of connections currently in use."""
        with self._lock:
            return sum(1 for c in self._connections if c.in_use)

    def start(self) -> None:
        """
        Start the pool: create initial connections and launch keep-alive thread.

        Raises:
            EPPConnectionError: If no connections could be created.
        """
        if self._started:
            return

        logger.info(
            "Starting sync pool (min=%d, max=%d, keepalive=%ds)",
            self.config.min_connections,
            self.config.max_connections,
            int(self.config.keepalive_interval),
        )

        # Create minimum connections
        for _ in range(self.config.min_connections):
            try:
                conn = self._create_connection()
                self._connections.append(conn)
            except Exception as e:
                logger.error("Failed to create initial connection: %s", e)

        if not self._connections:
            raise EPPConnectionError("Failed to create any pool connections")

        # Start background keep-alive thread
        self._stop_event.clear()
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            name="epp-keepalive",
            daemon=True,
        )
        self._keepalive_thread.start()
        self._started = True

        logger.info("Sync pool started with %d connection(s)", len(self._connections))

    def stop(self) -> None:
        """Stop the pool: signal keep-alive thread and close all connections."""
        if not self._started:
            return

        logger.info("Stopping sync pool")

        # Signal keep-alive thread to stop
        self._stop_event.set()
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            self._keepalive_thread.join(timeout=5)

        # Close all connections
        with self._lock:
            for conn in self._connections:
                try:
                    conn.client.disconnect()
                except Exception as e:
                    logger.warning("Error disconnecting: %s", e)
            self._connections.clear()

        self._started = False
        logger.info("Sync pool stopped")

    def _create_connection(self) -> _PooledConnection:
        """Create a new connected and logged-in EPP client."""
        client = EPPClient(
            host=self.config.host,
            port=self.config.port,
            cert_file=self.config.cert_file,
            key_file=self.config.key_file,
            ca_file=self.config.ca_file,
            timeout=self.config.timeout,
            verify_server=self.config.verify_server,
        )

        client.connect()
        client.login(self.config.client_id, self.config.password)

        now = time.time()
        return _PooledConnection(
            client=client,
            created_at=now,
            last_used_at=now,
            in_use=False,
        )

    @contextmanager
    def acquire(self):
        """
        Acquire a connection from the pool.

        Yields an EPPClient that is already connected and logged in.
        The connection is returned to the pool when the context exits.

        Yields:
            EPPClient: A connected, logged-in EPP client.

        Raises:
            EPPConnectionError: If no connection is available and the pool
                                is at max capacity.
        """
        if not self._started:
            raise EPPConnectionError("Pool not started")

        conn = self._get_connection()
        try:
            yield conn.client
        finally:
            self._release_connection(conn)

    def _get_connection(self) -> _PooledConnection:
        """Get an available connection, creating one if needed."""
        with self._lock:
            # Try to find an idle, healthy connection
            for conn in self._connections:
                if not conn.in_use and conn.is_healthy():
                    conn.in_use = True
                    conn.last_used_at = time.time()
                    return conn

            # Remove dead idle connections
            dead = [c for c in self._connections if not c.in_use and not c.is_healthy()]
            for c in dead:
                self._connections.remove(c)

            # Create a new connection if under max
            if len(self._connections) < self.config.max_connections:
                try:
                    conn = self._create_connection()
                    conn.in_use = True
                    self._connections.append(conn)
                    return conn
                except Exception as e:
                    logger.error("Failed to create new connection: %s", e)
                    raise EPPConnectionError(f"Cannot create connection: {e}")

        raise EPPConnectionError("No available connections in pool")

    def _release_connection(self, conn: _PooledConnection) -> None:
        """Return a connection to the pool."""
        with self._lock:
            conn.in_use = False
            conn.last_used_at = time.time()

    def execute_with_retry(self, func: Callable[[EPPClient], T]) -> T:
        """
        Execute a function with a pooled connection, retrying on failure.

        Args:
            func: Callable that takes an EPPClient and returns a result.

        Returns:
            The result of the function.

        Raises:
            EPPError: If all retries are exhausted.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, self.config.command_retries + 1):
            try:
                with self.acquire() as client:
                    return func(client)
            except EPPConnectionError as e:
                last_error = e
                logger.warning(
                    "Connection error on attempt %d/%d: %s",
                    attempt, self.config.command_retries, e,
                )
                # Force reconnect for next attempt
                self._try_replace_dead_connections()
            except EPPError:
                # Non-connection EPP errors (auth, command errors) are not retryable
                raise

        raise EPPConnectionError(
            f"All {self.config.command_retries} retries exhausted: {last_error}"
        )

    def _try_replace_dead_connections(self) -> None:
        """Replace dead connections up to min_connections."""
        with self._lock:
            # Remove dead idle connections
            dead = [c for c in self._connections if not c.in_use and not c.is_healthy()]
            for c in dead:
                try:
                    c.client.disconnect()
                except Exception:
                    pass
                self._connections.remove(c)

            # Replenish to min_connections
            alive = len(self._connections)
            for _ in range(max(0, self.config.min_connections - alive)):
                try:
                    conn = self._create_connection()
                    self._connections.append(conn)
                except Exception as e:
                    logger.warning("Failed to replace connection: %s", e)

    def _keepalive_loop(self) -> None:
        """Background thread: send hello on idle connections at the configured interval."""
        while not self._stop_event.is_set():
            # Wait for interval or stop signal
            if self._stop_event.wait(timeout=self.config.keepalive_interval):
                break  # stop_event was set

            self._perform_keepalive()

    def _perform_keepalive(self) -> None:
        """Send hello to idle connections and replace dead ones."""
        with self._lock:
            to_check = [c for c in self._connections if not c.in_use]

        for conn in to_check:
            try:
                conn.client.hello()
                conn.last_used_at = time.time()
                logger.debug("Keep-alive sent on connection")
            except Exception as e:
                logger.warning("Keep-alive failed: %s", e)

        # Replace any that died
        self._try_replace_dead_connections()

    def stats(self) -> dict:
        """Return pool statistics."""
        with self._lock:
            return {
                "size": len(self._connections),
                "available": sum(1 for c in self._connections if not c.in_use),
                "in_use": sum(1 for c in self._connections if c.in_use),
                "min_connections": self.config.min_connections,
                "max_connections": self.config.max_connections,
                "keepalive_interval": int(self.config.keepalive_interval),
            }
