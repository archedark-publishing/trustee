"""
Budget tracking for mandate spending.

Uses a SQLite transaction log so authorize/reserve/finalize operations are
atomic across threads and processes.
"""

from __future__ import annotations

import sqlite3
import time
import hashlib
import hmac
import secrets
import fcntl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from .money import (
    amount_usd_to_micros,
    format_usd_from_micros,
    limit_usd_to_micros,
    micros_to_usd_float,
)
from .storage import ensure_private_dir, ensure_private_file


DEFAULT_BUDGET_DIR = Path.home() / ".trustee" / "budgets"


@dataclass
class Transaction:
    """A single spending event."""

    tx_id: str
    mandate_id: str
    amount_micros: int
    merchant: str
    description: str
    timestamp: int
    status: str = "completed"  # pending, completed, failed, refunded
    x402_payment_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    category: Optional[str] = None
    merchant_endpoint: Optional[str] = None

    @property
    def amount_usd(self) -> float:
        return micros_to_usd_float(self.amount_micros)

    def to_dict(self) -> dict:
        return {
            "tx_id": self.tx_id,
            "mandate_id": self.mandate_id,
            "amount_usd": self.amount_usd,
            "merchant": self.merchant,
            "description": self.description,
            "timestamp": self.timestamp,
            "status": self.status,
            "x402_payment_id": self.x402_payment_id,
            "idempotency_key": self.idempotency_key,
            "category": self.category,
            "merchant_endpoint": self.merchant_endpoint,
        }


@dataclass
class BudgetState:
    """Tracks spending against a mandate's limits."""

    mandate_id: str
    total_spent_micros: int = 0
    daily_spent_micros: int = 0
    daily_reset_date: str = ""
    transaction_count: int = 0
    transactions: list[Transaction] = field(default_factory=list)
    last_updated: int = 0

    @property
    def total_spent_usd(self) -> float:
        return micros_to_usd_float(self.total_spent_micros)

    @property
    def daily_spent_usd(self) -> float:
        return micros_to_usd_float(self.daily_spent_micros)


@dataclass
class ReservationResult:
    """Result of a reserve attempt."""

    allowed: bool
    reason: str
    tx: Optional[Transaction] = None
    duplicate: bool = False


class BudgetTracker:
    """
    Manages budget state for mandates.

    State is persisted in SQLite with BEGIN IMMEDIATE transactions to guarantee
    atomicity for reserve/finalize operations under concurrency.
    """

    def __init__(self, budget_dir: Optional[Path] = None):
        self.budget_dir = budget_dir or DEFAULT_BUDGET_DIR
        ensure_private_dir(self.budget_dir)
        self.db_path = self.budget_dir / "budget.sqlite3"
        self._secret_dir = self.budget_dir.parent / ".trustee-secrets"
        ensure_private_dir(self._secret_dir)
        self._key_path = self._secret_dir / "budget_hmac.key"
        self._sig_path = self._secret_dir / f"{self.budget_dir.name}.budget.sig"
        self._lock_path = self._secret_dir / f"{self.budget_dir.name}.budget.lock"
        self._hmac_key = self._load_or_create_key()
        ensure_private_file(self._lock_path)
        self._init_db()
        self._seal_integrity()

    @contextmanager
    def _integrity_guard(self):
        with open(self._lock_path, "r+") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    def _load_or_create_key(self) -> bytes:
        if self._key_path.exists() and self._key_path.stat().st_size > 0:
            return self._key_path.read_bytes().strip()
        key = secrets.token_hex(32).encode()
        self._key_path.write_bytes(key)
        ensure_private_file(self._key_path)
        return key

    def _compute_integrity_hash(self) -> str:
        digest = hmac.new(self._hmac_key, digestmod=hashlib.sha256)
        for path in (
            self.db_path,
            Path(str(self.db_path) + "-wal"),
            Path(str(self.db_path) + "-shm"),
        ):
            if path.exists():
                digest.update(path.name.encode())
                digest.update(b":")
                digest.update(path.read_bytes())
                digest.update(b";")
        return digest.hexdigest()

    def _verify_integrity(self) -> None:
        if not self.db_path.exists():
            return
        if not self._sig_path.exists():
            self._seal_integrity()
            return
        expected = self._sig_path.read_text().strip()
        actual = self._compute_integrity_hash()
        if expected and not hmac.compare_digest(expected, actual):
            raise RuntimeError("Budget integrity check failed: local state was modified")

    def _seal_integrity(self) -> None:
        if not self.db_path.exists():
            return
        sig = self._compute_integrity_hash()
        self._sig_path.write_text(sig)
        ensure_private_file(self._sig_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mandate_budget (
                    mandate_id TEXT PRIMARY KEY,
                    total_spent_micros INTEGER NOT NULL DEFAULT 0,
                    daily_spent_micros INTEGER NOT NULL DEFAULT 0,
                    daily_reset_date TEXT NOT NULL DEFAULT '',
                    transaction_count INTEGER NOT NULL DEFAULT 0,
                    last_updated INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_id TEXT PRIMARY KEY,
                    mandate_id TEXT NOT NULL,
                    amount_micros INTEGER NOT NULL,
                    merchant TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    x402_payment_id TEXT,
                    idempotency_key TEXT,
                    category TEXT,
                    merchant_endpoint TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_idempotency
                ON transactions (mandate_id, idempotency_key)
                WHERE idempotency_key IS NOT NULL
                """
            )

    def _ensure_budget_row(self, conn: sqlite3.Connection, mandate_id: str) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO mandate_budget (
                mandate_id, total_spent_micros, daily_spent_micros,
                daily_reset_date, transaction_count, last_updated
            ) VALUES (?, 0, 0, '', 0, ?)
            """,
            (mandate_id, int(time.time())),
        )

    def _maybe_reset_daily(self, conn: sqlite3.Connection, mandate_id: str) -> None:
        today = time.strftime("%Y-%m-%d")
        row = conn.execute(
            "SELECT daily_reset_date FROM mandate_budget WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()
        if row and row["daily_reset_date"] != today:
            conn.execute(
                """
                UPDATE mandate_budget
                SET daily_spent_micros = 0, daily_reset_date = ?, last_updated = ?
                WHERE mandate_id = ?
                """,
                (today, int(time.time()), mandate_id),
            )

    def _row_to_tx(self, row: sqlite3.Row) -> Transaction:
        return Transaction(
            tx_id=row["tx_id"],
            mandate_id=row["mandate_id"],
            amount_micros=row["amount_micros"],
            merchant=row["merchant"],
            description=row["description"],
            timestamp=row["timestamp"],
            status=row["status"],
            x402_payment_id=row["x402_payment_id"],
            idempotency_key=row["idempotency_key"],
            category=row["category"],
            merchant_endpoint=row["merchant_endpoint"],
        )

    def _check_limits(
        self,
        amount_micros: int,
        total_spent_micros: int,
        daily_spent_micros: int,
        max_total_usd: float,
        max_per_tx_usd: float,
        daily_limit_usd: Optional[float],
    ) -> tuple[bool, str]:
        max_total_micros = limit_usd_to_micros(max_total_usd)
        max_per_tx_micros = limit_usd_to_micros(max_per_tx_usd)

        if amount_micros <= 0:
            return False, "Amount must be positive"

        if amount_micros > max_per_tx_micros:
            return False, (
                f"Amount {format_usd_from_micros(amount_micros)} exceeds per-transaction "
                f"limit {format_usd_from_micros(max_per_tx_micros)}"
            )

        remaining_total = max_total_micros - total_spent_micros
        if amount_micros > remaining_total:
            return False, (
                f"Amount {format_usd_from_micros(amount_micros)} exceeds remaining budget "
                f"{format_usd_from_micros(remaining_total)} "
                f"(spent {format_usd_from_micros(total_spent_micros)} "
                f"of {format_usd_from_micros(max_total_micros)})"
            )

        if daily_limit_usd is not None:
            daily_limit_micros = limit_usd_to_micros(daily_limit_usd)
            remaining_daily = daily_limit_micros - daily_spent_micros
            if amount_micros > remaining_daily:
                return False, (
                    f"Amount {format_usd_from_micros(amount_micros)} exceeds remaining daily budget "
                    f"{format_usd_from_micros(remaining_daily)} "
                    f"(spent {format_usd_from_micros(daily_spent_micros)} "
                    f"of {format_usd_from_micros(daily_limit_micros)} today)"
                )

        return True, "Within limits"

    def check_spending(
        self,
        mandate_id: str,
        amount_usd: float,
        max_total_usd: float,
        max_per_tx_usd: float,
        daily_limit_usd: Optional[float] = None,
    ) -> tuple[bool, str]:
        """Check if a proposed spend is within mandate limits."""
        with self._integrity_guard():
            self._verify_integrity()
            amount_micros = amount_usd_to_micros(amount_usd)
            with self._connect() as conn:
                self._ensure_budget_row(conn, mandate_id)
                self._maybe_reset_daily(conn, mandate_id)
                row = conn.execute(
                    """
                    SELECT total_spent_micros, daily_spent_micros
                    FROM mandate_budget WHERE mandate_id = ?
                    """,
                    (mandate_id,),
                ).fetchone()
                assert row is not None
                return self._check_limits(
                    amount_micros=amount_micros,
                    total_spent_micros=row["total_spent_micros"],
                    daily_spent_micros=row["daily_spent_micros"],
                    max_total_usd=max_total_usd,
                    max_per_tx_usd=max_per_tx_usd,
                    daily_limit_usd=daily_limit_usd,
                )

    def authorize_and_reserve(
        self,
        mandate_id: str,
        tx_id: str,
        amount_usd: float,
        merchant: str,
        description: str,
        max_total_usd: float,
        max_per_tx_usd: float,
        daily_limit_usd: Optional[float] = None,
        x402_payment_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        category: Optional[str] = None,
        merchant_endpoint: Optional[str] = None,
    ) -> ReservationResult:
        """
        Atomically authorize and reserve budget for a payment attempt.

        Reserves budget by creating a pending transaction before network I/O.
        """
        with self._integrity_guard():
            self._verify_integrity()
            amount_micros = amount_usd_to_micros(amount_usd)

            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._ensure_budget_row(conn, mandate_id)
                self._maybe_reset_daily(conn, mandate_id)

                if idempotency_key:
                    existing = conn.execute(
                        """
                        SELECT * FROM transactions
                        WHERE mandate_id = ? AND idempotency_key = ?
                        """,
                        (mandate_id, idempotency_key),
                    ).fetchone()
                    if existing is not None:
                        conn.execute("COMMIT")
                        existing_tx = self._row_to_tx(existing)
                        if existing_tx.status in {"pending", "completed"}:
                            return ReservationResult(
                                allowed=True,
                                reason=f"Duplicate idempotency key ({existing_tx.status})",
                                tx=existing_tx,
                                duplicate=True,
                            )
                        return ReservationResult(
                            allowed=False,
                            reason=f"Idempotency key already used with status {existing_tx.status}",
                            tx=existing_tx,
                            duplicate=True,
                        )

                budget_row = conn.execute(
                    """
                    SELECT total_spent_micros, daily_spent_micros, transaction_count
                    FROM mandate_budget WHERE mandate_id = ?
                    """,
                    (mandate_id,),
                ).fetchone()
                assert budget_row is not None

                allowed, reason = self._check_limits(
                    amount_micros=amount_micros,
                    total_spent_micros=budget_row["total_spent_micros"],
                    daily_spent_micros=budget_row["daily_spent_micros"],
                    max_total_usd=max_total_usd,
                    max_per_tx_usd=max_per_tx_usd,
                    daily_limit_usd=daily_limit_usd,
                )
                if not allowed:
                    conn.execute("COMMIT")
                    return ReservationResult(allowed=False, reason=reason)

                now = int(time.time())
                conn.execute(
                    """
                    INSERT INTO transactions (
                        tx_id, mandate_id, amount_micros, merchant, description,
                        timestamp, status, x402_payment_id, idempotency_key, category, merchant_endpoint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tx_id,
                        mandate_id,
                        amount_micros,
                        merchant,
                        description,
                        now,
                        "pending",
                        x402_payment_id,
                        idempotency_key,
                        category,
                        merchant_endpoint,
                    ),
                )
                conn.execute(
                    """
                    UPDATE mandate_budget
                    SET total_spent_micros = total_spent_micros + ?,
                        daily_spent_micros = daily_spent_micros + ?,
                        transaction_count = transaction_count + 1,
                        last_updated = ?
                    WHERE mandate_id = ?
                    """,
                    (amount_micros, amount_micros, now, mandate_id),
                )
                conn.execute("COMMIT")

            tx = Transaction(
                tx_id=tx_id,
                mandate_id=mandate_id,
                amount_micros=amount_micros,
                merchant=merchant,
                description=description,
                timestamp=int(time.time()),
                status="pending",
                x402_payment_id=x402_payment_id,
                idempotency_key=idempotency_key,
                category=category,
                merchant_endpoint=merchant_endpoint,
            )
            self._seal_integrity()
            return ReservationResult(allowed=True, reason="Reserved", tx=tx)

    def finalize_transaction(
        self,
        tx_id: str,
        success: bool,
        x402_payment_id: Optional[str] = None,
    ) -> Transaction:
        """Finalize a pending transaction and roll back reservation on failure."""
        with self._integrity_guard():
            self._verify_integrity()
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM transactions WHERE tx_id = ?",
                    (tx_id,),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise ValueError(f"Transaction not found: {tx_id}")

                tx = self._row_to_tx(row)
                if tx.status == "completed":
                    conn.execute("COMMIT")
                    return tx
                if tx.status == "failed":
                    conn.execute("COMMIT")
                    return tx
                if tx.status != "pending":
                    conn.execute("ROLLBACK")
                    raise ValueError(f"Cannot finalize transaction in status {tx.status}")

                now = int(time.time())
                if success:
                    conn.execute(
                        """
                        UPDATE transactions
                        SET status = 'completed',
                            x402_payment_id = COALESCE(?, x402_payment_id)
                        WHERE tx_id = ?
                        """,
                        (x402_payment_id, tx_id),
                    )
                else:
                    conn.execute(
                        "UPDATE transactions SET status = 'failed' WHERE tx_id = ?",
                        (tx_id,),
                    )
                    conn.execute(
                        """
                        UPDATE mandate_budget
                        SET total_spent_micros = MAX(0, total_spent_micros - ?),
                            daily_spent_micros = MAX(0, daily_spent_micros - ?),
                            last_updated = ?
                        WHERE mandate_id = ?
                        """,
                        (tx.amount_micros, tx.amount_micros, now, tx.mandate_id),
                    )
                conn.execute("COMMIT")

                refreshed = conn.execute(
                    "SELECT * FROM transactions WHERE tx_id = ?",
                    (tx_id,),
                ).fetchone()
                assert refreshed is not None
                tx = self._row_to_tx(refreshed)
            self._seal_integrity()
            return tx

    def record_transaction(
        self,
        mandate_id: str,
        tx_id: str,
        amount_usd: float,
        merchant: str,
        description: str,
        x402_payment_id: Optional[str] = None,
    ) -> Transaction:
        """
        Compatibility helper for local tests/dry runs.

        Records a completed transaction without reserve/finalize split.
        """
        with self._integrity_guard():
            self._verify_integrity()
            amount_micros = amount_usd_to_micros(amount_usd)
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._ensure_budget_row(conn, mandate_id)
                self._maybe_reset_daily(conn, mandate_id)
                now = int(time.time())
                conn.execute(
                    """
                    INSERT INTO transactions (
                        tx_id, mandate_id, amount_micros, merchant, description,
                        timestamp, status, x402_payment_id, idempotency_key, category, merchant_endpoint
                    ) VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, NULL, NULL, NULL)
                    """,
                    (tx_id, mandate_id, amount_micros, merchant, description, now, x402_payment_id),
                )
                conn.execute(
                    """
                    UPDATE mandate_budget
                    SET total_spent_micros = total_spent_micros + ?,
                        daily_spent_micros = daily_spent_micros + ?,
                        transaction_count = transaction_count + 1,
                        last_updated = ?
                    WHERE mandate_id = ?
                    """,
                    (amount_micros, amount_micros, now, mandate_id),
                )
                conn.execute("COMMIT")

            tx = Transaction(
                tx_id=tx_id,
                mandate_id=mandate_id,
                amount_micros=amount_micros,
                merchant=merchant,
                description=description,
                timestamp=int(time.time()),
                status="completed",
                x402_payment_id=x402_payment_id,
            )
            self._seal_integrity()
            return tx

    def get_state(self, mandate_id: str) -> BudgetState:
        """Load current budget state for a mandate."""
        with self._integrity_guard():
            self._verify_integrity()
            with self._connect() as conn:
                self._ensure_budget_row(conn, mandate_id)
                self._maybe_reset_daily(conn, mandate_id)
                row = conn.execute(
                    "SELECT * FROM mandate_budget WHERE mandate_id = ?",
                    (mandate_id,),
                ).fetchone()
                assert row is not None
                tx_rows = conn.execute(
                    """
                    SELECT * FROM transactions
                    WHERE mandate_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (mandate_id,),
                ).fetchall()

        return BudgetState(
            mandate_id=mandate_id,
            total_spent_micros=row["total_spent_micros"],
            daily_spent_micros=row["daily_spent_micros"],
            daily_reset_date=row["daily_reset_date"],
            transaction_count=row["transaction_count"],
            transactions=[self._row_to_tx(r) for r in tx_rows],
            last_updated=row["last_updated"],
        )

    def get_summary(self, mandate_id: str, max_total_usd: float) -> dict:
        """Get a human-readable budget summary."""
        state = self.get_state(mandate_id)
        max_total_micros = limit_usd_to_micros(max_total_usd)
        remaining_micros = max_total_micros - state.total_spent_micros
        utilization = (
            f"{(state.total_spent_micros / max_total_micros * 100):.1f}%"
            if max_total_micros > 0
            else "N/A"
        )
        return {
            "mandate_id": mandate_id,
            "total_spent": format_usd_from_micros(state.total_spent_micros),
            "total_budget": format_usd_from_micros(max_total_micros),
            "remaining": format_usd_from_micros(remaining_micros),
            "utilization": utilization,
            "transactions": state.transaction_count,
            "daily_spent": format_usd_from_micros(state.daily_spent_micros),
        }
