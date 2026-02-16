"""AP2 mandate persistence with atomic writes and integrity verification."""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .mandate import (
    AP2Mandate,
    AP2MandateStatus,
    compute_ap2_payload_hash,
    normalize_address,
)
from .storage import ensure_private_dir, ensure_private_file, safe_child_path


DEFAULT_MANDATE_STORE_DIR = Path.home() / ".trustee" / "ap2_mandates"


class MandateStore:
    """File-backed AP2 mandate store with lock-based concurrency control."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or DEFAULT_MANDATE_STORE_DIR
        ensure_private_dir(self.base_dir)
        self._lock_path = self.base_dir / ".lock"
        ensure_private_file(self._lock_path)

    @contextmanager
    def _lock(self):
        with open(self._lock_path, "r+") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    def _mandate_path(self, mandate_hash: str) -> Path:
        identifier = mandate_hash.lower().replace("0x", "")
        return safe_child_path(self.base_dir, identifier, ".json")

    def _read_mandate_path(self, path: Path) -> AP2Mandate:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        mandate = AP2Mandate.from_dict(raw)
        expected = compute_ap2_payload_hash(mandate.core_payload())
        if mandate.payload_hash != expected:
            raise ValueError(f"Mandate payload hash mismatch for {mandate.mandate_hash}")
        return mandate

    def _atomic_write(self, path: Path, payload: dict) -> None:
        tmp_path = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        ensure_private_file(path)

    def save_mandate(self, mandate: AP2Mandate) -> None:
        """Persist a mandate to local storage."""
        with self._lock():
            path = self._mandate_path(mandate.mandate_hash)
            self._atomic_write(path, mandate.to_dict())

    def get_mandate(self, mandate_hash: str) -> Optional[AP2Mandate]:
        """Load mandate by hash and lazily mark expired mandates."""
        with self._lock():
            path = self._mandate_path(mandate_hash)
            if not path.exists():
                return None
            mandate = self._read_mandate_path(path)
            if mandate.is_expired and mandate.status in {
                AP2MandateStatus.DRAFT.value,
                AP2MandateStatus.PENDING_ON_CHAIN.value,
                AP2MandateStatus.ACTIVE.value,
            }:
                mandate.status = AP2MandateStatus.EXPIRED.value
                self._atomic_write(path, mandate.to_dict())
            return mandate

    def list_mandates(self, agent: str, include_inactive: bool = False) -> list[AP2Mandate]:
        """List mandates for an agent, optionally including inactive entries."""
        normalized_agent = normalize_address(agent)
        mandates: list[AP2Mandate] = []

        with self._lock():
            for path in sorted(self.base_dir.glob("*.json")):
                mandate = self._read_mandate_path(path)
                if mandate.agent != normalized_agent:
                    continue
                if mandate.is_expired and mandate.status in {
                    AP2MandateStatus.DRAFT.value,
                    AP2MandateStatus.PENDING_ON_CHAIN.value,
                    AP2MandateStatus.ACTIVE.value,
                }:
                    mandate.status = AP2MandateStatus.EXPIRED.value
                    self._atomic_write(path, mandate.to_dict())

                if include_inactive or mandate.status == AP2MandateStatus.ACTIVE.value:
                    mandates.append(mandate)

        mandates.sort(key=lambda m: m.issued_at, reverse=True)
        return mandates

    def update_status(self, mandate_hash: str, status: str, reason: str | None = None) -> None:
        """Update local lifecycle status and optional failure reason."""
        allowed_statuses = {member.value for member in AP2MandateStatus}
        if status not in allowed_statuses:
            raise ValueError(f"Invalid mandate status: {status}")
        with self._lock():
            path = self._mandate_path(mandate_hash)
            if not path.exists():
                raise KeyError(f"Mandate not found: {mandate_hash}")
            mandate = self._read_mandate_path(path)
            mandate.status = status
            if reason is not None:
                mandate.failure_reason = reason
            self._atomic_write(path, mandate.to_dict())

    def mark_revoked(self, mandate_hash: str) -> None:
        """Mark mandate as revoked (compatibility helper)."""
        self.update_status(mandate_hash, AP2MandateStatus.REVOKED.value)

    def record_chain_confirmation(self, mandate_hash: str, tx_hash: str, block_number: int) -> None:
        """Attach chain confirmation metadata and activate mandate."""
        with self._lock():
            path = self._mandate_path(mandate_hash)
            if not path.exists():
                raise KeyError(f"Mandate not found: {mandate_hash}")
            mandate = self._read_mandate_path(path)
            mandate.chain_tx_hash = tx_hash
            mandate.chain_block_number = int(block_number)
            mandate.status = AP2MandateStatus.ACTIVE.value
            self._atomic_write(path, mandate.to_dict())

    def cleanup_expired(self) -> int:
        """Mark active/pending mandates expired when their expiry is reached."""
        updated = 0
        now = int(time.time())

        with self._lock():
            for path in sorted(self.base_dir.glob("*.json")):
                mandate = self._read_mandate_path(path)
                if mandate.expires_at == 0 or mandate.expires_at > now:
                    continue
                if mandate.status not in {
                    AP2MandateStatus.DRAFT.value,
                    AP2MandateStatus.PENDING_ON_CHAIN.value,
                    AP2MandateStatus.ACTIVE.value,
                }:
                    continue
                mandate.status = AP2MandateStatus.EXPIRED.value
                self._atomic_write(path, mandate.to_dict())
                updated += 1

        return updated
