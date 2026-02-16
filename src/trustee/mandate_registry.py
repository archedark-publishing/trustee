"""Registry client abstractions for AP2 mandate status and trust policy."""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .mandate import normalize_address, _normalize_hex32
from .storage import ensure_private_dir, ensure_private_file


DEFAULT_REGISTRY_STATE_PATH = Path.home() / ".trustee" / "ap2_registry_state.json"


@dataclass
class MandateRegistryStatus:
    exists: bool
    active: bool
    revoked: bool
    expires_at: int
    issuer: str
    agent: str
    payload_hash: str
    metadata_uri: str


class MandateRegistryClient(Protocol):
    def is_trusted_issuer(self, agent: str, issuer: str) -> bool: ...

    def is_agent_paused(self, agent: str) -> bool: ...

    def get_mandate_status(self, mandate_hash: str) -> MandateRegistryStatus: ...


class LocalMandateRegistry:
    """File-backed stand-in for on-chain registry behavior.

    This adapter enforces the same trust and revocation semantics expected from
    the real contract and is suitable for local development and tests.
    """

    def __init__(self, path: Path | None = None):
        self.path = path or DEFAULT_REGISTRY_STATE_PATH
        ensure_private_dir(self.path.parent)
        self._lock_path = self.path.parent / ".ap2-registry.lock"
        ensure_private_file(self._lock_path)
        if not self.path.exists():
            self._save_state(
                {
                    "trusted_issuers": {},
                    "agent_paused": {},
                    "mandates": {},
                    "mandates_by_agent": {},
                }
            )

    @contextmanager
    def _lock(self):
        with open(self._lock_path, "r+") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    def _load_state(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def _save_state(self, state: dict) -> None:
        tmp_path = self.path.with_suffix(self.path.suffix + f".tmp.{os.getpid()}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.path)
        ensure_private_file(self.path)

    def set_trusted_issuer(self, agent: str, issuer: str, allowed: bool) -> None:
        normalized_agent = normalize_address(agent)
        normalized_issuer = normalize_address(issuer)

        with self._lock():
            state = self._load_state()
            trusted = state.setdefault("trusted_issuers", {})
            issuers = set(trusted.get(normalized_agent, []))
            if allowed:
                issuers.add(normalized_issuer)
            else:
                issuers.discard(normalized_issuer)
            trusted[normalized_agent] = sorted(issuers)
            self._save_state(state)

    def is_trusted_issuer(self, agent: str, issuer: str) -> bool:
        normalized_agent = normalize_address(agent)
        normalized_issuer = normalize_address(issuer)

        with self._lock():
            state = self._load_state()
            trusted = state.get("trusted_issuers", {})
            return normalized_issuer in set(trusted.get(normalized_agent, []))

    def set_agent_paused(self, agent: str, paused: bool) -> None:
        normalized_agent = normalize_address(agent)

        with self._lock():
            state = self._load_state()
            state.setdefault("agent_paused", {})[normalized_agent] = bool(paused)
            self._save_state(state)

    def is_agent_paused(self, agent: str) -> bool:
        normalized_agent = normalize_address(agent)

        with self._lock():
            state = self._load_state()
            return bool(state.get("agent_paused", {}).get(normalized_agent, False))

    def issue_mandate(
        self,
        *,
        mandate_hash: str,
        payload_hash: str,
        issuer: str,
        agent: str,
        expires_at: int,
        metadata_uri: str,
    ) -> str:
        normalized_mandate_hash = _normalize_hex32(mandate_hash, "mandate_hash")
        normalized_payload_hash = _normalize_hex32(payload_hash, "payload_hash")
        normalized_issuer = normalize_address(issuer)
        normalized_agent = normalize_address(agent)

        with self._lock():
            state = self._load_state()
            trusted = set(state.get("trusted_issuers", {}).get(normalized_agent, []))
            if normalized_issuer not in trusted:
                raise PermissionError("Issuer is not trusted for this agent")
            if bool(state.get("agent_paused", {}).get(normalized_agent, False)):
                raise PermissionError("Agent is paused")

            mandates = state.setdefault("mandates", {})
            if normalized_mandate_hash in mandates:
                raise ValueError(f"Mandate already exists: {normalized_mandate_hash}")

            now = int(time.time())
            mandates[normalized_mandate_hash] = {
                "mandate_hash": normalized_mandate_hash,
                "payload_hash": normalized_payload_hash,
                "issuer": normalized_issuer,
                "agent": normalized_agent,
                "issued_at": now,
                "expires_at": int(expires_at),
                "revoked_at": 0,
                "metadata_uri": metadata_uri,
            }
            by_agent = state.setdefault("mandates_by_agent", {})
            by_agent.setdefault(normalized_agent, []).append(normalized_mandate_hash)
            self._save_state(state)

        return _pseudo_tx_hash("issue", normalized_mandate_hash)

    def revoke_mandate(self, mandate_hash: str, issuer: str) -> str:
        normalized_mandate_hash = _normalize_hex32(mandate_hash, "mandate_hash")
        normalized_issuer = normalize_address(issuer)

        with self._lock():
            state = self._load_state()
            mandates = state.setdefault("mandates", {})
            record = mandates.get(normalized_mandate_hash)
            if record is None:
                raise KeyError(f"Mandate not found: {normalized_mandate_hash}")
            if normalize_address(record["issuer"]) != normalized_issuer:
                raise PermissionError("Only original issuer can revoke mandate")
            if int(record.get("revoked_at", 0)) != 0:
                raise ValueError(f"Mandate already revoked: {normalized_mandate_hash}")
            record["revoked_at"] = int(time.time())
            self._save_state(state)

        return _pseudo_tx_hash("revoke", normalized_mandate_hash)

    def get_mandate_status(self, mandate_hash: str) -> MandateRegistryStatus:
        normalized_mandate_hash = _normalize_hex32(mandate_hash, "mandate_hash")

        with self._lock():
            state = self._load_state()
            record = state.get("mandates", {}).get(normalized_mandate_hash)
            if record is None:
                return MandateRegistryStatus(
                    exists=False,
                    active=False,
                    revoked=False,
                    expires_at=0,
                    issuer="",
                    agent="",
                    payload_hash="0x" + "0" * 64,
                    metadata_uri="",
                )

            revoked = int(record.get("revoked_at", 0)) != 0
            expires_at = int(record.get("expires_at", 0))
            expired = expires_at != 0 and expires_at <= int(time.time())
            return MandateRegistryStatus(
                exists=True,
                active=not revoked and not expired,
                revoked=revoked,
                expires_at=expires_at,
                issuer=normalize_address(record["issuer"]),
                agent=normalize_address(record["agent"]),
                payload_hash=_normalize_hex32(record["payload_hash"], "payload_hash"),
                metadata_uri=str(record.get("metadata_uri", "")),
            )

    def get_mandate_hashes_by_agent(self, agent: str, cursor: int = 0, size: int = 100) -> tuple[list[str], int]:
        normalized_agent = normalize_address(agent)
        if size <= 0:
            raise ValueError("size must be > 0")
        if cursor < 0:
            raise ValueError("cursor must be >= 0")

        with self._lock():
            state = self._load_state()
            hashes = list(state.get("mandates_by_agent", {}).get(normalized_agent, []))

        if cursor > len(hashes):
            raise ValueError("cursor out of range")
        end = min(len(hashes), cursor + size)
        return hashes[cursor:end], end


def _pseudo_tx_hash(prefix: str, mandate_hash: str) -> str:
    seed = f"{prefix}:{mandate_hash}:{int(time.time() * 1000)}".encode("utf-8")
    digest = os.urandom(8).hex() + seed.hex()[:48]
    return "0x" + digest[:64].ljust(64, "0")
