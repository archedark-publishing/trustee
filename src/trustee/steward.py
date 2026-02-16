"""
Steward — session-based signing controls for agent payments.

Private keys are held in a dedicated worker process. The caller only receives
opaque signer capabilities that can request policy-checked signatures.
"""

from __future__ import annotations

import hashlib
import json
import logging
import multiprocessing as mp
import os
import subprocess
import threading
import time
import traceback
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from eth_account import Account

from .money import amount_usd_to_micros, limit_usd_to_micros, micros_to_usd_float

logger = logging.getLogger(__name__)


@dataclass
class SessionConfig:
    """Configuration for a Steward session."""

    max_spend_usd: float = 10.0
    max_per_tx_usd: float = 1.0
    ttl_seconds: int = 3600
    allowed_networks: list[str] = field(default_factory=lambda: ["eip155:84532"])
    allowed_merchants: list[str] = field(default_factory=list)
    allowed_payees: list[str] = field(default_factory=list)


@dataclass
class _ExpectedPayment:
    network: str
    pay_to: str
    amount_base_units: int


@dataclass
class SessionState:
    """Runtime state of a Steward session (no key material)."""

    session_id: str
    created_at: float
    config: SessionConfig
    wallet_address: str
    total_spent_micros: int = 0
    tx_count: int = 0
    expected_payment: Optional[_ExpectedPayment] = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.created_at + self.config.ttl_seconds

    @property
    def total_spent_usd(self) -> float:
        return micros_to_usd_float(self.total_spent_micros)

    @property
    def remaining_usd(self) -> float:
        return micros_to_usd_float(max(0, self.max_spend_micros - self.total_spent_micros))

    @property
    def seconds_remaining(self) -> int:
        return max(0, int(self.created_at + self.config.ttl_seconds - time.time()))

    @property
    def max_spend_micros(self) -> int:
        return limit_usd_to_micros(self.config.max_spend_usd)

    @property
    def max_per_tx_micros(self) -> int:
        return limit_usd_to_micros(self.config.max_per_tx_usd)

    def check_spend_micros(self, amount_micros: int) -> tuple[bool, str]:
        if self.is_expired:
            return False, "Session expired"
        if amount_micros > self.max_per_tx_micros:
            return (
                False,
                f"Amount ${micros_to_usd_float(amount_micros):.6f} exceeds per-tx limit "
                f"${self.config.max_per_tx_usd:.6f}",
            )
        if self.total_spent_micros + amount_micros > self.max_spend_micros:
            return (
                False,
                "Would exceed session spend cap "
                f"(${micros_to_usd_float(self.total_spent_micros + amount_micros):.6f} "
                f"> ${self.config.max_spend_usd:.6f})",
            )
        return True, "OK"

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "wallet_address": self.wallet_address,
            "created_at": self.created_at,
            "expires_at": self.created_at + self.config.ttl_seconds,
            "seconds_remaining": self.seconds_remaining,
            "total_spent_usd": self.total_spent_usd,
            "remaining_usd": self.remaining_usd,
            "tx_count": self.tx_count,
            "config": {
                "max_spend_usd": self.config.max_spend_usd,
                "max_per_tx_usd": self.config.max_per_tx_usd,
                "ttl_seconds": self.config.ttl_seconds,
                "allowed_networks": self.config.allowed_networks,
                "allowed_merchants": self.config.allowed_merchants,
                "allowed_payees": self.config.allowed_payees,
            },
        }


class Steward:
    """Session manager for secure signing capabilities."""

    def __init__(self):
        self._sessions: dict[str, SessionState] = {}
        self._rpc_lock = threading.Lock()
        self._closed = False

        ctx = mp.get_context("spawn")
        self._conn, child_conn = ctx.Pipe()
        self._worker = ctx.Process(
            target=_signer_worker,
            args=(child_conn,),
            daemon=True,
        )
        self._worker.start()
        child_conn.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._rpc("shutdown")
        except Exception:
            pass
        if self._worker.is_alive():
            self._worker.join(timeout=1.0)
        if self._worker.is_alive():
            self._worker.terminate()
            self._worker.join(timeout=1.0)
        self._conn.close()
        self._closed = True

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def create_session(
        self,
        op_item: str,
        op_vault: str,
        op_field: str = "credential",
        config: Optional[SessionConfig] = None,
    ) -> SessionState:
        config = config or SessionConfig()
        session_id = self._generate_session_id()
        created_at = time.time()

        result = self._rpc(
            "create_session",
            session_id=session_id,
            created_at=created_at,
            config=asdict(config),
            op_item=op_item,
            op_vault=op_vault,
            op_field=op_field,
        )
        wallet_address = str(result["wallet_address"])

        session = SessionState(
            session_id=session_id,
            created_at=created_at,
            config=config,
            wallet_address=wallet_address,
        )
        self._sessions[session_id] = session
        logger.info(
            "Steward session created: %s (wallet: %s, ttl: %ds, cap: $%.2f)",
            session_id,
            wallet_address,
            config.ttl_seconds,
            config.max_spend_usd,
        )
        return session

    def create_session_from_private_key(
        self,
        private_key: str,
        config: Optional[SessionConfig] = None,
    ) -> SessionState:
        config = config or SessionConfig()
        session_id = self._generate_session_id()
        created_at = time.time()

        result = self._rpc(
            "create_session",
            session_id=session_id,
            created_at=created_at,
            config=asdict(config),
            private_key=private_key,
        )
        wallet_address = str(result["wallet_address"])

        session = SessionState(
            session_id=session_id,
            created_at=created_at,
            config=config,
            wallet_address=wallet_address,
        )
        self._sessions[session_id] = session
        logger.info(
            "Steward session created: %s (wallet: %s, ttl: %ds, cap: $%.2f)",
            session_id,
            wallet_address,
            config.ttl_seconds,
            config.max_spend_usd,
        )
        return session

    def get_session(self, session_id: str) -> SessionState:
        from .errors import SessionExpiredError, SessionNotFoundError

        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(f"Session not found: {session_id}")
        if session.is_expired:
            self.destroy_session(session_id)
            raise SessionExpiredError(f"Session expired: {session_id}")
        return session

    def get_signer(self, session_id: str) -> "StewardSigner":
        session = self.get_session(session_id)
        return StewardSigner(self, session_id=session.session_id, address=session.wallet_address)

    def destroy_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        try:
            self._rpc("destroy_session", session_id=session_id)
        except Exception:
            pass
        logger.info("Steward session destroyed: %s", session_id)

    def destroy_all(self) -> None:
        for sid in list(self._sessions.keys()):
            self.destroy_session(sid)

    def list_sessions(self) -> list[dict]:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            self.destroy_session(sid)
        return [s.to_dict() for s in self._sessions.values()]

    def _generate_session_id(self) -> str:
        entropy = f"{time.time()}-{os.urandom(16).hex()}"
        return f"st-{hashlib.sha256(entropy.encode()).hexdigest()[:12]}"

    def _rpc(self, command: str, **payload) -> dict:
        if self._closed:
            raise RuntimeError("Steward is closed")
        with self._rpc_lock:
            self._conn.send({"cmd": command, **payload})
            response = self._conn.recv()
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "Unknown steward worker error"))
        return response.get("result", {})

    def _check_and_record_spend(self, session_id: str, amount_usd: float) -> tuple[bool, str]:
        session = self.get_session(session_id)
        result = self._rpc(
            "check_and_record_spend",
            session_id=session_id,
            amount_micros=amount_usd_to_micros(amount_usd),
        )
        session.total_spent_micros = int(result["total_spent_micros"])
        session.tx_count = int(result["tx_count"])
        return bool(result["allowed"]), str(result["reason"])

    def _prepare_expected_payment(
        self,
        session_id: str,
        network: str,
        pay_to: str,
        amount_base_units: int,
    ) -> None:
        self.get_session(session_id)
        self._rpc(
            "prepare_expected_payment",
            session_id=session_id,
            network=network,
            pay_to=pay_to,
            amount_base_units=int(amount_base_units),
        )

    def _sign_typed_data(
        self,
        session_id: str,
        domain: Any,
        types: dict[str, list],
        primary_type: str,
        message: dict[str, Any],
    ) -> bytes:
        session = self.get_session(session_id)
        result = self._rpc(
            "sign_typed_data",
            session_id=session_id,
            domain=_domain_to_dict(domain),
            types=_types_to_plain(types),
            primary_type=primary_type,
            message=_message_to_plain(message),
        )
        session.total_spent_micros = int(result["total_spent_micros"])
        session.tx_count = int(result["tx_count"])
        return bytes.fromhex(str(result["signature_hex"]))


class StewardSigner:
    """Capability object that exposes policy-enforced signing only."""

    __slots__ = ("_steward", "_session_id", "_address")

    def __init__(self, steward: Steward, session_id: str, address: str):
        self._steward = steward
        self._session_id = session_id
        self._address = address

    @property
    def address(self) -> str:
        return self._address

    @property
    def remaining_usd(self) -> float:
        return self._steward.get_session(self._session_id).remaining_usd

    @property
    def seconds_remaining(self) -> int:
        return self._steward.get_session(self._session_id).seconds_remaining

    def check_and_record_spend(self, amount_usd: float) -> tuple[bool, str]:
        return self._steward._check_and_record_spend(self._session_id, amount_usd)

    def prepare_payment(self, network: str, pay_to: str, amount_base_units: int) -> None:
        self._steward._prepare_expected_payment(
            self._session_id,
            network=network,
            pay_to=pay_to,
            amount_base_units=amount_base_units,
        )

    def sign_typed_data(
        self,
        domain: Any,
        types: dict[str, list],
        primary_type: str,
        message: dict[str, Any],
    ) -> bytes:
        return self._steward._sign_typed_data(
            self._session_id,
            domain=domain,
            types=types,
            primary_type=primary_type,
            message=message,
        )

    def __repr__(self) -> str:
        return (
            f"StewardSigner(address={self.address}, "
            f"remaining=${self.remaining_usd:.2f}, ttl={self.seconds_remaining}s)"
        )


def _extract_network(domain: dict[str, Any]) -> Optional[str]:
    chain_id = domain.get("chainId") or domain.get("chain_id")
    if chain_id is None:
        return None
    return f"eip155:{int(chain_id)}"


def _domain_to_dict(domain: Any) -> dict[str, Any]:
    if isinstance(domain, dict):
        return dict(domain)
    result: dict[str, Any] = {}
    for src, dst in (
        ("name", "name"),
        ("version", "version"),
        ("chain_id", "chainId"),
        ("chainId", "chainId"),
        ("verifying_contract", "verifyingContract"),
        ("verifyingContract", "verifyingContract"),
        ("salt", "salt"),
    ):
        value = getattr(domain, src, None)
        if value is not None:
            result[dst] = value
    return result


def _types_to_plain(types: dict[str, list]) -> dict[str, list[dict[str, str]]]:
    plain: dict[str, list[dict[str, str]]] = {}
    for type_name, fields in types.items():
        plain[type_name] = [
            {
                "name": f["name"] if isinstance(f, dict) else getattr(f, "name"),
                "type": f["type"] if isinstance(f, dict) else getattr(f, "type"),
            }
            for f in fields
        ]
    return plain


def _message_to_plain(message: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(message)
    if "nonce" in normalized and isinstance(normalized["nonce"], bytes):
        normalized["nonce"] = "0x" + normalized["nonce"].hex()
    return normalized


def _sign_typed_data_with_account(
    account: Any,
    domain: dict[str, Any],
    types: dict[str, list[dict[str, str]]],
    primary_type: str,
    message: dict[str, Any],
) -> bytes:
    full_message = {
        "types": {**types, "EIP712Domain": _build_domain_type(domain)},
        "primaryType": primary_type,
        "domain": domain,
        "message": message,
    }
    signed = account.sign_typed_data(full_message=full_message)
    return bytes(signed.signature)


def _build_domain_type(domain: dict[str, Any]) -> list[dict[str, str]]:
    fields: list[dict[str, str]] = []
    if "name" in domain:
        fields.append({"name": "name", "type": "string"})
    if "version" in domain:
        fields.append({"name": "version", "type": "string"})
    if "chainId" in domain:
        fields.append({"name": "chainId", "type": "uint256"})
    if "verifyingContract" in domain:
        fields.append({"name": "verifyingContract", "type": "address"})
    if "salt" in domain:
        fields.append({"name": "salt", "type": "bytes32"})
    return fields


def _signer_worker(conn) -> None:
    sessions: dict[str, dict[str, Any]] = {}
    try:
        while True:
            req = conn.recv()
            cmd = req.get("cmd")
            try:
                if cmd == "shutdown":
                    conn.send({"ok": True, "result": {}})
                    return

                if cmd == "create_session":
                    session_id = str(req["session_id"])
                    key = req.get("private_key")
                    if key is None:
                        key = _load_key_from_1password_worker(
                            item=str(req["op_item"]),
                            vault=str(req["op_vault"]),
                            field=str(req.get("op_field", "credential")),
                        )
                    else:
                        key = str(key)
                    created_at = float(req["created_at"])
                    config = dict(req["config"])
                    account = Account.from_key(key)
                    sessions[session_id] = {
                        "account": account,
                        "created_at": created_at,
                        "config": config,
                        "total_spent_micros": 0,
                        "tx_count": 0,
                        "wallet_address": account.address,
                        "expected_payment": None,
                    }
                    conn.send({"ok": True, "result": {"wallet_address": account.address}})
                    continue

                if cmd == "destroy_session":
                    sessions.pop(str(req["session_id"]), None)
                    conn.send({"ok": True, "result": {}})
                    continue

                session_id = str(req["session_id"])
                session = sessions.get(session_id)
                if session is None:
                    raise RuntimeError(f"Session not found: {session_id}")
                _ensure_not_expired(session_id, session)

                if cmd == "check_and_record_spend":
                    amount_micros = int(req["amount_micros"])
                    allowed, reason = _check_spend(session, amount_micros)
                    if allowed:
                        session["total_spent_micros"] += amount_micros
                        session["tx_count"] += 1
                    conn.send(
                        {
                            "ok": True,
                            "result": {
                                "allowed": allowed,
                                "reason": reason,
                                "total_spent_micros": session["total_spent_micros"],
                                "tx_count": session["tx_count"],
                            },
                        }
                    )
                    continue

                if cmd == "prepare_expected_payment":
                    session["expected_payment"] = {
                        "network": str(req["network"]),
                        "pay_to": str(req["pay_to"]).lower(),
                        "amount_base_units": int(req["amount_base_units"]),
                    }
                    conn.send({"ok": True, "result": {}})
                    continue

                if cmd == "sign_typed_data":
                    domain = dict(req["domain"])
                    types = dict(req["types"])
                    primary_type = str(req["primary_type"])
                    message = dict(req["message"])

                    network = _extract_network(domain)
                    from_address = str(message.get("from", "")).lower()
                    pay_to = str(message.get("to", "")).lower()
                    value = int(message.get("value", 0))

                    allowed_networks = set(session["config"].get("allowed_networks", []))
                    if network and allowed_networks and network not in allowed_networks:
                        raise RuntimeError(f"Network {network} not allowed for session")

                    allowed_payees = set(
                        p.lower() for p in session["config"].get("allowed_payees", [])
                    )
                    allowed_payees.update(
                        str(m).lower()
                        for m in session["config"].get("allowed_merchants", [])
                        if str(m).startswith("0x")
                    )
                    if allowed_payees and pay_to not in allowed_payees:
                        raise RuntimeError(f"Payee {pay_to} not in session allowlist")

                    if from_address and from_address != session["wallet_address"].lower():
                        raise RuntimeError("Typed data payer does not match session wallet")

                    expected = session.get("expected_payment")
                    session["expected_payment"] = None
                    if expected is None:
                        raise RuntimeError("Signing intent not prepared")
                    if expected.get("network") and network != expected["network"]:
                        raise RuntimeError("Signing payload network mismatch")
                    if expected.get("pay_to") and pay_to != expected["pay_to"]:
                        raise RuntimeError("Signing payload recipient mismatch")
                    if expected.get("amount_base_units") and value > int(expected["amount_base_units"]):
                        raise RuntimeError("Signing payload amount exceeds approved amount")

                    amount_micros = value
                    allowed, reason = _check_spend(session, amount_micros)
                    if not allowed:
                        raise RuntimeError(reason)

                    session["total_spent_micros"] += amount_micros
                    session["tx_count"] += 1

                    try:
                        signature = _sign_typed_data_with_account(
                            account=session["account"],
                            domain=domain,
                            types=types,
                            primary_type=primary_type,
                            message=message,
                        )
                    except Exception:
                        session["total_spent_micros"] = max(
                            0, session["total_spent_micros"] - amount_micros
                        )
                        session["tx_count"] = max(0, session["tx_count"] - 1)
                        raise

                    conn.send(
                        {
                            "ok": True,
                            "result": {
                                "signature_hex": signature.hex(),
                                "total_spent_micros": session["total_spent_micros"],
                                "tx_count": session["tx_count"],
                            },
                        }
                    )
                    continue

                raise RuntimeError(f"Unknown command: {cmd}")
            except Exception as e:
                conn.send(
                    {
                        "ok": False,
                        "error": f"{type(e).__name__}: {e}",
                        "traceback": traceback.format_exc(),
                    }
                )
    finally:
        conn.close()


def _ensure_not_expired(session_id: str, session: dict[str, Any]) -> None:
    created_at = float(session["created_at"])
    ttl = int(session["config"]["ttl_seconds"])
    if time.time() > created_at + ttl:
        raise RuntimeError(f"Session expired: {session_id}")


def _check_spend(session: dict[str, Any], amount_micros: int) -> tuple[bool, str]:
    max_spend_micros = limit_usd_to_micros(float(session["config"]["max_spend_usd"]))
    max_per_tx_micros = limit_usd_to_micros(float(session["config"]["max_per_tx_usd"]))
    total_spent_micros = int(session["total_spent_micros"])

    if amount_micros > max_per_tx_micros:
        return (
            False,
            f"Amount ${micros_to_usd_float(amount_micros):.6f} exceeds per-tx limit "
            f"${float(session['config']['max_per_tx_usd']):.6f}",
        )
    if total_spent_micros + amount_micros > max_spend_micros:
        return (
            False,
            "Would exceed session spend cap "
            f"(${micros_to_usd_float(total_spent_micros + amount_micros):.6f} "
            f"> ${float(session['config']['max_spend_usd']):.6f})",
        )
    return True, "OK"


def _load_key_from_1password_worker(item: str, vault: str, field: str) -> str:
    result = subprocess.run(
        ["op", "item", "get", item, "--vault", vault, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"1Password error: {result.stderr.strip()}")
    fields = json.loads(result.stdout)["fields"]
    key = next((f["value"] for f in fields if f.get("label") == field), None)
    if not key:
        raise ValueError(f"Field '{field}' not found in 1Password item '{item}'")
    return key
