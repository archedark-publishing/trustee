"""Money conversion helpers using fixed micro-dollar precision."""

from __future__ import annotations

from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR


MICROS_PER_USD = 1_000_000
_USD_QUANT = Decimal("0.000001")


def amount_usd_to_micros(value: Decimal | float | int | str) -> int:
    """Convert spend amount to micro-dollars, rounding up (conservative)."""
    dec = Decimal(str(value)).quantize(_USD_QUANT, rounding=ROUND_CEILING)
    return int(dec * MICROS_PER_USD)


def limit_usd_to_micros(value: Decimal | float | int | str) -> int:
    """Convert budget limit to micro-dollars, rounding down (conservative)."""
    dec = Decimal(str(value)).quantize(_USD_QUANT, rounding=ROUND_FLOOR)
    return int(dec * MICROS_PER_USD)


def usd_to_micros(value: Decimal | float | int | str) -> int:
    """Backward-compatible alias: treat input as spend amount."""
    return amount_usd_to_micros(value)


def micros_to_usd_decimal(value: int) -> Decimal:
    """Convert integer micro-dollars to Decimal USD."""
    return (Decimal(value) / Decimal(MICROS_PER_USD)).quantize(_USD_QUANT)


def micros_to_usd_float(value: int) -> float:
    """Convert integer micro-dollars to float USD (for display APIs)."""
    return float(micros_to_usd_decimal(value))


def format_usd_from_micros(value: int) -> str:
    """Format integer micro-dollars as a currency string."""
    return f"${micros_to_usd_decimal(value):.2f}"
