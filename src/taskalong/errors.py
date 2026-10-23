"""Stable, safe error envelopes shared by the API and CLI."""

from __future__ import annotations

from typing import Any


class TaskAlongError(Exception):
    """A documented failure whose message must be safe for operator display.

    Do not pass provider output, filesystem exception text, or raw task content as
    the message.  Recovery is structured data produced by the core.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = 2,
        retryable: bool = False,
        effect_outcome: str = "not_sent",
        recovery: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.retryable = retryable
        self.effect_outcome = effect_outcome
        self.recovery = recovery or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "effect_outcome": self.effect_outcome,
            "recovery": self.recovery,
        }
