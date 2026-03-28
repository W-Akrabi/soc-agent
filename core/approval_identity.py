from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any


class ApprovalIdentityError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class MissingReviewerIdentityError(ApprovalIdentityError):
    def __init__(self) -> None:
        super().__init__(HTTPStatus.BAD_REQUEST, "reviewed_by is required")


class ReviewerIdentityNotAllowedError(ApprovalIdentityError):
    def __init__(self, reviewer: str, allowed: tuple[str, ...]):
        allowed_text = ", ".join(allowed) if allowed else "none"
        super().__init__(
            HTTPStatus.FORBIDDEN,
            f"reviewed_by {reviewer!r} is not in the approval allowlist ({allowed_text})",
        )


class InvalidApprovalTokenError(ApprovalIdentityError):
    def __init__(self) -> None:
        super().__init__(HTTPStatus.UNAUTHORIZED, "missing or invalid bearer token")


def _clean_identity(value: str) -> str:
    return " ".join(str(value).strip().split())


def normalize_identity_list(values: Iterable[str] | str | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = values.split(",")

    seen: set[str] = set()
    normalized: list[str] = []
    for value in values:
        text = _clean_identity(value)
        if not text:
            continue
        canonical = text.casefold()
        if canonical in seen:
            continue
        seen.add(canonical)
        normalized.append(text)
    return tuple(normalized)


@dataclass(slots=True)
class ApprovalIdentityPolicy:
    general_token: str | None = None
    approval_token: str | None = None
    allowed_reviewers: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_config(
        cls,
        config: Any | None = None,
        *,
        general_token: str | None = None,
        approval_token: str | None = None,
        allowed_reviewers: Iterable[str] | str | None = None,
    ) -> "ApprovalIdentityPolicy":
        if config is not None:
            if general_token is None:
                general_token = getattr(config, "api_token", None)
            if approval_token is None:
                approval_token = (
                    getattr(config, "api_approver_token", None)
                    or getattr(config, "approver_api_token", None)
                    or getattr(config, "approver_token", None)
                )
            if allowed_reviewers is None:
                allowed_reviewers = (
                    getattr(config, "approver_identities", None)
                    or getattr(config, "approval_identities", None)
                    or getattr(config, "api_approver_identities", None)
                )
        return cls(
            general_token=general_token,
            approval_token=approval_token,
            allowed_reviewers=normalize_identity_list(allowed_reviewers),
        )

    def expected_token(self, *, approval_route: bool) -> str | None:
        if approval_route and self.approval_token:
            return self.approval_token
        return self.general_token

    def authorize(self, headers: Mapping[str, str], *, approval_route: bool = False) -> None:
        expected = self.expected_token(approval_route=approval_route)
        if expected is None:
            return
        header = headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise InvalidApprovalTokenError()
        token = header.removeprefix("Bearer ").strip()
        if not token or token != expected:
            raise InvalidApprovalTokenError()

    def validate_reviewer(self, reviewer: str | None) -> str:
        if reviewer is None:
            raise MissingReviewerIdentityError()
        normalized = _clean_identity(reviewer)
        if not normalized:
            raise MissingReviewerIdentityError()
        if self.allowed_reviewers:
            allowed = {value.casefold() for value in self.allowed_reviewers}
            if normalized.casefold() not in allowed:
                raise ReviewerIdentityNotAllowedError(normalized, self.allowed_reviewers)
        return normalized
