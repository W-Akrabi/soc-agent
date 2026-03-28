"""Human-readable blast-radius summaries and rollback support metadata."""

from __future__ import annotations


ROLLBACK_MAP: dict[str, tuple[str, bool]] = {
    "block_ip": ("unblock_ip", False),
    "disable_account": ("enable_account", True),
    "isolate_host": ("unisolate_host", True),
    "revoke_sessions": ("", False),
    "patch_recommendation": ("", False),
}

_DESCRIPTIONS: dict[str, str] = {
    "block_ip": (
        "Will block all traffic to and from IP '{target}'. Legitimate traffic from this address "
        "will also be interrupted until the control is removed."
    ),
    "disable_account": (
        "Will disable account '{target}'. The user loses access immediately and downstream access "
        "failures should be expected until the account is re-enabled."
    ),
    "isolate_host": (
        "Will isolate host '{target}' from the network. Services or users depending on that host "
        "may lose connectivity until it is unisolated."
    ),
    "revoke_sessions": (
        "Will revoke active sessions for '{target}'. Users will need to re-authenticate and any "
        "active work relying on those sessions may be interrupted."
    ),
    "patch_recommendation": (
        "Advisory only for '{target}'. No automated change is executed by this action."
    ),
}


def estimate_blast_radius(action_type: str, target: str) -> str:
    normalized = (action_type or "").strip().lower()
    template = _DESCRIPTIONS.get(normalized)
    if template is None:
        return f"Action '{normalized or action_type}' affects target '{target}'. Review impact before execution."
    return template.format(target=target)


def rollback_details(action_type: str) -> tuple[str, bool]:
    normalized = (action_type or "").strip().lower()
    return ROLLBACK_MAP.get(normalized, ("", False))
