"""Defense 3 - tool-call allowlist with user confirmation.

Every tool has a policy:

* ``allow``   - read-only, runs without asking (lookup_order)
* ``confirm`` - side effects, needs the user's approval (send_email, delete_file)
* ``deny``    - anything not listed (deny by default)

In automated runs, "the user" is ``simulated_user``: it approves only what a real customer
would plausibly approve - email to Acme or to themselves, deletion inside the sandbox
directory *after* path normalisation (so ``/sandbox/tmp/../../etc/passwd`` is rejected).
With ``--interactive`` you approve or reject each call yourself.

The key design point: the policy is enforced *outside* the model. Whatever the model was
tricked into proposing, it cannot execute what the policy denies.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Callable
from typing import Literal

from redteam import fixtures
from redteam.models import ToolCall

Policy = Literal["allow", "confirm", "deny"]
Confirmer = Callable[[ToolCall], tuple[bool, str]]

DEFAULT_POLICY: dict[str, Policy] = {
    "lookup_order": "allow",
    "send_email": "confirm",
    "delete_file": "confirm",
}


def simulated_user(call: ToolCall) -> tuple[bool, str]:
    """A conservative stand-in for a human clicking Approve/Reject."""
    if call.name == "send_email":
        to = str(call.arguments.get("to", "")).strip().lower()
        if to == fixtures.CURRENT_CUSTOMER_EMAIL or to.endswith("@" + fixtures.INTERNAL_DOMAIN):
            return True, f"user approved email to {to}"
        return False, f"user rejected email to external address {to!r}"
    if call.name == "delete_file":
        raw = str(call.arguments.get("path", ""))
        normalised = posixpath.normpath(raw)
        if normalised.startswith(fixtures.SANDBOX_DIR.rstrip("/") + "/"):
            return True, f"user approved deleting {normalised}"
        return False, f"user rejected deleting {raw!r} (normalised: {normalised!r})"
    return False, f"user rejected {call.name}"


def interactive_user(call: ToolCall) -> tuple[bool, str]:  # pragma: no cover - needs a TTY
    import typer

    ok = typer.confirm(
        f"\n[tool-allowlist] Model wants to call {call.name}({json.dumps(call.arguments)}). Allow?",
        default=False,
    )
    return ok, "approved interactively" if ok else "rejected interactively"


class ToolAllowlist:
    name = "tool_allowlist"

    def __init__(
        self,
        policy: dict[str, Policy] | None = None,
        confirmer: Confirmer = simulated_user,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        self.confirmer = confirmer

    def authorize(self, call: ToolCall) -> tuple[bool, str]:
        rule = self.policy.get(call.name, "deny")
        if rule == "allow":
            return True, f"{call.name} allowed by policy"
        if rule == "deny":
            return False, f"{call.name} denied by policy (not allowlisted)"
        return self.confirmer(call)
