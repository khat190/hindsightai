"""SIMULATED security tools. Nothing here touches real infrastructure.

Read-only tools query the incident's synthetic telemetry. Consequential tools only mutate an
in-memory MockEnvironment and return a "simulated_success" result.
"""
from __future__ import annotations

import copy
import itertools
from datetime import datetime, timezone

from .errors import ValidationFailed

READ_ONLY = ("search_logs", "get_user_activity", "get_authentication_history", "check_indicator",
             "get_endpoint_activity")
CONSEQUENTIAL = ("preserve_evidence", "revoke_sessions", "disable_account", "isolate_endpoint",
                 "block_indicator", "remove_unauthorized_access", "create_ticket")
CONTAINMENT = ("revoke_sessions", "disable_account", "isolate_endpoint", "block_indicator",
               "remove_unauthorized_access")

TOOL_SPECS = {
    "search_logs": {"arg": "query", "consequential": False, "description": "Search logs for a term."},
    "get_user_activity": {"arg": "username", "consequential": False, "description": "Recent activity for a user."},
    "get_authentication_history": {"arg": "username", "consequential": False, "description": "Login history for a user."},
    "check_indicator": {"arg": "indicator", "consequential": False, "description": "Reputation of an IP/domain/hash."},
    "get_endpoint_activity": {"arg": "host", "consequential": False, "description": "Recent activity for a host."},
    "preserve_evidence": {"arg": "target", "consequential": True, "description": "Snapshot sessions, credentials and logs for a user/host."},
    "revoke_sessions": {"arg": "username", "consequential": True, "description": "Revoke all active sessions of a user."},
    "disable_account": {"arg": "username", "consequential": True, "description": "Disable a user account."},
    "isolate_endpoint": {"arg": "host", "consequential": True, "description": "Network-isolate a host."},
    "block_indicator": {"arg": "indicator", "consequential": True, "description": "Block an IP/domain/hash."},
    "remove_unauthorized_access": {"arg": "user", "consequential": True, "description": "Remove attacker-created credentials/grants/rules."},
    "create_ticket": {"arg": "summary", "consequential": True, "description": "Create an escalation ticket."},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class MockSecurityTools:
    """One instance per incident so state (revoked sessions, blocked IPs...) persists across approvals."""

    _ticket_counter = itertools.count(1001)

    def __init__(self, telemetry: dict | None = None):
        self.tel = copy.deepcopy(telemetry or {})
        self.state = {"revoked": [], "disabled": [], "isolated": [], "blocked": [], "tickets": [], "snapshots": []}

    # ---------- helpers ----------
    def _result(self, tool: str, target: str, status: str = "simulated_success", message: str = "", **extra) -> dict:
        r = {"tool": tool, "status": status, "target": target, "message": message, "simulated": True, "timestamp": _now()}
        r.update(extra)
        return r

    # ---------- read-only ----------
    def search_logs(self, query: str) -> dict:
        q = (query or "").lower()
        terms = [t for t in q.split() if t]
        hits = [l for l in self.tel.get("logs", []) if any(t in (l["message"] + l.get("source", "")).lower() for t in terms)] if terms else []
        return self._result("search_logs", query, message=f"{len(hits)} matching log entries.", results=hits)

    def get_user_activity(self, username: str) -> dict:
        prof = (self.tel.get("user_profiles") or {}).get(username)
        act = (self.tel.get("user_activity") or {}).get(username, [])
        return self._result("get_user_activity", username, message=f"{len(act)} activity events.",
                            profile=prof, events=act, active_sessions=(self.tel.get("active_sessions") or {}).get(username, []))

    def get_authentication_history(self, username: str) -> dict:
        ev = (self.tel.get("authentication_history") or {}).get(username, [])
        return self._result("get_authentication_history", username, message=f"{len(ev)} authentication events.", events=ev)

    def check_indicator(self, indicator: str) -> dict:
        info = (self.tel.get("indicators") or {}).get(indicator)
        if info is None:
            info = {"reputation": "unknown", "tags": []}
        return self._result("check_indicator", indicator, message=f"Reputation: {info['reputation']}.", **info)

    def get_endpoint_activity(self, host: str) -> dict:
        ev = (self.tel.get("endpoint_activity") or {}).get(host, [])
        return self._result("get_endpoint_activity", host, message=f"{len(ev)} endpoint events.", events=ev)

    # ---------- consequential (simulated) ----------
    def preserve_evidence(self, target: str) -> dict:
        auth = len((self.tel.get("authentication_history") or {}).get(target, []))
        act = len((self.tel.get("user_activity") or {}).get(target, []))
        sess = (self.tel.get("active_sessions") or {}).get(target, [])
        unauth = (self.tel.get("unauthorized_access") or {}).get(target, [])
        snap_id = f"EVD-{len(self.state['snapshots']) + 1:03d}"
        self.state["snapshots"].append(snap_id)
        return self._result("preserve_evidence", target, snapshot_id=snap_id,
                            message=f"Evidence snapshot {snap_id} stored (simulated): {auth} auth events, {act} activity events, "
                                    f"{len(sess)} active sessions, {len(unauth)} suspected unauthorized items.",
                            captured={"auth_events": auth, "activity_events": act, "active_sessions": sess, "suspected_unauthorized": unauth})

    def revoke_sessions(self, username: str) -> dict:
        sess = (self.tel.get("active_sessions") or {}).get(username, [])
        n = len(sess)
        if username in (self.tel.get("active_sessions") or {}):
            self.tel["active_sessions"][username] = []
        self.state["revoked"].append(username)
        return self._result("revoke_sessions", username, message=f"All active sessions for {username} were revoked in the simulation ({n} session(s)).", revoked_count=n)

    def disable_account(self, username: str) -> dict:
        deps = ((self.tel.get("user_profiles") or {}).get(username) or {}).get("dependent_services", [])
        self.state["disabled"].append(username)
        return self._result("disable_account", username, message=f"Account {username} was disabled in the simulation.",
                            services_impacted=deps)

    def isolate_endpoint(self, host: str) -> dict:
        self.state["isolated"].append(host)
        return self._result("isolate_endpoint", host, message=f"Host {host} was network-isolated in the simulation.")

    def block_indicator(self, indicator: str) -> dict:
        self.state["blocked"].append(indicator)
        return self._result("block_indicator", indicator, message=f"Indicator {indicator} was blocked in the simulation.")

    def remove_unauthorized_access(self, user: str) -> dict:
        items = (self.tel.get("unauthorized_access") or {}).get(user, [])
        removed = list(items)
        if user in (self.tel.get("unauthorized_access") or {}):
            self.tel["unauthorized_access"][user] = []
        return self._result("remove_unauthorized_access", user, message=f"Removed {len(removed)} unauthorized item(s) for {user} in the simulation.", removed=removed)

    def create_ticket(self, summary: str) -> dict:
        tid = f"TKT-{next(self._ticket_counter)}"
        self.state["tickets"].append(tid)
        return self._result("create_ticket", summary, message=f"Ticket {tid} created in the simulation.", ticket_id=tid)

    # ---------- dispatcher ----------
    def execute(self, tool: str, target: str) -> dict:
        if tool not in TOOL_SPECS:
            raise ValidationFailed(f"Unknown tool '{tool}'", hint=f"Valid tools: {sorted(TOOL_SPECS)}")
        if not isinstance(target, str) or not target.strip():
            raise ValidationFailed(f"Tool '{tool}' needs a non-empty target ({TOOL_SPECS[tool]['arg']})")
        return getattr(self, tool)(target.strip())
