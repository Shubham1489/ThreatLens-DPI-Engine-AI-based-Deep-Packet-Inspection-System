"""
ThreatLens – Rule Manager
Manages IP, domain, and app-category blocking rules.
Checks packets/flows against active rules.
"""

import threading
from typing import Set, List, Dict
from dataclasses import dataclass, field
from datetime import datetime

from .models import AppType


@dataclass
class BlockRule:
    id:         int
    rule_type:  str   # "IP" | "DOMAIN" | "APP"
    value:      str   # IP address, domain substring, or AppType value
    enabled:    bool = True
    notes:      str  = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


# Default blocklist: well-known adware/malware domains
DEFAULT_BLOCKED_DOMAINS = [
    "doubleclick.net", "googlesyndication.com", "adnxs.com",
    "taboola.com", "outbrain.com", "moatads.com", "openx.net",
    "rubiconproject.com", "pubmatic.com", "criteo.com",
    "malware-traffic-analysis.net", "zeroredirect.com",
]

DEFAULT_BLOCKED_IPS: List[str] = []

_id_counter = 0


def _next_id() -> int:
    global _id_counter
    _id_counter += 1
    return _id_counter


class RuleManager:
    def __init__(self):
        self._rules: List[BlockRule] = []
        self._lock  = threading.Lock()
        self._load_defaults()

    def _load_defaults(self):
        for domain in DEFAULT_BLOCKED_DOMAINS:
            self._rules.append(BlockRule(_next_id(), "DOMAIN", domain, True, "Default adware list"))
        for ip in DEFAULT_BLOCKED_IPS:
            self._rules.append(BlockRule(_next_id(), "IP", ip, True, "Default blocklist"))

    # ── Public API ──────────────────────────────────────────────────────────

    def add_rule(self, rule_type: str, value: str, notes: str = "") -> BlockRule:
        rule = BlockRule(_next_id(), rule_type.upper(), value.lower().strip(), True, notes)
        with self._lock:
            self._rules.append(rule)
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            return len(self._rules) < before

    def toggle_rule(self, rule_id: int) -> bool:
        with self._lock:
            for r in self._rules:
                if r.id == rule_id:
                    r.enabled = not r.enabled
                    return r.enabled
        return False

    def get_all_rules(self) -> List[BlockRule]:
        with self._lock:
            return list(self._rules)

    def is_blocked_ip(self, ip: str) -> bool:
        with self._lock:
            return any(r.enabled and r.rule_type == "IP" and r.value == ip for r in self._rules)

    def is_blocked_domain(self, domain: str) -> bool:
        if not domain:
            return False
        domain_lower = domain.lower()
        with self._lock:
            return any(
                r.enabled and r.rule_type == "DOMAIN" and r.value in domain_lower
                for r in self._rules
            )

    def is_blocked_app(self, app: AppType) -> bool:
        with self._lock:
            return any(r.enabled and r.rule_type == "APP" and r.value == app.value.lower() for r in self._rules)

    def should_block(self, src_ip: str, dst_ip: str, sni: str, app: AppType) -> bool:
        """Master check: return True if any rule matches."""
        return (
            self.is_blocked_ip(src_ip) or
            self.is_blocked_ip(dst_ip) or
            self.is_blocked_domain(sni)  or
            self.is_blocked_app(app)
        )
