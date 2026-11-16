"""Firewall rule review for CIP-003 Attachment 1, Section 3.1 (and the 6.x detection controls on vendor paths).

Reads a FortiGate configuration backup ("config firewall policy" blocks) or a Palo Alto PAN-OS / Panorama XML
configuration (security rulebase), and flags permit rules an auditor would question: any-to-any, any source or
destination, any service or application, no stated reason, logging off, and vendor VPN rules without threat
inspection or always on. Read-only: configs are parsed as data and never executed. Other brands can be added as
parsers that return the same Rule list.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

VPN_HINTS = ("ssl.root", "ssl.", "vpn", "ipsec", "dialup", "vendor", "remote", "globalprotect", "gp-")


@dataclass
class Rule:
    id: str
    attrs: dict[str, list[str]] = field(default_factory=dict)

    def get(self, k: str) -> list[str]:
        return self.attrs.get(k, [])

    def one(self, k: str, default: str = "") -> str:
        v = self.get(k)
        return v[0] if v else default

    @property
    def label(self) -> str:
        name = self.one("name")
        if name and name == self.id:
            return f"Rule '{name}'"
        return f"Policy {self.id}" + (f" ({name})" if name else "")


@dataclass
class Issue:
    severity: str  # high | medium | low
    rule: str
    code: str  # requirement it bears on
    text: str


def parse_fortigate_policies(text: str) -> list[Rule]:
    rules, in_block, cur, depth = [], False, None, 0
    for raw in text.splitlines():
        line = raw.strip()
        if not in_block:
            if line == "config firewall policy":
                in_block, depth = True, 0
            continue
        if line.startswith("config "):
            depth += 1
            continue
        if line == "end":
            if depth:
                depth -= 1
                continue
            in_block = False
            continue
        if depth:
            continue
        if line.startswith("edit "):
            cur = Rule(id=line[5:].strip().strip('"'))
        elif line == "next" and cur is not None:
            rules.append(cur)
            cur = None
        elif line.startswith("set ") and cur is not None:
            try:
                parts = shlex.split(line[4:])
            except ValueError:
                parts = line[4:].split()
            if parts:
                cur.attrs[parts[0]] = parts[1:]
    return rules


def _any(values: list[str]) -> bool:
    return any(v.lower() in ("all", "any", "all_icmp") for v in values) or not values


def review(rules: list[Rule]) -> list[Issue]:
    issues: list[Issue] = []
    for r in rules:
        if r.one("status") == "disable" or r.one("action", "deny") != "accept":
            continue
        src_any, dst_any = _any(r.get("srcaddr")), _any(r.get("dstaddr"))
        svc_any = any(v.upper() == "ALL" for v in r.get("service")) or not r.get("service")
        if r.get("application") and _any(r.get("application")) and not svc_any:
            issues.append(Issue("medium", r.label, "CIP-003 Att1 S3.1",
                                "Allows any application. Name the applications the business need requires."))
        vendor = any(h in i.lower() for i in r.get("srcintf") for h in VPN_HINTS) or \
            any(h in (r.one("name") + " " + " ".join(r.get("groups") + r.get("users"))).lower() for h in ("vendor",))
        if vendor and src_any and not dst_any and (r.get("groups") or r.get("users")):
            src_any = False  # VPN rules are scoped by user group, not source address
        if src_any and dst_any:
            issues.append(Issue("high", r.label, "CIP-003 Att1 S3.1",
                                "Allows any source to any destination. Section 3.1 expects only necessary access."))
        elif src_any or dst_any:
            issues.append(Issue("medium", r.label, "CIP-003 Att1 S3.1",
                                f"Allows {'any source' if src_any else 'any destination'}. Narrow it to the hosts "
                                f"that need it, or record why it must stay open."))
        if svc_any:
            issues.append(Issue("medium", r.label, "CIP-003 Att1 S3.1",
                                "Allows all services. List the protocols and ports the business need requires."))
        if not (r.one("comments") or r.one("name")):
            issues.append(Issue("low", r.label, "CIP-003 Att1 S3.1",
                                "No name or comment. Auditors look for the reason each permitted rule exists."))
        if r.one("logtraffic") == "disable":
            issues.append(Issue("low", r.label, "CIP-003 Att1 S6.1" if vendor else "CIP-003 Att1 S3.1",
                                "Traffic logging is off, so sessions through this rule leave no record."))
        if vendor:
            if not (r.get("ips-sensor") or r.get("av-profile") or r.one("utm-status") == "enable"):
                issues.append(Issue("medium", r.label, "CIP-003 Att1 S6.3",
                                    "Vendor remote access rule without IPS or antivirus inspection. That's the usual "
                                    "way to detect malicious communications on the vendor path."))
            if r.one("schedule", "always") == "always":
                issues.append(Issue("low", r.label, "CIP-003 Att1 S6.2",
                                    "Vendor rule is always on. A schedule, or disabling it between approved "
                                    "windows, makes 6.2 easy to show."))
    return issues


def summarize(rules: list[Rule], issues: list[Issue]) -> dict:
    accept = [r for r in rules if r.one("action", "deny") == "accept" and r.one("status") != "disable"]
    return {"rules": len(rules), "accept": len(accept),
            "high": sum(i.severity == "high" for i in issues), "medium": sum(i.severity == "medium" for i in issues),
            "low": sum(i.severity == "low" for i in issues)}


def parse_panos_rules(text: str) -> list[Rule]:
    """Security rules from a PAN-OS running-config or Panorama export (rulebase, pre- and post-rulebase)."""
    import xml.etree.ElementTree as ET
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        raise ValueError("Config contains a DTD; refusing to parse it.")
    root = ET.fromstring(text)

    def members(entry, tag):
        node = entry.find(tag)
        return [m.text.strip() for m in node.findall("member") if m.text] if node is not None else []

    rules = []
    for base in ("rulebase", "pre-rulebase", "post-rulebase"):
        for entry in root.iter():
            if entry.tag != base:
                continue
            for r in entry.findall("./security/rules/entry"):
                services = members(r, "service")
                apps = members(r, "application")
                attrs = {
                    "name": [r.get("name", "")],
                    "srcintf": members(r, "from"), "dstintf": members(r, "to"),
                    "srcaddr": members(r, "source"), "dstaddr": members(r, "destination"),
                    "users": [u for u in members(r, "source-user") if u.lower() != "any"],
                    "application": apps,
                    "service": ["ALL"] if (not services or services == ["any"]) and (not apps or "any" in apps)
                    else services,
                    "action": ["accept" if (r.findtext("action") or "") == "allow" else "deny"],
                    "comments": [r.findtext("description") or ""],
                    "schedule": [r.findtext("schedule") or "always"],
                }
                if (r.findtext("disabled") or "no") == "yes":
                    attrs["status"] = ["disable"]
                if (r.findtext("log-end") or "yes") == "no":
                    attrs["logtraffic"] = ["disable"]
                if r.find("profile-setting") is not None:
                    attrs["utm-status"] = ["enable"]
                rules.append(Rule(id=r.get("name", "?"), attrs={k: v for k, v in attrs.items() if v != [""]}))
    return rules


def looks_like_panos(text: str) -> bool:
    head = text[:5000]
    return "<config" in head and ("rulebase" in text and "<security>" in text)


def parse_any(text: str) -> tuple[str, list[Rule]]:
    if looks_like_fortigate(text):
        return "FortiGate", parse_fortigate_policies(text)
    if looks_like_panos(text):
        return "PAN-OS", parse_panos_rules(text)
    raise ValueError("That doesn't look like a FortiGate backup or a PAN-OS XML configuration.")


def looks_like_fortigate(text: str) -> bool:
    return bool(re.search(r"^\s*config firewall policy\s*$", text, re.M))
