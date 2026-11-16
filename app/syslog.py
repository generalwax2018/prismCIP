"""Live syslog intake (UDP and TCP) for FortiGate VPN events and Palo Alto GlobalProtect logs.

Off unless PRISMCIP_SYSLOG_PORT is set (e.g. 5514; ports under 1024 need root). Only listed senders are accepted:

  PRISMCIP_SYSLOG_SOURCES="10.0.5.1, 10.0.6.0/24=2"

Each entry is an IP or network, optionally "=<organization id>". Without an id, a single-organization install
uses its one organization. Anything else is dropped and counted. Lines are buffered and reconciled every few
seconds exactly like an upload, so findings, approvals and duplicates work the same way.

Syslog is unauthenticated, so keep the port reachable only from the firewalls (a host firewall rule or a private
network). TCP accepts newline-delimited and octet-counted framing (RFC 6587).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from collections import defaultdict

from .db import SessionLocal
from .models import AuditLog, Organization

FLUSH_SECONDS = 5
MAX_LINE = 8192
MAX_BUFFER = 20000
stats = {"listening": False, "port": None, "received": 0, "accepted": 0, "dropped_sender": 0, "irrelevant": 0,
         "batches": 0, "sessions_new": 0, "findings_new": 0, "last_at": None, "last_error": None}
_buffers: dict[int, list[str]] = defaultdict(list)


def parse_sources(spec: str) -> list[tuple[ipaddress._BaseNetwork, int | None]]:
    out = []
    for part in (p.strip() for p in (spec or "").split(",")):
        if not part:
            continue
        net, _, org = part.partition("=")
        out.append((ipaddress.ip_network(net.strip(), strict=False), int(org) if org.strip() else None))
    return out


def org_for(ip: str, sources, single_org: int | None) -> int | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, org in sources:
        if addr in net:
            return org if org is not None else single_org
    return None


def relevant(line: str) -> bool:
    return ("subtype=" in line and "vpn" in line and "tunnel-" in line) or (
        ",GLOBALPROTECT," in line and ("gateway-connected" in line or "gateway-logout" in line))


def accept(ip: str, line: str, sources, single_org) -> None:
    stats["received"] += 1
    org = org_for(ip, sources, single_org)
    if org is None:
        stats["dropped_sender"] += 1
        return
    line = line.strip()[:MAX_LINE]
    if not relevant(line):
        stats["irrelevant"] += 1
        return
    stats["accepted"] += 1
    buf = _buffers[org]
    if len(buf) < MAX_BUFFER:
        buf.append(line)


def flush() -> None:
    from .ingest import import_text
    for org_id in list(_buffers):
        lines, _buffers[org_id] = _buffers[org_id], []
        if not lines:
            continue
        groups = {"fortigate": [l for l in lines if "subtype=" in l], "globalprotect": [l for l in lines if
                                                                                      ",GLOBALPROTECT," in l]}
        with SessionLocal() as db:
            org = db.get(Organization, org_id)
            if not org:
                continue
            for fmt, ls in groups.items():
                if not ls:
                    continue
                batch, _ = import_text(db, org, "\n".join(ls), by="syslog", fmt=fmt, source=f"syslog-{fmt}")
                stats["batches"] += 1
                stats["sessions_new"] += batch.sessions_new
                stats["findings_new"] += batch.findings_new
                if batch.sessions_new or batch.sessions_matched or batch.findings_new:
                    db.add(AuditLog(org_id=org.id, actor="syslog", action="sessions_imported",
                                    detail=f"{fmt}: {batch.records} records, {batch.sessions_new} new, "
                                           f"{batch.sessions_matched} matched, {batch.findings_new} findings"))
            db.commit()
        stats["last_at"] = time.time()


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, sources, single_org):
        self.sources, self.single_org = sources, single_org

    def datagram_received(self, data, addr):
        for line in data.decode("utf-8", "replace").splitlines():
            if line.strip():
                accept(addr[0], line, self.sources, self.single_org)


async def _tcp_handler(reader, writer, sources, single_org):
    ip = (writer.get_extra_info("peername") or ("?",))[0]
    if org_for(ip, sources, single_org) is None:
        stats["dropped_sender"] += 1
        writer.close()
        return
    try:
        while True:
            head = await reader.readline()
            if not head:
                break
            text = head.decode("utf-8", "replace")
            # octet counting: "<len> <msg>" where the message may itself contain no newline
            first, _, rest = text.partition(" ")
            if first.isdigit() and not text.startswith("<"):
                need = int(first) - len(rest.encode())
                if 0 < need <= MAX_LINE * 4:
                    rest += (await reader.readexactly(need)).decode("utf-8", "replace")
                text = rest
            if text.strip():
                accept(ip, text, sources, single_org)
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
        pass
    finally:
        writer.close()


async def run() -> None:
    port = int(os.environ.get("PRISMCIP_SYSLOG_PORT", "0") or 0)
    if not port:
        return
    sources = parse_sources(os.environ.get("PRISMCIP_SYSLOG_SOURCES", ""))
    with SessionLocal() as db:
        orgs = [o.id for o in db.query(Organization).all()]
    single_org = orgs[0] if len(orgs) == 1 else None
    loop = asyncio.get_running_loop()
    host = os.environ.get("PRISMCIP_SYSLOG_HOST", "0.0.0.0")
    transport, _ = await loop.create_datagram_endpoint(lambda: _UDP(sources, single_org), local_addr=(host, port))
    server = await asyncio.start_server(lambda r, w: _tcp_handler(r, w, sources, single_org), host, port,
                                        limit=MAX_LINE * 4)
    stats.update(listening=True, port=port)
    try:
        while True:
            await asyncio.sleep(FLUSH_SECONDS)
            try:
                await asyncio.to_thread(flush)
            except Exception as exc:  # keep listening whatever one batch does
                stats["last_error"] = repr(exc)[:300]
    finally:
        transport.close()
        server.close()
        stats["listening"] = False
