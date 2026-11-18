"""nmap -> schema (recon).

We parse nmap's XML output (`-oX`), which is stable and unambiguous, into the
recon payload's `services` and `tech_stack`. Each open port becomes a Service;
service product/version strings (e.g. "Node.js Express framework") feed the
tech stack.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from apt.schema import Service


def parse(raw: str) -> dict:
    hosts: list[str] = []
    services: list[Service] = []
    tech: set[str] = set()

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"hosts": [], "services": [], "tech_stack": []}

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        if addr and addr not in hosts:
            hosts.append(addr)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            portid = int(port.get("portid", "0"))
            name = version = product = None
            if svc is not None:
                name = svc.get("name")
                product = svc.get("product")
                version = svc.get("version")
                for part in (product, svc.get("extrainfo")):
                    if part:
                        tech.add(part)
            services.append(Service(
                host=addr or "target",
                port=portid,
                protocol=port.get("protocol", "tcp"),
                service=name,
                version=" ".join(p for p in (product, version) if p) or version,
            ))
    return {"hosts": hosts, "services": services, "tech_stack": sorted(tech)}
