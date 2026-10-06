"""Graph intelligence: coordinated-fraud detection through shared devices / IPs / subnets.

Nodes: U:user, D:device, I:ip, S:/24 subnet. Edges expire after ``ttl`` seconds so communities decay.
Incremental union-find keeps per-event scoring O(alpha); the graph is rebuilt periodically from live edges.
"""
from __future__ import annotations

import math

import networkx as nx

from aegis.schemas import ClickEvent


class GraphEngine:
    def __init__(self, ttl: float = 900.0, rebuild_every: int = 200):
        self.ttl, self.rebuild_every = ttl, rebuild_every
        self.edges: dict[tuple[str, str], float] = {}
        self._reset_dsu()
        self._n = 0
        self._now = 0.0

    def _reset_dsu(self) -> None:
        self.parent: dict[str, str] = {}
        self.members: dict[str, dict[str, set]] = {}

    def _find(self, x: str) -> str:
        p = self.parent
        if x not in p:
            p[x] = x
            self.members[x] = {"U": set(), "D": set(), "I": set(), "S": set()}
            self.members[x][x[0]].add(x[2:])
        root = x
        while p[root] != root:
            root = p[root]
        while p[x] != root:
            p[x], x = root, p[x]
        return root

    def _union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return
        if sum(map(len, self.members[ra].values())) < sum(map(len, self.members[rb].values())):
            ra, rb = rb, ra
        self.parent[rb] = ra
        for k, v in self.members.pop(rb).items():
            self.members[ra][k] |= v

    @staticmethod
    def _subnet(ip: str) -> str | None:
        parts = ip.split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else None

    def update(self, e: ClickEvent) -> None:
        self._now = max(self._now, e.timestamp)
        u, d, i = f"U:{e.user_id}", f"D:{e.device_id}", f"I:{e.ip_address}"
        pairs = [(u, d), (d, i)]
        sn = self._subnet(e.ip_address)
        if sn:
            pairs.append((i, f"S:{sn}"))
        for a, b in pairs:
            self.edges[(a, b)] = e.timestamp
            self._union(a, b)
        self._n += 1
        if self._n % self.rebuild_every == 0:
            self.rebuild()

    def rebuild(self) -> None:
        cutoff = self._now - self.ttl
        self.edges = {k: t for k, t in self.edges.items() if t >= cutoff}
        self._reset_dsu()
        for a, b in self.edges:
            self._union(a, b)

    def component(self, e: ClickEvent) -> dict[str, set]:
        return self.members[self._find(f"D:{e.device_id}")]

    def score(self, e: ClickEvent) -> tuple[float, dict]:
        comp = self.component(e)
        size = max(len(comp["U"]), len(comp["D"]))
        score = 1.0 - math.exp(-max(0, size - 3) / 6.0)
        return score, {"users": len(comp["U"]), "devices": len(comp["D"]), "ips": len(comp["I"]),
                       "subnets": len(comp["S"])}

    def export(self, user_id: str | None = None, device_id: str | None = None, limit: int = 120) -> dict:
        """Subgraph (as JSON) around a user/device for the UI and the investigator agent."""
        g = nx.Graph()
        g.add_edges_from(self.edges)
        start = f"U:{user_id}" if user_id else f"D:{device_id}"
        if start not in g:
            return {"nodes": [], "edges": []}
        nodes = list(nx.node_connected_component(g, start))[:limit]
        sub = g.subgraph(nodes)
        return {"nodes": [{"id": n, "type": n[0]} for n in sub.nodes], "edges": [list(x) for x in sub.edges]}
