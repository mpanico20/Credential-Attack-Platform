"""Queries the Wazuh Indexer (OpenSearch) where alerts actually live.

Note: this is NOT the Wazuh manager REST API (port 55000, used for managing
agents/rules/config) - alerts are stored and searched on the indexer, default
port 9200, index pattern "wazuh-alerts-*".
"""
from __future__ import annotations

from datetime import datetime

import requests

from config import WazuhConfig


class WazuhClient:
    def __init__(self, cfg: WazuhConfig):
        self.cfg = cfg
        self.base_url = f"https://{cfg.host}:{cfg.port}"
        self.auth = (cfg.username, cfg.password)

    def _search(self, query: dict, size: int = 1000) -> list[dict]:
        url = f"{self.base_url}/{self.cfg.alerts_index}/_search"
        body = {"query": query, "size": size, "sort": [{"timestamp": "asc"}]}
        resp = requests.post(
            url, json=body, auth=self.auth, verify=self.cfg.verify_ssl, timeout=30
        )
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
        return [hit["_source"] for hit in hits]

    def search_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        rule_groups: list[str] | None = None,
        agent_name: str | None = None,
        size: int = 1000,
    ) -> list[dict]:
        must: list[dict] = [
            {
                "range": {
                    "timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat(),
                    }
                }
            }
        ]
        if rule_groups:
            must.append({"terms": {"rule.groups": rule_groups}})
        if agent_name:
            must.append({"term": {"agent.name": agent_name}})

        return self._search({"bool": {"must": must}}, size=size)

    def get_auth_events(
        self, start_time: datetime, end_time: datetime, agent_name: str | None = None
    ) -> list[dict]:
        return self.search_alerts(
            start_time,
            end_time,
            rule_groups=["authentication_failed", "authentication_success", "authentication_failures"],
            agent_name=agent_name,
        )
