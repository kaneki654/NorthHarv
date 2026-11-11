"""tests/test_db_exposure_engine.py — unit tests for DatabaseExposureEngine."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from unittest.mock import patch
import pytest

from engine.db_exposure_engine import (
    DatabaseExposureEngine,
    _probe_redis, _probe_memcached, _probe_elasticsearch,
    _DB_SERVICES,
)

_ENGINE = DatabaseExposureEngine()


# ── validate_input ────────────────────────────────────────────────────────────

def test_validate_input_accepts_valid_target():
    assert _ENGINE.validate_input({"ip": "1.1.1.1", "port": 6379})


def test_validate_input_rejects_missing_ip():
    assert not _ENGINE.validate_input({"port": 6379})


def test_validate_input_rejects_missing_port():
    assert not _ENGINE.validate_input({"ip": "1.1.1.1"})


def test_validate_input_rejects_non_dict():
    assert not _ENGINE.validate_input("not a dict")


# ── Redis probe ───────────────────────────────────────────────────────────────

def test_probe_redis_returns_info_on_pong():
    with patch("engine.db_exposure_engine._send_recv") as mock_sr:
        mock_sr.side_effect = [
            b"+PONG\r\n",
            b"$3999\r\nredis_version:7.0.5\r\nos:Linux\r\n",
        ]
        result = _probe_redis("127.0.0.1", 6379)
    assert result is not None
    assert result["ping_response"] == "+PONG"
    assert result["redis_version"] == "7.0.5"


def test_probe_redis_returns_none_without_pong():
    with patch("engine.db_exposure_engine._send_recv", return_value=b"-ERR auth required\r\n"):
        result = _probe_redis("127.0.0.1", 6379)
    assert result is None


# ── Memcached probe ───────────────────────────────────────────────────────────

def test_probe_memcached_returns_info_on_stat():
    resp = b"STAT version 1.6.17\r\nSTAT uptime 3600\r\nEND\r\n"
    with patch("engine.db_exposure_engine._send_recv", return_value=resp):
        result = _probe_memcached("127.0.0.1", 11211)
    assert result is not None
    assert result["version"] == "1.6.17"


def test_probe_memcached_returns_none_on_no_stat():
    with patch("engine.db_exposure_engine._send_recv", return_value=b""):
        result = _probe_memcached("127.0.0.1", 11211)
    assert result is None


# ── Elasticsearch probe ───────────────────────────────────────────────────────

def test_probe_elasticsearch_returns_cluster_info():
    es_resp = json.dumps({
        "cluster_name": "my-cluster",
        "name": "node-1",
        "tagline": "You Know, for Search",
        "version": {"number": "8.5.0"},
    }).encode()
    with patch("engine.db_exposure_engine._http_get", return_value=(200, "application/json", es_resp)):
        result = _probe_elasticsearch("127.0.0.1", 9200)
    assert result is not None
    assert result["cluster_name"] == "my-cluster"
    assert result["version"] == "8.5.0"


def test_probe_elasticsearch_returns_none_on_non_200():
    with patch("engine.db_exposure_engine._http_get", return_value=(401, "", b"Unauthorized")):
        result = _probe_elasticsearch("127.0.0.1", 9200)
    assert result is None


def test_probe_elasticsearch_returns_none_without_cluster_name():
    with patch("engine.db_exposure_engine._http_get", return_value=(200, "text/html", b"<html>nginx</html>")):
        result = _probe_elasticsearch("127.0.0.1", 9200)
    assert result is None


# ── analyze ───────────────────────────────────────────────────────────────────

def test_analyze_finds_redis_on_port_6379():
    target = {"ip": "192.0.2.10", "port": 6379}
    with patch("engine.db_exposure_engine._send_recv") as mock_sr:
        mock_sr.side_effect = [
            b"+PONG\r\n",
            b"$100\r\nredis_version:7.0.0\r\n",
        ]
        findings = _ENGINE.analyze(target)
    assert len(findings) >= 1
    redis_f = next((f for f in findings if "Redis" in f.title), None)
    assert redis_f is not None
    assert redis_f.severity == "critical"
    assert redis_f.finding_type == "database_exposure"


def test_analyze_finds_elasticsearch_on_port_9200():
    target = {"ip": "192.0.2.11", "port": 9200}
    es_resp = json.dumps({
        "cluster_name": "test", "tagline": "You Know, for Search",
        "version": {"number": "8.0.0"},
    }).encode()
    with patch("engine.db_exposure_engine._http_get", return_value=(200, "application/json", es_resp)):
        findings = _ENGINE.analyze(target)
    es_f = next((f for f in findings if "Elasticsearch" in f.title), None)
    assert es_f is not None
    assert es_f.severity == "critical"


def test_analyze_returns_empty_when_probes_fail():
    target = {"ip": "192.0.2.12", "port": 6379}
    with patch("engine.db_exposure_engine._send_recv", return_value=b""):
        findings = _ENGINE.analyze(target)
    assert findings == []


def test_analyze_finds_phpmyadmin_on_http():
    target = {"ip": "192.0.2.13", "port": 80, "service_name": "http"}
    pma_body = b"<html><title>phpMyAdmin</title><body>phpMyAdmin login</body></html>"
    with patch("engine.db_exposure_engine._http_get", return_value=(200, "text/html", pma_body)):
        findings = _ENGINE.analyze(target)
    pma_f = next((f for f in findings if "phpMyAdmin" in f.title), None)
    assert pma_f is not None
    assert pma_f.finding_type == "admin_panel_exposed"


def test_analyze_no_admin_panels_on_non_http_port():
    target = {"ip": "192.0.2.14", "port": 22, "service_name": "ssh"}
    with patch("engine.db_exposure_engine._http_get", return_value=(200, "text/html", b"phpMyAdmin")):
        findings = _ENGINE.analyze(target)
    assert all(f.finding_type != "admin_panel_exposed" for f in findings)


# ── service catalog ───────────────────────────────────────────────────────────

def test_service_catalog_not_empty():
    assert len(_DB_SERVICES) >= 8


def test_service_catalog_all_have_ports():
    for svc in _DB_SERVICES:
        assert len(svc.ports) >= 1
        assert all(isinstance(p, int) for p in svc.ports)


def test_service_catalog_severities_valid():
    valid = {"critical", "high", "medium", "low", "info"}
    for svc in _DB_SERVICES:
        assert svc.severity in valid
