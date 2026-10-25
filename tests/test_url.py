import pytest
from scamshield.detector import analyze_url
from scamshield.url_detector import parse_url, registered_domain


def ids(a): return {i["id"] for i in a["indicators"]}


def test_lookalike_http_keywords():
    a = analyze_url("http://paytrn-secure-login.xyz/verify")
    assert {"url_lookalike", "url_http", "url_hyphens", "url_keywords", "url_tld"} <= ids(a)
    assert a["level"] in ("High", "Critical")


def test_ip_url_and_userinfo_and_shortener():
    assert "url_ip" in ids(analyze_url("http://192.168.4.5/login"))
    assert "url_userinfo" in ids(analyze_url("https://google.com@evil.top/a"))
    assert "url_shortener" in ids(analyze_url("https://bit.ly/3xyz"))


def test_official_domain_not_flagged():
    a = analyze_url("https://www.sbi.co.in/web/home")
    assert a["score"] == 0 and a["level"] == "Low"
    assert "not a live verification" in a["explanation"] and "NOT verified" in a["explanation"]


def test_registered_domain_multi_tld():
    assert registered_domain("secure.login.sbi.co.in") == "sbi.co.in"


def test_no_scheme_and_malformed():
    assert parse_url("example.com/a")["scheme"] == "(not specified)"
    assert "url_malformed" in ids(analyze_url("http://"))


def test_never_makes_network_calls(monkeypatch):
    import socket
    def boom(*a, **k): raise AssertionError("network used")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    analyze_url("http://evil-login.xyz")
