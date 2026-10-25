"""SQLite persistence. Stores only a redacted excerpt (digit runs / emails masked) - never full inputs."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, date, timedelta

from .utils import redact

DB_PATH = os.environ.get("SCAMSHIELD_DB", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scamshield.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, input_type TEXT NOT NULL,
  input_excerpt TEXT, source TEXT NOT NULL DEFAULT 'user');
CREATE TABLE IF NOT EXISTS risk_assessments(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL, score INTEGER NOT NULL, level TEXT NOT NULL, explanation TEXT, recommendations TEXT);
CREATE TABLE IF NOT EXISTS detected_indicators(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  indicator_id TEXT, name TEXT NOT NULL, points INTEGER, awarded INTEGER, evidence TEXT);
CREATE TABLE IF NOT EXISTS incident_reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, category TEXT, incident_date TEXT,
  loss_amount REAL, description TEXT, urls TEXT, evidence_notes TEXT);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""


@contextmanager
def conn(path=None):
    c = sqlite3.connect(path or DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db(path=None):
    os.makedirs(os.path.dirname(path or DB_PATH), exist_ok=True)
    with conn(path) as c:
        c.executescript(SCHEMA)


def save_scan(a: dict, raw_input: str, source: str = "user", path=None) -> int:
    init_db(path)
    with conn(path) as c:
        cur = c.execute("INSERT INTO scans(created_at,input_type,input_excerpt,source) VALUES(?,?,?,?)",
                        (a.get("created_at") or datetime.now().isoformat(timespec="seconds"), a["input_type"],
                         redact(raw_input), source))
        sid = cur.lastrowid
        c.execute("INSERT INTO risk_assessments(scan_id,category,score,level,explanation,recommendations) VALUES(?,?,?,?,?,?)",
                  (sid, a["category"], a["score"], a["level"], a["explanation"], json.dumps(a["recommendations"])))
        c.executemany("INSERT INTO detected_indicators(scan_id,indicator_id,name,points,awarded,evidence) VALUES(?,?,?,?,?,?)",
                      [(sid, i["id"], i["name"], i["points"], i["awarded"], redact(i["evidence"], 140)) for i in a["indicators"]])
    return sid


def _where(start=None, end=None, input_type=None, level=None, category=None, source=None):
    w, p = [], []
    if start: w.append("date(s.created_at) >= date(?)"); p.append(str(start))
    if end: w.append("date(s.created_at) <= date(?)"); p.append(str(end))
    if input_type and input_type != "All": w.append("s.input_type=?"); p.append(input_type)
    if level and level != "All": w.append("r.level=?"); p.append(level)
    if category and category != "All": w.append("r.category=?"); p.append(category)
    if source: w.append("s.source=?"); p.append(source)
    return (" WHERE " + " AND ".join(w)) if w else "", p


def get_history(limit=500, path=None, **filters):
    init_db(path)
    where, p = _where(**filters)
    with conn(path) as c:
        rows = c.execute("SELECT s.id, s.created_at, s.input_type, s.source, r.category, r.score, r.level, s.input_excerpt "
                         "FROM scans s JOIN risk_assessments r ON r.scan_id=s.id" + where +
                         " ORDER BY s.id DESC LIMIT ?", p + [limit]).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id, path=None):
    with conn(path) as c:
        r = c.execute("SELECT s.*, r.category, r.score, r.level, r.explanation, r.recommendations FROM scans s "
                      "JOIN risk_assessments r ON r.scan_id=s.id WHERE s.id=?", (scan_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["recommendations"] = json.loads(d["recommendations"] or "[]")
        d["indicators"] = [dict(x) for x in c.execute("SELECT * FROM detected_indicators WHERE scan_id=?", (scan_id,))]
    return d


def dashboard_stats(path=None, **filters):
    init_db(path)
    where, p = _where(**filters)
    base = " FROM scans s JOIN risk_assessments r ON r.scan_id=s.id" + where
    with conn(path) as c:
        total = c.execute("SELECT COUNT(*)" + base, p).fetchone()[0]
        lv = {r[0]: r[1] for r in c.execute("SELECT r.level, COUNT(*)" + base + " GROUP BY r.level", p)}
        cats = {r[0]: r[1] for r in c.execute("SELECT r.category, COUNT(*)" + base + " GROUP BY r.category ORDER BY 2 DESC", p)}
        types = {r[0]: r[1] for r in c.execute("SELECT s.input_type, COUNT(*)" + base + " GROUP BY s.input_type", p)}
        avg = c.execute("SELECT AVG(r.score)" + base, p).fetchone()[0]
    flagged = {k: v for k, v in cats.items() if k != "No clear fraud pattern detected"}
    return {"total": total, "levels": lv, "categories": cats, "types": types, "avg_score": round(avg or 0, 1),
            "high": lv.get("High", 0), "critical": lv.get("Critical", 0),
            "top_category": max(flagged, key=flagged.get) if flagged else None}


def indicator_counts(limit=10, path=None, **filters):
    init_db(path)
    where, p = _where(**filters)
    with conn(path) as c:
        rows = c.execute("SELECT i.name, COUNT(*) n FROM detected_indicators i JOIN scans s ON s.id=i.scan_id "
                         "JOIN risk_assessments r ON r.scan_id=s.id" + where +
                         (" AND" if where else " WHERE") + " i.awarded>0 AND i.indicator_id!='corroboration' "
                         "GROUP BY i.name ORDER BY n DESC LIMIT ?", p + [limit]).fetchall()
    return [dict(r) for r in rows]


def clear_demo(path=None):
    init_db(path)
    with conn(path) as c:
        n = c.execute("DELETE FROM scans WHERE source='demo'").rowcount
    return n


def save_incident(d: dict, path=None) -> int:
    init_db(path)
    with conn(path) as c:
        cur = c.execute("INSERT INTO incident_reports(created_at,category,incident_date,loss_amount,description,urls,evidence_notes)"
                        " VALUES(?,?,?,?,?,?,?)",
                        (datetime.now().isoformat(timespec="seconds"), d.get("category"), str(d.get("incident_date")),
                         float(d.get("loss_amount") or 0), redact(d.get("description", ""), 2000), d.get("urls", ""),
                         redact(d.get("evidence_notes", ""), 2000)))
        return cur.lastrowid


def get_incidents(limit=50, path=None):
    init_db(path)
    with conn(path) as c:
        return [dict(r) for r in c.execute("SELECT * FROM incident_reports ORDER BY id DESC LIMIT ?", (limit,))]
