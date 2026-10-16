"""Jira simulator: stateful HTTP server backed by SQLite.

Implements:
- project search (updated issues)
- issue detail (security level, links)
- projects + project roles + members
- issue links

Permission semantics: a user can see an issue if they hold Browse permission
on the project (through a role) AND, if the issue has a security level,
they are a member of that level.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Query

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import parse_bearer, validate_token, mount_scenario_endpoints, is_sync_admin  # noqa: E402
from evaluators import jira_can_view  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    browse_role TEXT NOT NULL,
    role_members TEXT NOT NULL,     -- JSON: {role_name: [emails]}
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issues (
    key TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES projects(key),
    summary TEXT NOT NULL,
    status TEXT NOT NULL,
    security_level TEXT,             -- NULL or 'Security Team'
    links TEXT NOT NULL DEFAULT '[]', -- JSON: [item_key, ...]
    updated_ts REAL NOT NULL,
    fields TEXT NOT NULL DEFAULT '{}' -- JSON: {field_name: value}
);
CREATE INDEX IF NOT EXISTS issues_project_idx ON issues(project_key);
CREATE INDEX IF NOT EXISTS issues_updated_idx ON issues(updated_ts);

CREATE TABLE IF NOT EXISTS security_levels (
    level_name TEXT PRIMARY KEY,
    members TEXT NOT NULL             -- JSON: [emails]
);
"""

app = FastAPI(title="Jira Simulator")
_db_path: str | None = None


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def seed(data: dict, db_path: str):
    global _db_path
    _db_path = db_path

    conn = _conn()
    conn.executescript(SCHEMA)

    # Projects
    for proj_key, name, role, members, label in data["jira_projects"]:
        member_emails = [next(p[5] for p in data["people"] if p[0] == m) for m in members]
        conn.execute(
            "INSERT OR REPLACE INTO projects (key, name, browse_role, role_members, label) VALUES (?,?,?,?,?)",
            (proj_key, name, role, json.dumps({role: member_emails}), label),
        )

    # Security levels
    sec_emails = [next(p[5] for p in data["people"] if p[0] == "lena")]
    conn.execute(
        "INSERT OR REPLACE INTO security_levels (level_name, members) VALUES (?,?)",
        ("Security Team", json.dumps(sec_emails)),
    )

    # Issues
    for issue in data["jira_issues"]:
        key, project, summary, status, sec_level, links, updated_rel, description = issue
        from company_a.story import _resolve_ts
        updated_ts = _resolve_ts(updated_rel, data["now_ts"])
        conn.execute(
            "INSERT OR REPLACE INTO issues (key, project_key, summary, status, security_level, links, updated_ts, fields) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (key, project, summary, status, sec_level, json.dumps(links), updated_ts,
             json.dumps({"description": description})),
        )

    # Filler issues
    for fi in data["filler"]["jira"]:
        conn.execute(
            "INSERT OR REPLACE INTO issues (key, project_key, summary, status, security_level, links, updated_ts, fields) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (fi["key"], fi["project"], fi["summary"], fi["status"], fi["security_level"],
             json.dumps(fi["links"]), fi["updated_ts"],
             json.dumps(fi.get("fields", {}))),
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/projects")
def list_projects(authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        projects = conn.execute("SELECT * FROM projects ORDER BY key").fetchall()
        result = []
        for p in projects:
            result.append({
                "key": p["key"],
                "name": p["name"],
                "browse_role": p["browse_role"],
                "label": p["label"],
            })
        return {"projects": result}
    finally:
        conn.close()


@app.get("/projects/{project_key}/roles")
def get_project_roles(project_key: str, authorization: str = Header(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if not person:
            raise HTTPException(401, "invalid token")
        proj = conn.execute("SELECT * FROM projects WHERE key = ?", (project_key,)).fetchone()
        if proj is None:
            raise HTTPException(404, "project not found")
        return {"roles": json.loads(proj["role_members"])}
    finally:
        conn.close()


@app.get("/search")
def search_issues(jql: str = Query(""), updated_since: float = Query(None),
                  authorization: str = Header(None)):
    """Search issues. Simple jql support: project=KEY and updatedSince."""
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None

        query = "SELECT * FROM issues"
        params: list = []
        conditions = []
        if updated_since:
            conditions.append("updated_ts > ?")
            params.append(updated_since)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY updated_ts DESC"

        issues = conn.execute(query, params).fetchall()
        result = []
        for i in issues:
            proj = conn.execute("SELECT * FROM projects WHERE key = ?", (i["project_key"],)).fetchone()
            sec_members = conn.execute("SELECT * FROM security_levels WHERE level_name = ?", ("Security Team",)).fetchone()
            sec_level_members = {"Security Team": json.loads(sec_members["members"])} if sec_members else {}

            can = person and jira_can_view(
                person["email"], i["project_key"],
                json.loads(proj["role_members"]),
                i["security_level"],
                sec_level_members,
            ) if person else False

            result.append({
                "key": i["key"],
                "project_key": i["project_key"],
                "summary": i["summary"],
                "status": i["status"],
                "security_level": i["security_level"],
                "updated_ts": i["updated_ts"],
                "accessible": can,
            })
        return {"issues": result}
    finally:
        conn.close()


@app.get("/issue/{issue_key}")
def get_issue(issue_key: str, authorization: str = Header(None),
              as_user: str = Query(None)):
    conn = _conn()
    try:
        token = parse_bearer(authorization)
        person = validate_token(token, conn) if token else None
        if as_user and person:
            person = conn.execute("SELECT * FROM directory WHERE employee_id = ? OR email = ?",
                                    (as_user, as_user)).fetchone()
            if person:
                person = dict(person)

        issue = conn.execute("SELECT * FROM issues WHERE key = ?", (issue_key,)).fetchone()
        if issue is None:
            raise HTTPException(404, "issue not found")
        proj = conn.execute("SELECT * FROM projects WHERE key = ?", (issue["project_key"],)).fetchone()
        sec_members = conn.execute("SELECT * FROM security_levels WHERE level_name = ?", ("Security Team",)).fetchone()
        sec_level_members = {"Security Team": json.loads(sec_members["members"])} if sec_members else {}

        can = is_sync_admin(person) or (person and jira_can_view(
            person["email"], issue["project_key"],
            json.loads(proj["role_members"]),
            issue["security_level"],
            sec_level_members,
        )) if person else False

        if not can:
            raise HTTPException(403, "access denied")

        return {
            "key": issue["key"],
            "project_key": issue["project_key"],
            "summary": issue["summary"],
            "status": issue["status"],
            "security_level": issue["security_level"],
            "links": json.loads(issue["links"]),
            "updated_ts": issue["updated_ts"],
            "fields": json.loads(issue["fields"]),
            "url": f"/issue/{issue_key}",
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scenario events
# ---------------------------------------------------------------------------

def apply_event(event_name: str, extra: dict | None = None):
    conn = _conn()
    try:
        if event_name == "reset":
            return {"reset": True}
        return {"unknown_event": event_name}
    finally:
        conn.close()


mount_scenario_endpoints(app, "jira", apply_event)
