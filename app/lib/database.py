#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""OAuth+OIDC Platform for the Apache Software Foundation - SQLite storage layer.

This module owns the small SQLite database that backs registered client
applications, as well as two audit logs: one tracking every change to a client
application entry, and one tracking every successful OAuth login.

The database path is configured in oauth.yaml (``database.path``). All tables
are created on import (i.e. on startup) if they do not already exist.
"""

if not __debug__:
    raise RuntimeError("This code requires assert statements to be enabled")

import contextlib
import datetime
import fnmatch
import json
import os
import sqlite3
import time
import uuid

from . import config

# Allowed lifecycle states for a client application.
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
VALID_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_DENIED)


@contextlib.contextmanager
def _connect(path=None):
    """Yields a SQLite connection with row access by name.

    A fresh connection is opened per operation. SQLite handles this cheaply and
    it keeps us safe across Quart's worker threads/event loop without sharing a
    single connection object. Foreign keys are enabled for good measure.

    :param path: Database file to open. Defaults to the main database (config.database.path).
    """
    conn = sqlite3.connect(path or config.database.path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# DDL for the login audit log. This table lives in its own per-month database file
# (see _login_audit_db_path), not in the main database.
LOGIN_AUDIT_DDL = """
    CREATE TABLE IF NOT EXISTS login_audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       REAL NOT NULL,           -- epoch timestamp of the login
        ip              TEXT,                    -- IP the login came from
        user_id         TEXT,                    -- user ID that logged in
        user_agent      TEXT,                    -- browser/client user agent
        client_app_id   TEXT,                    -- registered client app ID (if matched)
        redirect_uri    TEXT                     -- redirect URI used for the login
    )
"""

# DDL for the token audit log. Like the login audit log, this lives in its own
# per-month database file (see _token_audit_db_path), separate from the main DB.
# It records calls to the token_oidc endpoint where a backend redeems a code.
TOKEN_AUDIT_DDL = """
    CREATE TABLE IF NOT EXISTS token_audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       REAL NOT NULL,           -- epoch timestamp of the token request
        ip              TEXT,                    -- IP the token request came from
        user_id         TEXT,                    -- user ID the token belongs to (if known)
        user_agent      TEXT,                    -- user agent of the requesting backend
        client_app_id   TEXT,                    -- registered client app ID (if matched)
        redirect_uri    TEXT,                    -- redirect URI tied to the login session
        success         INTEGER NOT NULL         -- 1 if credentials were served, 0 otherwise
    )
"""


def _monthly_audit_db_path(filename_template):
    """Return a path inside the audit directory for the current $year-$month.

    The audit directory (config.database.audit_path) is created if it does not yet
    exist. ``filename_template`` is formatted with ``month`` (e.g. "2026-06").
    """
    audit_dir = config.database.audit_path
    os.makedirs(audit_dir, exist_ok=True)
    month = datetime.datetime.now().strftime("%Y-%m")
    return os.path.join(audit_dir, filename_template.format(month=month))


def _login_audit_db_path():
    """Path to the login audit DB for the current month, e.g. ``audit/2026-06.db``."""
    return _monthly_audit_db_path("{month}.db")


def _token_audit_db_path():
    """Path to the token audit DB for the current month, e.g. ``audit/token-2026-06.db``."""
    return _monthly_audit_db_path("token-{month}.db")


@contextlib.contextmanager
def _connect_login_audit():
    """Yields a connection to the current month's login audit DB, ensuring its table exists.

    If the database file for this month does not yet exist, opening the connection
    creates it, and the login_audit_log table is created on demand.
    """
    with _connect(_login_audit_db_path()) as conn:
        conn.execute(LOGIN_AUDIT_DDL)
        yield conn


@contextlib.contextmanager
def _connect_token_audit():
    """Yields a connection to the current month's token audit DB, ensuring its table exists.

    If the database file for this month does not yet exist, opening the connection
    creates it, and the token_audit_log table is created on demand.
    """
    with _connect(_token_audit_db_path()) as conn:
        conn.execute(TOKEN_AUDIT_DDL)
        yield conn


def setup():
    """Create all tables if they do not already exist. Called on import (startup).

    The client and client-audit tables live in the main database. The login audit
    log lives in its own per-month database under the configured audit directory;
    the current month's file (and table) is created here on startup.
    """
    with _connect() as conn:
        # Registered client applications.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id       TEXT PRIMARY KEY,         -- UUID4 string
                description     TEXT NOT NULL,            -- human-friendly name of the app
                redirect_uris   TEXT NOT NULL,            -- JSON list of fnmatch glob patterns
                contact_email   TEXT NOT NULL,            -- contact address for the app
                status          TEXT NOT NULL,            -- pending | approved | denied
                registered_by   TEXT NOT NULL,            -- user ID that registered the app
                registered_ip   TEXT NOT NULL,            -- IP the registration came from
                registered_at   REAL NOT NULL             -- epoch timestamp of registration
            )
            """
        )

        # Audit log of every change to a client application entry.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id   TEXT NOT NULL,                -- which client entry was affected
                timestamp   REAL NOT NULL,               -- epoch timestamp of the change
                actor       TEXT,                        -- user ID that made the change (if known)
                actor_ip    TEXT,                        -- IP the change came from (if known)
                action      TEXT NOT NULL,               -- created | approved | denied | modified | ...
                details     TEXT                         -- JSON blob describing the change
            )
            """
        )

    # Ensure the current month's login and token audit databases (and tables) exist.
    with _connect_login_audit():
        pass
    with _connect_token_audit():
        pass


def _audit_client(conn, client_id, action, actor=None, actor_ip=None, details=None):
    """Append a row to the client audit log. Uses an existing open connection."""
    conn.execute(
        "INSERT INTO client_audit_log (client_id, timestamp, actor, actor_ip, action, details) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (client_id, time.time(), actor, actor_ip, action, json.dumps(details) if details is not None else None),
    )


def register_client(description, redirect_uris, contact_email, registered_by, registered_ip):
    """Register a new client application in 'pending' status.

    :param description: Human-friendly name of the application.
    :param redirect_uris: List of accepted redirect URIs (fnmatch glob patterns allowed).
    :param contact_email: Contact email address for the application.
    :param registered_by: User ID that registered the application.
    :param registered_ip: IP address the registration request came from.
    :return: The generated client_id (UUID4 string).
    """
    assert isinstance(redirect_uris, list) and redirect_uris, "redirect_uris must be a non-empty list"
    assert all(isinstance(uri, str) and uri for uri in redirect_uris), "every redirect URI must be a non-empty string"

    client_id = str(uuid.uuid4())
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO clients (client_id, description, redirect_uris, contact_email, status, "
            "registered_by, registered_ip, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                client_id,
                description,
                json.dumps(redirect_uris),
                contact_email,
                STATUS_PENDING,
                registered_by,
                registered_ip,
                now,
            ),
        )
        _audit_client(
            conn,
            client_id,
            action="created",
            actor=registered_by,
            actor_ip=registered_ip,
            details={
                "description": description,
                "redirect_uris": redirect_uris,
                "contact_email": contact_email,
                "status": STATUS_PENDING,
            },
        )
    return client_id


# Fields a client app entry exposes for in-place updates via update_client().
UPDATABLE_FIELDS = ("description", "redirect_uris", "contact_email")


def update_client(client_id, actor=None, actor_ip=None, **fields):
    """Update an existing client application, changing only the fields provided.

    Only keys present in UPDATABLE_FIELDS are honoured; any others are ignored.
    The change (old vs new values for each modified field) is recorded in the
    client audit log.

    :param client_id: The client application to update.
    :param fields: Any of the UPDATABLE_FIELDS to overwrite.
    :return: True if the client existed and was updated, False if it was not found.
    """
    # Keep only recognised, explicitly supplied fields.
    updates = {key: value for key, value in fields.items() if key in UPDATABLE_FIELDS and value is not None}
    if "redirect_uris" in updates:
        uris = updates["redirect_uris"]
        assert isinstance(uris, list) and uris, "redirect_uris must be a non-empty list"
        assert all(isinstance(uri, str) and uri for uri in uris), "every redirect URI must be a non-empty string"

    with _connect() as conn:
        row = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if row is None:
            return False
        existing = _row_to_client(row)

        # Work out which fields actually change, recording old/new for the audit log.
        changes = {}
        for key, value in updates.items():
            if existing.get(key) != value:
                changes[key] = {"old": existing.get(key), "new": value}

        if changes:
            # redirect_uris is stored as JSON; everything else is stored verbatim.
            assignments = []
            params = []
            for key in changes:
                assignments.append(f"{key} = ?")
                params.append(json.dumps(updates[key]) if key == "redirect_uris" else updates[key])
            params.append(client_id)
            conn.execute(f"UPDATE clients SET {', '.join(assignments)} WHERE client_id = ?", params)
            _audit_client(conn, client_id, action="modified", actor=actor, actor_ip=actor_ip, details=changes)
    return True


def _row_to_client(row):
    """Convert a sqlite3.Row from the clients table into a plain dict."""
    if row is None:
        return None
    client = dict(row)
    client["redirect_uris"] = json.loads(client["redirect_uris"])
    return client


def get_client(client_id):
    """Return a client application as a dict, or None if it does not exist."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    return _row_to_client(row)


def list_clients(status=None):
    """Return all client applications, optionally filtered by status."""
    with _connect() as conn:
        if status:
            rows = conn.execute("SELECT * FROM clients WHERE status = ? ORDER BY registered_at", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM clients ORDER BY registered_at").fetchall()
    return [_row_to_client(row) for row in rows]


def set_client_status(client_id, status, actor=None, actor_ip=None):
    """Approve or deny (or otherwise set the status of) a client application.

    :return: True if the client existed and was updated, False otherwise.
    """
    assert status in VALID_STATUSES, f"status must be one of {VALID_STATUSES}"
    with _connect() as conn:
        row = conn.execute("SELECT status FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if row is None:
            return False
        old_status = row["status"]
        conn.execute("UPDATE clients SET status = ? WHERE client_id = ?", (status, client_id))
        _audit_client(
            conn,
            client_id,
            action=status,  # 'approved' or 'denied' lines up with the lifecycle state
            actor=actor,
            actor_ip=actor_ip,
            details={"old_status": old_status, "new_status": status},
        )
    return True


def find_client_for_redirect(redirect_uri, status=STATUS_APPROVED):
    """Find a registered client whose redirect URI patterns match the given URI.

    Patterns are matched using fnmatch globbing. By default only approved clients
    are considered. Returns the matching client dict, or None if none match.
    """
    for client in list_clients(status=status):
        for pattern in client["redirect_uris"]:
            if fnmatch.fnmatch(redirect_uri, pattern):
                return client
    return None


def log_login(ip, user_id, user_agent, redirect_uri, client_app_id=None):
    """Record a successful OAuth login in the login audit log.

    The entry is written to the current month's dedicated login audit database
    (see _login_audit_db_path). If client_app_id is not supplied, we attempt to
    resolve it from the redirect URI by matching against approved clients' patterns.
    """
    if client_app_id is None and redirect_uri:
        match = find_client_for_redirect(redirect_uri)
        if match:
            client_app_id = match["client_id"]
    # Login audit entries go into the current month's dedicated audit database,
    # which is created (along with the audit directory) on demand if needed.
    with _connect_login_audit() as conn:
        conn.execute(
            "INSERT INTO login_audit_log (timestamp, ip, user_id, user_agent, client_app_id, redirect_uri) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), ip, user_id, user_agent, client_app_id, redirect_uri),
        )


def log_token(ip, user_id, user_agent, redirect_uri, success, client_app_id=None):
    """Record a call to the token_oidc endpoint in the token audit log.

    The entry is written to the current month's dedicated token audit database
    (see _token_audit_db_path). If client_app_id is not supplied, we attempt to
    resolve it from the redirect URI by matching against approved clients' patterns.

    :param success: Whether credentials were actually served for this token request.
    """
    if client_app_id is None and redirect_uri:
        match = find_client_for_redirect(redirect_uri)
        if match:
            client_app_id = match["client_id"]
    # Token audit entries go into the current month's dedicated audit database,
    # which is created (along with the audit directory) on demand if needed.
    with _connect_token_audit() as conn:
        conn.execute(
            "INSERT INTO token_audit_log (timestamp, ip, user_id, user_agent, client_app_id, redirect_uri, success) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), ip, user_id, user_agent, client_app_id, redirect_uri, 1 if success else 0),
        )


# Create/verify all tables on import, i.e. on application startup.
setup()
