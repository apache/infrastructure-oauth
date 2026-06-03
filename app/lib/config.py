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
"""OAuth+OIDC Platform for the Apache Software Foundation"""

if not __debug__:
    raise RuntimeError("This code requires assert statements to be enabled")


"""Configuration classes for the platform"""

import yaml
import os
import hashlib
import hmac

# If pipservice, we may use the pipservice module to define a config. Use if found.
PIPSERVICE_CONFIG = os.path.join(os.path.realpath("."), "oauth.yaml")
CONFIG_FILE = PIPSERVICE_CONFIG if os.path.isfile(PIPSERVICE_CONFIG) else "config.yaml"


class ServerConfiguration:
    def __init__(self, yml: dict):
        assert yml, f"No server configuration directives could be found in {CONFIG_FILE}!"
        self.bind = yml["bind"]
        self.port = int(yml["port"])
        self.error_reporting = yml.get("error_reporting", "json")
        # Whether to enforce that a login's redirect URI matches a registered,
        # approved client app. If disabled, any redirect URI is allowed.
        self.enforce_redirect_uris = bool(yml.get("enforce_redirect_uris", True))


class OIDCConfiguration:
    def __init__(self, yml: dict):
        assert yml, f"No OIDC configuration directives could be found in {CONFIG_FILE}!"
        self.client_id = yml["client-id"]
        self.client_secret = yml["client-secret"]
        self.issuer = yml["issuer"]
        self.endpoint = yml["endpoint"]
        self.redirect_uri = yml["redirect_uri"]


class DatabaseConfiguration:
    def __init__(self, yml: dict):
        assert yml, f"No database configuration directives could be found in {CONFIG_FILE}!"
        self.path = yml["path"]
        # Directory for the per-month login audit log databases. Defaults to "audit"
        # (created on startup if it does not yet exist).
        self.audit_path = yml.get("audit_path", "audit")


class AuthorizationConfiguration:
    """Team-based bearer-token authorization for the client-app endpoints.

    The 'authorization' section of the config is a mapping of team name -> the
    SHA-256 hex digest of that team's bearer token (NOT the token itself). A request
    authenticates by presenting its raw bearer token; we hash it and compare the
    digest against the configured ones, so plaintext tokens are never stored on disk.

    To generate a digest for a token, e.g.:
        python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" <token>
    """

    # Teams permitted to approve or deny client app registrations. Any team with a
    # valid token may *submit* a registration, but only these teams may review them.
    APPROVAL_TEAMS = ("infrastructure",)

    def __init__(self, yml: dict):
        # team -> sha256 hex digest of the token, as configured. Digests are stored
        # lower-cased so comparison is case-insensitive on the hex representation.
        self.digests = {team: str(digest).lower() for team, digest in (yml or {}).items() if digest}
        # Reverse lookup: digest -> team.
        self.team_by_digest = {digest: team for team, digest in self.digests.items()}

    def team_for_token(self, token):
        """Return the team a raw bearer token belongs to, or None if unknown/blank.

        The provided token is SHA-256 hashed and matched against the configured
        digests using a constant-time comparison.
        """
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        # Constant-time scan so a match doesn't leak timing about which digest hit.
        match = None
        for known_digest, team in self.team_by_digest.items():
            if hmac.compare_digest(known_digest, digest):
                match = team
        return match

    def can_approve(self, team):
        """Return True if the given team may approve/deny client app registrations."""
        return team in self.APPROVAL_TEAMS


cfg_yaml = yaml.safe_load(open(CONFIG_FILE, "r"))
server = ServerConfiguration(cfg_yaml.get("server", {}))
oidc = OIDCConfiguration(cfg_yaml.get("oidc", {}))
authorization = AuthorizationConfiguration(cfg_yaml.get("authorization", {}))
database = DatabaseConfiguration(cfg_yaml.get("database", {}))
