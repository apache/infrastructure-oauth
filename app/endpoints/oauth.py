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
"""OAuth+OIDC Portal for the Apache Software Foundation"""

import quart
import re
from ..lib import middleware, config, ldap, database

from oic import rndstr
from oic.oic import Client
import oic.utils.authn.client
import oic.oic.message
import oic.utils.keyio
import urllib.parse
import time

STATE_EXPIRY = 600  # All sessions expire 10 minutes after being created


def make_client():
    """Construct a useful OIDC client from our config yaml"""
    client = Client(
        client_id=config.oidc.client_id,
        client_authn_method=oic.utils.authn.client.CLIENT_AUTHN_METHOD,
    )

    client_reg = oic.oic.message.RegistrationResponse(
        client_id=config.oidc.client_id,
        client_secret=config.oidc.client_secret,
        redirect_uris=[config.oidc.redirect_uri],
    )

    provider = oic.oic.message.ProviderConfigurationResponse(
        version="1.0",
        issuer=config.oidc.issuer,
        authorization_endpoint=config.oidc.endpoint + "authorize/",
        token_endpoint=config.oidc.endpoint + "token/",
        jwks_uri=config.oidc.issuer + "jwks/",
        userinfo_endpoint=config.oidc.endpoint + "userinfo/",
    )

    client.handle_provider_config(provider, provider["issuer"])
    client.store_registration_info(client_reg)
    client.redirect_uris = [
        config.oidc.redirect_uri,
    ]

    return client


def make_redirect_url(url, **kwargs):
    """Appends any number of query string args to an existing URL"""
    # Parse original URL, so we can munge it with our token
    origin_url = urllib.parse.unquote(url)
    url_parsed = urllib.parse.urlparse(origin_url)
    args = dict(urllib.parse.parse_qsl(url_parsed.query))

    # Add the token
    args.update(**kwargs)

    # Encode args and reconstruct URL
    args_encoded = urllib.parse.urlencode(args, doseq=True)

    new_url = urllib.parse.ParseResult(
        url_parsed.scheme, url_parsed.netloc, url_parsed.path, url_parsed.params, args_encoded, url_parsed.fragment
    ).geturl()

    return new_url


states = {}  # Track current oauth states
client = make_client()  # OIDC client


async def init_oidc(form_data):
    """Initial OAuth gateway. Verify parameters, log state, punt auth to OIDC"""
    origin_state = form_data.get("state")
    redirect_uri = form_data.get("redirect_uri")

    # Validate state and callback
    if not origin_state or len(origin_state) < 10 or len(origin_state) > 64:
        return quart.Response(
            status=400, response="Origin OAuth state ID MUST be between 10 and 64 characters", mimetype="text/plain"
        )
    if not re.match(r"^[-a-z0-9]+$", origin_state):
        return quart.Response(status=400, response="Origin state ID MUST be hex or alphanumerical (dashes are allowed)")
    if not redirect_uri or not re.match(r"https://([-0-9a-zA-Z.]+)", redirect_uri):
        return quart.Response(
            status=400,
            response="Invalid redirect URI specified. MUST be of format https://foo.bar/baz.html and MUST be https",
        )
    # Ensure the redirect URI belongs to a registered, approved client app. We check every
    # approved client's redirect_uris list, matching each entry as an fnmatch glob pattern.
    # If no client app allows this redirect URI, we refuse the login. This enforcement can
    # be turned off via the server.enforce_redirect_uris config option, in which case any
    # (otherwise valid) redirect URI is allowed.
    if config.server.enforce_redirect_uris and not database.find_client_for_redirect(redirect_uri):
        return quart.Response(
            status=400,
            response="The redirect URI is not allowed. It must match a registered and approved client application.",
        )

    session = {
        "state": rndstr(),
        "nonce": rndstr(),
        "original_state": origin_state,
        "redirect_uri": redirect_uri,
    }
    args = {
        "client_id": config.oidc.client_id,
        "response_type": "code",
        "scope": ["openid", "profile", "email"],
        "state": session["state"],
        "nonce": session["nonce"],
        "redirect_uri": config.oidc.redirect_uri,
    }
    auth_req = client.construct_AuthorizationRequest(request_args=args)
    login_url = auth_req.request(client.authorization_endpoint)
    states[session["state"]] = session
    return quart.Response(
        status=302,
        response="Redirecting...",
        headers={
            "Location": login_url,
        },
    )


async def callback_oidc(form_data):
    """OIDC callback. Ensure OIDC response is valid, obtain a token, verify username"""
    aresp = client.parse_response(oic.oic.message.AuthorizationResponse, info=form_data, sformat="dict")
    oidc_state = aresp.get("state")
    oidc_code = aresp.get("code")
    if oidc_state not in states:
        return quart.Response(status=400, response="Unknown session, perhaps it expired? Please retry your login.")

    resp = client.do_access_token_request(
        scope=["openid", "profile", "email"],
        state=oidc_state,
        request_args={"code": oidc_code},
    )
    if isinstance(resp, oic.oic.message.AccessTokenResponse):  # Could be ErrorResponse, we don't want that...
        userinfo = client.do_user_info_request(state=oidc_state)
        if userinfo:
            username = userinfo["preferred_username"]
            committer = ldap.Committer(username)
            details = await committer.verify()
            if details:
                details["provider"] = "oidc"  # Distinguish between old oauth and OIDC-backed (2FA etc)
                # Some services require 2FA. Our OIDC workflows will always use 2FA if set up, though they may skip
                # it if not set up by the user. There is no way for the oauth backend to know if 2FA is enabled 
                # in the workflow, but since these apps need to know, we have to make an educated guess.
                # Currently, no in-production app make use of the 2FA requirement, but we do have services in 
                # development that do.
                details["mfa"] = True  # TODO: Discuss (100%) enforcement of 2FA on keycloak
                states[oidc_state]["credentials"] = details
                states[oidc_state]["timestamp"] = time.time()  # Set so we can check expiry of state
                redirect_uri = states[oidc_state]["redirect_uri"]
                # Record the successful login in the audit log. The client app ID, if any, is
                # resolved from the redirect URI against the registered (approved) clients.
                url = make_redirect_url(redirect_uri, code=oidc_state)
                database.log_login(
                    ip=quart.request.headers.get("X-Forwarded-For", quart.request.remote_addr),
                    user_id=username,
                    user_agent=quart.request.headers.get("User-Agent"),
                    redirect_uri=url,  # We keep the state ID here for forensics
                )

                return quart.Response(
                    status=302,
                    response="Redirecting...",
                    headers={
                        "Location": url,
                    },
                )
    return quart.Response(status=400, response="The OIDC provider did not respond well....booo")


async def token_oidc(form_data):
    """Token response. Given a valid oauth token, presents the backend client with committer details"""
    ip = quart.request.headers.get("X-Forwarded-For", quart.request.remote_addr)
    user_agent = quart.request.headers.get("User-Agent")
    code = form_data.get("code")
    if code and code in states:
        credentials = states[code]["credentials"]
        credentials["origin_uri"] = states[code]["redirect_uri"]
        redirect_uri = states[code]["redirect_uri"]
        user_id = credentials.get("uid")
        expiry = states[code]["timestamp"] + STATE_EXPIRY
        del states[code]
        # Record the token request in the audit log, whether or not it is still valid.
        success = expiry >= time.time()  # Only return creds if within expiry window
        database.log_token(
            ip=ip, user_id=user_id, user_agent=user_agent, redirect_uri=redirect_uri, success=success
        )
        if success:
            return credentials
    else:
        # Unknown/missing code: no session to tie this to, but still worth auditing.
        database.log_token(ip=ip, user_id=None, user_agent=user_agent, redirect_uri=None, success=False)
    return quart.Response(status=404, response="Could not find the login session that was requested.")


def _client_ip():
    """Best-effort source IP for the current request (honours a proxy header)."""
    return quart.request.headers.get("X-Forwarded-For", quart.request.remote_addr)


async def _authorize_registration(form_data):
    """Authorization placeholder for the client-app registration endpoint.

    TODO: Decide and implement the auth scheme for who may register a client app
    (e.g. any authenticated committer via an OAuth session, an API token, etc.).
    For now this is a no-op that returns the acting user ID, if one can be derived.
    """
    # TODO(auth): replace with real authentication/authorization.
    return form_data.get("user_id") or "anonymous"


async def _authorize_review(form_data):
    """Authorization placeholder for the approve/deny endpoint.

    TODO: Restrict to administrators (e.g. infra-root / a designated group) once
    the auth scheme is decided. For now this is a no-op that returns the acting
    user ID, if one can be derived.
    """
    # TODO(auth): replace with real authentication/authorization.
    return form_data.get("user_id") or "anonymous"


async def register_client(form_data):
    """Register a new client application, or update an existing one.

    If a 'client_id' is supplied, the matching client app is updated in place:
    only the fields that are provided are changed, and the change is recorded in
    the client audit log. Otherwise a brand new client app is registered, which
    starts life in 'pending' status.

    Expected fields:
      - client_id:      UUID of an existing client app to update (optional; omit to create)
      - description:    human-friendly name of the application
      - contact_email:  contact address for the application
      - redirect_uris:  one or more accepted redirect URIs (fnmatch globs allowed).
                        May be supplied as a JSON list, or as a single string.

    When creating, description, contact_email and redirect_uris are all required.
    When updating, any subset of those may be supplied; omitted fields are left as-is.
    """
    actor = await _authorize_registration(form_data)
    if not actor or actor == "anonymous":
        return quart.Response(
            status=403, response="Authorization required."
        )

    client_id = form_data.get("client_id")
    description = form_data.get("description")
    contact_email = form_data.get("contact_email")
    redirect_uris = form_data.get("redirect_uris")

    # Validate any fields that were supplied. On create these are all required (checked below);
    # on update they are optional, so we only validate the ones that are actually present.
    if contact_email is not None and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", contact_email):
        return quart.Response(status=400, response="A valid 'contact_email' is required.")

    # redirect_uris may arrive as a JSON list (JSON body) or a single string (form post).
    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]
    if redirect_uris is not None:
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return quart.Response(
                status=400, response="'redirect_uris' must be a non-empty list of URL patterns."
            )
        if not all(isinstance(uri, str) and uri for uri in redirect_uris):
            return quart.Response(status=400, response="Every entry in 'redirect_uris' must be a non-empty string.")

    # Update path: a client_id was supplied, so amend the existing entry.
    if client_id:
        updated = database.update_client(
            client_id,
            actor=actor,
            actor_ip=_client_ip(),
            description=description,
            contact_email=contact_email,
            redirect_uris=redirect_uris,
        )
        if not updated:
            return quart.Response(status=404, response="No client application with that ID was found.")
        entry = database.get_client(client_id)
        return quart.jsonify({"client_id": client_id, "status": entry["status"]})
    print("MOO")
    # Create path: no client_id, so register a brand new client app. All fields are required.
    if not description:
        return quart.Response(status=400, response="A client app 'description' (name) is required.")
    if not contact_email:
        return quart.Response(status=400, response="A valid 'contact_email' is required.")
    if not redirect_uris:
        return quart.Response(
            status=400, response="'redirect_uris' is required and must be a non-empty list of URL patterns."
        )

    client_id = database.register_client(
        description=description,
        redirect_uris=redirect_uris,
        contact_email=contact_email,
        registered_by=actor,
        registered_ip=_client_ip(),
    )
    return quart.jsonify({"client_id": client_id, "status": database.STATUS_PENDING})


async def review_client(form_data):
    """Approve or deny a pending client application registration.

    Expected fields:
      - client_id: the UUID of the client application to review (required)
      - action:    either 'approve' or 'deny' (required)
    """
    actor = await _authorize_review(form_data)

    client_id = form_data.get("client_id")
    action = (form_data.get("action") or "").lower()

    if not client_id:
        return quart.Response(status=400, response="A 'client_id' is required.")
    if action not in ("approve", "deny"):
        return quart.Response(status=400, response="'action' must be either 'approve' or 'deny'.")

    status = database.STATUS_APPROVED if action == "approve" else database.STATUS_DENIED
    updated = database.set_client_status(client_id, status, actor=actor, actor_ip=_client_ip())
    if not updated:
        return quart.Response(status=404, response="No client application with that ID was found.")
    return quart.jsonify({"client_id": client_id, "status": status})


# Endpoint for OAuth init
quart.current_app.add_url_rule(
    "/oauth-oidc",
    methods=[
        "GET",
    ],
    view_func=middleware.glued(init_oidc),
)

# Endpoint for callback from OIDC Provider
quart.current_app.add_url_rule(
    "/callback-oidc",
    methods=[
        "GET",
    ],
    view_func=middleware.glued(callback_oidc),
)

# Endpoint for backend requesting OAuth data
quart.current_app.add_url_rule(
    "/token-oidc",
    methods=["GET", "POST"],
    view_func=middleware.glued(token_oidc),
)

# Endpoint for registering a new client application (auth TBD)
quart.current_app.add_url_rule(
    "/clients/register",
    methods=[
        "POST",
    ],
    view_func=middleware.glued(register_client),
)

# Endpoint for approving or denying a client application registration (auth TBD)
quart.current_app.add_url_rule(
    "/clients/review",
    methods=[
        "GET",
    ],
    view_func=middleware.glued(review_client),
)
