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
from ..lib import middleware, config, ldap

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
    if not redirect_uri or not re.match(r"https://([-0-9a-zA-Z\.]+)", redirect_uri):
        return quart.Response(
            status=400,
            response="Invalid redirect URI specified. MUST be of format https://foo.bar/baz.html and MUST be https",
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
        "scope": ["openid"],
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
                url = make_redirect_url(states[oidc_state]["redirect_uri"], code=oidc_state)
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
    code = form_data.get("code")
    if code and code in states:
        credentials = states[code]["credentials"]
        credentials["origin_uri"] = states[code]["redirect_uri"]
        expiry = states[code]["timestamp"] + STATE_EXPIRY
        del states[code]
        if expiry >= time.time():  # Only return creds if within expiry window
            return credentials
    return quart.Response(status=404, response="Could not find the login session that was requested.")


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
