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
"""OAuth+OIDC wrapper for the Apache Software Foundation - middleware plugin"""

if not __debug__:
    raise RuntimeError("This code requires assert statements to be enabled")

import asfpy.clitools
import re


LDAP_PEOPLE_BASE = "ou=people,dc=apache,dc=org"
LDAP_MEMBER_BASE = "cn=member,ou=groups,dc=apache,dc=org"
LDAP_CHAIRS_BASE = "cn=pmc-chairs,ou=groups,ou=services,dc=apache,dc=org"
LDAP_PMCS_BASE = "ou=project,ou=groups,dc=apache,dc=org"
LDAP_DN = "uid=%s,ou=people,dc=apache,dc=org"
LDAP_OWNER_FILTER = "(|(ownerUid=%s)(owner=uid=%s,ou=people,dc=apache,dc=org))"
LDAP_MEMBER_FILTER = "(|(memberUid=%s)(member=uid=%s,ou=people,dc=apache,dc=org))"
LDAP_ROOT_BASE = "cn=infrastructure-root,ou=groups,ou=services,dc=apache,dc=org"
LDAP_TOOLING_BASE = "cn=tooling,ou=groups,ou=services,dc=apache,dc=org"


class OAuthException(Exception):
    """Simple exception with a message and an optional origin exception (WIP)"""

    def __init__(self, message, origin=None):
        super().__init__(message)
        self.origin = origin


def attr_to_list(attr):
    """Converts a list of bytestring attribute values to a unique list of strings"""
    return list(set([value for value in attr or []]))


class Committer:
    """Verifies and loads a committers credentials via LDAP"""

    def __init__(self, user):
        # Verify correct user ID syntax, construct DN
        if not re.match(r"^[-_a-z0-9]+$", user):
            raise OAuthException("Invalid characters in User ID. Only lower-case alphanumerics, '-' and '_' allowed.")
        self.user = user

    async def verify(self):
        # Verify the account exists
        try:
            result = await asfpy.clitools.ldapsearch_cli_async(ldap_base=LDAP_DN % self.user, ldap_scope="base")
            assert result and len(result) == 1, "User not found in LDAP"
        except Exception as ex:  # TODO: narrow the check to Exceptions that are expected
            raise OAuthException("An unknown error occurred, please retry later.") from ex
        # So far so good, set uid
        self.uid = self.user
        self.dn = LDAP_DN % self.user

        # Get full name etc
        try:
            fn = result[0].get("cn")
            assert type(fn) is list and len(fn) == 1
            self.fullname = fn[0]
            self.email = "%s@apache.org" % self.user
            # get emails used for forwarding
            self.emails = attr_to_list(result[0].get("mail"))
            # get alternative emails
            self.altemails = attr_to_list(result[0].get("asf-altEmail"))
            # Check for asf-banned parameter, bork if set.
            if result[0].get("asf-banned"):
                raise OAuthException(
                    "This account has been administratively locked. Please contact root@apache.org for further details."
                )
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        # Get membership status
        try:
            result = await asfpy.clitools.ldapsearch_cli_async(ldap_base=LDAP_MEMBER_BASE, ldap_scope="base")
            assert len(result) == 1
            members = result[0].get("memberUid")
            assert type(members) is list and len(members) > 100
            self.isMember = self.user in members
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        # Get chair status
        try:
            result = await asfpy.clitools.ldapsearch_cli_async(ldap_base=LDAP_CHAIRS_BASE, ldap_scope="base")
            assert len(result) == 1
            members = result[0].get("member")
            assert type(members) is list and len(members) > 100
            self.isChair = LDAP_DN % self.user in members
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        # Get infra-root status
        try:
            result = await asfpy.clitools.ldapsearch_cli_async(ldap_base=LDAP_ROOT_BASE, ldap_scope="base")
            assert len(result) == 1
            members = result[0].get("member")
            assert type(members) is list and len(members) > 3
            self.isRoot = LDAP_DN % self.user in members
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        # Get PMC memberships
        try:
            self.pmcs = []
            result = await asfpy.clitools.ldapsearch_cli_async(
                ldap_base=LDAP_PMCS_BASE,
                ldap_scope="sub",
                ldap_query=LDAP_OWNER_FILTER % (self.user, self.user),
                ldap_attrs=["cn"],
            )
            for hit in result:
                assert type(hit) is dict
                pmc = hit.get("cn")
                assert type(pmc) is list and len(pmc) == 1
                pmc = pmc[0]
                assert pmc and type(pmc) is str
                self.pmcs.append(pmc)
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        # Get committerships
        try:
            self.projects = []
            result = await asfpy.clitools.ldapsearch_cli_async(
                ldap_base=LDAP_PMCS_BASE,
                ldap_scope="sub",
                ldap_query=LDAP_MEMBER_FILTER % (self.user, self.user),
                ldap_attrs=["cn"],
            )
            for hit in result:
                assert type(hit) is dict
                pmc = hit.get("cn")
                assert type(pmc) is list and len(pmc) == 1
                pmc = pmc[0]
                assert pmc and type(pmc) is str
                self.projects.append(pmc)
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        # Get tooling membership
        try:
            result = await asfpy.clitools.ldapsearch_cli_async(ldap_base=LDAP_TOOLING_BASE, ldap_scope="base")
            assert len(result) == 1
            members = result[0].get("member")
            assert type(members) is list and len(members) > 1
            if LDAP_DN % self.user in members:
                self.pmcs.append("tooling")
                self.projects.append("tooling")
        except AssertionError as ex:
            raise OAuthException("Common backend assertions failed, LDAP corruption?") from ex

        return self.__dict__
