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

# If pipservice, we may use the pipservice module to define a config. Use if found.
PIPSERVICE_CONFIG = os.path.join(os.path.realpath("."), "oauth.yaml")
CONFIG_FILE = PIPSERVICE_CONFIG if os.path.isfile(PIPSERVICE_CONFIG) else "config.yaml"


class ServerConfiguration:
    def __init__(self, yml: dict):
        assert yml, f"No server configuration directives could be found in {CONFIG_FILE}!"
        self.bind = yml["bind"]
        self.port = int(yml["port"])
        self.error_reporting = yml.get("error_reporting", "json")


class OIDCConfiguration:
    def __init__(self, yml: dict):
        assert yml, f"No OIDC configuration directives could be found in {CONFIG_FILE}!"
        self.client_id = yml["client-id"]
        self.client_secret = yml["client-secret"]
        self.issuer = yml["issuer"]
        self.endpoint = yml["endpoint"]
        self.redirect_uri = yml["redirect_uri"]


cfg_yaml = yaml.safe_load(open(CONFIG_FILE, "r"))
server = ServerConfiguration(cfg_yaml.get("server", {}))
oidc = OIDCConfiguration(cfg_yaml.get("oidc", {}))
