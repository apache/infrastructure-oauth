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
"""Selfserve Portal for the Apache Software Foundation"""
import secrets
import quart
from .lib import middleware, config
import os

STATIC_DIR = os.path.join(os.path.realpath(".."), "htdocs")  # File location of static assets


def main():
    app = quart.Quart(__name__)
    app.secret_key = secrets.token_hex()  # For session management

    # Static files (or index.html if requesting a dir listing)
    @app.route("/<path:path>")
    @app.route("/")
    async def static_files(path="index.html"):
        if path.endswith("/"):
            path += "index.html"
        return await quart.send_from_directory(STATIC_DIR, path)

    @app.before_serving
    async def load_endpoints():
        """Load all API end points. This is run before Quart starts serving requests"""
        async with app.app_context():
            from . import endpoints

    @app.after_serving
    async def shutdown():
        """Ensure a clean shutdown of the portal by stopping background tasks"""
        app.background_tasks.clear()  # Clear repo polling etc

    return app
