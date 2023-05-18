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

import sys
import traceback
import typing
import uuid
import quart
from . import config


def glued(func: typing.Callable) -> typing.Callable:
    """Middleware that collects all form data (except file uploads!) and joins as one dict"""

    async def call(**args):
        form_data = dict()
        form_data.update(quart.request.args.to_dict())
        xform = await quart.request.form
        # Pre-parse check for form data size
        if quart.request.content_type and any(
            x in quart.request.content_type
            for x in (
                "multipart/form-data",
                "application/x-www-form-urlencoded",
                "application/x-url-encoded",
            )
        ):
            if xform:
                form_data.update(xform.to_dict())
        if quart.request.is_json:
            xjson = await quart.request.json
            form_data.update(xjson)
        try:
            resp = await func(form_data, **args)
            assert resp, "No response was provided by the underlying endpoint!"
        except Exception:  # Catch and spit out errors
            exc_type, exc_value, exc_traceback = sys.exc_info()
            err = "\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            headers = {
                "Server": "ASF OAuth Platform",
                "Content-Type": "text/plain",
            }
            # By default, we print the traceback to the user, for easy debugging.
            if config.server.error_reporting == "json":
                error_text = "API error occurred: \n" + err
                return quart.Response(headers=headers, status=500, response=error_text)
            # If client traceback is disabled, we print it to stderr instead, but leave an
            # error ID for the client to report back to the admin. Every line of the traceback
            # will have this error ID at the beginning of the line, for easy grepping.
            else:
                # We only need a short ID here, let's pick 18 chars.
                eid = str(uuid.uuid4())[:18]
                sys.stderr.write("API Endpoint %s got into trouble (%s): \n" % (quart.request.path, eid))
                for line in err.split("\n"):
                    sys.stderr.write("%s: %s\n" % (eid, line))
                return quart.Response(
                    headers=headers,
                    status=500,
                    response="API error occurred. The application journal will have information. Error ID: %s" % eid,
                )
        return resp

    # Quart will, if no rule name is specified, default to calling the rule "call" here,
    # which leads to carps about duplicate rule definitions. So, given the fact that call()
    # is dynamically made from within this function, we simply adjust its internal name to
    # refer to the calling module and function, thus providing Quart with a much better
    # name for the rule, which will also aid in debugging.
    call.__name__ = func.__module__ + "." + func.__name__
    return call
