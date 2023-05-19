#!/usr/bin/env python3

""" ASF OAuth example in Python 3"""
import cgi
import os
import requests
import urllib
import uuid


def init_oauth():
    """This is what is used to initiate an OAuth request"""

    # Make a state object where you can store things for later.
    state_id = str(uuid.uuid4())
    state_object = {"stuff": "mystuff", "id": state_id}

    # Save the state using whatever you wish, pseudo-call below!
    save_state(state_object)

    # Figure out where our own callback URL is, and what parameters we'd
    # like passed along, such as the state ID
    callback_url = "https://foo.apache.org/mycallback?state=%s" % state_id

    # Set the OAuth gateway URL
    oauth_gateway = "https://oauth.apache.org/oauth-oidc"

    # Construct the full redirect URL we are about to pass to browser
    redirect_url = "%s?state=%s&redirect_uri=%s" % (oauth_gateway, state_id, urllib.parse.quote(callback_url))

    # Redirect the browser!
    print("Status: 302 Found")
    print("Location: %s" % redirect_url)
    print("Content-Type: text/plain")
    print("")
    print("Moved to: %s" % redirect_url)


def callback():
    """This is our callback after the OAuth system has processed login"""
    params = cgi.FieldStorage()

    # Get state ID and OAuth token
    state_id = params.getvalue("state")
    code = params.getvalue("code")

    # Validate state ID and code if need be
    validate_parameters_somehow(state_id, code)

    # Fetch our state object from wherever we stored it (pseudo-call!)
    state_object = load_state(state_id)

    # Call up OAuth system and get results!
    rv = requests.get("https://oauth.apache.org/token-oidc?code=%s" % code).json()

    # Check that the token is valid and login worked
    if rv.status_code != 200:
        bork("Something went wrong!")
    # If all good, fetch data and load the JSON into python
    else:
        credentials = rv.json()

        # Validate that our state ID matches the one in the credentials
        if credentials["state"] != state_id:
            bork("This isn't the data I was hoping for!")
        else:
            # All good, do your stuff!
            do_stuff_with_credentials(credentials)


def main():
    """Simple CGI that derives an action from the URL"""
    action = os.environ.get("SCRIPT_NAME", "/auth")

    # Init OAuth session?
    if action == "/auth":
        init_oauth()
    # Callback??
    elif action == "/mycallback":
        callback()
    else:
        bork("I dunno what to do")


if __name__ == "__main__":
    main()
