# ASF Infrastructure OAuth/OIDC service

This service is intended to act as an OIDC-enabled replacement for the current 
oauth.apache.org service, utilizing keycloak for the auth process but still 
retaining all the features and simplicity of the existing oauth setup.


## Introduction to ASF OAuth:

The ASF OAuth system provides committers at the Apache Software Foundation with a focal point for services wishing to make use of authentication without security implications around storing sensitive user data. Many Apache services use it as a means of validating that the user requesting access is a committer within a project in the Apache Software Foundation and has lawful access to the systems in question.

The ASF Oauth system is only available to ASF committers, and shares no sensitive data (such as your password) with the service requesting the authentication. The OAuth system offers Apache services the following data when you sign in:

- Your user ID
- Your full name
- Your affiliation (committer or foundation member)
- The Project Management Committees (PMCs) or podlings (PPMCs) of which you are a member

To log in via the system, you must use your LDAP credentials. These are what you would typically use when committing code to Apache's Git or Subversion servers, or accessing private repositories. If you have forgotten your password, you may request a reset via id.apache.org.
This version of the ASF OAuth system uses [OpenID Connect](https://openid.net/connect/) 
(via [Keycloak](https://www.keycloak.org/)) and will enforce two-factor authentication if the user has configured and enabled this for their account.

If you have any questions that this documentation does not answer, get in touch with the Apache Infrastructure Team at: users@infra.apache.org.

## API Documentation:

How to use the ASF OAuth system for your own service:

- Your service callback URL MUST use HTTPS.
- Create a state object that will hold your service's own temporary request information. The ID of this object MUST be either alphanumerical or hexadecimal and between 10 and 64 characters in length. Dashes are also allowed. You may re-use the same ID, but we recommend that you do not. We recommend using UUID4 for this ID.
- Save your state object locally, and redirect the client to `https://oauth.apache.org/oauth-oidc?state=$stateID&redirect_uri=$callback`, where:
    - `$stateID` is the ID of the state object you created
    - `$callback` is a TLS-enabled URL which the OAuth system will redirect to upon successful authentication.
- The OAuth system will, upon successful authentication, redirect to the callback URL and pass on a `code` parameter in the URL's query string. If there are any query string parameters in your callback URL, the code will be appended to the existing URL.
- From the backend of your service, submit a request to: `https://oauth.apache.org/token-oidc?code=$code` to retrieve the information about the user who just authenticated, in JSON format (see below). You can only retrieve this information once, after which the token becomes invalid; and you MUSTcomplete the request no later than ten minutes after the callback URL was visited.
- Verify the request by comparing your own state ID against the state value in the JSON result.

An example user JSON result from our token endpoint could be:
~~~json
    {
        "state": "698da7bb-a273-4b6b-a305-e6d757ed979a",
        "uid": "janedoe",
        "fullname": "Jane Maria Doe",
        "email": "janedoe@apache.org",
        "isMember": false,
        "isChair": true,
        "pmcs": ["httpd", "openoffice", "zeppelin"],
        "projects": ["accumulo", "httpd", "ignite", "openoffice", "zeppelin"]
    }
~~~

For example scripts, see the [examples](examples/) directory in this repository.
