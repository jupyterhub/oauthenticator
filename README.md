# OAuthenticator

OAuth + JupyterHub Authenticator = OAuthenticator

OAuthenticator currently supports the following authentication services:

- [Auth0](oauthenticator/auth0.py)
- [Bitbucket](oauthenticator/bitbucket.py)
- [CILogon](oauthenticator/cilogon.py)
- [GitHub](#github-setup)
- [GitLab](#gitlab-setup)
- [Globus](#globus-setup)
- [Google](#google-setup)
- [MediaWiki](oauthenticator/mediawiki.py)
- [Okpy](#okpyauthenticator)
- [OpenShift](#openshift-setup)

A [generic implementation](oauthenticator/generic.py), which you can use with
any provider, is also available.

## Examples

For an example docker image using OAuthenticator, see the [example](example)
directory.

[Another example](https://github.com/jupyterhub/dockerspawner/tree/master/examples/oauth)
is using GitHub OAuth to spawn each user's server in a separate docker
container.

## Installation

Install with pip:

    pip3 install oauthenticator

Or clone the repo and do a dev install:

    git clone https://github.com/jupyterhub/oauthenticator.git
    cd oauthenticator
    pip3 install -e .

## General setup

The first step is to tell JupyterHub to use your chosen OAuthenticator. Each
authenticator is provided in a submodule of `oauthenticator`, and each
authenticator has a variant with `Local` (e.g. `LocalGitHubOAuthenticator`),
which will map OAuth usernames onto local system usernames.

### Set chosen OAuthenticator

In `jupyterhub_config.py`, add:

```python
from oauthenticator.github import GitHubOAuthenticator
c.JupyterHub.authenticator_class = GitHubOAuthenticator
```

### Set callback URL, client ID, and client secret

All OAuthenticators require setting a callback URL, client ID, and client
secret. You will generally get these when you register your OAuth application
with your OAuth provider. Provider-specific details are available in sections
below. When registering your oauth application with your provider, you will
probably need to specify a callback URL.
The callback URL should look like:

    http[s]://[your-host]/hub/oauth_callback

where `[your-host]` is where your server will be running. Such as
`example.com:8000`.

When JupyterHub runs, these values will be retrieved from the **environment variables**:

```bash
$OAUTH_CALLBACK_URL
$OAUTH_CLIENT_ID
$OAUTH_CLIENT_SECRET
```

You can also set these values in your **configuration file**, `jupyterhub_config.py`:

```python
c.MyOAuthenticator.oauth_callback_url = 'http[s]://[your-host]/hub/oauth_callback'
c.MyOAuthenticator.client_id = 'your-client-id'
c.MyOAuthenticator.client_secret = 'your-client-secret'
```


## GitHub Setup

First, you'll need to create a [GitHub OAuth
application](https://github.com/settings/applications/new).

Then, add the following to your `jupyterhub_config.py` file:

    from oauthenticator.github import GitHubOAuthenticator
    c.JupyterHub.authenticator_class = GitHubOAuthenticator

You can also use `LocalGitHubOAuthenticator` to map GitHub accounts onto local users.

You can use your own Github Enterprise instance by setting the `GITHUB_HOST` environment variable.

You can set `GITHUB_HTTP` environment variable to true or anything if your GitHub Enterprise supports http only.

GitHub allows expanded capabilities by
adding [GitHub-Specific Scopes](github_scope.md) to the requested token.

## GitLab Setup

First, you'll need to create a [GitLab OAuth
application](http://docs.gitlab.com/ce/integration/oauth_provider.html).


Then, add the following to your `jupyterhub_config.py` file:

    from oauthenticator.gitlab import GitLabOAuthenticator
    c.JupyterHub.authenticator_class = GitLabOAuthenticator

You can also use `LocalGitLabOAuthenticator` to map GitLab accounts onto local users.

You can use your own GitLab CE/EE instance by setting the `GITLAB_HOST` environment
flag.

## Google Setup

Visit https://console.developers.google.com to set up an OAuth client ID and secret. See [Google's documentation](https://developers.google.com/identity/protocols/OAuth2) on how to create OAUth 2.0 client credentials. The `Authorized JavaScript origins` should be set to to your hub's public address while `Authorized redirect URIs` should be set to the same but followed by `/hub/oauth_callback`.

Then, add the following to your `jupyterhub_config.py` file:

    from oauthenticator.google import GoogleOAuthenticator
    c.JupyterHub.authenticator_class = GoogleOAuthenticator

For a Google Apps domain you can set:

```python
c.GoogleOAuthenticator.hosted_domain = 'mycollege.edu'
c.GoogleOAuthenticator.login_service = 'My College'
```

## OpenShift Setup

In case you have an OpenShift deployment with OAuth properly configured (see the
following sections for a quick reference), you should set the client ID and
secret by the environment variables `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` and
`OAUTH_CALLBACK_URL`. The OpenShift API URL can be specified by setting the
variable `OPENSHIFT_URL`.

The `OAUTH_CALLBACK_URL` should match `http[s]://[your-app-route]/hub/oauth_callback`


### Global OAuth (admin)

As a cluster admin, you can create a global [OAuth client](https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#oauth-clients)
in your OpenShift cluster creating a new OAuthClient object using the API:
```
$ oc create -f - <<EOF
apiVersion: v1
kind: OAuthClient
metadata:
  name: <OAUTH_CLIENT_ID>
redirectURIs:
- <OUAUTH_CALLBACK_URL>
secret: <OAUTH_SECRET>
EOF
```

### Service Accounts as OAuth Clients

As a project member, you can use the [Service Accounts as OAuth Clients](https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#service-accounts-as-oauth-clients)
scenario. This gives you the possibility of defining clients associated with
service accounts. You just need to create the service account with the
proper annotations:
```
$ oc create -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: <name>
  annotations:
    serviceaccounts.openshift.io/oauth-redirecturi.1: '<OUAUTH_CALLBACK_URL>'
EOF
```

In this scenario your `OAUTH_CLIENT_ID` will be `system:serviceaccount:<serviceaccount_namespace>:<serviceaccount_name>`,
the OAUTH_CLIENT_SECRET is the API token of the service account (`oc sa get-token <serviceaccount_name>`)
and the OAUTH_CALLBACK_URL is the value of the annotation `serviceaccounts.openshift.io/oauth-redirecturi.1`.
More details can be found in the upstream documentation.

## OkpyAuthenticator

[Okpy](https://github.com/Cal-CS-61A-Staff/ok-client) is an auto-grading tool that
is widely used in UC Berkeley EECS and Data Science courses. This authenticator
enhances its support for Jupyter Notebook by enabling students to authenticate with
the [Hub](http://datahub.berkeley.edu/hub/home) first and saving relevant user states
to the `env` (the feature is redacted until a secure state saving mechanism is developed).


### Configuration

If you want to authenticate your Hub using OkpyAuthenticator, you need to specify
the authenticator class in your `jupyterhub_config.py` file:

```python
from oauthenticator.okpy import OkpyOAuthenticator
c.JupyterHub.authenticator_class = OkpyOAuthenticator
```

and set your `OAUTH_` environment variables.

## Globus Setup

Visit https://developers.globus.org/ to set up your app. Ensure _Native App_ is
unchecked and make sure the callback URL looks like:

    https://[your-host]/hub/oauth_callback

Set scopes for authorization and transfer. The defaults include:

    openid profile urn:globus:auth:scope:transfer.api.globus.org:all

Set the above settings in your `jupyterhub_config`:

```python
# Tell JupyterHub to create system accounts
from oauthenticator.globus import LocalGlobusOAuthenticator
c.JupyterHub.authenticator_class = LocalGlobusOAuthenticator
c.LocalGlobusOAuthenticator.enable_auth_state = True
c.LocalGlobusOAuthenticator.oauth_callback_url = 'https://[your-host]/hub/oauth_callback'
c.LocalGlobusOAuthenticator.client_id = '[your app client id]'
c.LocalGlobusOAuthenticator.client_secret = '[your app client secret]'
```

Alternatively you can set env variables for the following: `OAUTH_CALLBACK_URL`, `OAUTH_CLIENT_ID`,
and `OAUTH_CLIENT_SECRET`. Setting `JUPYTERHUB_CRYPT_KEY` is required, and can be generated
with OpenSSL: `openssl rand -hex 32`

You are all set by this point! Be sure to check below for tweaking settings
related to User Identity, Transfer, and additional security.

### User Identity

By default, all users are restricted to their *Globus IDs* (example@globusid.org)
with the default Jupyterhub config:

```python
c.GlobusOAuthenticator.identity_provider = 'globusid.org'
```

If you want to use a _Linked Identity_ such as `malcolm@universityofindependence.edu`,
go to your [App Developer page](http://developers.globus.org) and set
*Required Identity Provider* for your app to `<Your University>`, and set the
following in the config:

```python
c.GlobusOAuthenticator.identity_provider = 'universityofindependence.edu'
```

### Globus Scopes and Transfer

The default configuration will automatically setup user environments with tokens,
allowing them to start up python notebooks and initiate Globus Transfers. If you
want to transfer data onto your JupyterHub server, it's suggested you install
[Globus Connect Server](https://docs.globus.org/globus-connect-server-installation-guide/#install_section) and add the `globus_local_endpoint` uuid below. If you want
to change other behavior, you can modify the defaults below:

```python
# Allow Refresh Tokens in user notebooks. Disallow these for increased security,
# allow them for better usability.
c.LocalGlobusOAuthenticator.allow_refresh_tokens = True
# Default scopes are below if unspecified. Add a custom transfer server if you have one.
c.LocalGlobusOAuthenticator.scope = ['openid', 'profile', 'urn:globus:auth:scope:transfer.api.globus.org:all']
# Default tokens excluded from being passed into the spawner environment
c.LocalGlobusOAuthenticator.exclude = ['auth.globus.org']
# If the JupyterHub server is an endpoint, for convenience the endpoint id can be
# set here. It will show up in the notebook kernel for all users as 'GLOBUS_LOCAL_ENDPOINT'.
c.LocalGlobusOAuthenticator.globus_local_endpoint = '<Your Local JupyterHub UUID>'
# Set a custom logout URL for your identity provider
c.LocalGlobusOAuthenticator.logout_redirect_url = 'https://auth.globus.org/v2/web/logout'
# For added security, revoke all service tokens when users logout. (Note: users must start
# a new server to get fresh tokens, logging out does not shut it down by default)
c.LocalGlobusOAuthenticator.revoke_tokens_on_logout = False
```

If you only want to authenticate users with their Globus IDs but don't want to
allow them to do transfers, you can remove `urn:globus:auth:scope:transfer.api.globus.org:all`.
Conversely, you can add an additional scope for another transfer server if you wish.

Use `c.GlobusOAuthenticator.exclude` to prevent tokens from being passed into a
users environment. By default, `auth.globus.org` is excluded but `transfer.api.globus.org`
is allowed. If you want to disable transfers, modify `c.GlobusOAuthenticator.scope`
instead of `c.GlobusOAuthenticator.exclude` to avoid procuring unnecessary tokens.
