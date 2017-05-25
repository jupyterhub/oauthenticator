# OAuthenticator

OAuth + JupyterHub Authenticator = OAuthenticator

## Examples

For an example docker image using OAuthenticator, see the [example](example)
directory.

There is [another
example](https://github.com/jupyterhub/dockerspawner/tree/master/examples/oauth)
for using GitHub OAuth to spawn each user's server in a separate docker
container.

## Installation

Install with pip:

    pip3 install oauthenticator

Or clone the repo and do a dev install:

    git clone https://github.com/jupyterhub/oauthenticator.git
    cd oauthenticator
    pip3 install -e .


## GitHub Setup

First, you'll need to create a [GitHub OAuth
application](https://github.com/settings/applications/new). Make sure the
callback URL is:

    http[s]://[your-host]/hub/oauth_callback

Where `[your-host]` is where your server will be running. Such as
`example.com:8000`.

Then, add the following to your `jupyterhub_config.py` file:

    c.JupyterHub.authenticator_class = 'oauthenticator.GitHubOAuthenticator'

(you can also use `LocalGitHubOAuthenticator` to handle both local and GitHub
auth).

You will additionally need to specify the OAuth callback URL, the client ID, and
the client secret (you should have gotten these when you created your OAuth app
on GitHub). For example, if these values are in the environment variables
`$OAUTH_CALLBACK_URL`, `$GITHUB_CLIENT_ID` and `$GITHUB_CLIENT_SECRET`, you
should add the following to your `jupyterhub_config.py`:
```
    c.GitHubOAuthenticator.oauth_callback_url = os.environ['OAUTH_CALLBACK_URL']
    c.GitHubOAuthenticator.client_id = os.environ['GITHUB_CLIENT_ID']
    c.GitHubOAuthenticator.client_secret = os.environ['GITHUB_CLIENT_SECRET']
```

You can use your own Github Enterprise instance by setting the `GITHUB_HOST` environment
flag.
## GitLab Setup

First, you'll need to create a [GitLab OAuth
application](http://docs.gitlab.com/ce/integration/oauth_provider.html). Make sure the
callback URL is:

    http[s]://[your-host]/hub/oauth_callback

Where `[your-host]` is where your server will be running. Such as
`example.com:8000`.

Then, add the following to your `jupyterhub_config.py` file:

    c.JupyterHub.authenticator_class = 'oauthenticator.gitlab.GitLabOAuthenticator'

(you can also use `LocalGitLabOAuthenticator` to handle both local and GitLab
auth).

You will additionally need to specify the OAuth callback URL, the client ID, and
the client secret (you should have gotten these when you created your OAuth app
on GitLab). For example, if these values are in the environment variables
`$OAUTH_CALLBACK_URL`, `$GITLAB_CLIENT_ID` and `$GITLAB_CLIENT_SECRET`, you
should add the following to your `jupyterhub_config.py`:
```
    c.GitLabOAuthenticator.oauth_callback_url = os.environ['OAUTH_CALLBACK_URL']
    c.GitLabOAuthenticator.client_id = os.environ['GITLAB_CLIENT_ID']
    c.GitLabOAuthenticator.client_secret = os.environ['GITLAB_CLIENT_SECRET']
```

You can use your own GitLab CE/EE instance by setting the `GITLAB_HOST` environment
flag.
## Google Setup

Visit https://console.developers.google.com to set up an OAuth client ID and secret. See [Google's documentation](https://developers.google.com/identity/protocols/OAuth2) on how to create OAUth 2.0 client credentials. The `Authorized JavaScript origins` should be set to to your hub's public address while `Authorized redirect URIs` should be set to the same but followed by `/hub/oauth_callback`.

Set the generated client ID and secret in your `jupyterhub_config`:
```
    c.GoogleOAuthenticator.client_id = os.environ['OAUTH_CLIENT_ID']
    c.GoogleOAuthenticator.client_secret = os.environ['OAUTH_CLIENT_SECRET']
    c.GoogleOAuthenticator.oauth_callback_url = os.environ['OAUTH_CALLBACK_URL']
```
For a Google Apps domain you can set:
```
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
c.JupyterHub.authenticator_class = 'oauthenticator.okpy.OkpyOAuthenticator'
```

You also need to configure the following parameters:

```python
c.OkpyOAuthenticator.client_id =  #client_id recognized by Okpy
c.OkpyOAuthenticator.client_secret = #the associated client secret
c.OkpyOAuthenticator.oauth_callback_url = #callback url to the Hub
```

## Globus Setup

Visit https://developers.globus.org/ to set up your app. Ensure _Native App_ is
unchecked and make sure the callback URL looks like:

    https://[your-host]/hub/oauth_callback

Set scopes for authorization and transfer. The defaults include:

    openid profile urn:globus:auth:scope:transfer.api.globus.org:all

Set the above settings in your `jupyterhub_config`:
```
    # Set Jupyterhub to create system accounts
    c.JupyterHub.authenticator_class = 'oauthenticator.globus.LocalGlobusOAuthenticator'
    # Setup OAuth
    c.LocalGlobusOAuthenticator.client_id = os.environ['OAUTH_CLIENT_ID']
    c.LocalGlobusOAuthenticator.client_secret = os.environ['OAUTH_CLIENT_SECRET']
    c.LocalGlobusOAuthenticator.oauth_callback_url = os.environ['OAUTH_CALLBACK_URL']
```

### User Identity

By default, all users are restricted to their *Globus IDs* (malcolm@globusid.org)
with the default Jupyterhub config:

    c.GlobusOAuthenticator.identity_provider = 'globusid.org'

If you want to use a _Linked Identity_ such as `malcolm@universityofindependence.edu`,
go to your [App Developer page](http://www.developers.globus.org) and set
*Required Identity Provider* for your app to _<Your University>_, and set the
following in the config:

    c.GlobusOAuthenticator.identity_provider = 'universityofindependence.edu'


### Globus Scopes and Transfer

The default configuration will automatically setup user environments with tokens,
allowing them to start up python notebooks and initiate Globus Transfers. If you
want to transfer data onto your Jupyterhub server, it's suggested you install
[Globus Connect Server](https://docs.globus.org/globus-connect-server-installation-guide/#install_section) and add the `globus_local_endpoint` uuid below. If you want
to change other behavior, you can modify the defaults below:

```
    # Allow Refresh Tokens in user notebooks. Disallow these for increased security,
    # allow them for better usability.
    c.LocalGlobusOAuthenticator.allow_refresh_tokens = True
    # Default scopes are below if unspecified. Add a custom transfer server if you have one.
    c.LocalGlobusOAuthenticator.scope = ['openid', 'profile', 'urn:globus:auth:scope:transfer.api.globus.org:all']
    # Default tokens excluded from being passed into the spawner environment
    c.LocalGlobusOAuthenticator.exclude = ['auth.globus.org']
    # If the Jupyterhub server is an endpoint, for convenience the endpoint id can be
    # set here. It will show up in the notebook kernel for all users as 'GLOBUS_LOCAL_ENDPOINT'.
    c.LocalGlobusOAuthenticator.globus_local_endpoint = '<Your Local Jupyterhub UUID>'
```

If you only want to authenticate users with their Globus IDs but don't want to
allow them to do transfers, you can remove `urn:globus:auth:scope:transfer.api.globus.org:all`.
Conversely, you can add an additional scope for another transfer server if you wish.

Use `c.GlobusOAuthenticator.exclude` to prevent tokens from being passed into a
users environment. By default, `auth.globus.org` is excluded but `transfer.api.globus.org`
is allowed. If you want to disable transfers, modify `c.GlobusOAuthenticator.scope`
instead of `c.GlobusOAuthenticator.exclude` to avoid procuring unnecessary tokens.
