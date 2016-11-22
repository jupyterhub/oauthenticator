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
