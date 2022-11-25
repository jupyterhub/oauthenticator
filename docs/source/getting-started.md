(getting-started:front-page)=

# Getting started

The general steps to take when using OAuthenticator:

1. Register an OAuth2 application with the identity provider
2. Configure JupyterHub to use an authenticator class compatible with the identity provider
3. Configure the chosen authenticator class

OAuthenticator provides a few dedicated authentication classes, besides the
generic implementation `GenericOAuthenticator` that can be used with **any
OAuth2 identity provider**.

- `Auth0OAuthenticator`
- `AzureAdOAuthenticator`
- `BitbucketOAuthenticator`
- `CILogonOAuthenticator`
- `GitHubOAuthenticator`
- `GitLabOAuthenticator`
- `GlobusOAuthenticator`
- `GoogleOAuthenticator`
- `MediaWikiOAuthenticator`
- `OkpyOAuthenticator`
- `OpenShiftOAuthenticator`

## General setup

The first step is to tell JupyterHub to use your chosen authenticator class.
Each authenticator is provided in a submodule of `oauthenticator`, and
each authenticator has a variant with `Local`
(e.g. `LocalGitHubOAuthenticator`), which will map OAuth usernames
onto local system usernames.

### Set chosen OAuthenticator

In `jupyterhub_config.py`, add:

```python
from oauthenticator.github import GitHubOAuthenticator
c.JupyterHub.authenticator_class = GitHubOAuthenticator
```

### Set callback URL, client ID, and client secret

All `OAuthenticators` require setting a callback URL, client ID, and
client secret. You will generally get these when you register your OAuth
application with your OAuth provider. Provider-specific details are
available in sections below. When registering your oauth application
with your provider, you will probably need to specify a callback URL.
The callback URL should look like:

```
http[s]://[your-host]/hub/oauth_callback
```

where `[your-host]` is where your server will be running. Such as
`example.com:8000`.

When JupyterHub runs, these values will be retrieved from the
**environment variables**:

```
OAUTH_CALLBACK_URL
OAUTH_CLIENT_ID
OAUTH_CLIENT_SECRET
```

You can also set these values in your **configuration file**,
`jupyterhub_config.py`:

```python
# Replace MyOAuthenticator with your selected OAuthenticator class (e.g. c.GithubOAuthenticator).
c.MyOAuthenticator.oauth_callback_url = 'http[s]://[your-host]/hub/oauth_callback'
c.MyOAuthenticator.client_id = 'your-client-id'
c.MyOAuthenticator.client_secret = 'your-client-secret'
```

### Use a custom 403 error

1. Custom message

   When a user successfully logins at an OAuth provider,
   but is forbidden access based on the config,
   e.g. the ``allowed_users`` list or the ``blocked_users`` list,
   the following message is shown by default:

   ```{important}
   *Looks like you have not been added to the list of allowed users for this hub. Please contact the hub administrator.*
   ```

   But you can show a customized 403 error message instead,
   by changing the OAuthenticator config:

   ```python
   # Replace MyOAuthenticator with your selected OAuthenticator class (e.g. c.GithubOAuthenticator).
   c.MyOAuthenticator.custom_403_message = "Your message for the user"
   ```

2. Custom HTML page
   You can also show a customized 403 HTML page message by creating a
   [custom HTML template](https://jupyterhub.readthedocs.io/en/stable/reference/templates.html),
   and point JupyterHub to it.

   An example custom 403 html page can be found in the
   [examples directory](https://github.com/jupyterhub/oauthenticator/tree/main/examples/templates)

   ```python
   # Replace MyOAuthenticator with your selected OAuthenticator class (e.g. c.GithubOAuthenticator).
   c.JupyterHub.template_paths = ["examples/templates"]
   ```

## AWS Cognito Setup

First visit [Getting Started with User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/getting-started-with-cognito-user-pools.html)
for info on how to register and configure a cognito user pool and app.

Set the above settings in your `jupyterhub_config.py`:

```python
c.JupyterHub.authenticator_class = "generic"
c.OAuthenticator.oauth_callback_url = "https://[your-host]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your app ID]""
c.OAuthenticator.client_secret = "[your app Password]"

c.GenericOAuthenticator.login_service = "AWSCognito"
c.GenericOAuthenticator.username_key = "login"
c.GenericOAuthenticator.authorize_url = "https://your-AWSCognito-domain/oauth2/authorize"
c.GenericOAuthenticator.token_url = "https://your-AWSCognito-domain/oauth2/token"
c.GenericOAuthenticator.userdata_url = "https://your-AWSCognito-domain/oauth2/userInfo"
```

## Azure AD Setup

1. Install ``PyJWT>=2``

   ```bash
   pip3 install PyJWT
   ```

1. Set the ``AAD_TENANT_ID`` environment variable

   ```bash
   export AAD_TENANT_ID='{AAD-TENANT-ID}'
   ```

1. Add the code below to your `jupyterhub_config.py` file

   ```python
   import os
   from oauthenticator.azuread import AzureAdOAuthenticator
   c.JupyterHub.authenticator_class = AzureAdOAuthenticator

   c.Application.log_level = 'DEBUG'

   c.AzureAdOAuthenticator.tenant_id = os.environ.get('AAD_TENANT_ID')

   c.AzureAdOAuthenticator.oauth_callback_url = 'http://{your-domain}/hub/oauth_callback'
   c.AzureAdOAuthenticator.client_id = '{AAD-APP-CLIENT-ID}'
   c.AzureAdOAuthenticator.client_secret = '{AAD-APP-CLIENT-SECRET}'
   ```

   This sample code is provided for you in `examples > azuread > sample_jupyter_config.py`

1. Make sure to replace the values in `'{}'` with your APP, TENANT, DOMAIN, etc. values

1. You might need to add at least the `openid` scope if your
  organization requires MFA (`c.AzureAdOAuthenticator.scope = ['openid']`),
  in addition to whatever else you need.

1. Follow [this link to create an AAD APP](https://community.microfocus.com/cyberres/netiq-identity-governance-administration/idm/w/identity_mgr_tips/17052/creating-the-application-client-id-and-client-secret-from-microsoft-azure-new-portal---part-1)

<<<<<<< HEAD
1. CLIENT_ID === *Azure Application ID*, found in:
   ``Azure portal --> AD --> App Registrations --> App``

1. TENANT_ID === *Azure Directory ID*, found in:
   ``Azure portal --> AD --> Properties``
=======
1. CLIENT*ID === \_Azure Application ID*, found in:
   `Azure portal --> AD --> App Registrations --> App`

1. TENANT*ID === \_Azure Directory ID*, found in:
   `Azure portal --> AD --> Properties`
>>>>>>> 85debba ([pre-commit.ci] auto fixes from pre-commit.com hooks)

1. Run via:

   ```bash
   sudo jupyterhub -f ./path/to/jupyterhub_config.py
   ```

1.  See `run.sh` for an [example](https://github.com/jupyterhub/oauthenticator/tree/main/examples/azuread)

1. [Source Code](https://github.com/jupyterhub/oauthenticator/blob/HEAD/oauthenticator/azuread.py)


## GitHub Setup

First, you’ll need to create a [GitHub OAuth application](https://github.com/settings/applications/new).

Then, add the following to your `jupyterhub_config.py` file:

```python
from oauthenticator.github import GitHubOAuthenticator
c.JupyterHub.authenticator_class = GitHubOAuthenticator
```

You can also use `LocalGitHubOAuthenticator` to map GitHub accounts onto local users.

You can use your own Github Enterprise instance by setting the `GITHUB_HOST` environment variable.

You can set `GITHUB_HTTP` environment variable to true or anything if
your GitHub Enterprise supports http only.

GitHub allows expanded capabilities by adding [](github:scopes) to the requested token.

## GitLab Setup

First, you’ll need to create a [GitLab OAuth application](https://docs.gitlab.com/ee/integration/oauth_provider.html).

Then, add the following to your `jupyterhub_config.py` file:

```python
from oauthenticator.gitlab import GitLabOAuthenticator
c.JupyterHub.authenticator_class = GitLabOAuthenticator
```

You can also use ``LocalGitLabOAuthenticator`` to map GitLab accounts onto local users.

You can use your own GitLab CE/EE instance by setting the `GITLAB_HOST` environment flag.

You can restrict access to only accept members of certain projects or groups by setting

```python
c.GitLabOAuthenticator.allowed_project_ids = [ ... ]
```

and

```python
c.GitLabOAuthenticator.allowed_gitlab_groups = [ ... ]
```

but be aware that each entry incurs a separate API call, increasing the risk of rate limiting and timeouts.

```{note}
If restriction to projects or groups does not work, you might not be using jupyterHub 1.2. In that case you can still you use whitelists as noted in this 
[comment](https://github.com/jupyterhub/oauthenticator/pull/366#pullrequestreview-483095919).
```

## Google Setup

Visit https://console.developers.google.com to set up an OAuth client ID
and secret. See [Google’s documentation](https://developers.google.com/identity/protocols/oauth2)
on how to create OAUth 2.0 client credentials.
The `Authorized JavaScript origins` should be set to to your hub’s public
address while `Authorized redirect URIs` should be set to the same but
followed by `/hub/oauth_callback`.

Then, add the following to your `jupyterhub_config.py` file:

```python
from oauthenticator.google import GoogleOAuthenticator
c.JupyterHub.authenticator_class = GoogleOAuthenticator
```

By default, any domain is allowed to login but you can restrict
authorized domains with a list (recommended):

```python
c.GoogleOAuthenticator.hosted_domain = ['mycollege.edu', 'mycompany.com']
```

You can customize the sign in button text (optional):

```python
c.GoogleOAuthenticator.login_service = 'My College'
```

```{note}
Additional notes, that seem quite outdated at the time of writing May 2022,
are available about authorizing users part of specific Google Groups are
[available here](google:groups). Contributions to update these
and re-verify this functionality are most welcome.
```

## OpenShift Setup

In case you have an OpenShift deployment with OAuth properly configured
(see the following sections for a quick reference), you should set the
client ID and secret by the environment variables `OAUTH_CLIENT_ID`,
`OAUTH_CLIENT_SECRET` and `OAUTH_CALLBACK_URL`.

Prior to OpenShift 4.0, the OAuth provider and REST API URL endpoints
can be specified by setting the single environment variable
`OPENSHIFT_URL`. From OpenShift 4.0 onwards, these two endpoints are
on different hosts. You need to set `OPENSHIFT_AUTH_API_URL` to the
OAuth provider URL, and `OPENSHIFT_REST_API_URL` to the REST API URL
endpoint.

The `OAUTH_CALLBACK_URL` should match
`http[s]://[your-app-route]/hub/oauth_callback`

### Global OAuth (admin)

As a cluster admin, you can create a global [OAuth
client](https://docs.okd.io/latest/authentication/configuring-oauth-clients.html)
in your OpenShift cluster creating a new OAuthClient object using the
API:

```bash
oc create -f - <<EOF
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

As a project member, you can use the [Service Accounts as OAuth Clients](https://docs.openshift.com/container-platform/latest/authentication/using-service-accounts-as-oauth-client.html)
scenario. This gives you the possibility of defining clients associated
with service accounts. You just need to create the service account with
the proper annotations:

```bash
oc create -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
   name: <name>
   annotations:
      serviceaccounts.openshift.io/oauth-redirecturi.1: '<OUAUTH_CALLBACK_URL>'
EOF
```

In this scenario your `OAUTH_CLIENT_ID` will be
`system:serviceaccount:<serviceaccount_namespace>:<serviceaccount_name>`,
the OAUTH_CLIENT_SECRET is the API token of the service account
(`oc sa get-token <serviceaccount_name>`) and the OAUTH_CALLBACK_URL
is the value of the annotation
`serviceaccounts.openshift.io/oauth-redirecturi.1`. More details can
be found in the upstream documentation.

## OkpyAuthenticator

[Okpy](https://github.com/okpy/ok-client) is an
auto-grading tool that is widely used in UC Berkeley EECS and Data
Science courses. This authenticator enhances its support for Jupyter
Notebook by enabling students to authenticate with the
[Hub](https://datahub.berkeley.edu/hub/login) first and saving relevant
user states to the `env` (the feature is redacted until a secure state
saving mechanism is developed).

### Configuration

If you want to authenticate your Hub using OkpyAuthenticator, you need
to specify the authenticator class in your `jupyterhub_config.py`
file:

```python
from oauthenticator.okpy import OkpyOAuthenticator
c.JupyterHub.authenticator_class = OkpyOAuthenticator
```

and set your `OAUTH_` environment variables.

## Globus Setup

Visit https://developers.globus.org/ to set up your app. Ensure *Native
App* is unchecked and make sure the callback URL looks like:

```
https://[your-host]/hub/oauth_callback
```

Set scopes for authorization and transfer. The defaults include:

```
openid profile urn:globus:auth:scope:transfer.api.globus.org:all
```

Set the above settings in your `jupyterhub_config`:

```python
# Tell JupyterHub to create system accounts
from oauthenticator.globus import GlobusOAuthenticator
c.JupyterHub.authenticator_class = GlobusOAuthenticator
c.GlobusOAuthenticator.oauth_callback_url = 'https://[your-host]/hub/oauth_callback'
c.GlobusOAuthenticator.client_id = '[your app client id]'
c.GlobusOAuthenticator.client_secret = '[your app client secret]'
```

Alternatively you can set env variables for the following:
`OAUTH_CALLBACK_URL`, `OAUTH_CLIENT_ID`, and
`OAUTH_CLIENT_SECRET`. Setting `JUPYTERHUB_CRYPT_KEY` is required,
and can be generated with OpenSSL: `openssl rand -hex 32`

You are all set by this point! Be sure to check below for tweaking
settings related to User Identity, Transfer, and additional security.

### User Identity

By default, `identity_provider = ''` will allow anyone to login.
If you want to use a *Linked Identity* such as
`malcolm@universityofindependence.edu`, go to your [App Developer
page](https://developers.globus.org) and set *Required Identity
Provider* for your app to `<Your University>`, and set the following
in the config:

```python
c.GlobusOAuthenticator.identity_provider = 'uchicago.edu'
```

**Pitfall**: Don't set 'Required Identity Provider' on pre-existing apps!
Previous user login consents will be tied to the identity users initially used
to login, and will continue to be tied to that identity after changing this
setting. Create a new Globus App with your preferred 'Required Identity Provider'
to avoid this problem.

### Username from Email Address

By default, the JupyterHub `username` will be taken from the OIDC
`preferred_username` claim. In many cases, this is the same as the email
address. However, some identity providers use an opaque string, e.g.,
`046f34a240f0615e01420b3ff4350922@ucsd.edu`. You may set
`username_from_email = True` to get it from the user's email address. Setting
this will automatically add `email` to the list of scopes. When
`identity_provider` is set, the email address domain must still match the
identity provider domain.

### Globus Scopes and Transfer

The following shows how to get tokens into user Notebooks. You can see how users
use tokens [here](https://github.com/globus/globus-jupyter-notebooks/blob/HEAD/JupyterHub_Integration.ipynb).
If you want a demonstration, you can visit [The Jupyter Globus Demo Server](https://jupyter.demo.globus.org/hub/login).

The default server configuration will automatically setup user environments
with tokens, allowing them to start up python notebooks and initiate
Globus Transfers. If you want to transfer data onto your JupyterHub
server, it’s suggested you install [Globus Connect Server](https://docs.globus.org/globus-connect-server/v5/#install_section),
and add the `globus_local_endpoint` uuid below.
If you want to change other behavior, you can modify the defaults below:

```python
# Allow saving user tokens to the database
c.GlobusOAuthenticator.enable_auth_state = True
# Default scopes are below if unspecified. Add a custom transfer server if you have one.
c.GlobusOAuthenticator.scope = ['openid', 'profile', 'urn:globus:auth:scope:transfer.api.globus.org:all']
# Default tokens excluded from being passed into the spawner environment
c.GlobusOAuthenticator.exclude_tokens = ['auth.globus.org']
# If the JupyterHub server is an endpoint, for convenience the endpoint id can be
# set here. It will show up in the notebook kernel for all users as 'GLOBUS_LOCAL_ENDPOINT'.
c.GlobusOAuthenticator.globus_local_endpoint = '<Your Local JupyterHub UUID>'
# Set a custom logout URL for your identity provider
c.GlobusOAuthenticator.logout_redirect_url = 'https://globus.org/logout'
# For added security, revoke all service tokens when users logout. (Note: users must start
# a new server to get fresh tokens, logging out does not shut it down by default)
c.GlobusOAuthenticator.revoke_tokens_on_logout = False
```

If you only want to authenticate users with their Globus IDs but don’t
want to allow them to do transfers, you can remove
`urn:globus:auth:scope:transfer.api.globus.org:all`. Conversely, you
can add an additional scope for another transfer server if you wish.

Use `c.GlobusOAuthenticator.exclude` to prevent tokens from being
passed into a users environment. By default, `auth.globus.org` is
excluded but `transfer.api.globus.org` is allowed. If you want to
disable transfers, modify `c.GlobusOAuthenticator.scope` instead of
`c.GlobusOAuthenticator.exclude` to avoid procuring unnecessary
tokens.

### Group Management

Allowed and admin users can be managed through [Globus Groups](https://docs.globus.org/how-to/managing-groups/).
Globus Groups are identified using a UUID and multiple groups can be used for
each of these configuration settings. The lets JuptyerHub admininstators
choose whether to manage memership in the groups, or use groups
managed by others. For example, researchers could manage groups of
collaborators. Each of these settings can contain multiple Globus
Groups.

```python
# Groups of allowed users
c.GlobusOAuthenticator.allowed_globus_groups = set
authenticator.allowed_globus_groups =  {
      'd11abe71-5132-4c04-a4ad-50926885dc8c',
      '21c6bc5d-fc12-4f60-b999-76766cd596c2',
}
# Admin users
authenticator.admin_globus_groups = {'3f1f85c4-f084-4173-9efb-7c7e0b44291a'}
```

When any of these are set, the Globus Groups API scope will be
included in the default list of scopes. When
`c.GlobusOAuthenticator.admin_globus_groups` is set, only members of
those groups will be JupyterHub admins.

To block users, the [`c.Authenticator.blocked_users`](https://jupyterhub.readthedocs.io/en/stable/api/auth.html#jupyterhub.auth.Authenticator.blocked_users)
configuration can be used. Or, users can be removed from the allowed
Globus Groups, and the Group set require approval, so the user cannot
rejoin it without action by an administrator.


(getting-started:moodle-setup)=
## Moodle Setup

First install the [OAuth2 Server Plugin](https://github.com/projectestac/moodle-local_oauth) for
Moodle.

Use the `GenericOAuthenticator` for Jupyterhub by editing your `jupyterhub_config.py` accordingly:

```python
c.JupyterHub.authenticator_class = "generic"

c.GenericOAuthenticator.oauth_callback_url = 'http://YOUR-JUPYTERHUB.com/hub/oauth_callback'
c.GenericOAuthenticator.client_id = 'MOODLE-CLIENT-ID'
c.GenericOAuthenticator.client_secret = 'MOODLE-CLIENT-SECRET-KEY'
c.GenericOAuthenticator.login_service = 'NAME-OF-SERVICE'
c.GenericOAuthenticator.userdata_url = 'http://YOUR-MOODLE-DOMAIN.com/local/oauth/user_info.php'
c.GenericOAuthenticator.token_url = 'http://YOUR-MOODLE-DOMAIN.com/local/oauth/token.php'
c.GenericOAuthenticator.token_params = {
      'scope': 'user_info',
      'client_id': 'MOODLE-CLIENT-ID',
      'client_secret': 'MOODLE-CLIENT-SECRET-KEY',
}
```

And set your environmental variable `OAUTH2_AUTHORIZE_URL` to
`http://YOUR-MOODLE-DOMAIN.com/local/oauth/login.php?client_id=MOODLE-CLIENT-ID&response_type=code`


## Nextcloud Setup

Add a new OAuth2 Application in the Nextcloud Administrator
Security Settings. You will get a client id and a secret key.

Use the `GenericOAuthenticator` for Jupyterhub by editing your
`jupyterhub_config.py` accordingly:

```python
from oauthenticator.generic import GenericOAuthenticator
c.JupyterHub.authenticator_class = GenericOAuthenticator

c.GenericOAuthenticator.client_id = 'NEXTCLOUD-CLIENT-ID'
c.GenericOAuthenticator.client_secret = 'NEXTCLOUD-CLIENT-SECRET-KEY'
c.GenericOAuthenticator.login_service = 'NAME-OF-SERVICE'  # name to be displayed at login
c.GenericOAuthenticator.username_key = lambda r: r.get('ocs', {}).get('data', {}).get('id')
```

And set the following environmental variables:

```bash
OAUTH2_AUTHORIZE_URL=https://YOUR-NEXTCLOUD-DOMAIN.com/apps/oauth2/authorize
OAUTH2_TOKEN_URL=https://YOUR-NEXTCLOUD-DOMAIN.com/apps/oauth2/api/v1/token
OAUTH2_USERDATA_URL=https://YOUR-NEXTCLOUD-DOMAIN.com/ocs/v2.php/cloud/user?format=json
```
(getting-started:yandex_setup)=
## Yandex Setup

First visit [Yandex OAuth](https://oauth.yandex.com) to setup your
app. Ensure that **Web services** is checked (in the **Platform**
section) and make sure the **Callback URI #1** looks like:
`https://[your-host]/hub/oauth_callback`

Choose **Yandex.Passport API** in Permissions and check these options:

-  Access to email address
-  Access to username, first name and surname

Set the above settings in your `jupyterhub_config.py`:

```python
c.JupyterHub.authenticator_class = "generic"
c.OAuthenticator.oauth_callback_url = "https://[your-host]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your app ID]""
c.OAuthenticator.client_secret = "[your app Password]"

c.GenericOAuthenticator.login_service = "Yandex.Passport"
c.GenericOAuthenticator.username_key = "login"
c.GenericOAuthenticator.authorize_url = "https://oauth.yandex.ru/authorize"
c.GenericOAuthenticator.token_url = "https://oauth.yandex.ru/token"
c.GenericOAuthenticator.userdata_url = "https://login.yandex.ru/info"
```

## Examples

For an example docker image using OAuthenticator, see the
[examples](https://github.com/jupyterhub/oauthenticator/tree/HEAD/examples) directory.

[Another example](https://github.com/jupyterhub/dockerspawner/tree/HEAD/examples/oauth)
is using GitHub OAuth to spawn each user’s server in a separate docker
container.
