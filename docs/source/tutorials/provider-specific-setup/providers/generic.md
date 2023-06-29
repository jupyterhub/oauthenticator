(tutorials:provider-specific:generic)=

# Generic OAuthenticator setups for various identity providers

(tutorials:provider-specific:generic:oidc)=

## Setup for an OpenID Connect (OIDC) based identity provider

The GenericOAuthenticator can be configured to be used against an OpenID Connect
(OIDC) based identity provider, and this is an example demonstrating that.

```python
c.JupyterHub.authenticator_class = "generic"

# OAuth2 application info
# -----------------------
c.GenericOAuthenticator.client_id = "some-client-id"
c.GenericOAuthenticator.client_secret = "some-often-long-client-secret"

# Identity provider info
# ----------------------
c.GenericOAuthenticator.authorize_url =
c.GenericOAuthenticator.token_url = "https://accounts.example.com/auth/realms/example/protocol/openid-connect/token"
c.GenericOAuthenticator.userdata_url = "https://accounts.example.com/auth/realms/example/protocol/openid-connect/userinfo"

# What we request about the user
# ------------------------------
# scope represents requested information about the user, and since we configure
# this against an OIDC based identity provider, we should request "openid" at
# least.
#
# In this example we include "email" and "groups" as well, and then declare that
# we should set the username based on the "email" key in the response, and read
# group membership from the "groups" key in the response.
#
c.GenericOAuthenticator.scope = ["openid", "email", "groups"]
c.GenericOAuthenticator.username_claim = "email"
c.GenericOAuthenticator.claim_groups_key = "groups"

# Authorization
# -------------
c.GenericOAuthenticator.allowed_users = {"user1@example.com"}
c.GenericOAuthenticator.allowed_groups = {"staff"}
c.GenericOAuthenticator.admin_users = {"user2@example.com"}
c.GenericOAuthenticator.admin_groups = {"administrator"}
```

(tutorials:provider-specific:generic:moodle)=

## Setup for Moodle

First install the [OAuth2 Server Plugin](https://github.com/projectestac/moodle-local_oauth) for
Moodle.

Use the `GenericOAuthenticator` for Jupyterhub by editing your `jupyterhub_config.py` accordingly:

```python
c.JupyterHub.authenticator_class = "generic"

c.GenericOAuthenticator.oauth_callback_url = 'https://YOUR-JUPYTERHUB.com/hub/oauth_callback'
c.GenericOAuthenticator.client_id = 'MOODLE-CLIENT-ID'
c.GenericOAuthenticator.client_secret = 'MOODLE-CLIENT-SECRET-KEY'
c.GenericOAuthenticator.login_service = 'NAME-OF-SERVICE'

c.GenericOAuthenticator.authorize_url = 'https://YOUR-MOODLE-DOMAIN.com/local/oauth/login.php?client_id=MOODLE-CLIENT-ID&response_type=code'
c.GenericOAuthenticator.token_url = 'https://YOUR-MOODLE-DOMAIN.com/local/oauth/token.php'
c.GenericOAuthenticator.userdata_url = 'https://YOUR-MOODLE-DOMAIN.com/local/oauth/user_info.php'

c.GenericOAuthenticator.scope = ["user_info"]
```

(tutorials:provider-specific:generic:nextcloud)=

## Setup for Nextcloud

Add a new OAuth2 Application in the Nextcloud Administrator
Security Settings. You will get a client id and a secret key.

Use the `GenericOAuthenticator` for Jupyterhub by editing your
`jupyterhub_config.py` accordingly:

```python
c.JupyterHub.authenticator_class = "generic"

c.GenericOAuthenticator.client_id = 'NEXTCLOUD-CLIENT-ID'
c.GenericOAuthenticator.client_secret = 'NEXTCLOUD-CLIENT-SECRET-KEY'
c.GenericOAuthenticator.login_service = 'NAME-OF-SERVICE'  # name to be displayed at login
c.GenericOAuthenticator.username_claim = lambda r: r.get('ocs', {}).get('data', {}).get('id')

c.GenericOAuthenticator.authorize_url = 'https://YOUR-NEXTCLOUD-DOMAIN.com/apps/oauth2/authorize'
c.GenericOAuthenticator.token_url = 'https://YOUR-NEXTCLOUD-DOMAIN.com/apps/oauth2/api/v1/token'
c.GenericOAuthenticator.userdata_url = 'https://YOUR-NEXTCLOUD-DOMAIN.com/ocs/v2.php/cloud/user?format=json'
```

(tutorials:provider-specific:generic:yandex)=

## Setup for Yandex

First visit [Yandex OAuth](https://oauth.yandex.com) to setup your
app. Ensure that **Web services** is checked (in the **Platform**
section) and make sure the **Callback URI #1** looks like:
`https://[your-host]/hub/oauth_callback`

Choose **Yandex.Passport API** in Permissions and check these options:

- Access to email address
- Access to username, first name and surname

Set the above settings in your `jupyterhub_config.py`:

```python
c.JupyterHub.authenticator_class = "generic"
c.OAuthenticator.oauth_callback_url = "https://[your-host]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your app ID]"
c.OAuthenticator.client_secret = "[your app Password]"

c.GenericOAuthenticator.login_service = "Yandex.Passport"
c.GenericOAuthenticator.username_claim = "login"

c.GenericOAuthenticator.authorize_url = "https://oauth.yandex.ru/authorize"
c.GenericOAuthenticator.token_url = "https://oauth.yandex.ru/token"
c.GenericOAuthenticator.userdata_url = "https://login.yandex.ru/info"
```

(tutorials:provider-specific:generic:awscognito)=

## Setup for AWS Cognito

First visit AWS official documentation on [Getting started with user pools] for
info on how to register and configure a cognito user pool and an associated
OAuth2 application.

[Getting started with user pools]: https://docs.aws.amazon.com/cognito/latest/developerguide/getting-started-with-cognito-user-pools.html

Set the above settings in your `jupyterhub_config.py`:

```python
c.JupyterHub.authenticator_class = "generic"
c.OAuthenticator.oauth_callback_url = "https://[your-host]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"

c.GenericOAuthenticator.login_service = "AWS Cognito"
c.GenericOAuthenticator.username_claim = "login"

c.GenericOAuthenticator.authorize_url = "https://your-AWSCognito-domain/oauth2/authorize"
c.GenericOAuthenticator.token_url = "https://your-AWSCognito-domain/oauth2/token"
c.GenericOAuthenticator.userdata_url = "https://your-AWSCognito-domain/oauth2/userInfo"
```
