(tutorials:provider-specific:generic)=

# Generic OAuthenticator setups for various identity providers

(tutorials:provider-specific:generic:moodle)=

## Generic OAuthenticator Setup for Moodle

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

## Generic OAuthenticator Setup for Nextcloud

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

## Generic OAuthenticator Setup for Yandex

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

## Generic OAuthenticator Setup for AWS Cognito

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
