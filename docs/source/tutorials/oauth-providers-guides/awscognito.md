# AWS Cognito Setup

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