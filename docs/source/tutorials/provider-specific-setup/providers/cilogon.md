# CILogon Setup

You need to have an CILogon OAuth application registered ahead of time, see
CILogon's official documentation about [registering an app].

[registering an app]: https://www.cilogon.org/oidc

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "cilogon"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional required configuration

CILogonOAuthenticator expands OAuthenticator with the following required config,
read more about it in the configuration reference:

- {attr}`.CILogonOAuthenticator.allowed_idps`
