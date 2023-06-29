# Auth0 Setup

You need to have an Auth0 OAuth application registered ahead of time, see
Auth0's official documentation about [registering an app].

[registering an app]: https://auth0.com/docs/get-started/auth0-overview/create-applications/regular-web-apps

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "auth0"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional required configuration

Auth0OAuthenticator expands OAuthenticator with the following required config,
read more about it in the configuration reference:

- {attr}`.Auth0OAuthenticator.auth0_domain`
