(tutorials:provider-specific-setup:providers:google)=

# Google Setup

You need to have an Google OAuth application registered ahead of time, see
Google's official documentation about [registering an app].

[registering an app]: https://developers.google.com/identity/protocols/oauth2

```{note}
The `Authorized JavaScript origins` should be set to to your hub’s public
address while `Authorized redirect URIs` should be set to the same but
followed by `/hub/oauth_callback`.
```

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "google"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional configuration

GoogleOAuthenticator expands OAuthenticator with the following config that may
be relevant to read more about in the configuration reference:

- {attr}`.GoogleOAuthenticator.allowed_google_groups`
- {attr}`.GoogleOAuthenticator.admin_google_groups`
- {attr}`.GoogleOAuthenticator.hosted_domain`

If you configure `allowed_google_groups` or `admin_google_groups`, you are
required to also configure:

- {attr}`.GoogleOAuthenticator.gsuite_administrator`
- {attr}`.GoogleOAuthenticator.google_service_account_keys`
