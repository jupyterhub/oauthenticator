# BitBucket Setup

You need to have an BitBucket OAuth application registered ahead of time, see
BitBucket's official documentation about [registering an app].

[registering an app]: https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "bitbucket"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional configuration

BitBucketOAuthenticator expands OAuthenticator with the following config that may
be relevant to read more about in the configuration reference:

- {attr}`.BitBucketOAuthenticator.allowed_teams`
