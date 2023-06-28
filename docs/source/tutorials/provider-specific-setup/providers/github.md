# GitHub Setup

You need to have an GitHub OAuth application registered ahead of time, see
GitLab's official documentation about [registering an app].

[registering an app]: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "github"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional configuration

GitHubOAuthenticator expands OAuthenticator with the following config that may
be relevant to read more about in the configuration reference:

- {attr}`.GitHubOAuthenticator.allowed_organizations`
- {attr}`.GitHubOAuthenticator.populate_teams_in_auth_state`
- {attr}`.GitHubOAuthenticator.github_url`
