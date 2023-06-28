# GitLab Setup

You need to have an GitLab OAuth application registered ahead of time, see
GitLab's official documentation about [registering an app].

[registering an app]: https://docs.gitlab.com/ee/integration/oauth_provider.html

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "gitlab"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional configuration

GitLabOAuthenticator expands OAuthenticator with the following config that may
be relevant to read more about in the configuration reference:

- {attr}`.GitLabOAuthenticator.allowed_project_ids`
- {attr}`.GitLabOAuthenticator.allowed_gitlab_groups`
- {attr}`.GitLabOAuthenticator.gitlab_url`
