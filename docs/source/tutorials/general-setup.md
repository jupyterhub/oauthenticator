(tutorials:general-setup)=

# Getting started

The general steps to take when using `OAuthenticator`:

1. Register an OAuth2 application with the identity provider
2. Configure JupyterHub to use an authenticator class compatible with the identity provider
3. Configure the chosen authenticator class

## General setup

### 1. Set chosen OAuthenticator

The first step is to tell JupyterHub to use your chosen authenticator class.
Each authenticator is provided in a submodule of `oauthenticator`, and
each authenticator has a variant with `Local`
(e.g. `LocalGitHubOAuthenticator`), which will map OAuth usernames
onto local system usernames.

In `jupyterhub_config.py`, add:

```python
from oauthenticator.github import GitHubOAuthenticator
c.JupyterHub.authenticator_class = GitHubOAuthenticator
```

### 2. Set callback URL, client ID, and client secret

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

You can also set these values in your **configuration file**,
`jupyterhub_config.py`:

```python
# Replace MyOAuthenticator with your selected OAuthenticator class (e.g. c.GithubOAuthenticator).
c.MyOAuthenticator.oauth_callback_url = 'http[s]://[your-host]/hub/oauth_callback'
c.MyOAuthenticator.client_id = 'your-client-id'
c.MyOAuthenticator.client_secret = 'your-client-secret'
```

```{note}
When JupyterHub runs, these values can also be retrieved from the
**environment variables** `OAUTH_CALLBACK_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`.
But this approach is not recommended and might be deprecated in the future.
```

### 3. (Optional) Use a custom 403 error

1. Custom message

   When a user successfully logins at an OAuth provider,
   but is forbidden access based on the config,
   e.g. the `allowed_users` list or the `blocked_users` list,
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
