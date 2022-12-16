# GitHub Setup

First, you’ll need to create a [GitHub OAuth application](https://github.com/settings/applications/new).

Then, add the following to your `jupyterhub_config.py` file:

```python
from oauthenticator.github import GitHubOAuthenticator
c.JupyterHub.authenticator_class = GitHubOAuthenticator
```

You can also use `LocalGitHubOAuthenticator` to map GitHub accounts onto local users.

You can use your own Github Enterprise instance by setting the `GITHUB_HOST` environment variable.

You can set `GITHUB_HTTP` environment variable to true or anything if
your GitHub Enterprise supports http only.

GitHub allows expanded capabilities by adding [](github:scopes) to the requested token.