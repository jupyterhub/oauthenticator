
# GitLab Setup

First, you’ll need to create a [GitLab OAuth application](https://docs.gitlab.com/ee/integration/oauth_provider.html).

Then, add the following to your `jupyterhub_config.py` file:

```python
from oauthenticator.gitlab import GitLabOAuthenticator
c.JupyterHub.authenticator_class = GitLabOAuthenticator
```

You can also use `LocalGitLabOAuthenticator` to map GitLab accounts onto local users.

You can use your own GitLab CE/EE instance by setting the `GITLAB_HOST` environment flag.

You can restrict access to only accept members of certain projects or groups by setting

```python
c.GitLabOAuthenticator.allowed_project_ids = [ ... ]
```

and

```python
c.GitLabOAuthenticator.allowed_gitlab_groups = [ ... ]
```

but be aware that each entry incurs a separate API call, increasing the risk of rate limiting and timeouts.

```{note}
If restriction to projects or groups does not work, you might not be using jupyterHub 1.2. In that case you can still you use whitelists as noted in this
[comment](https://github.com/jupyterhub/oauthenticator/pull/366#pullrequestreview-483095919).
```
