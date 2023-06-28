# OkpyAuthenticator

[Okpy](https://github.com/okpy/ok-client) is an
auto-grading tool that is widely used in UC Berkeley EECS and Data
Science courses. This authenticator enhances its support for Jupyter
Notebook by enabling students to authenticate with the
[Hub](https://datahub.berkeley.edu/hub/login) first and saving relevant
user states to the `env` (the feature is redacted until a secure state
saving mechanism is developed).

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "okpy"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

## Additional configuration

OkpyOAuthenticator _does not_ expand OAuthenticator with additional config
options.
