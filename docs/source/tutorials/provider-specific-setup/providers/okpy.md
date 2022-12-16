# OkpyAuthenticator

[Okpy](https://github.com/okpy/ok-client) is an
auto-grading tool that is widely used in UC Berkeley EECS and Data
Science courses. This authenticator enhances its support for Jupyter
Notebook by enabling students to authenticate with the
[Hub](https://datahub.berkeley.edu/hub/login) first and saving relevant
user states to the `env` (the feature is redacted until a secure state
saving mechanism is developed).

## Configuration

If you want to authenticate your Hub using OkpyAuthenticator, you need
to specify the authenticator class in your `jupyterhub_config.py`
file:

```python
from oauthenticator.okpy import OkpyOAuthenticator
c.JupyterHub.authenticator_class = OkpyOAuthenticator
```

and set your `OAUTH_` environment variables.
