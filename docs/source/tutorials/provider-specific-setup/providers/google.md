# Google Setup

Visit https://console.developers.google.com to set up an OAuth client ID
and secret. See [Google’s documentation](https://developers.google.com/identity/protocols/oauth2)
on how to create OAUth 2.0 client credentials.
The `Authorized JavaScript origins` should be set to to your hub’s public
address while `Authorized redirect URIs` should be set to the same but
followed by `/hub/oauth_callback`.

Then, add the following to your `jupyterhub_config.py` file:

```python
from oauthenticator.google import GoogleOAuthenticator
c.JupyterHub.authenticator_class = GoogleOAuthenticator
```

By default, any domain is allowed to login but you can restrict
authorized domains with a list (recommended):

```python
c.GoogleOAuthenticator.hosted_domain = ['mycollege.edu', 'mycompany.com']
```

You can customize the sign in button text (optional):

```python
c.GoogleOAuthenticator.login_service = 'My College'
```

```{note}
Additional notes, that seem quite outdated at the time of writing May 2022,
are available about authorizing users part of specific Google Groups are
[available here](google:groups). Contributions to update these
and re-verify this functionality are most welcome.
```
