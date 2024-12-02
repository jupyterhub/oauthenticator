# Refreshing user authentication

JupyterHub has a mechanism called [`refresh_user`](inv:jupyterhub:py:method#jupyterhub.auth.Authenticator.refresh_user) that is meant to _refresh_ information from the Authentication provider periodically.
This allows you to make sure things like group membership or other authorization info is up-to-date.
In OAuth, this can also mean making sure the access token has not expired.
This is particularly useful in deployments where an access token from the oauth provider is passed to the Server environment,
e.g. for access to data sources, git repos, etc..
You don't want to start a server passing an expired token, do you?

OAuthenticator 17.2 introduces support in all OAuthenticator classes for refreshing user info via this mechanism, including requesting new access tokens if a `refresh_token` is available from the oauth provider.

```{seealso}
- [More about refresh tokens](https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/)
```

How it works:

- Every time a user takes an authenticated action with JupyterHub
  (making an API request, launching a server, visiting a page, etc.),
  JupyterHub checks when the last time auth info was loaded from the provider.
- If the auth info is older than [Authenticator.auth_refresh_age](inv:jupyterhub:py:attribute#jupyterhub.auth.Authenticator.auth_refresh_age), the auth info is refreshed,
  i.e. the user model is retrieved anew with the current access token, and any changes are applied (usually there aren't any).
  The default value for this age is five minutes.
  You can consider it an expiring cache of the information we retrieved from the OAuth provider.
- If the access token is expired and a refresh token is a available,
  a new access token is retrieved via the [refresh_token grant](https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/)
- If no auth info is retrievable (e.g. no refresh token and access token is expired or both are expired or revoked),
  then the user must login again before they are able to take actions in JupyterHub
  because at this point their authorization state is unknown and could no longer be valid.

There is also an option [Authenticator.refresh_pre_spawn](inv:jupyterhub:py:attribute#jupyterhub.auth.Authenticator.refresh_pre_spawn) which can be enabled:

```python
c.Authenticator.refresh_pre_spawn = True
```

to ensure auth is up-to-date before launching a server.
This is most useful when the server is being passed an access token
because it ensures the token is valid when the server starts.

## Refreshing tokens from user sessions

If your user sessions use access tokens from your oauth provider and those tokens may expire during user sessions,
you can rely on this mechanism to get fresh access tokens from JupyterHub.

The first step is to grant the _server_ token access to read auth state for its owner.
Users do not have permission to read their own auth state by default,
but `auth_state` is where the `access_token` is stored.
We need to grant the `admin:auth_state!user` scope to both the `user` and `server` roles,
so that requests with `$JUPYTERHUB_API_TOKEN` will have permission to read the access token:

```python
c.JupyterHub.load_roles = [
    {
        "name": "user",
        "scopes": [
            "self",
            "admin:auth_state!user",
        ],
    },
    {
        "name": "server",
        "scopes": [
            "users:activity!user",
            "access:servers!server",
            "admin:auth_state!user",
        ],
    },
]
```

We then also need to make sure "auth state" is enabled
(it is enabled by default in the jupyterhub helm chart):

```python
c.Authenticator.enable_auth_state = True
# also set $JUPYTERHUB_CRYPT_KEY env to 32-byte string
# e.g. with `openssl rand -hex 32`
```

At this point:

1. When a user logs in, the OAuth user info and access token are encrypted and persisted in the Hub database.
2. When the server token requests the user model at `/hub/api/user`, an `auth_state` field will be present, containing the current auth state.
3. Further, when accessing `/hub/api/user` the `refresh_user` logic is triggered if `auth_refresh_age` has elapsed since the last refresh.

This means that you can access `/hub/api/user` with `$JUPYTERHUB_API_TOKEN` and it will **always return a valid access token**,
even if the currently stored token has expired when the request is made.

To retrieve the access token, make a request to `${JUPYTERHUB_API_URL}/hub/user` with `${JUPYTERHUB_API_TOKEN}`, e.g. from Python:

```python
import os
import requests

hub_token = os.environ["JUPYTERHUB_API_TOKEN"]
hub_api_url = os.environ["JUPYTERHUB_API_URL"]
user_url = hub_api_url + "/user"

r = requests.get(user_url, headers={"Authorization": f"Bearer {hub_token}"})
user = r.json()
access_token = user["auth_state"]["access_token"]
```

The `access_token` retrieved here should always be a fresh, valid access token,
and will be updated by the `refresh_user` functionality when it expires.

```{note}
If you get a KeyError on `auth_state`, it means the request does not have the `admin:auth_state!user` permission.
Check your `load_roles` config, relaunch the user server, and try again.
```

## Disabling refresh

The time-based refresh_user trigger is enabled by default in JupyterHub if `auth_state` is enabled.
It can be disabled by setting:

```python
c.Authenticator.auth_refresh_age = 0
```

in which case the new `refresh_user` method will not be called.
This is equivalent to the behavior of OAuthenticator 17.1 and earlier,
where the default `refresh_user` was called, but did nothing.
