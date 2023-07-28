# Globus Setup

You need to have an Globus OAuth application registered ahead of time, see
Globus's official documentation about [registering an app].

[registering an app]: https://docs.globus.org/api/auth/developer-guide/#register-app

When you register the application, make sure _Native App_ is unchecked and that the callback URL looks like `https://[your-domain]/hub/oauth_callback`.

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "okpy"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
```

You are all set by this point! Be sure to check below for tweaking
settings related to User Identity, Transfer, and additional security.

## User Identity

You can restrict users to a specific identity provider with config like:

```python
c.GlobusOAuthenticator.identity_provider = "uchicago.edu"
```

If a user has _Linked Identity_ such as `malcolm@universityofindependence.edu`,
go to your [App Developer page](https://developers.globus.org) and set _Required
Identity Provider_ for your app to `<Your University>`.

```{warning}
Don't set 'Required Identity Provider' on pre-existing apps!

Previous user login consents will be tied to the identity users initially used
to login, and will continue to be tied to that identity after changing this
setting. Create a new Globus App with your preferred 'Required Identity Provider'
to avoid this problem.
```

## Username from Email Address

By default, the JupyterHub `username` will be taken from the OIDC
`preferred_username` claim. In many cases, this is the same as the email
address. However, some identity providers use an opaque string, e.g.,
`046f34a240f0615e01420b3ff4350922@ucsd.edu`. You may set
`username_from_email = True` to get it from the user's email address. Setting
this will automatically add `email` to the list of scopes. When
`identity_provider` is set, the email address domain must still match the
identity provider domain.

## Globus Scopes and Transfer

The following shows how to get tokens into user Notebooks. You can see how users
use tokens [here](https://github.com/globus/globus-jupyter-notebooks/blob/HEAD/JupyterHub_Integration.ipynb).
If you want a demonstration, you can visit [The Jupyter Globus Demo Server](https://jupyter.demo.globus.org/hub/login).

The default server configuration will automatically setup user environments
with tokens, allowing them to start up python notebooks and initiate
Globus Transfers. If you want to transfer data onto your JupyterHub
server, it’s suggested you install [Globus Connect Server](https://docs.globus.org/globus-connect-server/v5/#install_section),
and add the `globus_local_endpoint` uuid below.
If you want to change other behavior, you can modify the defaults below:

```python
# Allow saving user tokens to the database
# - requires JUPYTERHUB_CRYPT_KEY to be set, see
#   https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#authentication-state
c.GlobusOAuthenticator.enable_auth_state = True

# Default scopes are below if unspecified. Add a custom transfer server if you have one.
c.GlobusOAuthenticator.scope = ['openid', 'profile', 'urn:globus:auth:scope:transfer.api.globus.org:all']
# Default tokens excluded from being passed into the spawner environment
c.GlobusOAuthenticator.exclude_tokens = ['auth.globus.org']
# If the JupyterHub server is an endpoint, for convenience the endpoint id can be
# set here. It will show up in the notebook kernel for all users as 'GLOBUS_LOCAL_ENDPOINT'.
c.GlobusOAuthenticator.globus_local_endpoint = '<Your Local JupyterHub UUID>'
# Set a custom logout URL for your identity provider
c.GlobusOAuthenticator.logout_redirect_url = 'https://globus.org/logout'
# For added security, revoke all service tokens when users logout. (Note: users must start
# a new server to get fresh tokens, logging out does not shut it down by default)
c.GlobusOAuthenticator.revoke_tokens_on_logout = False
```

If you only want to authenticate users with their Globus IDs but don’t
want to allow them to do transfers, you can remove
`urn:globus:auth:scope:transfer.api.globus.org:all`. Conversely, you
can add an additional scope for another transfer server if you wish.

Use `c.GlobusOAuthenticator.exclude` to prevent tokens from being
passed into a users environment. By default, `auth.globus.org` is
excluded but `transfer.api.globus.org` is allowed. If you want to
disable transfers, modify `c.GlobusOAuthenticator.scope` instead of
`c.GlobusOAuthenticator.exclude` to avoid procuring unnecessary
tokens.

## Group Management

Allowed and admin users can be managed through [Globus Groups](https://docs.globus.org/how-to/managing-groups/).
Globus Groups are identified using a UUID and multiple groups can be used for
each of these configuration settings. The lets JuptyerHub admininstators
choose whether to manage memership in the groups, or use groups
managed by others. For example, researchers could manage groups of
collaborators. Each of these settings can contain multiple Globus
Groups.

```python
# Groups of allowed users
c.GlobusOAuthenticator.allowed_globus_groups = {
    'd11abe71-5132-4c04-a4ad-50926885dc8c',
    '21c6bc5d-fc12-4f60-b999-76766cd596c2',
}
# Admin users
c.GlobusOAuthenticator.admin_globus_groups = {'3f1f85c4-f084-4173-9efb-7c7e0b44291a'}
```

When any of these are set, the Globus Groups API scope will be included in the
default list of scopes. When `c.GlobusOAuthenticator.admin_globus_groups` is
set, only members of those groups will be JupyterHub admins.

To block users, the [`c.Authenticator.blocked_users`](https://jupyterhub.readthedocs.io/en/stable/reference/api/auth.html#jupyterhub.auth.Authenticator.blocked_users)
configuration can be used. Or, users can be removed from the allowed
Globus Groups, and the Group set require approval, so the user cannot
rejoin it without action by an administrator.
