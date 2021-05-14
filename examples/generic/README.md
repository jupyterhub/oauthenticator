# OAuthenticator

Example of `GenericOAuthenticator` using an IDM - identity and access management - solution (keycloak).

## Keycloak

`Keycloak` is an open source IDM solution.
In `Keycloak` one can map user roles or policies from a source,
e.g. Active Directory, configure the client scopes to include this information
within the id token and access token as claims.

This allows applications to obtain information that can be used to authorize
access to functionality within that application.

This functionality is supported by all major IDM tools, e.g. Auth0, Okta etc.

## `GenericOAuthenticator` configuration

The `GenericOAuthenticator` can be configured to provide authorization as well.

### Example configuration

```python
from oauthenticator.generic import GenericOAuthenticator

c.Application.log_level = 'DEBUG'

c.JupyterHub.authenticator_class = GenericOAuthenticator
c.GenericOAuthenticator.client_id = 'client-id'
c.GenericOAuthenticator.client_secret = 'some-long-secret-hash'
c.GenericOAuthenticator.token_url = 'https://accounts.example.com/auth/realms/example/protocol/openid-connect/token'
c.GenericOAuthenticator.userdata_url = 'https://accounts.example.com/auth/realms/example/protocol/openid-connect/userinfo'
c.GenericOAuthenticator.userdata_params = {'state': 'state'}
# the next can be a callable as well, e.g.: lambda t: t.get('complex').get('structure').get('username')
c.GenericOAuthenticator.username_key = 'preferred_username'
c.GenericOAuthenticator.login_service = 'EXAMPLE'
c.GenericOAuthenticator.scope = ['openid', 'profile']
```

### Example configuration with authorization enabled

In order to enable authorization, one needs to specify the at least one value for `allowed_groups`:

```python
from oauthenticator.generic import GenericOAuthenticator

c.Application.log_level = 'DEBUG'

c.JupyterHub.authenticator_class = GenericOAuthenticator
c.GenericOAuthenticator.client_id = 'client-id'
c.GenericOAuthenticator.client_secret = 'some-long-secret-hash'
c.GenericOAuthenticator.token_url = 'https://accounts.example.com/auth/realms/example/protocol/openid-connect/token'
c.GenericOAuthenticator.userdata_url = 'https://accounts.example.com/auth/realms/example/protocol/openid-connect/userinfo'
c.GenericOAuthenticator.userdata_params = {'state': 'state'}
# the next can be a callable as well, e.g.: lambda t: t.get('complex').get('structure').get('username')
c.GenericOAuthenticator.username_key = 'preferred_username'
c.GenericOAuthenticator.login_service = 'EXAMPLE'
# The next settings are responsible for enabling authorization
# the next can be a callable as well, e.g.: lambda t: t.get('complex').get('structure').get('roles')
c.GenericOAuthenticator.claim_groups_key = 'roles'
# users with `staff` role will be allowed
c.GenericOAuthenticator.allowed_groups = ['staff']
# users with `administrator` role will be marked as admin
c.GenericOAuthenticator.admin_groups = ['administrator']
c.GenericOAuthenticator.scope = ['openid', 'profile', 'roles']
```
