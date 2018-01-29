# Changes in oauthenticator


For detailed changes from the prior release, click on the version number, and
its link will bring up a GitHub listing of changes. Use `git log` on the
command line for details.


## [Unreleased]

## 0.7

### [0.7.2] - 2017-10-27

- Fix CILogon OAuth 2 implementation. ePPN claim is used for default username
  (typically institutional email).
  `CILogonOAuthenticator.username_claim` can be used to change which field is
  used for JupyterHub usernames.
- `GenericOAuthenticator.login_service` is now configurable.
- default to GitLab API version 4 and allow v3 via GITLAB_API_VERSION=3 environment variable.
- Add `GlobusOAuthenticator.revoke_tokens_on_logout` and
  `GlobusOAuthenticator.logout_redirect_url` config for further clearing
  of credentials on JupyterHub logout.

### [0.7.1] - 2017-10-04

- fix regression in 0.7.0 preventing authentication via providers other than GitHub, MediaWiki

### [0.7.0] - 2017-10-02

0.7.0 adds significant new functionality to all authenticators.

- CILogon now uses OAuth 2 instead of OAuth 1, to be more consistent with the rest.
- All OAuthenticators support `auth_state` when used with JupyterHub 0.8.
  In every case, the auth_state is a dict with two keys: `access_token` and the
  user-info reply identifying the user.
  For instance, GitHubOAuthenticator auth_state looks like:

  ```python
  {
    'acces_token': 'abc123',
    'github_user': {
      'username': 'fake-user',
      'email': 'fake@email.com',
      ...
    }
  }
  ```

  auth_state can be passed to Spawners by defining a `.pre_spawn_start` method.
  See [examples/auth_state](examples/auth_state) for an example.
- All OAuthenticators have a `.scope` trait, which is a list of string scopes to request.
  See your OAuth provider's documentation for what scopes you may want.
  This is useful in conjunction with `auth_state`, which may be used to pass access tokens
  to Spawners via environment variables. `.scope` can control what permissions those
  tokens will have. In general, OAuthenticator default scopes should only have read-only access to identify users.
- GITHUB_HTTP environment variable can be used to talk to HTTP-only GitHub Enterprise deployments.

## 0.6

### [0.6.1] - 2017-08-11

0.6.1 has bugfixes for new behaviors in 0.6.0

- Use `.login_url` and `next_url` from JupyterHub if defined (JupyterHub 0.8)
- Fix empty login_url where final login redirect could be omitted
- Fix mediawiki authenticator, which broke in 0.6.0
- Encode state as base64 instead of JSON, for easier passing in URLs

### [0.6.0] - 2017-07-25

- Support for changes in upcoming JupyterHub 0.8
- Refactor to share more code across providers
- Deprecated GITHUB_CLIENT_ID and other provider-specific environment variables
  for common options.
  All OAuthenticators support the same OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, and OAUTH_CALLBACK_URL environment variables.
- New authenticators:
  - auth0
  - globus
  - okpy
  - openshift
  - generic - a generic implementation that can work with any OAuth2 provider


## 0.5

### [0.5.1] - 2016-10-05

- Fixes in BitbucketOAuthenticator.check_whitelist

### [0.5.0] - 2016-09-02

- Add GitLabOAuthenticator

## 0.4

### [0.4.1] - 2016-05-18

- Fix typo preventing Google OAuth from working in 0.4.0

### [0.4.0] - 2016-05-11

- Enable username normalization (for mixed-case names on GitHub, requires JupyterHub 0.5).
  This removes `GitHubOAuthenticator.username_map` introduced in 0.3,
  because the oauth2 Authenticator has `.username_map` as of 0.5.

## [0.3] - 2016-04-20

- Add Google authenticator
- Allow specifying OAuth scope
- Add `GitHubOAuthenticator.username_map` for mapping GitHub usernames to system usernames.

## [0.2] - 2016-01-04

- Add mediawiki authenticator

## 0.1 - 2015-12-22

- First release

[Unreleased]: https://github.com/jupyterhub/oauthenticator/compare/0.7.2...HEAD
[0.7.2]: https://github.com/jupyterhub/oauthenticator/compare/0.7.1...0.7.2
[0.7.1]: https://github.com/jupyterhub/oauthenticator/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/jupyterhub/oauthenticator/compare/0.6.1...0.7.0
[0.6.1]: https://github.com/jupyterhub/oauthenticator/compare/0.6.0...0.6.1
[0.6.0]:https://github.com/jupyterhub/oauthenticator/compare/0.5.1...0.6.0
[0.5.1]:https://github.com/jupyterhub/oauthenticator/compare/0.5.0...0.5.1
[0.5.0]:https://github.com/jupyterhub/oauthenticator/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/jupyterhub/oauthenticator/compare/0.4.0...0.4.1
[0.4.0]:https://github.com/jupyterhub/oauthenticator/compare/0.3.0...0.4.0
[0.3]: https://github.com/jupyterhub/oauthenticator/compare/0.2.0...0.3.0
[0.2]: https://github.com/jupyterhub/oauthenticator/compare/0.1.0...0.2.0
