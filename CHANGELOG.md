# Changes in oauthenticator


For detailed changes from the prior release, click on the version number, and
its link will bring up a GitHub listing of changes. Use `git log` on the
command line for details.


## [Unreleased]

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


[Unreleased]: https://github.com/jupyterhub/oauthenticator/compare/0.6.1...HEAD
[0.6.1]: https://github.com/jupyterhub/oauthenticator/compare/0.6.0...0.6.1
[0.6.0]:https://github.com/jupyterhub/oauthenticator/compare/0.5.1...0.6.0
[0.5.1]:https://github.com/jupyterhub/oauthenticator/compare/0.5.0...0.5.1
[0.5.0]:https://github.com/jupyterhub/oauthenticator/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/jupyterhub/oauthenticator/compare/0.4.0...0.4.1
[0.4.0]:https://github.com/jupyterhub/oauthenticator/compare/0.3.0...0.4.0
[0.3]: https://github.com/jupyterhub/oauthenticator/compare/0.2.0...0.3.0
[0.2]: https://github.com/jupyterhub/oauthenticator/compare/0.1.0...0.2.0