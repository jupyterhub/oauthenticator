# Changes in oauthenticator

## 0.4

### 0.4.1

- Fix typo preventing Google OAuth from working in 0.4.0

### 0.4.0

- Enable username normalization (for mixed-case names on GitHub, requires JupyterHub 0.5).
  This removes `GitHubOAuthenticator.username_map` introduced in 0.3,
  because the base Authenticator has `.username_map` as of 0.5.

## 0.3

- Add Google authenticator
- Allow specifying OAuth scope
- Add `GitHubOAuthenticator.username_map` for mapping GitHub usernames to system usernames.

## 0.2

- Add mediawiki authenticator

## 0.1

- First release
