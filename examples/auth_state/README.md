# Providing GitHub API access via auth_state

JupyterHub 0.8 adds the ability to persist authentication state.
OAuthenticator 0.7 adds support for auth_state to all Authenticators.
Additional configuration is required in order to specify how and what information should be passed to the users' containers from this information.

Included is an example `jupyterhub_config.py` for specifying some of these options
and an example notebook that can be run in the user environment
to demonstrate uploading a gist.

The `jupyterhub_config.py` does:

- enable GitHub authentication
- enable persisted auth state
- request write-access to gists via `GitHubAuthenticator.scope`
- pass the GitHub API token and user info via `GITHUB_` environment variables
- launch users with docker

## Running the example

1. register GitHub oauth application
2. fill out client secret and client id in `./env`
3. `source ./env` to get github environment variables
4. `jupyterhub`
