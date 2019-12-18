# GitLab-specific scopes

Scopes may be added to the GitLab OAuthenticator by overriding the
scope list, like so:

    c.GitLabOAuthenticator.scope = ['read_user']


The following scopes are implemented in GitLab 11.x:

`api`: Grants complete read/write access to the API, including all
groups and projects. If no other scope is requested, this is the default.
This is a *very* powerful set of permissions, it is recommended to limit
the scope of authentication to something other than API.

`read_user`: Grants read-only access to the authenticated user's
profile through the /user API endpoint, which includes username,
public email, and full name. Also grants access to read-only
API endpoints under /users.

`read_repository`: Grants read-only access to repositories on
private projects using Git-over-HTTP (not using the API).

`write_repository`: Grants read-write access to repositories
on private projects using Git-over-HTTP (not using the API).

`read_registry`: Grants read-only access to container registry
images on private projects.

`sudo`: Grants permission to perform API actions as any user
in the system, when authenticated as an admin user.

`openid`: Grants permission to authenticate with GitLab using
OpenID Connect. Also gives read-only access to the user's
profile and group memberships.

`profile`: Grants read-only access to the user's profile data
using OpenID Connect.

`email`: Grants read-only access to the user's primary email
address using OpenID Connect.
