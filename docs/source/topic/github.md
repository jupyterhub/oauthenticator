(topic:github:specific-scopes)=

# GitHub-specific scopes

The following [GitHub scopes](https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps)
may be suitable for certain use cases:

`read:org` grants access to the users' organizations. This is handy if
you want to use GitHub organizations in your backend environment as Unix
groups for collaboration purposes. Having globally consistent UIDs
(from the GitHub ID) and GIDs (from the organization IDs) makes access
permissions on shared storage much easier.

`public_repo` allows "trusted users" read and write privileges for
public repositories. If you want to automatically provision `git`
pushes to GitHub, you can accomplish this by passing a token with this
scope to your Lab or classic Notebook instance.

`repo` does the same for private repositories too.

`user:email` allows the authenticator to determine email addresses even
if they are marked private. Having access to email addresses, in
conjunction with read/write repository access, allows preconfiguring the
user's git configuration for GitHub pushes without any required action
by the user.

The additional fields exposed by expanded scope are all stored in the
authenticator's `auth_state` structure, so you'll need to enable
`auth_state` and install the Python `cryptography` package to be able to
use these.

We currently use the following fields:

- `id` is an integer set to the GitHub account ID.
- `login` is the GitHub username
- `name` is the full name GitHub knows the user by.
- `email` is the publicly visible email address (if any) for the user.
- `access_token` is the token used to authenticate to GitHub.
- `teams` is list of teams the user is part of, fetched only if
  `populate_teams_in_auth_state` option is set to `True` on `GitHubOAuthenticator`.
  The `read:org` scope is also required for this to work.

To use this expanded user information, you will need to subclass your
current spawner and modify the subclass to read these fields from
`auth_state` and then use this information to provision your Notebook or
Lab user.
