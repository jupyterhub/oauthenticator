# GitHub-specific scopes

The following [GitHub scopes](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-scopes-for-oauth-apps/)
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

To use this expanded user information, you will need to subclass your
current spawner and modify the subclass to read these fields from
`auth_state` and then use this information to provision your Notebook or
Lab user.

## Restricting access

### Organizations

If you would like to restrict access to members of specific GitHub organizations
you can pass a list of organization names to `allowed_organizations`.

For example, the below will ensure that only members of `org_a` or
`org_b` will be authorized to access.

`c.GitHubOAuthenticator.allowed_organizations = ["org_a", "org_b"]`

### Teams

It is also possible to restrict access to members of specific teams within
organizations using the syntax: `<organization>:<team-name>`.

For example, the below will only allow members of `org_a`, or
`team_1` in `org_b` access. Members of `org_b` but not `team_1` will be
unauthorized to access.

`c.GitHubOAuthenticator.allowed_organizations = ["org_a", "org_b:team_1"]`

### Notes

- Restricting access by either organization or team requires the `read:org`
  scope
- Ensure you use the organization/team name as it appears in the GitHub url
  - E.g. Use `jupyter` instead of `Project Jupyter`
