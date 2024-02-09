(allowing)=

# Allowing access to your JupyterHub

OAuthenticator is about deferring **authentication** to an external source,
assuming your users all have accounts _somewhere_.
But many of these sources (e.g. Google, GitHub) have _lots_ of users, and you don't want _all_ of them to be able to use your hub.
This is where **authorization** comes in.

In OAuthenticator, authorization is represented via configuration options that start with `allow` or `block`.

There are also lots of OAuth providers, and as a result, lots of ways to tell OAuthenticator who should be allowed to access your hub.

## Default behavior: nobody is allowed!

Assuming you have provided no `allow` configuration, the default behavior of OAuthenticator (starting with version 16) is to not allow any users unless explicitly authorized via _some_ `allow` configuration.
If you want anyone to be able to use your hub, you must specify at least one `allow` configuration.

```{versionchanged} 16
Prior to OAuthenticator 16, `allow_all` was _implied_ if `allowed_users` was not specified.
Starting from 16, `allow_all` can only be enabled explicitly.
```

## Allowing access

There are several `allow_` configuration options, to grant access to users according to different rules.

When you have only one `allow` configuration, the behavior is generally unambiguous: anyone allowed by the rule can login to the Hub, while anyone not explicitly allowed cannot login.
However, once you start adding additional `allow` configuration, there is some ambiguity in how multiple rules are combined.

```{important}
Additional allow rules **can only grant access**, meaning they only _expand_ who has access to your hub.
Adding an `allow` rule cannot prevent access granted by another `allow` rule.
To block access, use `block` configuration.
```

That is, if a user is granted access by _any_ `allow` configuration, they are allowed.
An allow rule cannot _exclude_ access granted by another `allow` rule.

An example:

```python
c.GitHubOAuthenticator.allowed_users = {"mensah", "art"}
c.GitHubOAuthenticator.allowed_organizations = {"preservation"}
```

means that the users `mensah` and `art` are allowed, _and_ any member of the `preservation` organization are allowed.
Any user that doesn't meet any of the allow rules will not be allowed.

| user  | allowed | reason                                                  |
| ----- | ------- | ------------------------------------------------------- |
| art   | True    | in `allowed_users`                                      |
| amena | True    | member of `preservation`                                |
| tlacy | False   | not in `allowed_users` and not member of `preservation` |

### `allow_all`

The first and simplest way to allow access is to any user who can successfully authenticate:

```python
c.OAuthenticator.allow_all = True
```

This is appropriate when you use an authentication provider (e.g. an institutional single-sign-on provider), where everyone who has an account in the provider should have access to your Hub.
It may also be appropriate for unadvertised short-lived hubs, e.g. dedicated hubs for workshops that will be shutdown after a day, where you may decide it is acceptable to allow anyone who finds your hub to login.

If `allow_all` is enabled, no other `allow` configuration will have any effect.

```{seealso}
Configuration documentation for {attr}`.OAuthenticator.allow_all`
```

### `allowed_users`

This is top-level JupyterHub configuration, shared by all Authenticators.
This specifies a list of users that are allowed by name.
This is the simplest authorization mechanism when you have a small group of users whose usernames you know:

```python
c.OAuthenticator.allowed_users = {"mensah", "ratthi"}
```

If this is your only configuration, only these users will be allowed, no others.

Note that any additional usernames in the deprecated `admin_users` configuration will also be added to the `allowed_users` set.

```{seealso}
Configuration documentation for {attr}`.OAuthenticator.allowed_users`
```

### `allow_existing_users`

JupyterHub can allow you to add and remove users while the Hub is running via the admin page.
If you add or remove users this way, they will be added to the JupyterHub database, but their ability to login will not be affected unless they are also granted access via an `allow` rule.

To enable managing users via the admin panel, set

```python
c.OAuthenticator.allow_existing_users = True
```

```{warning}
Enabling `allow_existing_users` means that _removing_ users from any explicit allow mechanisms will no longer revoke their access.
Once the user has been added to the database, the only way to revoke their access to the hub is to remove the user from JupyterHub entirely, via the admin page.
```

```{seealso}
Configuration documentation for {attr}`.OAuthenticator.allow_existing_users`
```

### provider-specific rules

Each OAuthenticator provider may have its own provider-specific rules to allow groups of users access, such as:

- {attr}`.CILogonOAuthenticator.allowed_idps`
- {attr}`.GitHubOAuthenticator.allowed_organizations`
- {attr}`.GitLabOAuthenticator.allowed_gitlab_groups`
- {attr}`.GlobusOAuthenticator.allowed_globus_groups`
- {attr}`.GoogleOAuthenticator.allowed_google_groups`

## Blocking Access

It's possible that you want to limit who has access to your Hub to less than all of the users granted access by your `allow` configuration.
`block` configuration always has higher priority than `allow` configuration, so if a user is explicitly allowed _and_ explicitly blocked, they will not be able to login.

The only `block` configuration is the base Authenticators `block_users`,
a set of usernames that will not be allowed to login.

### Revoking previously-allowed access

Any users who have logged in previously will be present in the JupyterHub database.
Removing a user's login permissions (e.g. removing them from a GitLab project when using {attr}`.GitLabOAuthenticator.project_ids`) only prevents future logins;
it does not remove the user from the JupyterHub database.
This means that:

1. any API tokens, that the user still has access to will continue to be valid, and can continue to be used, and
2. any still-valid browser sessions will continue to be logged in.

```{important}
To fully remove a user's access to JupyterHub,
their login permission must be revoked _and_ their User fully deleted from the Hub,
e.g. via the admin page.
```
