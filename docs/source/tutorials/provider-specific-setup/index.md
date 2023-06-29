(tutorials:provider-specific-setup)=

# Identity provider specific setup

This project provides a general purpose authenticator class called
`GenericOAuthenticator` that can be used with _any OAuth2 identity provider_,
but it also provides a few identity provider specialized authenticator classes.

A specialized authenticator class can reduce the required configuration and
support custom ways of allowing users. As an example, the `GitHubOAuthenticator`
can allow users part of specific GitHub organizations.

```{toctree}
:maxdepth: 1
:caption: OAuth providers specific setup guides

providers/auth0.md
providers/azuread.md
providers/bitbucket.md
providers/cilogon.md
providers/github.md
providers/gitlab.md
providers/globus.md
providers/google.md
providers/mediawiki.md
providers/okpy.md
providers/openshift.md
providers/generic.md
```
