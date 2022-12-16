(tutorials:provider-specific-setup)=

# OAuth provider specific setup

OAuthenticator provides a generic implementation called `GenericOAuthenticator`
that can be used with **any OAuth2 identity provider**,
but also a few dedicated authentication classes.

Below, there is a list with provider specific setup instructions.

```{warning}
There are other OAuthenticators available in this repository,
but unfortunately currently there are some that don't have their specific setups documented.
```

```{toctree}
:maxdepth: 1
:caption: OAuth providers specific setup guides

providers/awscognito.md
providers/azuread.md
providers/github.md
providers/gitlab.md
providers/globus.md
providers/google.md
providers/okpy.md
providers/openshift.md
providers/generic.md
```

## Examples

For an example docker image using OAuthenticator, see the
[examples](https://github.com/jupyterhub/oauthenticator/tree/HEAD/examples) directory.

[Another example](https://github.com/jupyterhub/dockerspawner/tree/HEAD/examples/oauth)
is using GitHub OAuth to spawn each user’s server in a separate docker
container.
