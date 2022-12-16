(front-page)=

# OAuthenticator

OAuthenticator provides plugins for JupyterHub to use common OAuth providers,
as well as base classes for writing your own Authenticators with any OAuth 2.0 provider.

```{warning}
The OAuthenticator package is not accepting new OAuth providers,
but you can write your own OAuthenticator by `oauthenticator.oauth2.OAuthenticator`
```

## Get Started Guide
These sections help you get started installing, using and working with the `oauthenticator` project.
through step-by-step tutorials.

```{toctree}
:maxdepth: 1
:caption: Get Started Guide

tutorials/install
tutorials/general-setup
tutorials/provider-specific-setup
```

```{toctree}
:maxdepth: 2
:caption: Extending authenticators

extending
```

```{toctree}
:maxdepth: 2
:caption: Writing your own OAuthenticator

writing-an-oauthenticator
```

```{toctree}
:maxdepth: 2
:caption: API Reference

api/index
changelog
```

```{toctree}
:maxdepth: 2
:caption: Migrations Guide

migrations
```
