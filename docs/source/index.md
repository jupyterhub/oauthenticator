(front-page)=

# OAuthenticator

OAuthenticator provides plugins for JupyterHub to use common OAuth providers,
as well as base classes for writing your own Authenticators with any OAuth 2.0 provider.

```{warning}
The OAuthenticator package is not accepting new OAuth providers,
but you can write your own OAuthenticator by `oauthenticator.oauth2.OAuthenticator`
```

## Get Started Guide
These section helps you get started installing, using and working with the `oauthenticator` project.
through step-by-step tutorials.

```{toctree}
:maxdepth: 1
:caption: Get Started Guide

tutorials/install
tutorials/general-setup
tutorials/provider-specific-setup
```

## How-to guides

How-To guides answer the question 'How do I...?' for some relevant topics.}
Things like how to write your own `oauthenticator` or how to migrate to a newer `oauthenticator` version.

```{toctree}
:maxdepth: 1
:caption: How-to guides

how-to/writing-an-oauthenticator
how-to/migrations
```

## Topic guides

Topic guides go more in-depth on a particular topic.

```{toctree}
:maxdepth: 2
:caption: Writing your own OAuthenticator

topic/extending
```

```{toctree}
:maxdepth: 2
:caption: API Reference

api/index
changelog
```
