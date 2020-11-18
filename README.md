# OAuth + JupyterHub Authenticator = OAuthenticator :heart:

[![Documentation build status](https://img.shields.io/readthedocs/oauthenticator?logo=read-the-docs)](https://oauthenticator.readthedocs.org/en/latest)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/jupyterhub/oauthenticator/Tests?logo=github)](https://github.com/jupyterhub/oauthenticator/actions)
[![Latest PyPI version](https://img.shields.io/pypi/v/oauthenticator?logo=pypi)](https://pypi.python.org/pypi/oauthenticator)
[![Latest conda-forge version](https://img.shields.io/conda/vn/conda-forge/oauthenticator?logo=conda-forge)](https://anaconda.org/conda-forge/oauthenticator)
[![GitHub](https://img.shields.io/badge/issue_tracking-github-blue?logo=github)](https://github.com/jupyterhub/oauthenticator/issues)
[![Discourse](https://img.shields.io/badge/help_forum-discourse-blue?logo=discourse)](https://discourse.jupyter.org/c/jupyterhub)
[![Gitter](https://img.shields.io/badge/social_chat-gitter-blue?logo=gitter)](https://gitter.im/jupyterhub/jupyterhub)

[OAuth](https://en.wikipedia.org/wiki/OAuth) is a token based login mechanism that doesn't rely on a username and password mapping.
In order to use this login mechanism with JupyerHub the login handlers need to be overridden.
OAuthenticator overrides these handlers for the common OAuth2 identity providers allowing them to be
plugged in and used with JupyterHub.

The following authentication services are supported through their own authenticator: [Auth0](oauthenticator/auth0.py),
[Azure AD](oauthenticator/azuread.py), [Bitbucket](oauthenticator/bitbucket.py), [CILogon](oauthenticator/cilogon.py),
[GitHub](oauthenticator/github.py), [GitLab](oauthenticator/gitlab.py), [Globus](oauthenticator/globus.py),
[Google](oauthenticator/google.py), [MediaWiki](oauthenticator/mediawiki.py), [Okpy](oauthenticator/okpy.py),
[OpenShift](oauthenticator/openshift.py).

There is also a [GenericAuthenticator](oauthenticator/generic.py)
that can be configured with any OAuth 2.0 identity provider or can be used
to create a new authenticator class when additional customization is needed.

## Installation
The installation guide can be found in the [docs](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#installation).

The docs also provide example setups for different OAuth2 identity providers:

* [General Setup](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#general-setup)
* [Azure AD](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#azure-ad-setup)
* [GitHub](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#github-setup)
* [GitLab](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#gitlab-setup)
* [Google](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#google-setup)
* [OpenShift](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#openshift-setup)
* [Okpy](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#okpyauthenticator)
* [Globus](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#globus-setup)
* [Moodle](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#moodle-setup)
* [Yandex](https://oauthenticator.readthedocs.io/en/latest/getting-started.html#yandex-setup)

## Running tests
To run the tests locally:

```
$ pip install --upgrade --pre -r test-requirements.txt
```

```
$ pytest -v ./oauthenticator/tests/
```
Or you run a specific test file with:

```
$ pytest -v ./oauthenticator/tests/<test-file-name>
```
