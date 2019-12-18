# [OAuthenticator](https://github.com/jupyterhub/oauthenticator)

[![PyPI](https://img.shields.io/pypi/v/oauthenticator.svg)](https://pypi.python.org/pypi/oauthenticator)
[![Build Status](https://travis-ci.org/jupyterhub/oauthenticator.svg?branch=master)](https://travis-ci.org/jupyterhub/oauthenticator)

OAuth + JupyterHub Authenticator = OAuthenticator

OAuthenticator currently supports the following authentication services:

- [Auth0](oauthenticator/auth0.py)
- [Azure AD](#azure-ad-setup)
- [Azure AD B2C](#azure-ad-b2c-setup)
- [Bitbucket](oauthenticator/bitbucket.py)
- [CILogon](oauthenticator/cilogon.py)
- [GitHub](#github-setup)
- [GitLab](#gitlab-setup)
- [Globus](#globus-setup)
- [Google](#google-setup)
- [MediaWiki](oauthenticator/mediawiki.py)
- [Moodle](#moodle-setup)
- [Okpy](#okpyauthenticator)
- [OpenShift](#openshift-setup)

A [generic implementation](oauthenticator/generic.py), which you can use with
any provider, is also available.
