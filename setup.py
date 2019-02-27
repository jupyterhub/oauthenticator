#!/usr/bin/env python
# coding: utf-8

# Copyright (c) Juptyer Development Team.
# Distributed under the terms of the Modified BSD License.

#-----------------------------------------------------------------------------
# Minimal Python version sanity check (from IPython/Jupyterhub)
#-----------------------------------------------------------------------------
from __future__ import print_function

import os
import sys

v = sys.version_info
if v[:2] < (3,3):
    error = "ERROR: Jupyter Hub requires Python version 3.3 or above."
    print(error, file=sys.stderr)
    sys.exit(1)


if os.name in ('nt', 'dos'):
    error = "ERROR: Windows is not supported"
    print(error, file=sys.stderr)

# At least we're on the python version we need, move on.

from distutils.core import setup

pjoin = os.path.join
here = os.path.abspath(os.path.dirname(__file__))

# Get the current package version.
version_ns = {}
with open(pjoin(here, 'oauthenticator', '_version.py')) as f:
    exec(f.read(), {}, version_ns)


setup_args = dict(
    name                = 'oauthenticator',
    packages            = ['oauthenticator'],
    version             = version_ns['__version__'],
    description         = "OAuthenticator: Authenticate JupyterHub users with common OAuth providers",
    long_description    = open("README.md").read(),
    long_description_content_type = "text/markdown",
    author              = "Jupyter Development Team",
    author_email        = "jupyter@googlegroups.com",
    url                 = "https://jupyter.org",
    license             = "BSD",
    platforms           = "Linux, Mac OS X",
    keywords            = ['Interactive', 'Interpreter', 'Shell', 'Web'],
    entry_points={
        'jupyterhub.authenticators': [
            'auth0 = oauthenticator.auth0:Auth0OAuthenticator',
            'local-auth0 = oauthenticator.auth0:LocalAuth0OAuthenticator',

            'azuread = oauthenticator.azuread:AzureAdOAuthenticator',
            'local-azuread = oauthenticator.azuread:LocalAzureAdOAuthenticator',

            'bitbucket = oauthenticator.bitbucket:BitbucketOAuthenticator',
            'local-bitbucket = oauthenticator.bitbucket:LocalBitbucketOAuthenticator',

            'cilogon = oauthenticator.cilogon:CILogonOAuthenticator',
            'local-cilogon = oauthenticator.cilogon:LocalCILogonOAuthenticator',

            'generic-oauth = oauthenticator.generic:GenericOAuthenticator',
            'local-generic-oauth = oauthenticator.generic:LocalGenericOAuthenticator',

            'github = oauthenticator.github:GitHubOAuthenticator',
            'local-github = oauthenticator.github:LocalGitHubOAuthenticator',

            'gitlab = oauthenticator.gitlab:GitLabOAuthenticator',
            'local-gitlab = oauthenticator.gitlab:LocalGitLabOAuthenticator',

            'globus = oauthenticator.globus:GlobusOAuthenticator',
            'local-globus = oauthenticator.globus:LocalGlobusOAuthenticator',

            'google = oauthenticator.google:GoogleOAuthenticator',
            'local-google = oauthenticator.google:LocalGoogleOAuthenticator',

            'mediawiki = oauthenticator.mediawiki:MWOAuthenticator',
            'local-mediawiki = oauthenticator.mediawiki:LocalMWOAuthenticator',

            'okpy = oauthenticator.okpy:OkpyOAuthenticator',
            'local-okpy = oauthenticator.okpy:LocalOkpyOAuthenticator',

            'openshift = oauthenticator.openshift:OpenShiftOAuthenticator',
            'local-openshift = oauthenticator.openshift:LocalOpenShiftOAuthenticator',
        ],
    },
    classifiers         = [
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
)

if 'bdist_wheel' in sys.argv:
    import setuptools

# setuptools requirements
if 'setuptools' in sys.modules:
    setup_args['install_requires'] = install_requires = []
    with open('requirements.txt') as f:
        for line in f.readlines():
            req = line.strip()
            if not req or req.startswith(('-e', '#')):
                continue
            install_requires.append(req)


def main():
    setup(**setup_args)

if __name__ == '__main__':
    main()
