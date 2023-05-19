"""oauthenticator version info"""
# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

version_info = (
    15,
    1,
    1,
    'dev',  # comment-out this line for a release
)
__version__ = '.'.join(map(str, version_info[:3]))

if len(version_info) > 3:
    __version__ = f'{__version__}{version_info[3]}'
