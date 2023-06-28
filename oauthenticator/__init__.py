# include github, bitbucket, google here for backward-compatibility
# don't add new oauthenticators here.
from ._version import __version__, version_info  # noqa
from .bitbucket import *  # noqa
from .cilogon import *  # noqa
from .github import *  # noqa
from .google import *  # noqa
from .oauth2 import *  # noqa
