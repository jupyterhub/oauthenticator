# include github, bitbucket, google here for backward-compatibility
# don't add new oauthenticators here.
from ._version import __version__
from ._version import version_info
from .bitbucket import *
from .cilogon import *
from .github import *
from .google import *
from .oauth2 import *
