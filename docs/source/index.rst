.. OAuthenticator documentation master file, created by
   sphinx-quickstart on Tue Dec  3 10:38:44 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

OAuthenticator = OAuth for JupyterHub
=====================================

This is the documentation for OAuthenticator |version|.

OAuthenticator provides plugins for JupyterHub to use common OAuth providers,
as well as base classes for writing your own Authenticators with any OAuth 2.0 provider.


Install oauthenticator:

.. sourcecode:: bash

   python3 -m pip install oauthenticator
   # or
   conda install oauthenticator

See :doc:`getting-started` for getting started with OAuthenticator.

The OAuthenticator package is not accepting new OAuth providers,
but you can write your own OAuthenticator by subclassing :class:`oauthenticator.oauth2.OAuthenticator`

.. seealso::

    :doc:`writing-an-oauthenticator`



.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting-started
   api/index
   writing-an-oauthenticator



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
