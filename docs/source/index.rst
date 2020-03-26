.. OAuthenticator documentation master file, created by
   sphinx-quickstart on Tue Dec  3 10:38:44 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==============
OAuthenticator
==============

OAuthenticator provides plugins for JupyterHub to use common OAuth providers,
as well as base classes for writing your own Authenticators with any OAuth 2.0 provider.


The OAuthenticator package is not accepting new OAuth providers,
but you can write your own OAuthenticator by subclassing :class:`oauthenticator.oauth2.OAuthenticator`

Version: |version|


Contents
========
Installation Guide
------------------
.. toctree::
   :maxdepth: 1

   install

Get Started Guide
-----------------
.. toctree::
   :maxdepth: 2

   getting-started

Extending authenticators
------------------------
.. toctree::
   :maxdepth: 2

   extending

Writing your own OAuthenticator
-------------------------------
.. toctree::
   :maxdepth: 2

   writing-an-oauthenticator

API Reference
-------------
.. toctree::
   :maxdepth: 1

   api/index
   changelog


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
