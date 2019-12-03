Writing your own OAuthenticator
===============================

There are two ways to write your own OAuthenticator.

Using GenericOAuthenticator
---------------------------

The first and simplest is to use :class:`~.oauthenticator.generic.GenericOAuthenticator`
and configuration to set the necessary configuration variables.

TODO: flesh out required configuration

- client_id
- client_secret
- login_service
- userdata_url
- token_url
- username_key


Writing your own OAuthenticator class
-------------------------------------

If you want more advanced features and customization beyond the basics of OAuth,
you can write your own full OAuthenticator subclass,
which enables more detailed customization login and logout actions.

TODO: flesh this out

The skeleton of an OAuthenticator looks like this:

.. literalinclude:: example-oauthenticator.py


where you will need to find and define the URLs and requests necessary to complete OAuth with your provider.
