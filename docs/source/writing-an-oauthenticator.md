# Writing your own OAuthenticator

There are two ways to write your own OAuthenticator.

## Using GenericOAuthenticator

The first and simplest is to use the `oauthenticator.generic.GenericOAuthenticator` class
and configuration to set the necessary configuration variables.

- client_id
- client_secret
- login_service
- authorize_url
- userdata_url
- token_url
- username_key

Example config:

```python
c.JupyterHub.authenticator_class = 'generic-oauth'

c.GenericOAuthenticator.oauth_callback_url = 'https://{host}/hub/oauth_callback'
c.GenericOAuthenticator.client_id = 'OAUTH-CLIENT-ID'
c.GenericOAuthenticator.client_secret = 'OAUTH-CLIENT-SECRET-KEY'
c.GenericOAuthenticator.login_service = 'name-of-service-provider'
c.GenericOAuthenticator.authorize_url = 'url-submitting-authorization-request'
c.GenericOAuthenticator.userdata_url = 'url-retrieving-user-data-with-access-token'
c.GenericOAuthenticator.token_url = 'url-retrieving-access-token-oauth-completion'
c.GenericOAuthenticator.username_key = 'username-key-for-USERDATA-URL'
```

Checkout [](getting-started:moodle-setup) and [](getting-started:yandex_setup) for how to configure
GenericOAuthenticator for Moodle and Yandex.

## Writing your own OAuthenticator class

If you want more advanced features and customization beyond the basics of OAuth,
you can write your own full OAuthenticator subclass,
which enables more detailed customization login and logout actions.

The skeleton of an OAuthenticator looks like this:

```{literalinclude} example-oauthenticator.py

```

where you will need to find and define the URLs and requests necessary to complete OAuth with your provider.
