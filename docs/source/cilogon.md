# CILogon-specific scopes

[CILogon scopes](http://www.cilogon.org/oidc) can
be used to extend the CILogon OAuthenticator. By overriding the scope
list in the authenticator, additional features can be enabled for
specific deployment needs.

The additional fields exposed by expanded scope are all stored in the
authenticator's `auth_state` structure, so you'll need to enable
`auth_state` and install the Python `cryptography` package to be able to
use these.
