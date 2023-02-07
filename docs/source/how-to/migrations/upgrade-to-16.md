(migrations:upgrade-to-16)=

# Upgrading your OAuthenticator to version 16.0

The following section describes what to pay attention to when upgrading to OAuthenticator 16.0.

## Breaking changes

1. `username_key` replaced by `username_claim` in _all oauthenticators_

   - {attr}`.GenericOAuthenticator.username_key` is deprecated and replaced by {attr}`.OAuthenticator.username_claim`.

   - {attr}`.Auth0OAuthenticator.username_key` is deprecated and replaced by {attr}`.OAuthenticator.username_claim`.

   ```{note}
   The `username_claim` and the deprecated `username_key` refers to the field in the `userdata` response from which to get the JupyterHub username. Examples include: email, username, nickname. What keys are available depend on the scopes requested and the authenticator used.
   ```

2. {attr}`.GenericOAuthenticator.extra_params` is deprecated and replaced by {attr}`.OAuthenticator.token_params`.

3. The following public functions were removed:

   - `OkpyOAuthenticator.get_auth_request(self, code)`
   - `OkpyOAuthenticator.get_user_info_request(self, access_token)`

## New

1. The name of the user key expected to be present in `auth_state` is now configurable through {attr}`.OAuthenticator.user_auth_state_key` for _all oauthenticators_, and it defaults to their prior specific values.

2. The [`Authenticator.refresh_pre_spawn`](https://jupyterhub.readthedocs.io/en/stable/api/auth.html#jupyterhub.auth.Authenticator.refresh_pre_spawn) option is enabled by default if {attr}`.OAuthenticator.enable_auth_state` is set.

3. The userdata query parameters {attr}`.OAuthenticator.userdata_params` to be added to the request sent to {attr}`.OAuthenticator.userdata_url` to get user data login information is now a configurable feature of _all the oauthenticators_.

   ```{note}
   Previously, a GenericOAuthenticator only trait.
   ```

4. The method used for sending the `access token` in the userdata request[^userdata_request], called {attr}`.OAuthenticator.userdata_token_method`, is now a configurable feature of _all the oauthenticators_.

   ```{note}
   Previously, a GenericOAuthenticator only trait.
   ```

5. It is now possible to pass extra parameters to the token request[^token_request], using {attr}`.OAuthenticator.token_params` for _all of the oauthenticators_.

   ```{note}
   Previously, a GenericOAuthenticator only trait.
   ```

6. It is now possible to set whether or not to use basic authentication for the access token request[^token_request] using {attr}`.OAuthenticator.basic_auth` for _all of the oauthenticators_.
   Currently it defaults to `False`.

   ```{note}
   Previously, a GenericOAuthenticator only trait.
   ```

[^token_request]: **The token request.**

    Whenever _token request_ is used, it refers to the HTTP request exchanging the [oauth code](https://www.rfc-editor.org/rfc/rfc6749#section-1.3.1) for the [access token](https://www.rfc-editor.org/rfc/rfc6749#section-1.4).

    This request is sent to the {attr}`.OAuthenticator.token_url` in {meth}`.OAuthenticator.get_token_info` method.

[^userdata_request]: **The userdata request.**

    Whenever _userdata request_ is used, it refers to the HTTP request that's exchanging the the `access token` to get the `userdata`.

    This request is sent to {attr}`.OAuthenticator.userdata_url` in {meth}`.OAuthenticator.token_to_user` method.
