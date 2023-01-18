# Upgrading your OAuthenticator to version 16.0

The following section describes what to keep in mind when upgrading to OAuthenticator 16.0.

````{important}
(token_request)=

```{rubric} The token request
```
Whenever _token request_ is used, it refers to the HTTP request exchanging the [oauth code](https://www.rfc-editor.org/rfc/rfc6749#section-1.3.1) for the [access token](https://www.rfc-editor.org/rfc/rfc6749#section-1.4).

This request is sent to the [`token_url`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.token_url) in [`get_token_info()`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.get_token_info) method.

(userdata_request)=

```{rubric} The userdata request
```
Whenever _userdata request_ is used, it refers to the HTTP request that's exchanging the the `access token` to get the `userdata`.

This request is sent to [`userdata_url`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.userdata_url) in [`token_to_user`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.get_token_info).
````

## Deprecations

1. `username_key` replaced by `username_claim` in _all oauthenticators_
- [`GenericOAuthenticator.username_key`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.generic.html#oauthenticator.generic.GenericOAuthenticator.username_key) is deprecated and replaced by [`username_claim`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.username_claim).

- [`Auth0OAuthenticator.username_key`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.auth0.html#oauthenticator.auth0.Auth0OAuthenticator.username_key) is deprecated and replaced by [`username_claim`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.username_claim).

    ```{note}
    The `username_claim` and the deprecated `username_key` refers to the field in the `userdata` response from which to get the JupyterHub username. Examples include: email, username, nickname. What keys are available depend on the scopes requested and the authenticator used.
    ```

2. [`GenericOAuthenticator.extra_params`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.generic.html#oauthenticator.generic.GenericOAuthenticator.extra_params) is deprecated and replaced by [`token_params`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.token_params).


3. The following public functions were removed:
- `OkpyOAuthenticator.get_auth_request(self, code)`
- `OkpyOAuthenticator.get_user_info_request(self, access_token)`

## New

1. The name of the user key expected to be present in `auth_state` is now configurable through [`user_auth_state_key`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.user_auth_state_key) for _all oauthenticators_, and it defaults to their prior values for each authenticator.

2. The [`refresh_pre_spawn`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.refresh_pre_spawn) is enabled by default if [`enable_auth_state`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.enable_auth_state) is set.


3. The userdata query parameters ([`userdata_params`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.userdata_params)) to be added to the request to [`userdata_url`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.userdata_url) to get user data login information is now a configurable feature of _all the oauthenticators_.

    ```{note}
    Previously, a GenericOAuthenticator only trait
    ```

4. The method used for sending the `access token` in the [userdata request](userdata_request), called [`userdata_token_method`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.userdata_token_method), is now a configurable feature of _all the oauthenticators_.

    ```{note}
    Previously, a GenericOAuthenticator only trait
    ```

5. It is now possible to pass extra parameters to the [token request](token_request), using [token_params](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.token_params)for _all of the oauthenticators_.

    ```{note}
    Previously, a GenericOAuthenticator only trait
    ```

6. It is now possible to set whether or not to use basic authentication for the access [token request](token_request) using the [`basic_auth`](https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.oauth2.html#oauthenticator.oauth2.OAuthenticator.basic_auth) for _all of the oauthenticators_.Currently it defaults to `False`.

     ```{note}
    Previously, a GenericOAuthenticator only trait
    ```
