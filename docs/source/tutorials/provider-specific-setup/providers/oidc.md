(tutorials:provider-specific:oidc)=
(tutorials:provider-specific:generic:oidc)=

# OpenID Connect (OIDC) Setup

{class}`.OIDCOAuthenticator` is an extension of GenericOAuthenticator,
but which loads some standard configuration from `.well-known/openid-configuration`.
This means you'll have fewer options that you need to configure for most
OIDC providers.

## JupyterHub configuration

Your `jupyterhub_config.py` file should look something like this:

```python
c.JupyterHub.authenticator_class = "oidc"
c.OAuthenticator.oauth_callback_url = "https://[your-domain]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"
c.JupyterHub.openid_provider_url = "https://yourprovider.example.org"
```

`openid_provider_url` should be the base URL of your provider.
OIDCOAuthenticator will fetch `{openid_provider_url}/.well-known/openid-configuration`
to set up the following configuration:

| OAuthenticator option | openid-configuration key | notes                   |
| --------------------- | ------------------------ | ----------------------- |
| `authorize_url`       | `authorization_endpoint` |                         |
| `token_url`           | `token_endpoint`         |                         |
| `jwks_uri`            | `jwks_uri`               | for verifying id tokens |
| `jwt_issuer`          | `issuer`                 | for verifying id tokens |
| `userdata_url`        | `userinfo_endpoint`      | if defined (not always) |

You can get the exact same behavior as `OIDCOAuthenticator` with the base `OAuthenticator`, if you set all of these parameters by hand.

```{note}
not all providers define `userinfo_endpoint`.
You can _either_ set `c.OAuthenticator.userdata_url`,
or set `c.OAuthenticator.userdata_from_id_token = True` to rely on the claims in the `id_token` of the token response.
```

Examples of `openid_provider_url` for common providers:

- auth0: `https://$yourdomain.auth0.com`
- github: `https://github.com/login/oauth`
- google: `https://accounts.google.com`
- orcid: `https://orcid.org`

## Additional configuration

Typically, when configuring with OIDC, you'll need to configure the `scope`, which will always include `openid`.
The remaining scopes may vary.

The default `username_claim` for OIDCOAuthenticator is `sub`,
but is very likely to vary, depending on your provider.
Make sure that you use a _verified_ and _unique_ claim from your

```python
c.OIDCOAuthenticator.scope = ["openid", "email", "groups"]
c.OIDCOAuthenticator.username_claim = "sub" # the default
c.OIDCOAuthenticator.auth_state_groups_key = "oauth_user.groups"
```

You will likely want to set the `user`

And as with all Authenticators, you will need to `allow` specific users or groups.

(tutorials:provider-specific:generic:orcid)=
(tutorials:provider-specific:oidc:orcid)=

## Setup for ORCID iD

```{note}
The `OAuthenticator` will by default lowercase your username. For example, an ORCID iD of `0000-0002-9079-593X` will produce a JupyterHub username of `0000-0002-9079-593x`.
```

Follow the ORCID [API Tutorial](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/) to create an application via the Developer Tools submenu after clicking on your name in the top right of the page.

Edit your `jupyterhub_config.py` with the following:

```python
c.JupyterHub.authenticator_class = "oidc"

# Fill these in with your values
c.OIDCOAuthenticator.oauth_callback_url = "YOUR CALLBACK URL"
c.OIDCOAuthenticator.client_id = "YOUR CLIENT ID"
c.OIDCOAuthenticator.client_secret = "YOUR CLIENT SECRET"

c.OIDCOAuthenticator.login_service = "ORCID iD" # Text of login button
c.OIDCOAuthenticator.openid_provider_url = "https://orcid.org"
c.GenericOAuthenticator.scope = ["/authenticate", "openid"]
```

The default `username_claim` of `sub` selects the ORCID iD from the JSON response as the individual's JupyterHub username. An example response is below:

```json
{
  "sub": "0000-0002-2601-8132",
  "name": "Credit Name",
  "family_name": "Jones",
  "given_name": "Tom"
}
```

Please refer to the [Authorization Code Flow](https://github.com/ORCID/ORCID-Source/blob/main/orcid-web/ORCID_AUTH_WITH_OPENID_CONNECT.md#authorization-code-flow) section of the ORCID documentation for more information.

(tutorials:provider-specific:generic:awscognito)=
(tutorials:provider-specific:oidc:awscognito)=

## Setup for AWS Cognito

First visit AWS official documentation on [Getting started with user pools] for
info on how to register and configure a cognito user pool and an associated
OAuth2 application.

[Getting started with user pools]: https://docs.aws.amazon.com/cognito/latest/developerguide/getting-started-user-pools.html

Set the above settings in your `jupyterhub_config.py`:

```python
c.JupyterHub.authenticator_class = "oidc"
c.OAuthenticator.oauth_callback_url = "https://[your-host]/hub/oauth_callback"
c.OAuthenticator.client_id = "[your oauth2 application id]"
c.OAuthenticator.client_secret = "[your oauth2 application secret]"

c.OAuthenticator.login_service = "AWS Cognito"
c.OAuthenticator.username_claim = "login"
c.OIDCOAuthenticator.openid_provider_url = "https://your-AWSCognito-domain"
```
