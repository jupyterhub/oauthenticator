# Migrations

The following section describes how to migrate your OAuthenticator to a newer version given some upgrade scenarios.

## Migrating CILogonOAuthenticator to version 15.0.0

OAuthenticator release of 15.0.0 version introduced some breaking changes for the CILogonOAuthenticator. This is a description of what breaking changes have been made and a step by step guide on how to update your JupyterHub CILogonOAuthenticator to this version.

The following configurations have been deprecated in oauthenticator 15.0.0

1. `idp` -> **replaced**

   The `idp` Unicode config refers to the SAML Entity ID of the user's selected identity provider and prior to 15.0.0 was used to set the [CILogon `selected_idp` optional authorization parameter](https://www.cilogon.org/oidc#h.p_IWGvXH0okDI_) in order to show only this identity provider in the CILogon IDP list.

   Starting with oauthenticator 15.0.0, this config has been renamed to `shown_idps` and must now be a list of such SAML Entity IDs. Only the identity providers in this list will be shown in the CILogon IDP list, with the first one being considered the default.

   **Old config Example**

   ```python
   c.CILogonOAuthenticator.idp = "https://accounts.google.com/o/oauth2/auth"
   ```

   **New config Example**

   ```python
   c.CILogonOAuthenticator.shown_idps = ["https://accounts.google.com/o/oauth2/auth"]
   ```

2. `strip_idp_domain` -> **removed**

   The `strip_idp_domain` boolean config was previously used to enable stripping the domains listed in the `allowed_idps` from the hub usernames. In oauthenticator 15.0.0 this config option was removed and such behaviour can only be achieved using the `allowed_idps` dictionary config as documented in a section below.

   **Old config Example**

   ```python
   c.CILogonOAuthenticator.username_claim = "email"
   c.CILogonOAuthenticator.allowed_idps = ["uni.edu"]
   c.CILogonOAuthenticator.strip_idp_domain = True
   ```

   **New config Example**

   ```python
   c.CILogonOAuthenticator.allowed_idps = {
       'https://uni-idp.com/login/oauth/authorize': {
           'username_derivation': {
               'username_claim': 'email',
               'action': 'strip_idp_domain',
               'domain': 'uni.edu',
           }
       },
   }
   ```

   ```{note}
   If allowed_idps used to contain more than one domain, then check the section bellow to find out how to also use prefixes for usernames to avoid username clashes.
   ```

3. `allowed_idps` -> **changed type**

   The `allowed_idps` List config was used prior to oauthenticator version 15.0.0 to only allow acces into the hub to usernames containing only these domains, after the @ sign. If `strip_idp_domain` was enabled, these domains would have been stripped from the hub username.

   Starting with oauthenticator 15.0.0 this config option must now be a Dict that contains a `username_derivation` dictionary that describes how the hub usernames will be derived for each allowed identity provider. More information about each configuration option that can go into the `username_derivation` can be found in the `allowed_idps` docstring. Also, [this json schema](https://github.com/jupyterhub/oauthenticator/tree/main/oauthenticator/schemas/cilogon-schema.yaml) has information about how its validity it's checked.

   **Stripping the domain from one IDP username and adding prefixes to another**

   ```python
   c.CILogonOAuthenticator.allowed_idps = {
       'https://some-idp.com/login/oauth/authorize': {
           'username_derivation': {
               'username_claim': 'email',
               'action': 'strip_idp_domain',
               'domain': 'uni.edu',
           }
       },
       'https://another-idp.com/login/oauth/authorize': {
           'username_derivation': {
               'username_claim': 'nickname',
               'action': 'prefix',
               'prefix': 'idp',
           }
       },
   }
   ```

   This config means that if you login using a `some-idp` provider, the hub username will be the email registered for that IDP, from which the domain `uni.edu` will be stripped (assuming this is domain in the email provided by `some-idp`).
   But if you login using `another-idp` the hub username will be your `another-idp` provided `nickname` claim, username prefixed with `idp:`. This way, multiple users can log in without clashes across IDPs

   ```{note}
   If `allowed_idps` is specified, then each IDP in the dict must define the `username_derivation` dict, including `username_derivation.username_claim`. `CILogonOAuthenticator.username_claim` will only be used if `allowed_idps` is not specified!
   ```
