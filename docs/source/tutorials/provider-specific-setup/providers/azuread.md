# Azure AD Setup

You need to have an Azure OAuth application registered ahead of time, see
Azure's official documentation about [registering an app].

[registering an app]: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols#app-registration

1. Install oauthenticator with the optional dependency `azuread`, as required
   for use with AzureAdOAuthenticator.

   ```bash
   pip install "oauthenticator[azuread]"
   ```

2. Add code like below to a `jupyterhub_config.py` file

   ```python
   c.JupyterHub.authenticator_class = "azuread"

   c.OAuthenticator.oauth_callback_url = "https://[your-host]/hub/oauth_callback"
   c.OAuthenticator.client_id = "[your oauth2 application id]"
   c.OAuthenticator.client_secret = "[your oauth2 application secret]"

   c.AzureAdOAuthenticator.tenant_id = "[your azure tenant id]"
   c.AzureAdOAuthenticator.scope = ["openid", "email"]
   ```

## Additional configuration

AzureAdOAuthenticator expands OAuthenticator with the following config that may
be relevant to read more about in the configuration reference:

- {attr}`.AzureAdOAuthenticator.tenant_id`

## Loading user groups

The `AzureAdOAuthenticator` can load the group-membership of users from the access token.
This is done by setting the `AzureAdOAuthenticator.groups_claim` to the name of the claim that contains the
group-membership.

```python
import os
from oauthenticator.azuread import AzureAdOAuthenticator

c.JupyterHub.authenticator_class = AzureAdOAuthenticator

# {...} other settings (see above)

c.AzureAdOAuthenticator.user_groups_claim = 'groups'
```

This requires Azure AD to be configured to include the group-membership in the access token.
