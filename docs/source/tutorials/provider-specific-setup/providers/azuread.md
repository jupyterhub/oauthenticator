# Azure AD Setup

1. Install oauthenticator with required dependency

   ```bash
   pip3 install "oauthenticator[azuread]"
   ```

1. Set the `AAD_TENANT_ID` environment variable

   ```bash
   export AAD_TENANT_ID='{AAD-TENANT-ID}'
   ```

1. Add the code below to your `jupyterhub_config.py` file

   ```python
   import os
   from oauthenticator.azuread import AzureAdOAuthenticator
   c.JupyterHub.authenticator_class = AzureAdOAuthenticator

   c.Application.log_level = 'DEBUG'

   c.AzureAdOAuthenticator.tenant_id = os.environ.get('AAD_TENANT_ID')

   c.AzureAdOAuthenticator.oauth_callback_url = 'http://{your-domain}/hub/oauth_callback'
   c.AzureAdOAuthenticator.client_id = '{AAD-APP-CLIENT-ID}'
   c.AzureAdOAuthenticator.client_secret = '{AAD-APP-CLIENT-SECRET}'
   ```

   This sample code is provided for you in `examples > azuread > sample_jupyter_config.py`

1. Make sure to replace the values in `'{}'` with your APP, TENANT, DOMAIN, etc. values

1. You might need to add at least the `openid` scope if your
   organization requires MFA (`c.AzureAdOAuthenticator.scope = ['openid']`),
   in addition to whatever else you need.

1. Follow [this link to create an AAD APP](https://community.microfocus.com/cyberres/netiq-identity-governance-administration/idm/w/identity_mgr_tips/17052/creating-the-application-client-id-and-client-secret-from-microsoft-azure-new-portal---part-1)

1. CLIENT_ID === Azure Application ID, found in:
   `Azure portal --> AD --> App Registrations --> App`

1. TENANT_ID === Azure Directory ID, found in:
   `Azure portal --> AD --> Properties`

1. Run via:

   ```bash
   sudo jupyterhub -f ./path/to/jupyterhub_config.py
   ```

1. See `run.sh` for an [example](https://github.com/jupyterhub/oauthenticator/tree/main/examples/azuread)

1. [Source Code](https://github.com/jupyterhub/oauthenticator/blob/HEAD/oauthenticator/azuread.py)
