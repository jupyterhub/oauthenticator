import os

from oauthenticator.azuread import AzureAdOAuthenticator

c.JupyterHub.authenticator_class = AzureAdOAuthenticator

c.Application.log_level = 'DEBUG'

c.AzureAdOAuthenticator.tenant_id = os.environ.get('AAD_TENANT_ID')

c.AzureAdOAuthenticator.oauth_callback_url = 'http://{your-domain}/hub/oauth_callback'
c.AzureAdOAuthenticator.client_id = '{AAD-APP-CLIENT-ID}'
c.AzureAdOAuthenticator.client_secret = '{AAD-APP-CLIENT-SECRET}'

# if the user's name returned by Azure isn't acceptable to JupyterHub then we can use an alternate field,
# uncomment the line below to use 'unique_name' rather than the default 'name'. Consult the Azure
# documentation for other field names.
#c.AzureAdOAuthenticator.username_claim = 'unique_name'
#
# If the alternate field defined by username_claim is not part of the default OAuth request,
# we can do an additional lookup request to the Microsoft Graph API to fetch it. You can enable it
# by uncommenting the settings below (if needed)
#c.AzureAdOAuthenticator.username_claim_request = True
