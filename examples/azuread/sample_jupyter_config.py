import os
from oauthenticator.azuread import AzureAdOAuthenticator
c.JupyterHub.authenticator_class = AzureAdOAuthenticator

c.Application.log_level = 'DEBUG'

c.AzureAdOAuthenticator.tenant_id = os.environ.get('AAD_TENANT_ID')

c.AzureAdOAuthenticator.oauth_callback_url = 'http://{your-domain}/hub/oauth_callback'
c.AzureAdOAuthenticator.client_id = '{AAD-APP-CLIENT-ID}'
c.AzureAdOAuthenticator.client_secret = '{AAD-APP-CLIENT-SECRET}'
