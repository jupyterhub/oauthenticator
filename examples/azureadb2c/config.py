import sys
import os

#load from local path
#sys.path.insert(1, '/home/linkcd/github/oauthenticator/oauthenticator')
#from azureadb2c import AzureAdB2COAuthenticator, LocalAzureAdB2COAuthenticator

#load from package
from oauthenticator.azureadb2c import AzureAdB2COAuthenticator, LocalAzureAdB2COAuthenticator
c.JupyterHub.authenticator_class = LocalAzureAdB2COAuthenticator

c.Application.log_level = 'DEBUG'


c.AzureAdB2COAuthenticator.oauth_callback_url = 'http://localhost:8000/hub/oauth_callback'
c.AzureAdB2COAuthenticator.client_id = 'YOUR_VALUE'
c.AzureAdB2COAuthenticator.client_secret = 'YOUR_VALUE'

c.Authenticator.delete_invalid_users = True

c.LocalAzureAdB2COAuthenticator.add_user_cmd = ['adduser', '-q', '--gecos', '""', '--disabled-password', '--force-badname']
c.LocalAzureAdB2COAuthenticator.create_system_users = True
