import os
from unittest.mock import patch

from pytest import fixture

with patch.dict(os.environ, AWSCOGNITO_DOMAIN='jupyterhub-test.auth.us-west-1.amazoncognito.com'):
    from ..awscognito import AWSCognitoAuthenticator, AWSCOGNITO_DOMAIN

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'username': username,
        'scope': 'basic',
    }

def Authenticator():
    return AWSCognitoAuthenticator()

@fixture
def awscognito_client(client):
    setup_oauth_mock(client,
        host=AWSCOGNITO_DOMAIN,
        access_token_path='/oauth2/token',
        user_path='/oauth2/userInfo',
        token_request_style='json',
    )
    return client


async def test_awscognito(awscognito_client):
    authenticator = Authenticator()
    handler = awscognito_client.handler_for_user(user_model('foo'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'foo'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'awscognito_user' in auth_state
