import os
from unittest.mock import patch

from pytest import fixture, mark

with patch.dict(os.environ, AUTH0_SUBDOMAIN='jupyterhub-test'):
    from ..auth0 import Auth0OAuthenticator, AUTH0_SUBDOMAIN

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'email': username,
    }

@fixture
def auth0_client(client):
    setup_oauth_mock(client,
        host='%s.auth0.com' % AUTH0_SUBDOMAIN,
        access_token_path='/oauth/token',
        user_path='/userinfo',
        token_request_style='json',
    )
    return client


@mark.gen_test
def test_auth0(auth0_client):
    authenticator = Auth0OAuthenticator()
    handler = auth0_client.handler_for_user(user_model('kaylee@serenity.now'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'kaylee@serenity.now'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'auth0_user' in auth_state

