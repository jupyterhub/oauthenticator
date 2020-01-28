import os
from unittest.mock import patch

from pytest import fixture, mark

from ..auth0 import Auth0OAuthenticator
from .mocks import setup_oauth_mock

auth0_subdomain = "jupyterhub-test"


def user_model(username):
    """Return a user model"""
    return {'email': username}


@fixture
def auth0_client(client):
    setup_oauth_mock(
        client,
        host='%s.auth0.com' % auth0_subdomain,
        access_token_path='/oauth/token',
        user_path='/userinfo',
        token_request_style='json',
    )
    return client


async def test_auth0(auth0_client):
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    handler = auth0_client.handler_for_user(user_model('kaylee@serenity.now'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'kaylee@serenity.now'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'auth0_user' in auth_state
