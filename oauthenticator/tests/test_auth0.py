from pytest import fixture

from ..auth0 import Auth0OAuthenticator
from .mocks import setup_oauth_mock

auth0_subdomain = "jupyterhub-test"


def user_model(email, nickname=None):
    """Return a user model"""
    return {
        'email': email,
        'nickname': nickname if nickname else email,
        'name': 'Hoban Washburn',
    }


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


async def test_username_key(auth0_client):
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    authenticator.username_key = 'nickname'
    handler = auth0_client.handler_for_user(user_model('kaylee@serenity.now', 'kayle'))
    user_info = await authenticator.authenticate(handler)

    assert user_info['name'] == 'kayle'
