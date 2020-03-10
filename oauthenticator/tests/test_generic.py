from pytest import fixture, mark

from ..generic import GenericOAuthenticator

from .mocks import setup_oauth_mock
from unittest import mock


def user_model(username, **kwargs):
    """Return a user model"""
    user = {
        'username': username,
        'scope': 'basic',
    }
    user.update(kwargs)
    return user

def Authenticator(**kwargs):
    return GenericOAuthenticator(
        token_url='https://generic.horse/oauth/access_token',
        userdata_url='https://generic.horse/oauth/userinfo',
        **kwargs
    )

@fixture
def generic_client(client):
    setup_oauth_mock(client,
        host='generic.horse',
        access_token_path='/oauth/access_token',
        user_path='/oauth/userinfo',
    )
    return client


async def test_generic(generic_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = generic_client
        authenticator = Authenticator()

        handler = generic_client.handler_for_user(user_model('wash'))
        user_info = await authenticator.authenticate(handler)
        assert sorted(user_info) == ['auth_state', 'name']
        name = user_info['name']
        assert name == 'wash'
        auth_state = user_info['auth_state']
        assert 'access_token' in auth_state
        assert 'oauth_user' in auth_state
        assert 'refresh_token' in auth_state
        assert 'scope' in auth_state


async def test_generic_callable_username_key(generic_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = generic_client
        authenticator = Authenticator(
            username_key=lambda r: r['alternate_username']
        )
        handler = generic_client.handler_for_user(
            user_model('wash', alternate_username='zoe')
        )
        user_info = await authenticator.authenticate(handler)
        assert user_info['name'] == 'zoe'
