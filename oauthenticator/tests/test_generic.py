from pytest import fixture, mark

from ..generic import GenericOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'username': username,
    }

def Authenticator():
    return GenericOAuthenticator(
        token_url='https://generic.horse/oauth/access_token',
        userdata_url='https://generic.horse/oauth/userinfo'
    )
@fixture
def generic_client(client):
    setup_oauth_mock(client,
        host='generic.horse',
        access_token_path='/oauth/access_token',
        user_path='/oauth/userinfo',
    )
    return client


@mark.gen_test
def test_generic(generic_client):
    authenticator = Authenticator()
    handler = generic_client.handler_for_user(user_model('wash'))
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


