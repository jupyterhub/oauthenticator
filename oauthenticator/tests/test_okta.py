from pytest import fixture, mark

from ..okta import OktaOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


def user_model(username):
    """Return a user model"""
    return {
        'username': username,
    }

@fixture
def okta_client(client):
    setup_oauth_mock(client,
        host='okta.com',
        access_token_path='/oauth2/v1/token',
        user_path='/oauth2/v1/user',
    )
    return client


@mark.gen_test
def test_okta(okta_client):
    authenticator = OktaOAuthenticator()
    handler = okta_client.handler_for_user(user_model('wash'))
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


@mark.gen_test
def test_no_code(okta_client):
    yield no_code_test(OktaOAuthenticator())
