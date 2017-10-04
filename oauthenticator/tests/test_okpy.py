from pytest import fixture, mark

from ..okpy import OkpyOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


def user_model(email):
    """Return a user model"""
    return {
        'email': email,
    }

@fixture
def okpy_client(client):
    setup_oauth_mock(client,
        host=['okpy.org'],
        access_token_path='/oauth/token',
        user_path='/api/v3/user',
        token_type='Bearer',
    )
    return client


@mark.gen_test
def test_okpy(okpy_client):
    authenticator = OkpyOAuthenticator()
    handler = okpy_client.handler_for_user(user_model('testing@example.com'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'testing@example.com'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'okpy_user' in auth_state


@mark.gen_test
def test_no_code(okpy_client):
    yield no_code_test(OkpyOAuthenticator())
