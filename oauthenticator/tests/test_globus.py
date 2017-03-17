from pytest import fixture, mark

from ..globus import GlobusOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


def user_model(username):
    """Return a user model"""
    return {
        'login': username,
    }

@fixture
def globus_client(client):
    setup_oauth_mock(client,
        host=['github.com', 'api.github.com'],
        access_token_path='/login/oauth/access_token',
        user_path='/user',
        token_type='token',
    )
    return client


@mark.gen_test
def test_globus(github_client):
    authenticator = GlobusOAuthenticator()
    handler = globus_client.handler_for_user(user_model('wash'))
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


@mark.gen_test
def test_no_code(test_globus):
    yield no_code_test(GlobusOAuthenticator())