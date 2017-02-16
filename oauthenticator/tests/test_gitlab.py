from pytest import fixture, mark

from ..gitlab import GitLabOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


def user_model(username):
    """Return a user model"""
    return {
        'username': username,
    }

@fixture
def gitlab_client(client):
    setup_oauth_mock(client,
        host='gitlab.com',
        access_token_path='/oauth/token',
        user_path='/api/v3/user',
    )
    return client


@mark.gen_test
def test_gitlab(gitlab_client):
    authenticator = GitLabOAuthenticator()
    handler = gitlab_client.handler_for_user(user_model('wash'))
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


@mark.gen_test
def test_no_code(gitlab_client):
    yield no_code_test(GitLabOAuthenticator())
