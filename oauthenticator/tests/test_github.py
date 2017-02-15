from unittest.mock import Mock

from pytest import fixture, mark, raises
from tornado import web

from ..github import GitHubOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'login': username,
    }

@fixture
def github_client(client):
    setup_oauth_mock(client,
        host=['github.com', 'api.github.com'],
        access_token_path='/login/oauth/access_token',
        user_path='/user',
        token_type='token',
    )
    return client


@mark.gen_test
def test_github(github_client):
    authenticator = GitHubOAuthenticator()
    handler = github_client.handler_for_user(user_model('wash'))
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


@mark.gen_test
def test_github_no_code(github_client):
    authenticator = GitHubOAuthenticator()
    handler = Mock(spec=web.RequestHandler)
    handler.get_argument = Mock(return_value=None)
    with raises(web.HTTPError) as exc:
        name = yield authenticator.authenticate(handler)
    assert exc.value.status_code == 400
