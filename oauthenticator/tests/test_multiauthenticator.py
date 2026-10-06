"""Test module for the MultiAuthenticator class"""
from pytest import fixture

from ..github import GitHubOAuthenticator
from ..gitlab import GitLabOAuthenticator
from ..google import GoogleOAuthenticator
from ..multiauthenticator import MultiAuthenticator


@fixture
def different_authenticators():
    return [
        (
            GitLabOAuthenticator,
            "/gitlab",
            {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/gitlab/oauth_callback",
            },
        ),
        (
            GitHubOAuthenticator,
            "/github",
            {
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/github/oauth_callback",
            },
        ),
    ]


@fixture
def same_authenticators():
    return [
        (
            GoogleOAuthenticator,
            "/mygoogle",
            {
                "login_service": "My Google",
                "client_id": "yyyyy",
                "client_secret": "yyyyy",
                "oauth_callback_url": "http://example.com/hub/mygoogle/oauth_callback",
            },
        ),
        (
            GoogleOAuthenticator,
            "/othergoogle",
            {
                "login_service": "Other Google",
                "client_id": "xxxx",
                "client_secret": "xxxx",
                "oauth_callback_url": "http://example.com/hub/othergoogle/oauth_callback",
            },
        ),
    ]


def test_different_authenticators(different_authenticators):
    MultiAuthenticator.authenticators = different_authenticators

    authenticator = MultiAuthenticator()
    assert len(authenticator._authenticators) == 2

    handlers = authenticator.get_handlers("")
    assert len(handlers) == 6
    for path, handler in handlers:
        if "gitlab" in path:
            assert isinstance(handler.authenticator, GitLabOAuthenticator)
        elif "github" in path:
            assert isinstance(handler.authenticator, GitHubOAuthenticator)
        else:
            raise ValueError(f"Unknown path: {path}")


def test_same_authenticators(same_authenticators):
    MultiAuthenticator.authenticators = same_authenticators

    authenticator = MultiAuthenticator()
    assert len(authenticator._authenticators) == 2

    handlers = authenticator.get_handlers("")
    assert len(handlers) == 6
    for path, handler in handlers:
        assert isinstance(handler.authenticator, GoogleOAuthenticator)
        if "mygoogle" in path:
            assert handler.authenticator.login_service == "My Google"
        elif "othergoogle" in path:
            assert handler.authenticator.login_service == "Other Google"
        else:
            raise ValueError(f"Unknown path: {path}")
