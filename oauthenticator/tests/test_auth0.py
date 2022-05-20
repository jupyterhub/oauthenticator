from unittest.mock import Mock

import pytest
from pytest import fixture
from tornado import web

from ..auth0 import Auth0OAuthenticator
from ..oauth2 import OAuthLogoutHandler
from .mocks import mock_handler, setup_oauth_mock

auth0_subdomain = "jupyterhub-test"
auth0_custom_domain = 'auth.serenity.now'


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


def test_auth0_missing_domain_config_throws_error():
    authenticator = Auth0OAuthenticator()
    with pytest.raises(ValueError):
        authenticator.auth0_domain


def test_both_custom_and_subdomain_set_throw_error():
    authenticator = Auth0OAuthenticator()
    authenticator.auth0_subdomain = 'subdomain'
    authenticator.auth0_custom_domain = 'custom.domain.org'
    with pytest.raises(ValueError):
        authenticator.auth0_domain


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


def test_auth0_standard_subdomain_for_authorize():
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    assert authenticator.authorize_url == "https://jupyterhub-test.auth0.com/authorize"


def test_auth0_custom_domain_for_authorize():
    authenticator = Auth0OAuthenticator(auth0_custom_domain=auth0_custom_domain)
    assert authenticator.authorize_url == "https://auth.serenity.now/authorize"


def test_auth0_standard_subdomain_for_token():
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    assert authenticator.token_url == "https://jupyterhub-test.auth0.com/oauth/token"


def test_auth0_custom_domain_for_token():
    authenticator = Auth0OAuthenticator(auth0_custom_domain=auth0_custom_domain)
    assert authenticator.token_url == "https://auth.serenity.now/oauth/token"


def test_auth0_standard_subdomain_for_logout():
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    assert (
        authenticator.logout_redirect_url
        == "https://jupyterhub-test.auth0.com/v2/logout"
    )


def test_auth0_custom_domain_for_logout():
    authenticator = Auth0OAuthenticator(auth0_custom_domain=auth0_custom_domain)
    assert authenticator.logout_redirect_url == "https://auth.serenity.now/v2/logout"


def test_auth0_standard_subdomain_for_user_info():
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    assert authenticator.user_info_url == "https://jupyterhub-test.auth0.com/userinfo"


def test_auth0_custom_domain_for_user_info():
    authenticator = Auth0OAuthenticator(auth0_custom_domain=auth0_custom_domain)
    assert authenticator.user_info_url == "https://auth.serenity.now/userinfo"


async def test_username_key(auth0_client):
    authenticator = Auth0OAuthenticator(auth0_subdomain=auth0_subdomain)
    authenticator.username_key = 'nickname'
    handler = auth0_client.handler_for_user(user_model('kaylee@serenity.now', 'kayle'))
    user_info = await authenticator.authenticate(handler)

    assert user_info['name'] == 'kayle'


async def test_custom_logout(monkeypatch):
    auth0_subdomain = 'auth0-domain.org'
    authenticator = Auth0OAuthenticator()
    logout_handler = mock_handler(OAuthLogoutHandler, authenticator=authenticator)
    monkeypatch.setattr(web.RequestHandler, 'redirect', Mock())

    logout_handler.clear_login_cookie = Mock()
    logout_handler.clear_cookie = Mock()
    logout_handler._jupyterhub_user = Mock()
    monkeypatch.setitem(logout_handler.settings, 'statsd', Mock())

    # Sanity check: Ensure the logout handler and url are set on the hub
    handlers = [handler for _, handler in authenticator.get_handlers(None)]
    assert any([h == OAuthLogoutHandler for h in handlers])
    assert authenticator.logout_url('http://myhost') == 'http://myhost/logout'

    # Check redirection to the custom logout url
    authenticator.auth0_subdomain = auth0_subdomain
    await logout_handler.get()
    custom_logout_url = f'https://{auth0_subdomain}.auth0.com/v2/logout'
    logout_handler.redirect.assert_called_with(custom_logout_url)
