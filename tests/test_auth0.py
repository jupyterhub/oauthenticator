import logging
from unittest.mock import Mock

from pytest import fixture, mark
from tornado import web
from traitlets.config import Config

from ..auth0 import Auth0OAuthenticator
from ..oauth2 import OAuthLogoutHandler
from .mocks import mock_handler, setup_oauth_mock

auth0_subdomain = "jupyterhub-test"
auth0_domain = "jupyterhub-test.auth0.com"


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
        host=auth0_domain,
        access_token_path='/oauth/token',
        user_path='/userinfo',
        token_request_style='json',
    )
    return client


@mark.parametrize(
    'config', [{"auth0_domain": auth0_domain}, {"auth0_subdomain": auth0_subdomain}]
)
async def test_auth0(config, auth0_client):
    authenticator = Auth0OAuthenticator(**config)
    handler = auth0_client.handler_for_user(user_model('kaylee@serenity.now'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'kaylee@serenity.now'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'auth0_user' in auth_state


@mark.parametrize(
    'config', [{"auth0_domain": auth0_domain}, {"auth0_subdomain": auth0_subdomain}]
)
async def test_username_key(config, auth0_client):
    authenticator = Auth0OAuthenticator(**config)
    authenticator.username_key = 'nickname'
    handler = auth0_client.handler_for_user(user_model('kaylee@serenity.now', 'kayle'))
    user_info = await authenticator.authenticate(handler)

    assert user_info['name'] == 'kayle'


async def test_custom_logout(monkeypatch):
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
    authenticator.auth0_domain = auth0_domain
    await logout_handler.get()
    custom_logout_url = f'https://{auth0_domain}/v2/logout'
    logout_handler.redirect.assert_called_with(custom_logout_url)


def test_deprecated_config(caplog):
    cfg = Config()
    cfg.Auth0OAuthenticator.username_key = 'nickname'
    log = logging.getLogger("testlog")
    authenticator = Auth0OAuthenticator(config=cfg, log=log)

    assert (
        log.name,
        logging.WARNING,
        'Auth0OAuthenticator.username_key is deprecated in Auth0OAuthenticator 16.0.0, use '
        'Auth0OAuthenticator.username_claim instead',
    ) in caplog.record_tuples

    assert authenticator.username_claim == 'nickname'
