import json
import logging
from unittest.mock import Mock

from pytest import fixture, mark, raises
from tornado import web
from traitlets.config import Config

from ..auth0 import Auth0OAuthenticator
from ..oauth2 import OAuthLogoutHandler
from .mocks import mock_handler, setup_oauth_mock

AUTH0_DOMAIN = "jupyterhub-test.auth0.com"


@fixture
def auth0_client(client):
    setup_oauth_mock(
        client,
        host=AUTH0_DOMAIN,
        access_token_path='/oauth/token',
        user_path='/userinfo',
    )
    return client


def user_model():
    """Return a user model"""
    return {
        "email": "user1@example.com",
        "name": "user1",
    }


@mark.parametrize(
    "test_variation_id,class_config,expect_allowed,expect_admin",
    [
        # no allow config tested
        ("00", {}, False, None),
        # allow config, individually tested
        ("01", {"allow_all": True}, True, None),
        ("02", {"allowed_users": {"user1"}}, True, None),
        ("03", {"allowed_users": {"not-test-user"}}, False, None),
        ("04", {"admin_users": {"user1"}}, True, True),
        ("05", {"admin_users": {"not-test-user"}}, False, None),
        # allow config, some combinations of two tested
        (
            "10",
            {
                "allow_all": False,
                "allowed_users": {"not-test-user"},
            },
            False,
            None,
        ),
        (
            "11",
            {
                "admin_users": {"user1"},
                "allowed_users": {"not-test-user"},
            },
            True,
            True,
        ),
    ],
)
async def test_auth0(
    auth0_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.Auth0OAuthenticator = Config(class_config)
    c.Auth0OAuthenticator.auth0_domain = AUTH0_DOMAIN
    c.Auth0OAuthenticator.username_claim = "name"
    authenticator = Auth0OAuthenticator(config=c)

    handled_user_model = user_model()
    handler = auth0_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
        assert auth_model["name"] == user_info[authenticator.username_claim]
    else:
        assert auth_model == None


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
    authenticator.auth0_domain = AUTH0_DOMAIN
    await logout_handler.get()
    custom_logout_url = f'https://{AUTH0_DOMAIN}/v2/logout'
    logout_handler.redirect.assert_called_with(custom_logout_url)


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "username_key",
            {"username_key": "dummy"},
            {"username_claim": "dummy"},
            logging.WARNING,
            "Auth0OAuthenticator.username_key is deprecated in Auth0OAuthenticator 16.0.0, use Auth0OAuthenticator.username_claim instead",
        ),
    ],
)
async def test_deprecated_config(
    caplog,
    test_variation_id,
    class_config,
    expect_config,
    expect_loglevel,
    expect_message,
):
    """
    Tests that a warning is emitted when using a deprecated config and that
    configuring the old config ends up configuring the new config.
    """
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.Auth0OAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            Auth0OAuthenticator(config=c, log=test_logger)
    else:
        authenticator = Auth0OAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
