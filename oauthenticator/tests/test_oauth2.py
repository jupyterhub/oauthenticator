import re
import uuid
from unittest.mock import Mock, PropertyMock

from pytest import mark
from traitlets.config import Config

from ..oauth2 import (
    STATE_COOKIE_NAME,
    OAuthenticator,
    OAuthLogoutHandler,
    _deserialize_state,
    _serialize_state,
)
from .mocks import mock_handler


async def test_serialize_state():
    state1 = {
        'state_id': uuid.uuid4().hex,
        'next': 'url',
    }
    b64_state = _serialize_state(state1)
    assert isinstance(b64_state, str)
    state2 = _deserialize_state(b64_state)
    assert state2 == state1


async def test_custom_logout(monkeypatch):
    login_url = "http://myhost/login"
    authenticator = OAuthenticator()
    logout_handler = mock_handler(
        OAuthLogoutHandler, authenticator=authenticator, login_url=login_url
    )
    logout_handler.clear_login_cookie = Mock()
    logout_handler.clear_cookie = Mock()
    logout_handler._jupyterhub_user = Mock()
    monkeypatch.setitem(logout_handler.settings, 'statsd', Mock())

    # Sanity check: Ensure the logout handler and url are set on the hub
    handlers = [handler for _, handler in authenticator.get_handlers(None)]
    assert any([h == OAuthLogoutHandler for h in handlers])
    assert authenticator.logout_url('http://myhost') == 'http://myhost/logout'

    await logout_handler.get()
    assert logout_handler.clear_login_cookie.called
    logout_handler.clear_cookie.assert_called_once_with(STATE_COOKIE_NAME)


async def test_httpfetch(client):
    authenticator = OAuthenticator()
    authenticator.http_request_kwargs = {
        "proxy_host": "proxy.example.org",
        "proxy_port": 8080,
    }

    # Return request fields as the response so we can examine it
    client.add_host(
        "example.org",
        [
            (
                re.compile(".*"),
                lambda req: [req.url, req.method, req.proxy_host, req.proxy_port],
            ),
        ],
    )
    authenticator.http_client = client

    r = await authenticator.httpfetch("http://example.org/a")
    assert r == ['http://example.org/a', 'GET', "proxy.example.org", 8080]


@mark.parametrize(
    "test_variation_id,class_config",
    [
        ("01", {"allow_existing_users": False}),
        ("02", {"allow_existing_users": True}),
    ],
)
async def test_add_user_override(
    test_variation_id,
    class_config,
):
    """
    This test validates expectations on the Authenticator.add_user override
    we've implemented in OAuthenticator in place to implement
    allow_existing_users.

    This is not fully testing the allow_existing_users config though, as we for
    example are not validating the assumptions that the add_user hook is called
    for each existing user at least once or that adjusting the allowed_users
    list works well.
    """
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.OAuthenticator = Config(class_config)
    authenticator = OAuthenticator(config=c)

    # prepare dummy user object with a name property
    added_user = Mock()
    added_user_name_property = PropertyMock(return_value="user1")
    type(added_user).name = added_user_name_property

    authenticator.add_user(added_user)

    # assert that the user object's name property was accessed as expected, and
    # that the allowed_users set was updated as expected
    assert added_user_name_property.called
    if authenticator.allow_existing_users:
        assert added_user.name in authenticator.allowed_users
    else:
        assert added_user.name not in authenticator.allowed_users
