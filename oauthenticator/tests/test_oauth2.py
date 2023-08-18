import re
import uuid
from unittest.mock import Mock, PropertyMock

from pytest import mark
from traitlets.config import Config

from ..oauth2 import (
    STATE_COOKIE_NAME,
    OAuthenticator,
    OAuthLoginHandler,
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


def test_login_states():
    login_url = "http://myhost/login"
    login_request_uri = "http://myhost/login?next=/ABC"
    authenticator = OAuthenticator()
    login_handler = mock_handler(
        OAuthLoginHandler,
        uri=login_request_uri,
        authenticator=authenticator,
        login_url=login_url,
    )

    state_id = '66383228bb924e9bb8a8ff9e311b7966'
    login_handler._generate_state_id = Mock(return_value=state_id)

    login_handler.set_state_cookie = Mock()
    login_handler.authorize_redirect = Mock()

    login_handler.get()  # no await, we've mocked the authorizer_redirect to NOT be async

    expected_cookie_value = _serialize_state(
        {
            'state_id': state_id,
            'next_url': '/ABC',
        }
    )

    login_handler.set_state_cookie.assert_called_once_with(expected_cookie_value)

    expected_state_param_value = _serialize_state(
        {
            'state_id': state_id,
        }
    )

    login_handler.authorize_redirect.assert_called_once()
    assert (
        login_handler.authorize_redirect.call_args.kwargs['extra_params']['state']
        == expected_state_param_value
    )


def test_callback_check_states_match():
    raise NotImplementedError


def test_callback_check_states_nomatch():
    raise NotImplementedError


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
