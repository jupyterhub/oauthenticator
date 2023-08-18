import re
import uuid
from unittest.mock import Mock, PropertyMock

from pytest import mark, raises
from tornado.web import HTTPError
from traitlets.config import Config

from ..oauth2 import (
    STATE_COOKIE_NAME,
    OAuthCallbackHandler,
    OAuthenticator,
    OAuthLoginHandler,
    OAuthLogoutHandler,
    _deserialize_state,
    _serialize_state,
)
from .mocks import mock_handler, mock_login_user_coro


async def test_serialize_state():
    state1 = {
        'state_id': uuid.uuid4().hex,
        'next': 'url',
    }
    b64_state = _serialize_state(state1)
    assert isinstance(b64_state, str)
    state2 = _deserialize_state(b64_state)
    assert state2 == state1


TEST_STATE_ID = '123'
TEST_NEXT_URL = '/ABC'


async def test_login_states():
    login_request_uri = f"http://myhost/login?next={TEST_NEXT_URL}"
    authenticator = OAuthenticator()
    login_handler = mock_handler(
        OAuthLoginHandler,
        uri=login_request_uri,
        authenticator=authenticator,
    )

    login_handler._generate_state_id = Mock(return_value=TEST_STATE_ID)

    login_handler.set_state_cookie = Mock()
    login_handler.authorize_redirect = Mock()

    login_handler.get()  # no await, we've mocked the authorizer_redirect to NOT be async

    expected_cookie_value = _serialize_state(
        {
            'state_id': TEST_STATE_ID,
            'next_url': TEST_NEXT_URL,
        }
    )

    login_handler.set_state_cookie.assert_called_once_with(expected_cookie_value)

    expected_state_param_value = _serialize_state(
        {
            'state_id': TEST_STATE_ID,
        }
    )

    login_handler.authorize_redirect.assert_called_once()
    assert (
        login_handler.authorize_redirect.call_args.kwargs['extra_params']['state']
        == expected_state_param_value
    )


async def test_callback_check_states_match(monkeypatch):
    url_state = _serialize_state({'state_id': TEST_STATE_ID})
    callback_request_uri = f"http://myhost/callback?code=123&state={url_state}"

    cookie_state = _serialize_state(
        {
            'state_id': TEST_STATE_ID,
            'next_url': TEST_NEXT_URL,
        }
    )

    authenticator = OAuthenticator()
    callback_handler = mock_handler(
        OAuthCallbackHandler,
        uri=callback_request_uri,
        authenticator=authenticator,
    )

    callback_handler.get_secure_cookie = Mock(return_value=cookie_state.encode('utf8'))
    callback_handler.login_user = Mock(return_value=mock_login_user_coro())
    callback_handler.redirect = Mock()

    await callback_handler.get()

    callback_handler.redirect.assert_called_once_with('/ABC')


async def test_callback_check_states_nomatch():
    wrong_url_state = _serialize_state({'state_id': 'wr0ng'})
    callback_request_uri = f"http://myhost/callback?code=123&state={wrong_url_state}"

    cookie_state = _serialize_state(
        {
            'state_id': TEST_STATE_ID,
            'next_url': TEST_NEXT_URL,
        }
    )

    authenticator = OAuthenticator()
    callback_handler = mock_handler(
        OAuthCallbackHandler,
        uri=callback_request_uri,
        authenticator=authenticator,
    )

    callback_handler.get_secure_cookie = Mock(return_value=cookie_state.encode('utf8'))

    with raises(HTTPError, match="OAuth state mismatch"):
        await callback_handler.get()


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
