import re
import uuid
from http.cookies import SimpleCookie
from unittest.mock import Mock, PropertyMock, call
from urllib.parse import urlencode

from pytest import FixtureRequest, fixture, mark, raises
from tornado.web import HTTPError, RequestHandler
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


@mark.parametrize("enable_pkce", [True, False])
async def test_login_states(enable_pkce):
    login_request_uri = f"http://myhost/login?next={TEST_NEXT_URL}"
    authenticator = OAuthenticator(enable_pkce=enable_pkce)
    login_handler = mock_handler(
        OAuthLoginHandler,
        uri=login_request_uri,
        authenticator=authenticator,
    )

    login_handler._generate_state_id = Mock(return_value=TEST_STATE_ID)
    code_verifier, code_challenge = login_handler._generate_pkce_params()
    login_handler._generate_pkce_params = Mock(
        return_value=(code_verifier, code_challenge)
    )
    login_handler.set_state_cookie = Mock()
    login_handler.authorize_redirect = Mock()

    login_handler.get()  # no await, we've mocked the authorizer_redirect to NOT be async

    expected_state = {
        'state_id': TEST_STATE_ID,
        'next_url': TEST_NEXT_URL,
    }
    if enable_pkce:
        expected_state['code_verifier'] = code_verifier
    login_handler.set_state_cookie.assert_called_once_with(expected_state)

    expected_state_param_value = {
        'state': _serialize_state({'state_id': TEST_STATE_ID})
    }
    if enable_pkce:
        expected_state_param_value['code_challenge'] = code_challenge
        expected_state_param_value['code_challenge_method'] = 'S256'

    login_handler.authorize_redirect.assert_called_once()
    assert (
        login_handler.authorize_redirect.call_args.kwargs['extra_params']
        == expected_state_param_value
    )


class Browser:
    """Carries signed cookies between Hub handlers, as a browser would."""

    def __init__(self, authenticator: OAuthenticator) -> None:
        self.authenticator = authenticator
        self.cookies = SimpleCookie()
        self.cookie_secret = uuid.uuid4().bytes

    def _request(self, handler_class: type[RequestHandler], uri: str):
        handler = mock_handler(handler_class, uri=uri, authenticator=self.authenticator)
        handler.settings["cookie_secret"] = self.cookie_secret
        handler.request.headers["Cookie"] = self.cookies.output(
            attrs=[], header="", sep=";"
        )
        return handler

    def _store_cookies(self, handler: RequestHandler) -> None:
        for name, morsel in handler._new_cookie.items():
            if morsel.value:
                self.cookies[name] = morsel
            else:
                self.cookies.pop(name, None)

    def login(self, next_url: str) -> str:
        """Start a login and return the state sent to the identity provider."""
        login = self._request(
            OAuthLoginHandler, f"http://myhost/login?{urlencode({'next': next_url})}"
        )
        login.authorize_redirect = Mock()
        login.get()
        self._store_cookies(login)
        return login.authorize_redirect.call_args.kwargs["extra_params"]["state"]

    def callback(self, url_state: str) -> OAuthCallbackHandler:
        callback = self._request(
            OAuthCallbackHandler,
            f"http://myhost/callback?{urlencode({'code': '123', 'state': url_state})}",
        )
        callback.check_arguments()
        self._store_cookies(callback)
        return callback

    async def logout(self) -> None:
        logout = self._request(OAuthLogoutHandler, "http://myhost/logout")
        await logout.handle_logout()
        self._store_cookies(logout)


@fixture(params=[True, False], ids=["pkce", "no-pkce"])
def browser(request: FixtureRequest) -> Browser:
    return Browser(OAuthenticator(enable_pkce=request.param))


async def test_overlapping_logins_complete_in_order(browser: Browser) -> None:
    first = browser.login("/hub/user/alice/lab")
    second = browser.login("/hub/home")
    assert len(browser.cookies) == 2
    assert all(
        morsel["max-age"] == "600" and not morsel["expires"] and morsel["httponly"]
        for morsel in browser.cookies.values()
    )

    first_callback = browser.callback(first)
    second_callback = browser.callback(second)

    assert first_callback.get_next_url() == "/hub/user/alice/lab"
    assert second_callback.get_next_url() == "/hub/home"
    assert not browser.cookies


async def test_overlapping_logins_complete_in_reverse_order(browser: Browser) -> None:
    first = browser.login("/hub/user/alice/lab")
    second = browser.login("/hub/home")

    second_callback = browser.callback(second)
    first_callback = browser.callback(first)

    assert first_callback.get_next_url() == "/hub/user/alice/lab"
    assert second_callback.get_next_url() == "/hub/home"
    assert not browser.cookies


async def test_logout_cancels_overlapping_logins(browser: Browser) -> None:
    first = browser.login("/hub/user/alice/lab")
    second = browser.login("/hub/home")

    await browser.logout()

    assert not browser.cookies
    for url_state in (first, second):
        with raises(HTTPError, match="OAuth state missing from cookies"):
            browser.callback(url_state)


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
    callback_handler.get_secure_cookie.assert_called_once_with(
        f"{STATE_COOKIE_NAME}-{TEST_STATE_ID}"
    )
    assert list(callback_handler._new_cookie) == [
        f"{STATE_COOKIE_NAME}-{TEST_STATE_ID}"
    ]


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


@mark.parametrize(
    "url_state",
    [
        None,
        "",
        "not-base64",
        _serialize_state({}),
        _serialize_state({"state_id": "unknown"}),
        _serialize_state({"state_id": "invalid;cookie=name"}),
    ],
)
async def test_callback_missing_state_cookie(url_state: str | None) -> None:
    arguments = {"code": "123"}
    if url_state is not None:
        arguments["state"] = url_state
    callback = mock_handler(
        OAuthCallbackHandler,
        uri=f"http://myhost/callback?{urlencode(arguments)}",
        authenticator=OAuthenticator(),
    )
    expected_error = (
        "Missing argument state"
        if url_state is None
        else "OAuth state missing from cookies"
    )
    with raises(HTTPError, match=expected_error) as error:
        await callback.get()
    assert error.value.status_code == 400
    assert not getattr(callback, "_new_cookie", {})


async def test_custom_logout(monkeypatch):
    login_url = "http://myhost/login"
    authenticator = OAuthenticator()
    logout_handler = mock_handler(
        OAuthLogoutHandler, authenticator=authenticator, login_url=login_url
    )
    logout_handler.clear_login_cookie = Mock()
    logout_handler.clear_cookie = Mock()
    logout_handler._jupyterhub_user = Mock()
    logout_handler.request.headers["Cookie"] = (
        f"{STATE_COOKIE_NAME}-first=one; {STATE_COOKIE_NAME}-second=two; unrelated=keep"
    )
    monkeypatch.setitem(logout_handler.settings, 'statsd', Mock())

    # Sanity check: Ensure the logout handler and url are set on the hub
    handlers = [handler for _, handler in authenticator.get_handlers(None)]
    assert any([h == OAuthLogoutHandler for h in handlers])
    assert authenticator.logout_url('http://myhost') == 'http://myhost/logout'

    await logout_handler.get()
    assert logout_handler.clear_login_cookie.called
    assert logout_handler.clear_cookie.call_args_list == [
        call(STATE_COOKIE_NAME),
        call(f"{STATE_COOKIE_NAME}-first"),
        call(f"{STATE_COOKIE_NAME}-second"),
    ]


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
