import json
import re
import time
from unittest.mock import Mock

import jwt
import requests_mock
from pytest import fixture, mark
from tornado import web
from traitlets.config import Config

from ..mediawiki import AUTH_REQUEST_COOKIE_NAME, MWOAuthenticator
from .mocks import mock_handler


@fixture
def mediawiki():
    def post_token(request, context):
        authorization_header = request.headers['Authorization'].decode('utf8')
        request_nonce = re.search(r'oauth_nonce="(.*?)"', authorization_header).group(1)
        content = jwt.encode(
            {
                'username': 'user1',
                'aud': 'client_id',
                'iss': 'https://meta.wikimedia.org',
                'iat': time.time(),
                'nonce': request_nonce,
            },
            'client_secret',
        ).encode()

        return content

    with requests_mock.Mocker() as mock:
        mock.post(
            '/w/index.php?title=Special%3AOAuth%2Finitiate',
            text='oauth_token=key&oauth_token_secret=secret',
        )
        mock.post(
            '/w/index.php?title=Special%3AOAuth%2Ftoken',
            text='oauth_token=key&oauth_token_secret=secret',
        )
        mock.post('/w/index.php?title=Special%3AOAuth%2Fidentify', content=post_token)
        yield mock


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
async def test_mediawiki(
    mediawiki,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.MWOAuthenticator = Config(class_config)
    c.MWOAuthenticator.client_id = "client_id"
    c.MWOAuthenticator.client_secret = "client_secret"
    c.MWOAuthenticator.username_claim = "username"
    authenticator = MWOAuthenticator(config=c)

    handler = Mock(
        spec=web.RequestHandler,
        get_secure_cookie=Mock(return_value=json.dumps(['key', 'secret'])),
        request=Mock(query='oauth_token=key&oauth_verifier=me'),
        find_user=Mock(return_value=None),
    )
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "ACCESS_TOKEN_KEY" in auth_state
        assert "ACCESS_TOKEN_SECRET" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert auth_model["name"] == user_info[authenticator.username_claim]
    else:
        assert auth_model == None


async def test_login_redirect(mediawiki):
    authenticator = MWOAuthenticator(
        client_id='client_id',
        client_secret='client_secret',
    )
    record = []
    handler = mock_handler(
        authenticator.login_handler,
        'https://hub.example.com/hub/login',
        authenticator=authenticator,
    )
    handler.write = lambda buf: record.append(buf)
    await handler.get()
    assert handler.get_status() == 302
    assert 'Location' in handler._headers
    assert handler._headers['Location'].startswith(authenticator.mw_index_url)
    assert 'Set-Cookie' in handler._headers
    assert AUTH_REQUEST_COOKIE_NAME in handler._headers['Set-Cookie']
