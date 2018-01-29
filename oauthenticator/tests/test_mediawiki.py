import json
import re
import time
from unittest.mock import Mock

from pytest import fixture, mark
from tornado import web
import requests_mock

from ..mediawiki import MWOAuthenticator, AUTH_REQUEST_COOKIE_NAME

from .mocks import mock_handler
import jwt

MW_URL = 'https://meta.wikimedia.org/w/index.php'

@fixture
def mediawiki():
    def post_token(request, context):
        authorization_header = request.headers['Authorization'].decode('utf8')
        request_nonce = re.search(r'oauth_nonce="(.*?)"',
                                  authorization_header).group(1)
        return jwt.encode({
                        'username': 'wash',
                        'aud': 'client_id',
                        'iss': 'https://meta.wikimedia.org',
                        'iat': time.time(),
                        'nonce': request_nonce,
                    }, 'client_secret')

    with requests_mock.Mocker() as mock:
        mock.post('/w/index.php?title=Special%3AOAuth%2Finitiate',
            text='oauth_token=key&oauth_token_secret=secret',
        )
        mock.post('/w/index.php?title=Special%3AOAuth%2Ftoken',
            text='oauth_token=key&oauth_token_secret=secret')
        mock.post('/w/index.php?title=Special%3AOAuth%2Fidentify',
            content=post_token)
        yield mock

def new_authenticator():
    return MWOAuthenticator(
        client_id='client_id',
        client_secret='client_secret',
    )

@mark.gen_test
def test_mediawiki(mediawiki):
    authenticator = new_authenticator()
    handler = Mock(spec=web.RequestHandler,
        get_secure_cookie=Mock(
            return_value=json.dumps(
                ['key', 'secret']
            ).encode('utf8')
        ),
        request=Mock(
            query='oauth_token=key&oauth_verifier=me'
        )
    )
    user = yield authenticator.authenticate(handler, None)
    assert user['name'] == 'wash'
    auth_state = user['auth_state']
    assert auth_state['ACCESS_TOKEN_KEY'] == 'key'
    assert auth_state['ACCESS_TOKEN_SECRET'] == 'secret'
    identity = auth_state['MEDIAWIKI_USER_IDENTITY']
    assert identity['username'] == user['name']


@mark.gen_test
def test_login_redirect(mediawiki):
    authenticator = new_authenticator()
    record = []
    handler = mock_handler(authenticator.login_handler,
        'https://hub.example.com/hub/login',
        authenticator=authenticator,
        )
    handler.write = lambda buf: record.append(buf)
    yield handler.get()
    assert handler.get_status() == 302
    assert 'Location' in handler._headers
    assert handler._headers['Location'].startswith(MW_URL)
    assert 'Set-Cookie' in handler._headers
    assert AUTH_REQUEST_COOKIE_NAME in handler._headers['Set-Cookie']
