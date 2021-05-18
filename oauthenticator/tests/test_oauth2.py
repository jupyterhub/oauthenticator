import uuid
from unittest.mock import Mock

from ..oauth2 import _deserialize_state
from ..oauth2 import _serialize_state
from ..oauth2 import OAuthenticator
from ..oauth2 import OAuthLogoutHandler
from ..oauth2 import STATE_COOKIE_NAME
from .mocks import mock_handler


def test_serialize_state():
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
