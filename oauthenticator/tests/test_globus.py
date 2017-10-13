from pytest import fixture, mark, raises
from tornado import web, gen
from unittest.mock import Mock

from globus_sdk import ConfidentialAppAuthClient

from ..globus import GlobusOAuthenticator, GlobusLogoutHandler

from .mocks import setup_oauth_mock, no_code_test, mock_handler


def user_model(username):
    """Return a user model"""
    return {
        'login': username,
    }


@fixture
def mock_globus_sdk(monkeypatch):
    """Mock the globus_sdk request for 'oauth2_exchange_code_for_tokens', and
    mock some of the items within the returned 'Tokens' class. """

    class Tokens:

        by_resource_server = {
            'transfer.api.globus.org': {'access_token': 'TRANSFER_TOKEN'},
            'auth.globus.org': {'access_token': 'AUTH_TOKEN'}

        }
        id_token = {'preferred_username': 'wash@globusid.org'}

        def decode_id_token(self, client):
            return self.id_token

    tokens = Tokens()
    monkeypatch.setattr(
        ConfidentialAppAuthClient,
        'oauth2_exchange_code_for_tokens',
        lambda self, code: tokens
    )
    return tokens


@fixture
def globus_client(client):
    setup_oauth_mock(
        client,
        host=['auth.globus.org'],
        access_token_path='/v2/oauth2/token',
        user_path='/userinfo',
        token_type='bearer',
    )
    return client


@mark.gen_test
def test_globus(globus_client, mock_globus_sdk):
    authenticator = GlobusOAuthenticator()
    handler = globus_client.handler_for_user(user_model('wash'))
    data = yield authenticator.authenticate(handler)
    assert data['name'] == 'wash'
    tokens = list(data['auth_state']['tokens'].keys())
    assert tokens == ['transfer.api.globus.org']


@mark.gen_test
def test_allow_refresh_tokens(globus_client, mock_globus_sdk, monkeypatch):
    authenticator = GlobusOAuthenticator()
    # Sanity check, this field should be set to True
    assert authenticator.allow_refresh_tokens is True
    authenticator.allow_refresh_tokens = False
    monkeypatch.setattr(
        ConfidentialAppAuthClient,
        'oauth2_start_flow',
        Mock()
    )
    handler = globus_client.handler_for_user(user_model('wash'))
    yield authenticator.authenticate(handler)
    ConfidentialAppAuthClient.oauth2_start_flow.assert_called_with(
        authenticator.get_callback_url(None),
        requested_scopes=' '.join(authenticator.scope),
        refresh_tokens=False
    )


@mark.gen_test
def test_restricted_domain(globus_client, mock_globus_sdk):
    mock_globus_sdk.id_token = {'preferred_username': 'wash@serenity.com'}
    authenticator = GlobusOAuthenticator()
    authenticator.identity_provider = 'alliance.gov'
    handler = globus_client.handler_for_user(user_model('wash'))
    with raises(web.HTTPError) as exc:
        yield authenticator.authenticate(handler)
    assert exc.value.status_code == 403


@mark.gen_test
def test_token_exclusion(globus_client, mock_globus_sdk):
    authenticator = GlobusOAuthenticator()
    authenticator.exclude_tokens = [
        'transfer.api.globus.org',
        'auth.globus.org'
    ]
    handler = globus_client.handler_for_user(user_model('wash'))
    data = yield authenticator.authenticate(handler)
    assert data['name'] == 'wash'
    assert list(data['auth_state']['tokens'].keys()) == []


def test_revoke_tokens(monkeypatch):
    monkeypatch.setattr(
        ConfidentialAppAuthClient,
        'oauth2_revoke_token',
        Mock()
    )
    authenticator = GlobusOAuthenticator()
    service = {'transfer.api.globus.org': {'access_token': 'foo',
                                           'refresh_token': 'bar'}}
    authenticator.revoke_service_tokens(service)
    assert ConfidentialAppAuthClient.oauth2_revoke_token.called


@mark.gen_test
def test_custom_logout(monkeypatch):
    custom_logout_url = 'https://universityofindependence.edu/logout'
    authenticator = GlobusOAuthenticator()
    logout_handler = mock_handler(GlobusLogoutHandler,
                                  authenticator=authenticator)
    monkeypatch.setattr(
        web.RequestHandler,
        'redirect',
        Mock()
    )
    logout_handler.clear_login_cookie = Mock()
    logout_handler.get_current_user = Mock()

    authenticator.logout_redirect_url = custom_logout_url
    yield logout_handler.get()
    logout_handler.redirect.assert_called_once_with(custom_logout_url)
    assert logout_handler.clear_login_cookie.called


@mark.gen_test
def test_logout_revokes_tokens(monkeypatch):

    class User:
        @gen.coroutine
        def get_auth_state(self):
            return {'tokens': {}}

        save_auth_state = Mock()
        name = 'Wash'

    user = User()
    authenticator = GlobusOAuthenticator()
    logout_handler = mock_handler(GlobusLogoutHandler,
                                  authenticator=authenticator)
    monkeypatch.setattr(
        web.RequestHandler,
        'redirect',
        Mock()
    )
    logout_handler.clear_login_cookie = Mock()
    authenticator.revoke_service_tokens = Mock()
    authenticator.revoke_tokens_on_logout = True

    yield logout_handler.clear_tokens(user)
    assert authenticator.revoke_service_tokens.called
    assert user.save_auth_state.called
