from pytest import fixture, mark, raises
from tornado import web
from unittest.mock import Mock

from globus_sdk import ConfidentialAppAuthClient

from ..globus import GlobusOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


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
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'globus_data' in auth_state
    assert list(auth_state['globus_data']['tokens'].keys()) == \
        ['transfer.api.globus.org']


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
    user_info = yield authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'globus_data' in auth_state
    assert list(auth_state['globus_data']['tokens'].keys()) == []
