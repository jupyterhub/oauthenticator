from io import BytesIO
import json
from urllib.parse import parse_qs
from pytest import fixture, raises
from tornado import web
from tornado.httpclient import HTTPResponse

from unittest.mock import Mock


from ..globus import GlobusOAuthenticator, GlobusLogoutHandler

from .mocks import setup_oauth_mock, mock_handler


def user_model(username):
    """Return a user model"""
    return {
        'preferred_username': username,
    }


def revoke_token_request_handler(request):
    assert request.method == 'POST', request.method
    auth_header = request.headers.get('Authorization')
    if auth_header:
        resp = BytesIO(json.dumps({'active': False}).encode('utf8'))
        return HTTPResponse(request=request, code=200, buffer=resp)
    else:
        return HTTPResponse(request=request, code=401)


@fixture
def mock_globus_token_response():
    return {
        'access_token': 'de48bedc44b79937f7aa67',
        'id_token': 'ClRha2UgbXkgbG92ZSwgdGFrZSBteSBsYW5kClRha2UgbWUgd2hlcmUgSS'
                    'BjYW5ub3Qgc3RhbmQKSSBkb24ndCBjYXJlIGNhdXNlIEknbSBzdGlsbCBm'
                    'cmVlCllvdSBjYW4ndCB0YWtlIHRoZSBza3kgZnJvbSBtZQpUYWtlIG1lIG'
                    '91dCwgdG8gdGhlIGJsYWNrClRlbGwgJ2VtIEkgYWluJ3QgY29taW5nIGJh'
                    'Y2sKQnVybiB0aGUgbGFuZCBhbmQgYm9pbCB0aGUgc2VhCllvdSBjYW4ndC'
                    'B0YWtlIHRoZSBza3kgZnJvbSBtZQpUaGVyZSdzIG5vIHBsYWNlIEkgY2Fu'
                    'IGJlClNpbmNlIEkgZm91bmQgc2VyZW5pdHkKWW91IGNhbid0IHRha2UgdG'
                    'hlIHNreSBmcm9tIG1lCg==',
        'expires_in': 172800,
        'resource_server': 'auth.globus.org',
        'token_type': 'Bearer',
        'state': '5a5929fa3c0210042c2fbb455e1e39d0',
        'other_tokens': [{
            'access_token': 'fceb9836f9b6d1ae7d',
            'expires_in': 172800,
            'resource_server': 'transfer.api.globus.org',
            'token_type': 'Bearer',
            'state': '5a5929fa3c0210042c2fbb455e1e39d0',
            'scope': 'urn:globus:auth:scope:transfer.api.globus.org:all'}],
        'scope': 'profile openid'}


@fixture
def globus_tokens_by_resource_server(mock_globus_token_response):
    token_attrs = ['expires_in', 'resource_server', 'scope',
                   'token_type', 'refresh_token', 'access_token']
    auth_token_dict = {attr_name: mock_globus_token_response.get(attr_name) for attr_name in
                       token_attrs}
    other_tokens = [{attr_name: token_dict.get(attr_name) for attr_name in token_attrs}
                    for token_dict in mock_globus_token_response['other_tokens']]
    tokens = other_tokens + [auth_token_dict]
    return {token_dict['resource_server']: token_dict for token_dict in tokens}


def set_extended_token_response(client, host, access_token_path, new_token_response):
    """The default client fixture does a nice job of checking the access code
    response while returning tokens in the oauth2 spec, but Globus returns
    a bunch of other tokens, including an id_token. We want to make sure we
    capture the full Globus token response. This will attach the dict
    new_token_response to the built-in test response if it returns successfully"""
    # Find the existing endpoint, function pair in client.hosts
    url, func = next(filter(lambda host: host[0]==access_token_path,
                            client.hosts[host]))
    # Wrap the built-in token response with our custom response, but only if
    # it returns successfully with an access token!
    def custom_token_response(request):
        response = func(request)
        if response.get('access_token'):
            # The original access_token is checked,
            new_token_response['access_token'] = response['access_token']
            return new_token_response
        else:
            return response

    # Return all existing paths with the addition of our custom wrapped handler.
    hosts = filter(lambda chost: chost[0] != access_token_path, client.hosts[host])
    client.add_host(host, [(url, custom_token_response)] + list(hosts))
    return client


@fixture
def globus_client(client, mock_globus_token_response):
    setup_oauth_mock(
        client,
        host='auth.globus.org',
        access_token_path='/v2/oauth2/token',
        user_path='/v2/oauth2/userinfo',
        token_type='bearer',
        token_request_style='post',
    )
    set_extended_token_response(client, 'auth.globus.org', '/v2/oauth2/token',
                                mock_globus_token_response)
    return client


@fixture
def mock_globus_user(globus_tokens_by_resource_server):
    class User:
        name = 'Wash'
        state = {'tokens': globus_tokens_by_resource_server}

        async def get_auth_state(self):
            return self.state

        async def save_auth_state(self, state):
            self.state = state
    return User()


async def test_globus(globus_client):
    authenticator = GlobusOAuthenticator()
    handler = globus_client.handler_for_user(user_model('wash@uflightacademy.edu'))
    data = await authenticator.authenticate(handler)
    assert data['name'] == 'wash'
    tokens = list(data['auth_state']['tokens'].keys())
    assert tokens == ['transfer.api.globus.org']


async def test_globus_pre_spawn_start(mock_globus_user):
    authenticator = GlobusOAuthenticator()
    spawner = Mock()
    spawner.environment = {}
    await authenticator.pre_spawn_start(mock_globus_user, spawner)
    assert 'GLOBUS_DATA' in spawner.environment

def test_globus_defaults():
    authenticator = GlobusOAuthenticator()
    assert all('https://auth.globus.org' in url for url in [
        authenticator.userdata_url,
        authenticator.authorize_url,
        authenticator.revocation_url,
        authenticator.token_url,
    ])
    assert authenticator.scope == [
        'openid', 'profile', 'urn:globus:auth:scope:transfer.api.globus.org:all'
    ]


async def test_restricted_domain(globus_client):
    authenticator = GlobusOAuthenticator()
    authenticator.identity_provider = 'alliance.gov'
    handler = globus_client.handler_for_user(user_model('wash@uflightacademy.edu'))
    with raises(web.HTTPError) as exc:
        await authenticator.authenticate(handler)
    assert exc.value.status_code == 403


async def test_namespaced_domain(globus_client):
    authenticator = GlobusOAuthenticator()
    # Allow any idp
    authenticator.identity_provider = ''
    um = user_model('wash@legitshipping.com@serenity.com')
    handler = globus_client.handler_for_user(um)
    data = await authenticator.authenticate(handler)
    assert data['name'] == 'wash'


async def test_token_exclusion(globus_client):
    authenticator = GlobusOAuthenticator()
    authenticator.exclude_tokens = [
        'transfer.api.globus.org',
        'auth.globus.org'
    ]
    handler = globus_client.handler_for_user(user_model('wash@uflightacademy.edu'))
    data = await authenticator.authenticate(handler)
    assert data['name'] == 'wash'
    assert list(data['auth_state']['tokens'].keys()) == []


async def test_revoke_tokens(globus_client, mock_globus_user):

    # Wrap the revocation host to 'revoke' tokens by setting them in user auth
    # state. This way, we can get feedback to tell if the token was actually
    # sent to our 'host'
    def tok_revoke(request):
        resp = revoke_token_request_handler(request)
        token = parse_qs(request.body.decode('utf8'))['token'][0]
        for token_dict in mock_globus_user.state['tokens'].values():
            if token_dict['access_token'] == token:
                token_dict['access_token'] = 'token_revoked'
            if token_dict['refresh_token'] == token:
                token_dict['refresh_token'] = 'token_revoked'
        return resp
    # Add the token revocation endpoint. It's the only revocation endpoint we need.
    globus_client.add_host('auth.globus.org', [('/v2/oauth2/token/revoke',
                                               tok_revoke)])
    # Add refresh tokens to ensure those get revoked too.
    mock_globus_user.state['tokens']['auth.globus.org']['refresh_token'] = \
        'my_active_auth_refresh_token'
    mock_globus_user.state['tokens']['transfer.api.globus.org']['refresh_token'] = \
        'my_active_transfer_refresh_token'

    # Revoke the tokens!
    authenticator = GlobusOAuthenticator()
    await authenticator.revoke_service_tokens(mock_globus_user.state['tokens'])

    # Check tokens were properly revoked.
    user_tokens = mock_globus_user.state['tokens']
    assert user_tokens['auth.globus.org']['access_token'] == 'token_revoked'
    assert user_tokens['auth.globus.org']['access_token'] == 'token_revoked'
    assert user_tokens['transfer.api.globus.org']['access_token'] == 'token_revoked'
    assert user_tokens['transfer.api.globus.org']['access_token'] == 'token_revoked'


async def test_custom_logout(monkeypatch, mock_globus_user):
    custom_logout_url = 'https://universityofindependence.edu/logout'
    authenticator = GlobusOAuthenticator()
    logout_handler = mock_handler(GlobusLogoutHandler,
                                  authenticator=authenticator)
    monkeypatch.setattr(web.RequestHandler, 'redirect', Mock())
    logout_handler.clear_login_cookie = Mock()
    logout_handler.get_current_user = Mock(return_value=mock_globus_user)
    logout_handler._jupyterhub_user = mock_globus_user
    monkeypatch.setitem(logout_handler.settings, 'statsd', Mock())

    # Sanity check: Ensure the logout handler and url are set on the hub
    handlers = [handler for _, handler in authenticator.get_handlers(None)]
    assert any([h == GlobusLogoutHandler for h in handlers])
    assert authenticator.logout_url('http://myhost') == 'http://myhost/logout'

    # Test the logout handler uses the custom URL
    authenticator.logout_redirect_url = custom_logout_url
    await logout_handler.get()
    logout_handler.redirect.assert_called_once_with(custom_logout_url)
    assert logout_handler.clear_login_cookie.called


async def test_logout_revokes_tokens(globus_client, monkeypatch, mock_globus_user):
    globus_client.add_host('auth.globus.org', [('/v2/oauth2/token/revoke',
                                               revoke_token_request_handler)])
    authenticator = GlobusOAuthenticator()
    logout_handler = mock_handler(GlobusLogoutHandler, authenticator=authenticator)

    # Setup
    monkeypatch.setattr(web.RequestHandler, 'redirect', Mock())
    logout_handler.get_current_user = Mock(return_value=mock_globus_user)
    logout_handler._jupyterhub_user = mock_globus_user
    monkeypatch.setitem(logout_handler.settings, 'statsd', Mock())
    monkeypatch.setitem(logout_handler.settings, 'login_url', '')

    logout_handler.clear_login_cookie = Mock()
    authenticator.revoke_tokens_on_logout = True

    await logout_handler.get()
    auth_state = await mock_globus_user.get_auth_state()
    assert auth_state == {'tokens': {}}
