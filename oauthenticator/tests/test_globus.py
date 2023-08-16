import json
from io import BytesIO
from unittest.mock import Mock
from urllib.parse import parse_qs

from pytest import fixture, mark, raises
from tornado import web
from tornado.httpclient import HTTPResponse
from traitlets.config import Config

from ..globus import GlobusLogoutHandler, GlobusOAuthenticator
from ..oauth2 import STATE_COOKIE_NAME
from .mocks import mock_handler, setup_oauth_mock


def user_model(username, **kwargs):
    """Return a user model"""
    return {
        "preferred_username": username,
        **kwargs,
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
        'other_tokens': [
            {
                'access_token': 'fceb9836f9b6d1ae7d',
                'expires_in': 172800,
                'resource_server': 'transfer.api.globus.org',
                'token_type': 'Bearer',
                'state': '5a5929fa3c0210042c2fbb455e1e39d0',
                'scope': 'urn:globus:auth:scope:transfer.api.globus.org:all',
            },
            {
                'access_token': '309f9e6367d1ffffae0da625cb87b9ac543ee72a',
                'expires_in': 172800,
                'resource_server': 'groups.api.globus.org',
                'token_type': 'Bearer',
                'scope': 'urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships',
            },
        ],
        'scope': 'profile openid',
    }


def get_groups_request_handler(request):
    mock_globus_groups_response = [
        {
            # group's IDs should really be UUIDs, but a simpler string is used
            # for consistency between tests
            'id': 'group1',
            'my_memberships': [{'role': 'member'}],
        },
    ]
    assert request.method == 'GET', request.method
    resp = BytesIO(json.dumps(mock_globus_groups_response).encode('utf-8'))
    return HTTPResponse(
        request=request,
        code=200,
        headers={'Content-Type': 'application/json'},
        buffer=resp,
    )


@fixture
def globus_tokens_by_resource_server(mock_globus_token_response):
    token_attrs = [
        'expires_in',
        'resource_server',
        'scope',
        'token_type',
        'refresh_token',
        'access_token',
    ]
    auth_token_dict = {
        attr_name: mock_globus_token_response.get(attr_name)
        for attr_name in token_attrs
    }
    other_tokens = [
        {attr_name: token_dict.get(attr_name) for attr_name in token_attrs}
        for token_dict in mock_globus_token_response['other_tokens']
    ]
    tokens = other_tokens + [auth_token_dict]
    return {token_dict['resource_server']: token_dict for token_dict in tokens}


def set_extended_token_response(client, host, access_token_path, new_token_response):
    """The default client fixture does a nice job of checking the access code
    response while returning tokens in the oauth2 spec, but Globus returns
    a bunch of other tokens, including an id_token. We want to make sure we
    capture the full Globus token response. This will attach the dict
    new_token_response to the built-in test response if it returns successfully"""
    # Find the existing endpoint, function pair in client.hosts
    url, func = next(
        filter(lambda host: host[0] == access_token_path, client.hosts[host])
    )

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
    )
    set_extended_token_response(
        client, 'auth.globus.org', '/v2/oauth2/token', mock_globus_token_response
    )
    client.add_host(
        'groups.api.globus.org',
        [
            ('/v2/groups/my_groups', get_groups_request_handler),
        ],
    )
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
        ("06", {"allowed_globus_groups": {"group1"}}, True, None),
        ("07", {"allowed_globus_groups": {"test-user-not-in-group"}}, False, None),
        ("08", {"admin_globus_groups": {"group1"}}, True, True),
        ("09", {"admin_globus_groups": {"test-user-not-in-group"}}, False, False),
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
                "allowed_users": {"not-test-user"},
                "admin_users": {"user1"},
            },
            True,
            True,
        ),
        (
            "12",
            {
                "allowed_globus_groups": {"group1"},
                "admin_globus_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "13",
            {
                "allowed_globus_groups": {"group1"},
                "admin_globus_groups": {"test-user-not-in-group"},
            },
            True,
            False,
        ),
        (
            "14",
            {
                "allowed_globus_groups": {"test-user-not-in-group"},
                "admin_globus_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "15",
            {
                "allowed_globus_groups": {"test-user-not-in-group"},
                "admin_globus_groups": {"test-user-not-in-group"},
            },
            False,
            False,
        ),
        (
            "16",
            {
                "admin_users": {"user1"},
                "admin_globus_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "17",
            {
                "admin_users": {"user1"},
                "admin_globus_groups": {"test-user-not-in-group"},
            },
            True,
            True,
        ),
        (
            "18",
            {
                "admin_users": {"not-test-user"},
                "admin_globus_groups": {"group1"},
            },
            True,
            True,
        ),
        (
            "19",
            {
                "admin_users": {"not-test-user"},
                "admin_globus_groups": {"test-user-not-in-group"},
            },
            False,
            False,
        ),
    ],
)
async def test_globus(
    globus_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.GlobusOAuthenticator = Config(class_config)
    c.GlobusOAuthenticator.username_claim = "preferred_username"
    authenticator = GlobusOAuthenticator(config=c)

    handled_user_model = user_model("user1")
    handler = globus_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "tokens" in auth_state
        assert "transfer.api.globus.org" in auth_state["tokens"]
        user_info = auth_state[authenticator.user_auth_state_key]
        assert auth_model["name"] == user_info[authenticator.username_claim]
        if authenticator.allowed_globus_groups or authenticator.admin_globus_groups:
            assert auth_state["globus_groups"] == ["group1"]
    else:
        assert auth_model == None


@mark.parametrize(
    "name, allowed",
    [
        ("allowed", True),
        ("notallowed", False),
    ],
)
async def test_check_allowed_no_auth_state(name, allowed):
    authenticator = GlobusOAuthenticator(allowed_users={"allowed"})
    # allow check always gets called with no auth model during Hub startup
    # these are previously-allowed users who should pass until subsequent
    # this check is removed in JupyterHub 5
    assert await authenticator.check_allowed(name, None)


async def test_globus_pre_spawn_start(mock_globus_user):
    authenticator = GlobusOAuthenticator()
    spawner = Mock()
    spawner.environment = {}
    await authenticator.pre_spawn_start(mock_globus_user, spawner)
    assert 'GLOBUS_DATA' in spawner.environment


async def test_globus_defaults():
    authenticator = GlobusOAuthenticator()
    print(f"userdata_url: {authenticator.userdata_url}")
    print(f"authorize_url: {authenticator.authorize_url}")
    print(f"revocation_url: {authenticator.revocation_url}")
    print(f"token_url: {authenticator.token_url}")

    assert all(
        'https://auth.globus.org' in url
        for url in [
            authenticator.userdata_url,
            authenticator.authorize_url,
            authenticator.revocation_url,
            authenticator.token_url,
        ]
    )
    assert authenticator.scope == [
        'openid',
        'profile',
        'urn:globus:auth:scope:transfer.api.globus.org:all',
    ]


async def test_restricted_domain(globus_client):
    c = Config()
    c.GlobusOAuthenticator.allow_all = True
    c.GlobusOAuthenticator.identity_provider = "allowed.example.com"
    authenticator = GlobusOAuthenticator(config=c)

    handled_user_model = user_model("user1@example.com")
    handler = globus_client.handler_for_user(handled_user_model)
    with raises(web.HTTPError) as exc:
        await authenticator.get_authenticated_user(handler, None)
    assert exc.value.status_code == 403


async def test_namespaced_domain(globus_client):
    c = Config()
    c.GlobusOAuthenticator.allow_all = True
    authenticator = GlobusOAuthenticator(config=c)

    handled_user_model = user_model('wash@legitshipping.com@serenity.com')
    handler = globus_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model['name'] == 'wash'


async def test_username_from_email_scope_added(globus_client):
    c = Config()
    c.GlobusOAuthenticator.username_from_email = True
    authenticator = GlobusOAuthenticator(config=c)
    assert authenticator.scope == [
        'openid',
        'profile',
        'urn:globus:auth:scope:transfer.api.globus.org:all',
        'email',
    ]


async def test_username_from_email_restricted_pass(globus_client):
    c = Config()
    c.GlobusOAuthenticator.allow_all = True
    c.GlobusOAuthenticator.username_from_email = True
    c.GlobusOAuthenticator.identity_provider = "allowed.example.com"
    authenticator = GlobusOAuthenticator(config=c)

    handled_user_model = user_model(
        'dummy@example.com', email='user1@allowed.example.com'
    )
    handler = globus_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model
    assert auth_model["name"] == "user1"


async def test_username_from_email_restricted_fail(globus_client):
    c = Config()
    c.GlobusOAuthenticator.allow_all = True
    c.GlobusOAuthenticator.username_from_email = True
    c.GlobusOAuthenticator.identity_provider = "allowed.example.com"
    authenticator = GlobusOAuthenticator(config=c)

    handled_user_model = user_model(
        "user1@allowed.example.com", email="dummy@example.com"
    )
    handler = globus_client.handler_for_user(handled_user_model)
    with raises(web.HTTPError) as exc:
        await authenticator.get_authenticated_user(handler, None)
    assert exc.value.status_code == 403


async def test_token_exclusion(globus_client):
    c = Config()
    c.GlobusOAuthenticator.allow_all = True
    c.GlobusOAuthenticator.exclude_tokens = [
        "auth.globus.org",
        "groups.api.globus.org",
        "transfer.api.globus.org",
    ]
    authenticator = GlobusOAuthenticator(config=c)

    handled_user_model = user_model("user1@example.com")
    handler = globus_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model
    assert auth_model['auth_state']
    assert not auth_model['auth_state']['tokens']


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
    globus_client.add_host('auth.globus.org', [('/v2/oauth2/token/revoke', tok_revoke)])
    # Add refresh tokens to ensure those get revoked too.
    mock_globus_user.state['tokens']['auth.globus.org'][
        'refresh_token'
    ] = 'my_active_auth_refresh_token'
    mock_globus_user.state['tokens']['transfer.api.globus.org'][
        'refresh_token'
    ] = 'my_active_transfer_refresh_token'

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
    logout_handler = mock_handler(GlobusLogoutHandler, authenticator=authenticator)
    monkeypatch.setattr(web.RequestHandler, 'redirect', Mock())
    logout_handler.clear_login_cookie = Mock()
    logout_handler.clear_cookie = Mock()
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
    logout_handler.clear_cookie.assert_called_once_with(STATE_COOKIE_NAME)


async def test_logout_revokes_tokens(globus_client, monkeypatch, mock_globus_user):
    globus_client.add_host(
        'auth.globus.org', [('/v2/oauth2/token/revoke', revoke_token_request_handler)]
    )
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


async def test_group_scope_added(globus_client):
    authenticator = GlobusOAuthenticator()
    authenticator.allowed_globus_groups = {'group-manager'}
    assert authenticator.scope == [
        'openid',
        'profile',
        'urn:globus:auth:scope:transfer.api.globus.org:all',
        'urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships',
    ]
