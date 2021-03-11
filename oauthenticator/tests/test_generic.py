from functools import partial

from pytest import fixture

from ..generic import GenericOAuthenticator
from .mocks import setup_oauth_mock


def user_model(username, **kwargs):
    """Return a user model"""
    user = {
        'username': username,
        'scope': 'basic',
    }
    user.update(kwargs)
    return user


def _get_authenticator(**kwargs):
    return GenericOAuthenticator(
        token_url='https://generic.horse/oauth/access_token',
        userdata_url='https://generic.horse/oauth/userinfo',
        **kwargs
    )


def get_simple_handler(generic_client):
    return generic_client.handler_for_user(user_model('wash'))


@fixture
def generic_client(client):
    setup_oauth_mock(
        client,
        host='generic.horse',
        access_token_path='/oauth/access_token',
        user_path='/oauth/userinfo',
    )
    return client


@fixture
def get_authenticator(generic_client, **kwargs):
    return partial(_get_authenticator, http_client=generic_client)


async def test_generic(get_authenticator, generic_client):
    authenticator = get_authenticator()

    handler = get_simple_handler(generic_client)
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'oauth_user' in auth_state
    assert 'refresh_token' in auth_state
    assert 'scope' in auth_state


async def test_generic_callable_username_key(get_authenticator, generic_client):
    authenticator = get_authenticator(username_key=lambda r: r['alternate_username'])
    handler = generic_client.handler_for_user(
        user_model('wash', alternate_username='zoe')
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info['name'] == 'zoe'


async def test_generic_callable_groups_claim_key_with_allowed_groups(
    get_authenticator, generic_client
):
    authenticator = get_authenticator(
        scope=['openid', 'profile', 'roles'],
        claim_groups_key=lambda r: r.get('policies').get('roles'),
        allowed_groups=['super_user'],
    )
    handler = generic_client.handler_for_user(
        user_model('wash', alternate_username='zoe', policies={'roles': ['super_user']})
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info['name'] == 'wash'


async def test_generic_groups_claim_key_with_allowed_groups(
    get_authenticator, generic_client
):
    authenticator = get_authenticator(
        scope=['openid', 'profile', 'roles'],
        claim_groups_key='groups',
        allowed_groups=['super_user'],
    )
    handler = generic_client.handler_for_user(
        user_model('wash', alternate_username='zoe', groups=['super_user'])
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info['name'] == 'wash'


async def test_generic_groups_claim_key_with_allowed_groups_unauthorized(
    get_authenticator, generic_client
):
    authenticator = get_authenticator(
        scope=['openid', 'profile', 'roles'],
        claim_groups_key='groups',
        allowed_groups=['user'],
    )
    handler = generic_client.handler_for_user(
        user_model('wash', alternate_username='zoe', groups=['public'])
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info is None


async def test_generic_groups_claim_key_with_allowed_groups_and_admin_groups(
    get_authenticator, generic_client
):
    authenticator = get_authenticator(
        scope=['openid', 'profile', 'roles'],
        claim_groups_key='groups',
        allowed_groups=['user'],
        admin_groups=['administrator'],
    )
    handler = generic_client.handler_for_user(
        user_model('wash', alternate_username='zoe', groups=['user', 'administrator'])
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info['name'] == 'wash'
    assert user_info['admin'] is True


async def test_generic_groups_claim_key_with_allowed_groups_and_admin_groups_not_admin(
    get_authenticator, generic_client
):
    authenticator = get_authenticator(
        scope=['openid', 'profile', 'roles'],
        claim_groups_key='groups',
        allowed_groups=['user'],
        admin_groups=['administrator'],
    )
    handler = generic_client.handler_for_user(
        user_model('wash', alternate_username='zoe', groups=['user'])
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info['name'] == 'wash'
    assert user_info['admin'] is False


async def test_generic_callable_groups_claim_key_with_allowed_groups_and_admin_groups(
    get_authenticator, generic_client
):
    authenticator = get_authenticator(
        username_key=lambda r: r['alternate_username'],
        scope=['openid', 'profile', 'roles'],
        claim_groups_key=lambda r: r.get('policies').get('roles'),
        allowed_groups=['user', 'public'],
        admin_groups=['administrator'],
    )
    handler = generic_client.handler_for_user(
        user_model(
            'wash',
            alternate_username='zoe',
            policies={'roles': ['user', 'administrator']},
        )
    )
    user_info = await authenticator.authenticate(handler)
    assert user_info['name'] == 'zoe'
    assert user_info['admin'] is True
