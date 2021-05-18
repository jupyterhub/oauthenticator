from pytest import fixture

from ..openshift import OpenShiftOAuthenticator
from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'metadata': {'name': username},
        "groups": ["group1", "group2"],
    }


@fixture
def openshift_client(client):
    setup_oauth_mock(
        client,
        host=['openshift.default.svc.cluster.local'],
        access_token_path='/oauth/token',
        user_path='/apis/user.openshift.io/v1/users/~',
    )
    return client


async def test_openshift(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'openshift_user' in auth_state


async def test_openshift_allowed_groups(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.allowed_groups = {'group1'}
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'openshift_user' in auth_state
    groups = auth_state['openshift_user']['groups']
    assert 'group1' in groups


async def test_openshift_not_in_allowed_groups(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.allowed_groups = {'group3'}
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert user_info == None


async def test_openshift_not_in_allowed_groups_but_is_admin(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.allowed_groups = {'group3'}
    authenticator.admin_groups = {'group1'}
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['admin'] == True


async def test_openshift_in_allowed_groups_and_is_admin(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.allowed_groups = {'group2'}
    authenticator.admin_groups = {'group1'}
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['admin'] == True


async def test_openshift_in_allowed_groups_and_is_not_admin(openshift_client):
    authenticator = OpenShiftOAuthenticator()
    authenticator.allowed_groups = {'group2'}
    authenticator.admin_groups = {'group3'}
    authenticator.openshift_auth_api_url = "https://openshift.default.svc.cluster.local"
    handler = openshift_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['admin'] == False
