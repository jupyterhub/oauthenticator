import re
from unittest.mock import Mock

from pytest import fixture, mark, raises
from tornado.web import Application, HTTPError

from ..google import GoogleOAuthenticator

from .mocks import setup_oauth_mock


def user_model(email):
    """Return a user model"""
    return {'email': email, 'hd': email.split('@')[1], 'verified_email': True}


@fixture
def google_client(client):
    setup_oauth_mock(
        client,
        host=['accounts.google.com', 'www.googleapis.com'],
        access_token_path=re.compile('^(/o/oauth2/token|/oauth2/v4/token)$'),
        user_path='/oauth2/v1/userinfo',
    )
    return client


async def test_google(google_client):
    authenticator = GoogleOAuthenticator()
    handler = google_client.handler_for_user(user_model('fake@email.com'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'fake@email.com'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'google_user' in auth_state


async def test_hosted_domain(google_client):
    authenticator = GoogleOAuthenticator(hosted_domain=['email.com'])
    handler = google_client.handler_for_user(user_model('fake@email.com'))
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'fake'

    handler = google_client.handler_for_user(user_model('notallowed@notemail.com'))
    with raises(HTTPError) as exc:
        name = await authenticator.authenticate(handler)
    assert exc.value.status_code == 403


async def test_multiple_hosted_domain(google_client):
    authenticator = GoogleOAuthenticator(hosted_domain=['email.com', 'mycollege.edu'])
    handler = google_client.handler_for_user(user_model('fake@email.com'))
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'fake@email.com'

    handler = google_client.handler_for_user(user_model('fake2@mycollege.edu'))
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'fake2@mycollege.edu'

    handler = google_client.handler_for_user(user_model('notallowed@notemail.com'))
    with raises(HTTPError) as exc:
        name = await authenticator.authenticate(handler)
    assert exc.value.status_code == 403


async def test_admin_google_groups(google_client):
    authenticator = GoogleOAuthenticator(
        hosted_domain=['email.com', 'mycollege.edu'],
        admin_google_groups={'email.com': ['fakeadmingroup']},
        google_group_whitelist={'email.com': ['fakegroup']}
    )
    handler = google_client.handler_for_user(user_model('fakeadmin@email.com'))
    admin_user_info = await authenticator.authenticate(handler, google_groups=['anotherone', 'fakeadmingroup'])
    admin_user = admin_user_info['admin']
    assert admin_user == True
    handler = google_client.handler_for_user(user_model('fakewhitelisted@email.com'))
    whitelist_user_info = await authenticator.authenticate(handler, google_groups=['anotherone', 'fakegroup'])
    whitelisted_user_groups = whitelist_user_info['auth_state']['google_user']['google_groups']
    admin_user = whitelist_user_info['admin']
    assert 'fakegroup' in whitelisted_user_groups
    assert admin_user == False
    handler = google_client.handler_for_user(user_model('fakenonwhitelisted@email.com'))
    whitelisted_user_groups = await authenticator.authenticate(handler, google_groups=['anotherone', 'fakenonwhitelistedgroup'])
    assert whitelisted_user_groups is None


async def test_whitelisted_google_groups(google_client):
    authenticator = GoogleOAuthenticator(
        hosted_domain=['email.com', 'mycollege.edu'],
        google_group_whitelist={'email.com': ['fakegroup']}
    )
    handler = google_client.handler_for_user(user_model('fakeadmin@email.com'))
    admin_user_info = await authenticator.authenticate(handler, google_groups=['anotherone', 'fakeadmingroup'])
    assert admin_user_info is None
    handler = google_client.handler_for_user(user_model('fakewhitelisted@email.com'))
    whitelist_user_info = await authenticator.authenticate(handler, google_groups=['anotherone', 'fakegroup'])
    whitelisted_user_groups = whitelist_user_info['auth_state']['google_user']['google_groups']
    admin_field = whitelist_user_info.get('admin')
    assert 'fakegroup' in whitelisted_user_groups
    assert admin_field is None
    handler = google_client.handler_for_user(user_model('fakenonwhitelisted@email.com'))
    whitelisted_user_groups = await authenticator.authenticate(handler, google_groups=['anotherone', 'fakenonwhitelistedgroup'])
    assert whitelisted_user_groups is None
