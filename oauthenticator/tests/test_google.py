import os
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


async def test_user_in_groups(google_client):
    authenticator = GoogleOAuthenticator(
        hosted_domain=['email.com', 'mycollege.edu'],
        admin_google_groups={'email.com': ['fakeadmingroup']},
        google_group_whitelist={'email.com': ['fakegroup']}
    )
    admin_handler = google_client.handler_for_user(user_model('fakeadmin@email.com'))
    admin_user_info = await authenticator.authenticate(admin_handler, google_groups=['anotherone', 'fakeadmingroup'])
    user_is_admin = admin_user_info['admin']
    assert user_is_admin == True
    whitelist_handler = google_client.handler_for_user(user_model('fakewhitelisted@email.com'))
    whitelist_user_info = await authenticator.authenticate(whitelist_handler, google_groups=['anotherone', 'fakegroup'])
    user_is_whitelisted = whitelist_user_info['auth_state']['google_user']['google_groups']
    user_is_not_admin = whitelist_user_info['admin']
    assert 'fakegroup' in user_is_whitelisted
    assert user_is_not_admin == False
    non_whitelist_handler = google_client.handler_for_user(user_model('fakenonwhitelisted@email.com'))
    non_whitelist_user_info = await authenticator.authenticate(non_whitelist_handler, google_groups=['anotherone', 'fakenonwhitelistedgroup'])
    assert non_whitelist_user_info is None
    non_admin_authenticator = GoogleOAuthenticator(
        hosted_domain=['email.com', 'mycollege.edu'],
        google_group_whitelist={'email.com': ['fakegroup']}
    )
    admin_handler = google_client.handler_for_user(user_model('fakeadmin@email.com'))
    admin_user_info = await non_admin_authenticator.authenticate(admin_handler, google_groups=['anotherone', 'fakeadmingroup'])
    assert admin_user_info is None
    whitelist_handler = google_client.handler_for_user(user_model('fakewhitelisted@email.com'))
    whitelist_user_info = await non_admin_authenticator.authenticate(whitelist_handler, google_groups=['anotherone', 'fakegroup'])
    user_is_whitelisted = whitelist_user_info['auth_state']['google_user']['google_groups']
    assert 'fakegroup' in user_is_whitelisted
    non_whitelist_handler = google_client.handler_for_user(user_model('fakenonwhitelisted@email.com'))
    non_whitelist_user_info = await non_admin_authenticator.authenticate(non_whitelist_handler, google_groups=['anotherone', 'fakenonwhitelistedgroup'])
    assert non_whitelist_user_info is None
