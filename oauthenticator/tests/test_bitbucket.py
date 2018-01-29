import os
from unittest.mock import patch

from pytest import fixture, mark

from ..bitbucket import BitbucketOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'username': username,
    }

@fixture
def bitbucket_client(client):
    setup_oauth_mock(client,
        host=['bitbucket.org', 'api.bitbucket.org'],
        access_token_path='/site/oauth2/access_token',
        user_path='/2.0/user',
    )
    return client


@mark.gen_test
def test_bitbucket(bitbucket_client):
    authenticator = BitbucketOAuthenticator()
    handler = bitbucket_client.handler_for_user(user_model('yorba'))
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'yorba'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'bitbucket_user' in auth_state


@mark.gen_test
def test_team_whitelist(bitbucket_client):
    client = bitbucket_client
    authenticator = BitbucketOAuthenticator()
    authenticator.bitbucket_team_whitelist = ['blue']

    teams = {
        'red': ['grif', 'simmons', 'donut', 'sarge', 'lopez'],
        'blue': ['tucker', 'caboose', 'burns', 'sheila', 'texas'],
    }
    def list_teams(request):
        token = request.headers['Authorization'].split(None, 1)[1]
        username = client.access_tokens[token]['username']
        values = []
        for team, members in teams.items():
            if username in members:
                values.append({'username': team})
        return {
            'values': values
        }

    client.hosts['api.bitbucket.org'].append(
        ('/2.0/teams', list_teams)
    )

    handler = client.handler_for_user(user_model('caboose'))
    user_info = yield authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'caboose'

    handler = client.handler_for_user(user_model('donut'))
    name = yield authenticator.authenticate(handler)
    assert name is None

    # reverse it, just to be safe
    authenticator.team_whitelist = ['red']

    handler = client.handler_for_user(user_model('caboose'))
    name = yield authenticator.authenticate(handler)
    assert name is None

    handler = client.handler_for_user(user_model('donut'))
    user_info = yield authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'donut'
