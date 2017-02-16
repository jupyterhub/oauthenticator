import os
from unittest.mock import patch

from pytest import fixture, mark

from ..bitbucket import BitbucketOAuthenticator

from .mocks import setup_oauth_mock, no_code_test


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
    name = yield authenticator.authenticate(handler)
    assert name == 'yorba'


@mark.gen_test
def test_no_code(bitbucket_client):
    yield no_code_test(BitbucketOAuthenticator())


@mark.gen_test
def test_team_whitelist(bitbucket_client):
    client = bitbucket_client
    authenticator = BitbucketOAuthenticator()
    authenticator.team_whitelist = ['blue']

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
    name = yield authenticator.authenticate(handler)
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
    name = yield authenticator.authenticate(handler)
    assert name == 'donut'



    