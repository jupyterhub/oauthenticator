import os
from unittest.mock import patch

import logging
from pytest import fixture, mark
from traitlets.config import Config

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


async def test_bitbucket(bitbucket_client):
    authenticator = BitbucketOAuthenticator()
    handler = bitbucket_client.handler_for_user(user_model('yorba'))
    user_info = await authenticator.authenticate(handler)
    assert sorted(user_info) == ['auth_state', 'name']
    name = user_info['name']
    assert name == 'yorba'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'bitbucket_user' in auth_state


async def test_allowed_teams(bitbucket_client):
    client = bitbucket_client
    authenticator = BitbucketOAuthenticator()
    authenticator.allowed_teams = ['blue']

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
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'caboose'

    handler = client.handler_for_user(user_model('donut'))
    name = await authenticator.authenticate(handler)
    assert name is None

    # reverse it, just to be safe
    authenticator.allowed_teams = ['red']

    handler = client.handler_for_user(user_model('caboose'))
    name = await authenticator.authenticate(handler)
    assert name is None

    handler = client.handler_for_user(user_model('donut'))
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'donut'

def test_deprecated_config(caplog):
    cfg = Config()
    cfg.BitbucketOAuthenticator.team_whitelist = ['red']
    cfg.BitbucketOAuthenticator.whitelist = {"blue"}

    log = logging.getLogger("testlog")
    authenticator = BitbucketOAuthenticator(config=cfg, log=log)
    assert (
        log.name,
        logging.WARNING,
        'BitbucketOAuthenticator.team_whitelist is deprecated in BitbucketOAuthenticator 0.12.0, use '
        'BitbucketOAuthenticator.allowed_teams instead',
    ) in caplog.record_tuples

    assert authenticator.allowed_teams == {"red"}
    assert authenticator.allowed_users == {"blue"}
