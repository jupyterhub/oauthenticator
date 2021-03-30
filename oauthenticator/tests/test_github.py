import re
import functools
import json
from io import BytesIO

import logging
from pytest import fixture, mark
from urllib.parse import urlparse, parse_qs
from tornado.httpclient import HTTPRequest, HTTPResponse
from tornado.httputil import HTTPHeaders
from traitlets.config import Config

from ..github import GitHubOAuthenticator

from .mocks import setup_oauth_mock


def user_model(username):
    """Return a user model"""
    return {
        'email': 'dinosaurs@space',
        'id': 5,
        'login': username,
        'name': 'Hoban Washburn',
    }

@fixture
def github_client(client):
    setup_oauth_mock(client,
        host=['github.com', 'api.github.com'],
        access_token_path='/login/oauth/access_token',
        user_path='/user',
        token_type='token',
    )
    return client


async def test_github(github_client):
    authenticator = GitHubOAuthenticator()
    handler = github_client.handler_for_user(user_model('wash'))
    user_info = await authenticator.authenticate(handler)
    name = user_info['name']
    assert name == 'wash'
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state

    assert auth_state == {
        'access_token': auth_state['access_token'],
        'github_user': {
            'email': 'dinosaurs@space',
            'id': 5,
            'login': name,
            'name': 'Hoban Washburn',
        }
    }


def make_link_header(urlinfo, page):
    return {'Link': '<{}://{}{}?page={}>;rel="next"'
                    .format(urlinfo.scheme, urlinfo.netloc, urlinfo.path, page)}


async def test_allowed_org_membership(github_client):
    client = github_client
    authenticator = GitHubOAuthenticator()

    ## Mock Github API

    orgs = {
        'red': ['grif', 'simmons', 'donut', 'sarge', 'lopez'],
        'blue': ['tucker', 'caboose', 'burns', 'sheila', 'texas'],
    }

    member_regex = re.compile(r'/orgs/(.*)/members')

    def org_members(paginate, request):
        urlinfo = urlparse(request.url)
        org = member_regex.match(urlinfo.path).group(1)

        if org not in orgs:
            return HTTPResponse(request, 404)

        if not paginate:
            return [user_model(m) for m in orgs[org]]
        else:
            page = parse_qs(urlinfo.query).get('page', ['1'])
            page = int(page[0])
            return org_members_paginated(
                org, page, urlinfo, functools.partial(HTTPResponse, request))

    def org_members_paginated(org, page, urlinfo, response):
        if page < len(orgs[org]):
            headers = make_link_header(urlinfo, page + 1)
        elif page == len(orgs[org]):
            headers = {}
        else:
            return response(400)

        headers.update({'Content-Type': 'application/json'})

        ret = [user_model(orgs[org][page - 1])]

        return response(200,
                        headers=HTTPHeaders(headers),
                        buffer=BytesIO(json.dumps(ret).encode('utf-8')))


    org_membership_regex = re.compile(r'/orgs/(.*)/members/(.*)')

    def org_membership(request):
        urlinfo = urlparse(request.url)
        urlmatch = org_membership_regex.match(urlinfo.path)
        org = urlmatch.group(1)
        username = urlmatch.group(2)
        print('Request org = %s, username = %s' % (org, username))
        if org not in orgs:
            print('Org not found: org = %s' %(org))
            return HTTPResponse(request, 404)
        if username not in orgs[org]:
            print('Member not found: org = %s, username = %s' %(org, username))
            return HTTPResponse(request, 404)
        return HTTPResponse(request, 204)


    ## Perform tests

    for paginate in (False, True):
        client_hosts = client.hosts['api.github.com']
        client_hosts.append((org_membership_regex, org_membership))
        client_hosts.append((member_regex, functools.partial(org_members, paginate)))

        authenticator.allowed_organizations = ['blue']

        handler = client.handler_for_user(user_model('caboose'))
        user = await authenticator.authenticate(handler)
        assert user['name'] == 'caboose'

        handler = client.handler_for_user(user_model('donut'))
        user = await authenticator.authenticate(handler)
        assert user is None

        # reverse it, just to be safe
        authenticator.allowed_organizations = ['red']

        handler = client.handler_for_user(user_model('caboose'))
        user = await authenticator.authenticate(handler)
        assert user is None

        handler = client.handler_for_user(user_model('donut'))
        user = await authenticator.authenticate(handler)
        assert user['name'] == 'donut'

        client_hosts.pop()
        client_hosts.pop()

def test_deprecated_config(caplog):
    cfg = Config()
    cfg.GitHubOAuthenticator.github_organization_whitelist = ["jupy"]
    cfg.Authenticator.whitelist = {"user1"}

    log = logging.getLogger("testlog")
    authenticator = GitHubOAuthenticator(config=cfg, log=log)
    assert (
        log.name,
        logging.WARNING,
        'GitHubOAuthenticator.github_organization_whitelist is deprecated in GitHubOAuthenticator 0.12.0, use '
        'GitHubOAuthenticator.allowed_organizations instead',
    ) in caplog.record_tuples

    assert authenticator.allowed_organizations == {"jupy"}
    assert authenticator.allowed_users == {"user1"}
