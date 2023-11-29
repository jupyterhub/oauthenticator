import functools
import json
import logging
import re
from io import BytesIO
from urllib.parse import parse_qs, urlparse

from pytest import fixture, mark, raises
from tornado.httpclient import HTTPResponse
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
    setup_oauth_mock(
        client,
        host=['github.com', 'api.github.com'],
        access_token_path='/login/oauth/access_token',
        user_path='/user',
        token_type='token',
    )
    return client


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
                "admin_users": {"user1"},
                "allowed_users": {"not-test-user"},
            },
            True,
            True,
        ),
    ],
)
async def test_github(
    github_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.GitHubOAuthenticator = Config(class_config)
    c.GitHubOAuthenticator.username_claim = "login"
    authenticator = GitHubOAuthenticator(config=c)

    handled_user_model = user_model("user1")
    handler = github_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)

    if expect_allowed:
        assert auth_model
        assert set(auth_model) == {"name", "admin", "auth_state"}
        assert auth_model["admin"] == expect_admin
        auth_state = auth_model["auth_state"]
        assert json.dumps(auth_state)
        assert "access_token" in auth_state
        user_info = auth_state[authenticator.user_auth_state_key]
        assert user_info == handled_user_model
        assert auth_model["name"] == user_info[authenticator.username_claim]
    else:
        assert auth_model == None


def make_link_header(urlinfo, page):
    return {
        "Link": f'<{urlinfo.scheme}://{urlinfo.netloc}{urlinfo.path}?page={page}>;rel="next"'
    }


async def test_allowed_org_membership(github_client):
    authenticator = GitHubOAuthenticator()

    ## Mock Github API

    allowed_org_members = {
        "org1": ["user1"],
    }
    allowed_org_team_members = {
        "org1": {
            "team1": ["user1"],
        },
    }

    member_regex = re.compile(r'/orgs/(.*)/members')

    def org_members(paginate, request):
        urlinfo = urlparse(request.url)
        org = member_regex.match(urlinfo.path).group(1)

        if org not in allowed_org_members:
            return HTTPResponse(request, 404)

        if not paginate:
            return [user_model(m) for m in allowed_org_members[org]]
        else:
            page = parse_qs(urlinfo.query).get('page', ['1'])
            page = int(page[0])
            return org_members_paginated(
                org, page, urlinfo, functools.partial(HTTPResponse, request)
            )

    def org_members_paginated(org, page, urlinfo, response):
        if page < len(allowed_org_members[org]):
            headers = make_link_header(urlinfo, page + 1)
        elif page == len(allowed_org_members[org]):
            headers = {}
        else:
            return response(400)

        headers.update({'Content-Type': 'application/json'})

        ret = [user_model(allowed_org_members[org][page - 1])]

        return response(
            200,
            headers=HTTPHeaders(headers),
            buffer=BytesIO(json.dumps(ret).encode('utf-8')),
        )

    org_membership_regex = re.compile(r'/orgs/(.*)/members/(.*)')

    def org_membership(request):
        urlinfo = urlparse(request.url)
        urlmatch = org_membership_regex.match(urlinfo.path)
        org = urlmatch.group(1)
        username = urlmatch.group(2)
        print(f"Request org = {org}, username = {username}")
        if org not in allowed_org_members:
            print(f"Org not found: org = {org}")
            return HTTPResponse(request, 404)
        if username not in allowed_org_members[org]:
            print(f"Member not found: org = {org}, username = {username}")
            return HTTPResponse(request, 404)
        return HTTPResponse(request, 204)

    team_membership_regex = re.compile(r'/orgs/(.*)/teams/(.*)/members/(.*)')

    def team_membership(request):
        urlinfo = urlparse(request.url)
        urlmatch = team_membership_regex.match(urlinfo.path)
        org = urlmatch.group(1)
        team = urlmatch.group(2)
        username = urlmatch.group(3)
        print(f"Request org = {org}, team = {team} username = {username}")
        if org not in allowed_org_members:
            print(f"Org not found: org = {org}")
            return HTTPResponse(request, 404)
        if team not in allowed_org_team_members[org]:
            print(f"Team not found in org: team = {team}, org = {org}")
            return HTTPResponse(request, 404)
        if username not in allowed_org_team_members[org][team]:
            print(
                f"Member not found: org = {org}, team = {team}, username = {username}"
            )
            return HTTPResponse(request, 404)
        return HTTPResponse(request, 204)

    ## Perform tests

    client_hosts = github_client.hosts['api.github.com']
    client_hosts.append((team_membership_regex, team_membership))
    client_hosts.append((org_membership_regex, org_membership))

    # Run tests twice, once with paginate and once without
    for paginate in (False, True):
        client_hosts.append((member_regex, functools.partial(org_members, paginate)))

        # test org membership
        authenticator.allowed_organizations = ["org1"]

        handled_user_model = user_model("user1")
        handler = github_client.handler_for_user(handled_user_model)
        auth_model = await authenticator.get_authenticated_user(handler, None)
        assert auth_model

        handled_user_model = user_model("user-not-in-org")
        handler = github_client.handler_for_user(handled_user_model)
        auth_model = await authenticator.get_authenticated_user(handler, None)
        assert auth_model is None

        # test org team membership
        authenticator.allowed_organizations = ["org1:team1"]

        handled_user_model = user_model("user1")
        handler = github_client.handler_for_user(handled_user_model)
        auth_model = await authenticator.get_authenticated_user(handler, None)
        assert auth_model

        handled_user_model = user_model("user-not-in-org-team")
        handler = github_client.handler_for_user(handled_user_model)
        auth_model = await authenticator.get_authenticated_user(handler, None)
        assert auth_model is None

        client_hosts.pop()


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "github_organization_whitelist",
            {"github_organization_whitelist": {"dummy"}},
            {"allowed_organizations": {"dummy"}},
            logging.WARNING,
            "GitHubOAuthenticator.github_organization_whitelist is deprecated in GitHubOAuthenticator 0.12.0, use GitHubOAuthenticator.allowed_organizations instead",
        ),
    ],
)
async def test_deprecated_config(
    caplog,
    test_variation_id,
    class_config,
    expect_config,
    expect_loglevel,
    expect_message,
):
    """
    Tests that a warning is emitted when using a deprecated config and that
    configuring the old config ends up configuring the new config.
    """
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.GitHubOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            GitHubOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = GitHubOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
