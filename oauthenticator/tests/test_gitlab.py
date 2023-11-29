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

from ..gitlab import GitLabOAuthenticator
from .mocks import setup_oauth_mock

API_ENDPOINT = f"/api/v{GitLabOAuthenticator().gitlab_api_version}"


id_to_username_map = {}


def user_model(username):
    """Return a user model"""

    # generate an id based on the username hash and remember it
    id = abs(hash(username)) % (10**8)
    id_to_username_map[id] = username
    return {
        "username": username,
        "id": id,
    }


@fixture
def gitlab_client(client):
    setup_oauth_mock(
        client,
        host='gitlab.com',
        access_token_path='/oauth/token',
        user_path=API_ENDPOINT + '/user',
    )
    return client


def mock_api_version(client, version):
    def mock_version_response(request):
        ret = {'version': version, 'revision': "f79c1794977"}
        return HTTPResponse(
            request,
            200,
            headers={'Content-Type': 'application/json'},
            buffer=BytesIO(json.dumps(ret).encode('utf-8')),
        )

    regex = re.compile(API_ENDPOINT + '/version')
    client.hosts['gitlab.com'].append((regex, mock_version_response))


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
async def test_gitlab(
    gitlab_client,
    test_variation_id,
    class_config,
    expect_allowed,
    expect_admin,
):
    print(f"Running test variation id {test_variation_id}")
    c = Config()
    c.GitLabOAuthenticator = Config(class_config)
    c.GitLabOAuthenticator.username_claim = "username"
    authenticator = GitLabOAuthenticator(config=c)

    handled_user_model = user_model("user1")
    handler = gitlab_client.handler_for_user(handled_user_model)
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


@mark.parametrize(
    "paginate",
    [
        False,
        True,
    ],
)
async def test_allowed_groups(gitlab_client, paginate):
    authenticator = GitLabOAuthenticator()
    mock_api_version(gitlab_client, '12.4.0-ee')

    ## set up fake Gitlab API

    user_groups = {
        "user1": ["group0", "group1"],
    }

    groups_members_api_regex = re.compile(
        API_ENDPOINT + r'/groups/(.*)/members/all/(.*)'
    )

    def mocked_groups_members_api(request):
        """
        Is user_id a member of a group?

        https://docs.gitlab.com/ee/api/members.html#get-a-member-of-a-group-or-project
        is mocked solely by the HTTP response code.
        """
        urlinfo = urlparse(request.url)
        group, user_id = groups_members_api_regex.match(urlinfo.path).group(1, 2)
        username = id_to_username_map[int(user_id)]
        if group in user_groups.get(username, []):
            return HTTPResponse(request, 200)
        else:
            return HTTPResponse(request, 404)

    def mocked_groups_api(paginate, request):
        """
        What groups are the user that makes a request to the /groups API part
        of?

        https://docs.gitlab.com/ee/api/groups.html#list-groups is mocked by
        returning a list of dictionaries like {"path": <group_name>}, and only
        one group per page.
        """
        urlinfo = urlparse(request.url)
        _, token = request._headers.get('Authorization').split()
        username = gitlab_client.access_tokens[token]['username']
        if not paginate:
            return [{'path': group} for group in user_groups[username]]
        else:
            page = parse_qs(urlinfo.query).get('page', ['1'])
            page = int(page[0])
            return _mocked_groups_api_paginated(
                username, page, urlinfo, functools.partial(HTTPResponse, request)
            )

    def _mocked_groups_api_paginated(username, page, urlinfo, response):
        """
        Helper function for mocked_groups_api.
        """
        if page < len(user_groups[username]):
            headers = make_link_header(urlinfo, page + 1)
        elif page == len(user_groups[username]):
            headers = {}
        else:
            return response(400)

        headers.update({'Content-Type': 'application/json'})
        ret = [{'path': user_groups[username][page - 1]}]
        return response(
            200,
            headers=HTTPHeaders(headers),
            buffer=BytesIO(json.dumps(ret).encode('utf-8')),
        )

    gitlab_client.hosts['gitlab.com'].append(
        (groups_members_api_regex, mocked_groups_members_api)
    )
    gitlab_client.hosts['gitlab.com'].append(
        (API_ENDPOINT + '/groups', functools.partial(mocked_groups_api, paginate))
    )

    ## actual tests

    authenticator.allowed_gitlab_groups = ["group1"]

    handled_user_model = user_model("user1")
    handler = gitlab_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model
    assert json.dumps(auth_model["auth_state"])

    handled_user_model = user_model("user-not-in-group")
    handler = gitlab_client.handler_for_user(handled_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model is None


async def test_allowed_project_ids(gitlab_client):
    authenticator = GitLabOAuthenticator()
    mock_api_version(gitlab_client, '12.4.0-pre')

    non_project_member_user_model = user_model('non-project-member')
    guest_user_model = user_model('guest')
    developer_user_model = user_model('developer')
    user_projects = {
        '1': {
            str(guest_user_model["id"]): {
                'id': guest_user_model["id"],
                'name': guest_user_model["username"],
                'username': guest_user_model["username"],
                'state': 'active',
                'avatar_url': 'https://secure.gravatar.com/avatar/382a6b306679b2d97b547bfff3d73242?s=80&d=identicon',
                'web_url': f'https://gitlab.com/{guest_user_model["username"]}',
                'access_level': 10,  # Guest
                'expires_at': '2040-02-23',
            },
            str(developer_user_model["id"]): {
                'id': developer_user_model["id"],
                'name': developer_user_model["username"],
                'username': developer_user_model["username"],
                'state': 'active',
                'avatar_url': 'https://secure.gravatar.com/avatar/382a6b306679b2d97b547bfff3d73242?s=80&d=identicon',
                'web_url': f'https://gitlab.com/{guest_user_model["username"]}',
                'access_level': 30,  # Developer
                'expires_at': '2040-02-23',
            },
        }
    }

    projects_members_api_regex = re.compile(
        API_ENDPOINT + r'/projects/(.*)/members/all/(.*)'
    )

    def mocked_projects_members_api(request):
        """
        Is user_id a member of a project?

        https://docs.gitlab.com/ee/api/members.html#get-a-member-of-a-group-or-project
        is mocked by somewhat realistic response.
        """
        urlinfo = urlparse(request.url)
        project_id, user_id = projects_members_api_regex.match(urlinfo.path).group(1, 2)

        if user_projects.get(project_id) and user_projects[project_id].get(user_id):
            res = user_projects[project_id][user_id]
            return HTTPResponse(
                request=request,
                code=200,
                buffer=BytesIO(json.dumps(res).encode('utf8')),
                headers={'Content-Type': 'application/json'},
            )
        else:
            return HTTPResponse(request=request, code=404, buffer=BytesIO(b''))

    gitlab_client.hosts['gitlab.com'].append(
        (projects_members_api_regex, mocked_projects_members_api)
    )

    authenticator.allowed_project_ids = [1]

    # Forbidden, user doesn't have access to a project in allowed_project_ids
    handler = gitlab_client.handler_for_user(non_project_member_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model is None

    # Forbidden, user only has has guest access a project in allowed_project_ids
    handler = gitlab_client.handler_for_user(guest_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model is None

    # Authorized, user has developer access a project in allowed_project_ids
    handler = gitlab_client.handler_for_user(developer_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model
    assert json.dumps(auth_model["auth_state"])

    # Forbidden, project doesn't exist
    authenticator.allowed_project_ids = [0]
    handler = gitlab_client.handler_for_user(developer_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model is None

    # Authorized, user has developer access to one of the allowed_project_ids
    authenticator.allowed_project_ids = [0, 1]
    handler = gitlab_client.handler_for_user(developer_user_model)
    auth_model = await authenticator.get_authenticated_user(handler, None)
    assert auth_model
    assert json.dumps(auth_model["auth_state"])


@mark.parametrize(
    "test_variation_id,class_config,expect_config,expect_loglevel,expect_message",
    [
        (
            "gitlab_group_whitelist",
            {"gitlab_group_whitelist": {"dummy"}},
            {"allowed_gitlab_groups": {"dummy"}},
            logging.WARNING,
            "GitLabOAuthenticator.gitlab_group_whitelist is deprecated in GitLabOAuthenticator 0.12.0, use GitLabOAuthenticator.allowed_gitlab_groups instead",
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
    c.GitLabOAuthenticator = Config(class_config)

    test_logger = logging.getLogger('testlog')
    if expect_loglevel == logging.ERROR:
        with raises(ValueError, match=expect_message):
            GitLabOAuthenticator(config=c, log=test_logger)
    else:
        authenticator = GitLabOAuthenticator(config=c, log=test_logger)
        for key, value in expect_config.items():
            assert getattr(authenticator, key) == value

    captured_log_tuples = caplog.record_tuples
    print(captured_log_tuples)

    expected_log_tuple = (test_logger.name, expect_loglevel, expect_message)
    assert expected_log_tuple in captured_log_tuples
