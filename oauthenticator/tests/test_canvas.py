"""
Unit tests for CanvasOAuthenticator
"""
import json
from unittest.mock import patch
from pytest import fixture

from oauthenticator.canvas import CanvasOAuthenticator
from .mocks import setup_oauth_mock

CANVAS_HOST = 'example.com'

def user_model(username):
    return {
        'username': username,
    }

@fixture
def sample_courses():
    """
    Sample redacted structure of 'courses'.

    See full spec here: https://canvas.instructure.com/doc/api/courses.html#Course

    We'll mock the API call to return this, so *all* users, regardless
    of name, will have this list of enrolled courses.
    """
    return [
      {
        "id": 1,
        "name": "Computational Structures in Data Science (Fall 2018)",
        "enrollments": [
          {
            "type": "designer",
            "role": "DesignerEnrollment",
            "role_id": 6312,
            "user_id": 95341,
            "enrollment_state": "active",
          }
        ],
      },
      {
        "id": 2,
        "name": "Human Contexts and Ethics of Data (Fall 2018)",
        "enrollments": [
          {
            "type": "student",
            "role": "StudentEnrollment",
            "role_id": 6309,
            "user_id": 95341,
            "enrollment_state": "active",
            "limit_privileges_to_course_section": False
          }
        ],
      }
    ]

@fixture
def canvas_client(client):
    """
    Http client mocking appropriate OAuth endpoints
    """
    setup_oauth_mock(
        client,
        host=CANVAS_HOST,
        access_token_path='/login/oauth2/token',
        user_path='/api/v1/users/self/profile'
    )
    return client

async def test_simple_canvas(canvas_client):
    """
    Simple canvas authenticator test
    """
    with patch.object(CanvasOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = canvas_client

        authenticator = CanvasOAuthenticator(canvas_url=f'https://{CANVAS_HOST}/')

        handler = canvas_client.handler_for_user(user_model('test'))
        user_info = await authenticator.authenticate(handler)

        assert user_info is not None
        oauth_user = user_info['auth_state']['oauth_user']

        # courses should be picked up only if allowed_courses is set
        assert 'courses' not in oauth_user
        assert 'username' in oauth_user

async def test_get_courses(canvas_client, sample_courses):
    """
    Test retreiving course information from canvas API

    We mock the API request, but make sure that authenticate fetches
    it and passes it along properly
    """

    # Mock response to courses endpoint, return sample courses fixture
    canvas_client.hosts[CANVAS_HOST].append(
        ('/api/v1/courses', lambda req: json.dumps(sample_courses))
    )

    with patch.object(CanvasOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = canvas_client

        authenticator = CanvasOAuthenticator(
            canvas_url=f'https://{CANVAS_HOST}/',
            fetch_enrolled_courses=True
        )

        handler = canvas_client.handler_for_user(user_model(
            'test'
        ))

        user_info = await authenticator.authenticate(handler)

        assert user_info is not None
        oauth_user = user_info['auth_state']['oauth_user']
        assert oauth_user['courses'] == sample_courses

async def test_allowed_courses(canvas_client, sample_courses):
    """
    Test that allowed_courses is respected
    """
    canvas_client.hosts[CANVAS_HOST].append(
        ('/api/v1/courses', lambda req: json.dumps(sample_courses))
    )
    with patch.object(CanvasOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = canvas_client

        authenticator = CanvasOAuthenticator(
            canvas_url=f'https://{CANVAS_HOST}/',
            allowed_courses=[2, 3],
            fetch_enrolled_courses=True
        )

        handler = canvas_client.handler_for_user(user_model(
            'test'
        ))

        # All users are members of course 1, 2
        user_info = await authenticator.authenticate(handler)
        assert await authenticator.check_allowed('test', user_info)

        # If only course 3 users are allowed, we should deny this user
        authenticator.allowed_courses = [3]
        assert not await authenticator.check_allowed('test', user_info)


async def test_inclusive_allowed_list(canvas_client, sample_courses):
    """
    Test adding users with allowed_list, in addition to allowed_courses
    """
    canvas_client.hosts[CANVAS_HOST].append(
        ('/api/v1/courses', lambda req: json.dumps(sample_courses))
    )
    with patch.object(CanvasOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = canvas_client

        authenticator = CanvasOAuthenticator(
            canvas_url=f'https://{CANVAS_HOST}/',
            allowed_users=[
                'explicitly_allowed_user_1',
                'explicitly_allowed_user_2'
            ],
            fetch_enrolled_courses=True
        )

        # An explicitly allowed user must be allowed in
        handler = canvas_client.handler_for_user(user_model(
            'explicitly_allowed_user_1'
        ))

        user_info = await authenticator.authenticate(handler)

        assert await authenticator.check_allowed('explicitly_allowed_user_1', user_info)

        # By default, a user who has just logged in via canvas,
        # but isn't explicilty allowed, should not be allowed to login
        handler = canvas_client.handler_for_user(user_model(
            'implicitly_allowed_user_1'
        ))

        user_info = await authenticator.authenticate(handler)
        assert not await authenticator.check_allowed('implicitly_allowed_user_1', user_info)

        authenticator.allowed_courses = {2}
        authenticator.inclusive_allow_list = True

        handler = canvas_client.handler_for_user(user_model(
            'implicitly_allowed_user_1'
        ))
        user_info = await authenticator.authenticate(handler)

        assert await authenticator.check_allowed('implicitly_allowed_user_1', user_info)

        authenticator.allowed_courses = {3}
        assert not await authenticator.check_allowed('implicitly_allowed_user_1', user_info)

