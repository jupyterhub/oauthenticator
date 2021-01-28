import json
import urllib

from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPClientError
from tornado.httputil import url_concat
from traitlets import List, Unicode, Set, Bool
from jupyterhub.utils import maybe_future, url_path_join
from jupyterhub.auth import LocalAuthenticator

from .generic import GenericOAuthenticator

class CanvasOAuthenticator(GenericOAuthenticator):
    """
    Canvas OAuth2 based authenticator for JupyterHub.

    Collects info about user & enrolled courses from canvas,
    puts them into auth_state. To refresh, user has to re-login.
    """

    strip_email_domain = Unicode(
        '',
        config=True,
        help="""
        Strip this domain from user emails when making their JupyterHub user name.

        For example, if almost all your users have emails of form username@berkeley.edu,
        you can set this to 'berkeley.edu'. A canvas user with email yuvipanda@berkeley.edu
        will get a JupyterHub user name of 'yuvipanda', while a canvas user with email
        yuvipanda@gmail.com will get a JupyterHub username of 'yuvipanda@gmail.com'.

        By default, *no* domain stripping is performed, and the JupyterHub username
        is the primary email of the canvas user.
        """
    )

    canvas_url = Unicode(
        '',
        config=True,
        help="""
        URL to canvas installation to use for authentication.
        """
    )

    allowed_courses = Set(
        set(),
        config=True,
        help="""
        Set of classes ids whose enrolees get access to this hub.

        You can find the IDs from the URL of the course page on
        canvas.

        If left empty, all users are allowed.

        Requires fetch_enrolled_courses to be set to True
        """
    )

    inclusive_allow_list = Bool(
        False,
        config=True,
        help="""
        Allow users in allow_list in addition to those enrolled in courses.

        By default, when allowed_list is specified, *only* those users
        can login. However, often you want to grant access to additional
        users who aren't in the courses - infrastructure admins, for example.

        Setting this to True will allow both folks in the course *and*
        those in the allowed_list.

        If this is set to True, allowed_courses must *also* be set.
        """
    )

    fetch_enrolled_courses = Bool(
        False,
        config=True,
        help="""
        Fetch list of courses user is enrolled in & put it in auth_state.

        Having the list of courses a user is currently enrolled in can
        help with access control, API access, etc. When set to True,
        CanvasOAuthenticator will make a second request to get the
        list of courses the user is enrolled in, so other actions (such as
        only allowing some - see allowed_courses) can be performed.
        """
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.canvas_url:
            raise ValueError('c.CanvasAuthenticator.canvas_url must be set')

        self.token_url = url_path_join(self.canvas_url, 'login/oauth2/token')
        self.userdata_url = url_path_join(self.canvas_url, 'api/v1/users/self/profile')

        self.extra_params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

    async def get_courses(self, username, token):
        """
        Get list of courses enrolled by the current user
        """
        headers = dict(Authorization = f"Bearer {token}")
        url = url_concat(
            url_path_join(self.canvas_url, '/api/v1/courses'),
            self.extra_params
        )

        req = HTTPRequest(url, headers=headers)

        http_client = self.http_client()

        try:
            resp = await http_client.fetch(req)
        except HTTPClientError as e:
            error_text = e.response.body.decode()
            raise Exception(f"error fetching course info for {username}: {e.code} -- {error_text}")
        return json.loads(resp.body.decode())

    async def check_allowed(self, username, user_data):
        """
        Return true if user with current set of courses is allowed in.

        If allowed_users is set and inclusive_allow_list is not True, we only
        allow those users.

        If allowed_users is set and inclusive_allow_list is True, we allow
        allow users in allowed_list *in addition* to those who are in the
        enrolled courses

        If allowed_courses is not set, we allow everyone who has authenticated.

        If allowed_courses is set, we only allow users who are in those courses.
        """
        if self.allowed_users:
            if username in self.allowed_users:
                # Always return true for users in allowed_list
                return True
            else:
                # If user isn't explicitly in allowed_list, we go to the
                # next phase of checking *only* if inclusive_allow_list is True.
                # Else, we just return False here.
                if not self.inclusive_allow_list:
                    return False

        if not self.allowed_courses:
            return True

        courses = user_data['auth_state']['oauth_user']['courses']

        user_course_ids = set([c['id'] for c in courses])

        for c in self.allowed_courses:
            if c in user_course_ids:
                return True

        return False

    async def authenticate(self, handler, data=None):
        """
        Augment base user auth info with course info
        """
        user = await super().authenticate(handler, data)
        if self.fetch_enrolled_courses:
            courses = await self.get_courses(user['name'], user['auth_state']['access_token'])
            user['auth_state']['oauth_user']['courses'] = courses

        return user

    def normalize_username(self, username):
        username = username.lower()
        # To make life easier & match usernames with existing users who were
        # created with google auth, we want to strip the domain name. If not,
        # we use the full email as the official user name
        if self.strip_email_domain and username.endswith('@' + self.strip_email_domain):
            return username.split('@')[0]
        return username

    async def pre_spawn_start(self, user, spawner):
        """Pass oauth data to spawner via OAUTH2_ prefixed env variables."""
        auth_state = yield user.get_auth_state()
        if not auth_state:
            return
        if 'access_token' in auth_state:
            spawner.environment["OAUTH2_ACCESS_TOKEN"] = auth_state['access_token']
        # others are lti_user_id, id, integration_id
        if 'oauth_user' in auth_state:
            for k in ['login_id', 'name', 'sortable_name', 'primary_email']:
                if k in auth_state['oauth_user']:
                    spawner.environment[f"OAUTH2_{k.upper()}"] = auth_state['oauth_user'][k]


class LocalCanvasOAuthenticator(LocalAuthenticator, CanvasOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
