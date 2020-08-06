import os
import logging
import hashlib
import re

import json
import jwt
import time

from josepy.jws import JWS
from josepy.jws import Header

from typing import Any, Dict, List, cast

from traitlets.config import LoggingConfigurable
from traitlets import Unicode, Bool, Union
from .traitlets import Callable


from .oauth2 import OAuthenticator
from .oauth2 import guess_callback_uri
from .oauth2 import OAuthLoginHandler
from .oauth2 import OAuthCallbackHandler

from tornado.httpclient import AsyncHTTPClient
from tornado.web import HTTPError
from tornado.httputil import url_concat
from tornado.web import RequestHandler


class LTI13LoginHandler(OAuthLoginHandler):
    """
    LTI 1.3 login handler
    """

    def _process_login_request(self, iss, login_hint, lti_message_hint):
        """
        Validates required login arguments sent from platform and then uses the authorize_redirect() method
        to redirect users to the authorization url.
        """

        #redirect_uri = guess_callback_uri('http', self.request.host, self.hub.server.base_url)
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('redirect_uri: %r', redirect_uri)
        state = self.get_state()
        self.set_state_cookie(state)
        
        # TODO: validate that received nonces haven't been received before
        # and that they are within the time-based tolerance window
        
        nonce_raw = hashlib.sha256(state.encode())
        extra_params = {}
        extra_params['nonce'] = nonce_raw.hexdigest()
        extra_params['state'] = state
        extra_params['response_mode'] = 'form_post'
        extra_params['prompt'] = 'none'
        extra_params['login_hint'] = login_hint
        extra_params['lti_message_hint'] = lti_message_hint
        
        self.authorize_redirect(
            redirect_uri = redirect_uri,
            client_id = self.authenticator.client_id,
            scope = self.authenticator.scope,
            extra_params = extra_params,
            response_type = 'id_token',
        )

    def post(self):
        iss = self.get_argument('iss')
        login_hint = self.get_argument('login_hint')
        lti_message_hint = self.get_argument('lti_message_hint')

        self._process_login_request(iss, login_hint, lti_message_hint)
        
    def get(self):
        iss = self.get_argument('iss')
        login_hint = self.get_argument('login_hint')
        lti_message_hint = self.get_argument('lti_message_hint')

        self._process_login_request(iss, login_hint, lti_message_hint)

class LTI13CallbackHandler(OAuthCallbackHandler):
    """
    LTI 1.3 call back handler
    """

    async def get(self):
        """
        Overrides the upstream get handler which is not allowed in LTI 1.3
        """
        raise HTTPError(400, "OAuth callback request not allowed")

    async def post(self):
        """
        implements the LTI 1.3 CallBackHandler
        """
        self.check_state()
        user = await self.login_user()
        if user is None:
            raise HTTPError(403, 'User missing or null')
        self.log.debug('Redirecting user %s to %s' % (user.id, self.get_next_url(user)))
        self.redirect(self.get_next_url(user))
       

class LTI13OAuthenticator(OAuthenticator):
    """Authenticator used with LTI 1.3 requests"""

    login_service = 'LTI13OAuthenticator'

    # handlers used for login, callback, and jwks endpoints
    login_handler = LTI13LoginHandler
    callback_handler = LTI13CallbackHandler


    jwks_endpoint = Unicode(
        os.environ.get('OAUTH2_JWKS_ENDPOINT', ''),
        config=True,
        help="""
        The platform's base endpoint used when redirecting requests to the platform
        after receiving the initial login request.
        """,
    ).tag(config=True)

    username_key = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'sub')), Callable()],
        config=True,
        help="""
        Userdata username key from returned json for USERDATA_URL.

        Can be a string key name or a callable that accepts the returned
        json (as a dict) and returns the username.  The callable is useful
        e.g. for extracting the username from a nested object in the
        response.
        """,
    )

    jwk_verify = Bool(
        os.environ.get('OAUTH2_JWK_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request",
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request",
    )

    oauth_callback_url = Unicode(
        os.getenv('LTI13_CALLBACK_URL', ''),
        config=True,
        help="""Callback URL to use.
        Should match the redirect_uri sent from the platform during the
        initial login request.""",
    ).tag(config=True)

    def http_client(self):
        return AsyncHTTPClient(force_instance=True, defaults=dict(validate_cert=self.tls_verify))

    async def authenticate(
        self, handler: LTI13LoginHandler, data: Dict[str, str] = None
    ) -> Dict[str, str]:
        """
        Overrides authenticate from base class to handle LTI 1.3 authentication requests.

        Args:
          handler: handler object
          data: authentication dictionary

        Returns:
          Authentication dictionary
        """
        
        id_token = handler.get_argument('id_token') 
        # get signing key id
        kid = jwt.get_unverified_header(id_token)['kid'] 
        
        if self.jwk_verify:
            # get jwks endpoint and token to use as args to decode jwt.
            http_client = self.http_client()
            resp = await http_client.fetch(self.jwks_endpoint)
            
            jwks = json.loads(resp.body)
            self.log.debug('Retrieved jwks from lms platform %s' % jwks)

            if not jwks or 'keys' not in jwks:
                raise ValueError('Platform endpoint returned an empty jwks')

            key = None
            for jwk in jwks['keys']:
                if jwk['kid'] != kid:
                    continue
                key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                self.log.debug('Get keys from jwks dict  %s' % key)

            if key is None:
                error_msg = f'There is not a key matching in the platform jwks for the jwt received. kid: {kid}'
                raise ValueError(error_msg)

        id_token = jwt.decode(id_token, key=key, verify=self.jwk_verify, audience=self.client_id, algorithms=['RS256'])

        self.log.debug('Decoded JWT is %s' % id_token)

        
        if callable(self.username_key):
            name = self.username_key(id_token)
        else:
            name = id_token.get(self.username_key)
            if not name:
                self.log.error(
                    "OAuth user contains no key %s: %s", self.username_key, id_token
                )
                return

        course_id = id_token['https://purl.imsglobal.org/spec/lti/claim/context']['label']
        self.log.debug('Normalized course label is %s' % course_id)

        # set role to learner role if instructor roles is not sent with the request
        user_role = 'Learner'
        for role in id_token['https://purl.imsglobal.org/spec/lti/claim/roles']:
            if role.find('Instructor') >= 1:
                user_role = 'Instructor'
                break
        
        self.log.debug('user_role is %s' % user_role)

        lms_user_id = id_token.get('sub', '')
        
        # Values for the send-grades functionality
        course_lineitems = []
        if 'https://purl.imsglobal.org/spec/lti-ags/claim/endpoint' in id_token:
            course_lineitems = id_token['https://purl.imsglobal.org/spec/lti-ags/claim/endpoint'].get(
                'lineitems'
            )


        return {
            'name': name,
            'auth_state': {
                'course_id': course_id,
                'user_role': user_role,
                'course_lineitems': course_lineitems,
                'lms_user_id': lms_user_id,
                'id_token': 'id_token'
            },
        }