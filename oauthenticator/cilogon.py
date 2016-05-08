"""CILogon OAuthAuthenticator for JupyterHub

Usese OAuth 1.0a with cilogon.org

Setup:

1. generate rsa keypair:

       openssl genrsa -out oauth-privkey.pem 2048
       openssl rsa -in oauth-privkey.pem -pubout -out oauth-pubkey.pem

2. generate certificate request (interactive)

       openssl req -new -key oauth-privkey.pem -out oauth-cert.csr

3. register with CILogon: https://cilogon.org/oauth/register
4. save your client_id from the request.
   It will be used as CILOGON_CLIENT_ID env

Caveats:

- For user whitelist/admin names,
  usernames will be email addresses where '@' is replaced with '.'

"""

import errno
import os
import pwd
from urllib.parse import parse_qs

try:
    from OpenSSL.crypto import load_certificate, FILETYPE_PEM
except ImportError:
    raise ImportError("CILogon OAuth requires PyOpenSSL")

try:
    from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_TYPE_QUERY, Client as OAuthClient
except ImportError:
    raise ImportError("CILogon requires oauthlib")

from tornado import gen
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.httputil import url_concat

from traitlets.config import Configurable

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.utils import url_path_join as ujoin

from traitlets import Unicode, Instance

from .oauth2 import OAuthenticator


class CILogonHandler(BaseHandler):
    """OAuth handler for redirecting to CILogon delegator"""
    
    @gen.coroutine
    def get(self):
        token = yield self.authenticator.get_oauth_token()
        self.redirect(url_concat(self.authenticator.authorization_url,
            {'oauth_token': token, 'cilogon_skin': self.authenticator.cilogon_skin}))


class CILogonOAuthenticator(OAuthenticator):
    """CILogon OAuthenticator
    
    required env:
    
    CILOGON_CLIENT_ID - the client ID for CILogon OAuth
    CILOGON_RSA_KEY_PATH - path to file containing rsa private key
    CILOGON_CSR_PATH - path to file certificate request (.csr)
    """
    login_service = "CILogon"
    
    authorization_url = "https://cilogon.org/delegate"
    cilogon_skin = "xsede"
    oauth_url = "https://cilogon.org/oauth"
    
    login_handler = CILogonHandler
    client_id_env = 'CILOGON_CLIENT_ID'
    
    rsa_key_path = Unicode(config=True)
    def _rsa_key_path_default(self):
        return os.getenv('CILOGON_RSA_KEY_PATH') or 'oauth-privkey.pem'
    
    rsa_key = Unicode()
    def _rsa_key_default(self):
        with open(self.rsa_key_path) as f:
            return f.read()
    
    certreq_path = Unicode(config=True)
    def _certreq_path_default(self):
        return os.getenv('CILOGON_CSR_PATH') or 'oauth-certreq.csr'
    
    certreq = Unicode()
    def _certreq_default(self):
        # read certreq. CILogon API can't handle standard BEGIN/END lines, so strip them
        lines = []
        with open(self.certreq_path) as f:
            for line in f:
                if not line.isspace() and '----' not in line:
                    lines.append(line)
        return ''.join(lines)
    
    user_cert_dir = Unicode(config=True,
        help="""Directory in which to store user credentials.
        This directory will be made user-private.
        If not specified, user credentials will not be stored.
        """
    )
    def _user_cert_dir_changed(self, name, old, new):
        # ensure dir exists
        if not new:
            return
        try:
            os.mkdir(new)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        # make it private
        os.chmod(new, 0o700)
        # double-check that it's private
        mode = os.stat(new).st_mode
        if mode & 0o077:
            raise IOError("Bad permissions on user cert dir %r: %o" % (new, mode))

    oauth_client = Instance(OAuthClient)
    def _oauth_client_default(self):
        return OAuthClient(
            self.client_id,
            rsa_key=self.rsa_key,
            signature_method=SIGNATURE_RSA,
            signature_type=SIGNATURE_TYPE_QUERY,
        )
    
    client = Instance(AsyncHTTPClient, args=())
    
    @gen.coroutine
    def get_oauth_token(self):
        """Get the temporary OAuth token"""
        uri = url_concat(ujoin(self.oauth_url, "initiate"), {
            'oauth_callback': self.oauth_callback_url,
            'certreq': self.certreq,
        })
        uri, _, _ = self.oauth_client.sign(uri)
        req = HTTPRequest(uri)
        # FIXME: handle failure (CILogon replies with 200 on failure)
        resp = yield self.client.fetch(req)
        reply = resp.body.decode('utf8', 'replace')
        credentials = parse_qs(reply)
        return credentials['oauth_token'][0]
    
    @gen.coroutine
    def get_user_token(self, token, verifier):
        """Get a user token from an oauth callback parameters"""
        uri = url_concat(ujoin(self.oauth_url, 'token'), {
            'oauth_token': token,
            'oauth_verifier': verifier,
        })
        uri, _, _ = self.oauth_client.sign(uri)
        resp = yield self.client.fetch(uri)
        # FIXME: handle failure
        reply = resp.body.decode('utf8', 'replace')
        return parse_qs(reply)['oauth_token'][0]
    
    @gen.coroutine
    def username_from_token(self, token):
        """Turn a user token into a username"""
        uri = url_concat(ujoin(self.oauth_url, 'getcert'), {
            'oauth_token': token,
        })
        uri, _, _ = self.oauth_client.sign(uri)
        resp = yield self.client.fetch(uri)
        # FIXME: handle failure
        reply = resp.body.decode('utf8', 'replace')
        _, cert_txt = reply.split('\n', 1)
        cert = load_certificate(FILETYPE_PEM, cert_txt)
        username = None
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name().decode('ascii', 'replace') == 'subjectAltName':
                data = ext.get_data()
                # cert starts with some weird bytes. Not sure why or if they are consistent
                username = data[4:].decode('utf8').lower()
                # workaround notebook bug not handling @
                username = username.replace('@', '.')
                break
        if username is None:
            raise ValueError("Failed to get username from cert: %s", cert_txt)
        
        return username, cert_txt
    
    def _user_cert_path(self, username):
        return os.path.join(self.user_cert_dir, username + '.crt')
    
    def save_user_cert(self, username, cert):
        """Save the certificate for a given user in self.user_cert_dir"""
        if not self.user_cert_dir:
            return
        cert_path = self._user_cert_path(username)
        self.log.info("Saving cert for %s in %s", username, cert_path)
        with open(cert_path, 'w') as f:
            f.write(cert)
    
    def user_cert(self, username):
        """Get the certificate for a user by name"""
        if not self.user_cert_dir:
            # not storing certs
            return
        # FIXME: handle cert file missing?
        with open(self._user_cert_path(username)) as f:
            return f.read()
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        """Called on the OAuth callback"""
        token = yield self.get_user_token(
            handler.get_argument('oauth_token'),
            handler.get_argument('oauth_verifier'),
        )
        username, cert = yield self.username_from_token(token)
        if not username:
            return
        self.save_user_cert(username, cert)
        return username


class LocalCILogonOAuthenticator(LocalAuthenticator, CILogonOAuthenticator):
    """A version that mixes in local system user creation"""
    pass


class CILogonSpawnerMixin(Configurable):
    """Spawner Mixin for staging the CILogon cert file"""
    
    cert_file_path = Unicode("cilogon.crt", config=True,
        help="The path (relative to home) where the CILogon cert should be placed.")
    
    def get_user_info(self):
        """Get the user's home dir, uid, gid, for resolving relative cert_file_path.
        
        Returns a dict with 'home', 'uid', 'gid' keys.
        
        By default, populated from pwd.getpwname(self.user.name).
        """
        pw_struct = pwd.getpwnam(self.user.name)
        return {
            'home': pw_struct.pw_dir,
            'uid': pw_struct.pw_uid,
            'gid': pw_struct.pw_gid,
        }
    
    _cert = None
    @property
    def cert(self):
        if self._cert is None:
            self._cert = self.authenticator.user_cert(self.user.name)
        return self._cert
    
    def stage_cert_file(self):
        """Stage the CILogon user cert for the spawner.
        
        Override for Spawners not on the local filesystem.
        """
        if not self.cert:
            self.log.info("No cert found for %s", self.user.name)
        
        uinfo = self.get_user_info()
        dst = os.path.join(uinfo['home'], self.cert_file_path)
        self.log.info("Staging cert for %s: %s", self.user.name, dst)
        
        with open(dst, 'w') as f:
            fd = f.fileno()
            os.fchmod(fd, 0o600) # make private before writing content
            f.write(self.cert)
            # set user as owner
            os.fchown(fd, uinfo['uid'], uinfo['gid'])
    
    @gen.coroutine
    def start(self):
        yield gen.maybe_future(self.stage_cert_file())
        result = yield gen.maybe_future(super().start())
        return result
    
    def unstage_cert_file(self):
        """Unstage user cert
        
        called after stopping
        """
        uinfo = self.get_user_info()
        dst = os.path.join(uinfo['home'], self.cert_file_path)
        if not os.path.exists(dst):
            self.log.debug("No cert for %s: %s", self.user.name, dst)
            return
        self.log.info("Unstaging cert for %s: %s", self.user.name, dst)
        try:
            os.remove(dst)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            self.log.error("Failed to unstage cert for %s (%s): %s",
                self.user.name, dst, e)
        
    @gen.coroutine
    def stop(self):
        result = yield gen.maybe_future(super().stop())
        yield gen.maybe_future(self.unstage_cert_file())
        return result

